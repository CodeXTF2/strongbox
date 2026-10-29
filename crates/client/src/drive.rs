//! An unlocked drive: path-based operations over sealed directory nodes.
//!
//! Every mutation is a single atomic `/v1/commit` with optimistic concurrency. On a version
//! conflict (another device changed the same directory) the operation is re-planned against
//! fresh state and retried.

use std::collections::VecDeque;
use std::fs::File;
use std::future::Future;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use strongbox_core::account::AccountKeys;
use strongbox_core::aead::TAG_LEN;
use strongbox_core::content::{Decryptor, Encryptor};
use strongbox_core::keyslot::{Keyslot, KeyslotKind, Unlock};
use strongbox_core::node::{self, Dir, DirRef, Entry, FileEntry, Timestamp, TrashInfo};
use strongbox_core::{recovery, Id, Key};
use strongbox_fido::Authenticator;
use strongbox_proto::{CommitAction, CommitOp, CommitRequest, UsageResponse};
use tokio::task::{JoinHandle, JoinSet};

use crate::api::Api;
use crate::profile::{Profile, VersionCache};
use crate::session::enroll_keyslot;
use crate::{Error, Result};

const MAX_RETRIES: usize = 8;
/// Chunk transfers kept in flight per file.
const PARALLEL_TRANSFERS: usize = 4;
const MAX_SEARCH_RESULTS: usize = 500;
/// Reserved root entry that holds trashed items. Hidden from listings and not addressable
/// by path; only the trash methods touch it.
pub const TRASH_NAME: &str = ".strongbox-trash";

/// Progress callback: `(bytes done, bytes total)`.
pub type Progress<'a> = &'a (dyn Fn(u64, u64) + Send + Sync);

/// What an upload does when the target name is already taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnConflict {
    /// Replace an existing file (its old content is deleted).
    #[default]
    Replace,
    /// Keep both, storing the new one as "name (1).ext".
    KeepBoth,
    /// Fail with [`Error::Exists`].
    Fail,
}

#[derive(Clone, Copy, Default)]
pub struct TransferOptions<'a> {
    pub progress: Option<Progress<'a>>,
    /// Checked between chunks; setting it aborts the transfer with [`Error::Cancelled`].
    pub cancel: Option<&'a AtomicBool>,
    pub on_conflict: OnConflict,
}

impl TransferOptions<'_> {
    pub(crate) fn check_cancel(&self) -> Result<()> {
        match self.cancel {
            Some(c) if c.load(Ordering::Relaxed) => Err(Error::Cancelled),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ListEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SearchHit {
    /// Full path of the match.
    pub path: String,
    /// Path of the directory containing it.
    pub parent: String,
    #[serde(flatten)]
    pub entry: ListEntry,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TrashEntry {
    /// Opaque handle for restore / delete.
    pub id: String,
    pub name: String,
    /// Directory it was deleted from.
    pub parent: String,
    pub deleted_at: Timestamp,
    pub is_dir: bool,
    pub size: u64,
}

pub struct Drive {
    api: Api,
    profile: Profile,
    /// `None` once wiped (panic / lock): the account master key and everything derived from it
    /// on demand are gone, and every operation fails.
    keys: std::sync::RwLock<Option<AccountKeys>>,
    versions: Mutex<VersionCache>,
}

struct Loaded {
    id: Id,
    key: Key,
    version: u64,
    dir: Dir,
}

type PlanFuture<'f, T> = Pin<Box<dyn Future<Output = Result<Plan<T>>> + Send + 'f>>;

/// A planned commit and the value to return if it succeeds.
struct Plan<T> {
    ops: Vec<CommitOp>,
    delete_blobs: Vec<Id>,
    value: T,
}

/// Aborts the task when dropped, so early returns do not leave transfers running.
struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn wiped() -> Error {
    Error::Invalid("the drive is locked".into())
}

fn now_ms() -> Timestamp {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn to_ms(t: std::io::Result<SystemTime>) -> Option<Timestamp> {
    t.ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as i64)
}

/// Split "/a/b/c" into validated components. The trash directory is not addressable.
fn components(path: &str) -> Result<Vec<String>> {
    let comps = path
        .split('/')
        .filter(|c| !c.is_empty())
        .map(|c| {
            node::validate_name(c)
                .map(|_| c.to_string())
                .map_err(Error::from)
        })
        .collect::<Result<Vec<_>>>()?;
    if comps.first().is_some_and(|c| c == TRASH_NAME) {
        return Err(Error::Invalid(format!("{TRASH_NAME} is a reserved name")));
    }
    Ok(comps)
}

fn path_of(comps: &[String]) -> String {
    format!("/{}", comps.join("/"))
}

fn parent_and_name(path: &str) -> Result<(Vec<String>, String)> {
    let mut comps = components(path)?;
    let name = comps
        .pop()
        .ok_or_else(|| Error::Invalid("path refers to the root directory".into()))?;
    Ok((comps, name))
}

fn put_op(d: &Loaded) -> Result<CommitOp> {
    Ok(CommitOp {
        id: d.id,
        expect_version: d.version,
        action: CommitAction::Put {
            data: node::seal_dir(&d.key, &d.id, d.version + 1, &d.dir)?,
        },
    })
}

fn list_entry(name: &str, e: &Entry) -> ListEntry {
    match e {
        Entry::File(f) => ListEntry {
            name: name.to_string(),
            is_dir: false,
            size: f.content.size,
            mtime: f.mtime,
        },
        Entry::Dir(r) => ListEntry {
            name: name.to_string(),
            is_dir: true,
            size: 0,
            mtime: r.mtime,
        },
    }
}

/// `name` if free in `dir`, otherwise "stem (n).ext" for the first free n.
fn unique_name(dir: &Dir, name: &str) -> String {
    if !dir.entries.contains_key(name) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    };
    (1..)
        .map(|n| format!("{stem} ({n}){ext}"))
        .find(|c| !dir.entries.contains_key(c))
        .unwrap()
}

/// Make a remote name safe as a local file name on every platform (no path separators,
/// no characters or device names Windows rejects). Remote names come from other devices of
/// the same account, but must never be able to escape the chosen download folder.
pub fn local_safe_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if s.is_empty() || reserved {
        s.insert(0, '_');
    }
    s
}

/// Fail if two entries of one remote folder would get the same local name (e.g. `a:b` and
/// `a_b`, or names differing only in case), since the second download would overwrite the first.
pub fn check_local_name_clashes<'a>(names: impl Iterator<Item = &'a String>) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for n in names {
        let local = local_safe_name(n);
        if !seen.insert(local.to_lowercase()) {
            return Err(Error::Invalid(format!(
                "“{n}” would be saved under the same name as another item in its folder (“{local}”), so nothing was downloaded. Rename one of them first"
            )));
        }
    }
    Ok(())
}

/// `path`, or "path (n)" if it already exists locally.
pub fn unique_local_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name.as_str(), ""),
    };
    (1..)
        .map(|n| path.with_file_name(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

impl Drive {
    pub(crate) fn new(api: Api, profile: Profile, keys: AccountKeys) -> Result<Self> {
        let versions = Mutex::new(VersionCache::open(&profile)?);
        Ok(Drive {
            api,
            profile,
            keys: std::sync::RwLock::new(Some(keys)),
            versions,
        })
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// Root directory id and key (fails once wiped). The guard is never held across an await.
    fn root(&self) -> Result<(Id, Key)> {
        let keys = self.keys.read().unwrap();
        let k = keys.as_ref().ok_or_else(wiped)?;
        Ok((k.root_id(), k.root_key()))
    }

    fn amk(&self) -> Result<Key> {
        Ok(self
            .keys
            .read()
            .unwrap()
            .as_ref()
            .ok_or_else(wiped)?
            .amk()
            .clone())
    }

    /// Securely erase the account master key now, even while other tasks still hold this
    /// drive. `Key` zeroizes on drop (volatile writes + compiler fence, i.e. what
    /// RtlSecureZeroMemory does), so taking it out of the lock wipes it immediately. Keys that
    /// in-flight operations derived (directory and content keys) are zeroized as those
    /// operations end; cancel them first. Every later call fails.
    pub fn wipe(&self) {
        drop(self.keys.write().unwrap_or_else(|e| e.into_inner()).take());
    }

    pub fn is_wiped(&self) -> bool {
        self.keys.read().map(|k| k.is_none()).unwrap_or(true)
    }

    /// End the server session without consuming the drive (used after [`Drive::wipe`]).
    pub async fn end_session(&self) -> Result<()> {
        self.api.logout().await
    }

    async fn load(&self, id: Id, key: &Key) -> Result<Option<Loaded>> {
        let Some((version, data)) = self.api.get_node(&id).await? else {
            // The root is never deleted, so a server that "loses" one we have seen is hiding
            // the drive (and would get us to create an empty one in its place).
            if self.root().is_ok_and(|(root, _)| root == id) {
                if let Some(seen) = self.versions.lock().unwrap().seen(&id) {
                    return Err(Error::Rollback { seen, got: 0 });
                }
            }
            return Ok(None);
        };
        self.versions.lock().unwrap().check(&id, version)?;
        let dir = node::open_dir(key, &id, version, &data)?;
        // Persist right away so rollback detection survives a restart, not only commits.
        let mut v = self.versions.lock().unwrap();
        if v.record(id, version) {
            v.save()?;
        }
        Ok(Some(Loaded {
            id,
            key: key.clone(),
            version,
            dir,
        }))
    }

    pub(crate) async fn ensure_root(&self) -> Result<()> {
        let (id, key) = self.root()?;
        if self.load(id, &key).await?.is_some() {
            return Ok(());
        }
        let root = Loaded {
            id,
            key,
            version: 0,
            dir: Dir::default(),
        };
        match self
            .api
            .commit(&CommitRequest {
                ops: vec![put_op(&root)?],
                delete_blobs: vec![],
            })
            .await
        {
            Ok(_) | Err(Error::Conflict(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    async fn walk(&self, comps: &[String]) -> Result<Loaded> {
        let (root_id, root_key) = self.root()?;
        let mut cur = match self.load(root_id, &root_key).await? {
            Some(r) => r,
            None => {
                self.ensure_root().await?;
                self.load(root_id, &root_key)
                    .await?
                    .ok_or_else(|| Error::NotFound("/".into()))?
            }
        };
        for (i, c) in comps.iter().enumerate() {
            let (id, key) = match cur.dir.entries.get(c) {
                Some(Entry::Dir(d)) => (d.id, d.key.clone()),
                Some(Entry::File(_)) => {
                    return Err(Error::Invalid(format!(
                        "{} is a file",
                        comps[..=i].join("/")
                    )))
                }
                None => return Err(Error::NotFound(format!("/{}", comps[..=i].join("/")))),
            };
            cur = self
                .load(id, &key)
                .await?
                .ok_or_else(|| Error::NotFound(format!("/{}", comps[..=i].join("/"))))?;
        }
        Ok(cur)
    }

    /// Plan-and-commit loop with conflict retry.
    async fn commit_with_retry<'f, T>(
        &self,
        mut plan: impl FnMut() -> PlanFuture<'f, T>,
    ) -> Result<T> {
        for attempt in 0..MAX_RETRIES {
            let p = plan().await?;
            let req = CommitRequest {
                ops: p.ops,
                delete_blobs: p.delete_blobs,
            };
            match self.api.commit(&req).await {
                Ok(resp) => {
                    let mut v = self.versions.lock().unwrap();
                    for nv in resp.versions {
                        v.record(nv.id, nv.version);
                    }
                    v.save()?;
                    return Ok(p.value);
                }
                Err(Error::Conflict(_)) if attempt + 1 < MAX_RETRIES => {
                    tokio::time::sleep(Duration::from_millis(50 << attempt)).await;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    /// Collect every directory node and blob under (and including) a directory.
    async fn subtree(&self, id: Id, key: Key) -> Result<(Vec<(Id, u64)>, Vec<Id>)> {
        let (mut nodes, mut blobs) = (Vec::new(), Vec::new());
        let mut stack = vec![(id, key)];
        while let Some((id, key)) = stack.pop() {
            let Some(d) = self.load(id, &key).await? else {
                continue;
            };
            nodes.push((d.id, d.version));
            for e in d.dir.entries.values() {
                match e {
                    Entry::File(f) => blobs.extend(f.content.chunk_ids()),
                    Entry::Dir(r) => stack.push((r.id, r.key.clone())),
                }
            }
        }
        Ok((nodes, blobs))
    }

    /// Commit ops and blob deletions that permanently destroy `entry` (already unlinked).
    async fn destroy_ops(&self, entry: Entry) -> Result<(Vec<CommitOp>, Vec<Id>)> {
        match entry {
            Entry::File(f) => Ok((vec![], f.content.chunk_ids())),
            Entry::Dir(r) => {
                let (nodes, blobs) = self.subtree(r.id, r.key).await?;
                let ops = nodes
                    .into_iter()
                    .map(|(id, version)| CommitOp {
                        id,
                        expect_version: version,
                        action: CommitAction::Delete,
                    })
                    .collect();
                Ok((ops, blobs))
            }
        }
    }

    pub async fn list(&self, path: &str) -> Result<Vec<ListEntry>> {
        let comps = components(path)?;
        let d = self.walk(&comps).await?;
        Ok(d.dir
            .entries
            .iter()
            .filter(|(name, _)| !(comps.is_empty() && name.as_str() == TRASH_NAME))
            .map(|(name, e)| list_entry(name, e))
            .collect())
    }

    pub async fn mkdir(&self, path: &str) -> Result<()> {
        let (parent, name) = parent_and_name(path)?;
        let (parent, name) = (&parent, &name);
        self.commit_with_retry(|| {
            Box::pin(async move {
                let mut p = self.walk(parent).await?;
                if p.dir.entries.contains_key(name) {
                    return Err(Error::Exists(path.to_string()));
                }
                let child = Loaded {
                    id: Id::random(),
                    key: Key::random(),
                    version: 0,
                    dir: Dir::default(),
                };
                p.dir.entries.insert(
                    name.clone(),
                    Entry::Dir(DirRef {
                        id: child.id,
                        key: child.key.clone(),
                        mtime: now_ms(),
                        trashed: None,
                    }),
                );
                Ok(Plan {
                    ops: vec![put_op(&p)?, put_op(&child)?],
                    delete_blobs: vec![],
                    value: (),
                })
            })
        })
        .await
    }

    /// Create a directory and any missing parents. Existing directories are fine.
    pub async fn mkdir_p(&self, path: &str) -> Result<()> {
        let comps = components(path)?;
        for i in 1..=comps.len() {
            match self.mkdir(&path_of(&comps[..i])).await {
                Ok(()) => {}
                Err(Error::Exists(_)) => {
                    // Make sure it is a directory, not a file of the same name.
                    self.walk(&comps[..i]).await?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Encrypt and upload a local file into directory `remote_dir`, replacing a file of the
    /// same name. Returns the stored name.
    pub async fn upload(
        &self,
        local: &Path,
        remote_dir: &str,
        progress: Option<Progress<'_>>,
    ) -> Result<String> {
        self.upload_with(
            local,
            remote_dir,
            TransferOptions {
                progress,
                ..Default::default()
            },
        )
        .await
    }

    /// Encrypt and upload a local file into directory `remote_dir`. Memory use is bounded to a
    /// few chunks regardless of file size. Returns the stored name (which differs from the
    /// local one with [`OnConflict::KeepBoth`]).
    pub async fn upload_with(
        &self,
        local: &Path,
        remote_dir: &str,
        opts: TransferOptions<'_>,
    ) -> Result<String> {
        let name = local
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::Invalid("local path has no usable file name".into()))?
            .to_string();
        node::validate_name(&name)?;
        let dir = components(remote_dir)?;
        if dir.is_empty() && name == TRASH_NAME {
            return Err(Error::Invalid(format!("{TRASH_NAME} is a reserved name")));
        }
        let meta = std::fs::metadata(local)?;
        if !meta.is_file() {
            return Err(Error::Invalid(format!(
                "{} is not a regular file",
                local.display()
            )));
        }
        let mtime = to_ms(meta.modified()).unwrap_or_else(now_ms);
        let ctime = to_ms(meta.created()).unwrap_or(mtime);
        let total = strongbox_core::padding::content_len(meta.len());

        // Encrypt on a blocking thread, upload a few chunks concurrently on this task; the
        // channel and the in-flight cap bound memory.
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let file = File::open(local)?;
        let encryptor = tokio::task::spawn_blocking(move || -> strongbox_core::Result<_> {
            let mut enc = Encryptor::new(BufReader::new(file));
            while let Some(chunk) = enc.next_chunk()? {
                if tx.blocking_send(chunk).is_err() {
                    return Err(strongbox_core::Error::Malformed("upload aborted"));
                }
            }
            enc.finish()
        });

        let mut sent = Vec::new();
        let result: Result<()> = async {
            let mut inflight = JoinSet::new();
            let mut done = 0u64;
            let mut eof = false;
            loop {
                opts.check_cancel()?;
                if !eof && inflight.len() < PARALLEL_TRANSFERS {
                    match rx.recv().await {
                        Some(chunk) => {
                            let api = self.api.clone();
                            let len = (chunk.data.len() - TAG_LEN) as u64;
                            sent.push(chunk.id);
                            inflight.spawn(async move {
                                api.put_blob(&chunk.id, chunk.data).await.map(|_| len)
                            });
                            continue;
                        }
                        None => eof = true,
                    }
                }
                match inflight.join_next().await {
                    Some(r) => {
                        done +=
                            r.map_err(|e| Error::Invalid(format!("upload task failed: {e}")))??;
                        if let Some(p) = opts.progress {
                            p(done.min(total), total);
                        }
                    }
                    None => return Ok(()),
                }
            }
        }
        .await;
        drop(rx);
        let content = encryptor.await.expect("encryptor panicked");
        let committed = match (result, content) {
            (Ok(()), Ok(content)) => {
                let (dir, name, content) = (&dir, &name, &content);
                self.commit_with_retry(|| {
                    Box::pin(async move {
                        let mut d = self.walk(dir).await?;
                        let (stored, old_blobs) = match (d.dir.entries.get(name), opts.on_conflict)
                        {
                            (None, _) => (name.clone(), vec![]),
                            (Some(_), OnConflict::KeepBoth) => (unique_name(&d.dir, name), vec![]),
                            (Some(Entry::File(old)), OnConflict::Replace) => {
                                (name.clone(), old.content.chunk_ids())
                            }
                            (Some(Entry::Dir(_)), OnConflict::Replace) => {
                                return Err(Error::Exists(format!("a folder named {name}")))
                            }
                            (Some(_), OnConflict::Fail) => return Err(Error::Exists(name.clone())),
                        };
                        let entry = FileEntry {
                            content: content.clone(),
                            mtime,
                            ctime,
                            trashed: None,
                        };
                        d.dir.entries.insert(stored.clone(), Entry::File(entry));
                        Ok(Plan {
                            ops: vec![put_op(&d)?],
                            delete_blobs: old_blobs,
                            value: stored,
                        })
                    })
                })
                .await
            }
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => Err(e.into()),
        };
        if committed.is_err() {
            for id in sent {
                let _ = self.api.delete_blob(&id).await;
            }
        }
        committed
    }

    async fn file_entry(&self, remote: &str) -> Result<FileEntry> {
        let (parent, name) = parent_and_name(remote)?;
        let d = self.walk(&parent).await?;
        match d.dir.entries.get(&name) {
            Some(Entry::File(f)) => Ok(f.clone()),
            Some(Entry::Dir(_)) => Err(Error::Invalid(format!("{remote} is a directory"))),
            None => Err(Error::NotFound(remote.to_string())),
        }
    }

    /// Fetch (a few chunks ahead), authenticate and decrypt a file into `out`.
    async fn fetch_into<W: Write>(
        &self,
        f: &FileEntry,
        out: W,
        opts: TransferOptions<'_>,
    ) -> Result<W> {
        let mut dec = Decryptor::new(&f.content, out);
        let max_len = f.content.chunk_size as usize + TAG_LEN;
        let mut ids = f.content.chunk_ids().into_iter();
        let mut pending = VecDeque::new();
        let mut done = 0u64;
        loop {
            while pending.len() < PARALLEL_TRANSFERS {
                let Some(id) = ids.next() else { break };
                let api = self.api.clone();
                pending.push_back(AbortOnDrop(tokio::spawn(async move {
                    api.get_blob(&id, max_len).await
                })));
            }
            let Some(mut next) = pending.pop_front() else {
                break;
            };
            opts.check_cancel()?;
            let data = (&mut next.0)
                .await
                .map_err(|e| Error::Invalid(format!("download task failed: {e}")))??;
            done += data.len().saturating_sub(TAG_LEN) as u64;
            tokio::task::block_in_place(|| dec.push(&data))?;
            if let Some(p) = opts.progress {
                p(done.min(f.content.padded_size), f.content.padded_size);
            }
        }
        Ok(dec.finish()?)
    }

    /// Download and decrypt `remote` to `local`. The file only appears at `local` once every
    /// chunk has been authenticated and the whole-file hash matches.
    pub async fn download(
        &self,
        remote: &str,
        local: &Path,
        progress: Option<Progress<'_>>,
    ) -> Result<()> {
        self.download_with(
            remote,
            local,
            TransferOptions {
                progress,
                ..Default::default()
            },
        )
        .await
    }

    pub async fn download_with(
        &self,
        remote: &str,
        local: &Path,
        opts: TransferOptions<'_>,
    ) -> Result<()> {
        let f = self.file_entry(remote).await?;
        self.download_entry(&f, local, opts).await
    }

    async fn download_entry(
        &self,
        f: &FileEntry,
        local: &Path,
        opts: TransferOptions<'_>,
    ) -> Result<()> {
        let tmp = local.with_file_name(format!(
            ".{}.fdpart",
            local
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("download")
        ));
        let result: Result<()> = async {
            let out = self
                .fetch_into(f, BufWriter::new(File::create(&tmp)?), opts)
                .await?;
            let file = out.into_inner().map_err(|e| e.into_error())?;
            let mtime = UNIX_EPOCH + Duration::from_millis(f.mtime.max(0) as u64);
            let _ = file.set_modified(mtime);
            drop(file);
            std::fs::rename(&tmp, local)?;
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// Download a directory tree into a new folder inside `local_parent` (named after the
    /// remote folder, made unique if needed). Returns the folder created.
    pub async fn download_dir(
        &self,
        remote: &str,
        local_parent: &Path,
        opts: TransferOptions<'_>,
    ) -> Result<PathBuf> {
        let comps = components(remote)?;
        let name = comps
            .last()
            .map_or("Strongbox".to_string(), |n| local_safe_name(n));
        let root = self.walk(&comps).await?;

        // Gather the tree first so progress can cover the whole folder.
        let mut dirs = vec![PathBuf::new()];
        let mut files = Vec::new();
        let mut stack = vec![(PathBuf::new(), root)];
        while let Some((rel, d)) = stack.pop() {
            check_local_name_clashes(d.dir.entries.keys())?;
            for (n, e) in &d.dir.entries {
                let child = rel.join(local_safe_name(n));
                match e {
                    Entry::File(f) => files.push((child, f.clone())),
                    Entry::Dir(r) => {
                        if let Some(sub) = self.load(r.id, &r.key).await? {
                            dirs.push(child.clone());
                            stack.push((child, sub));
                        }
                    }
                }
            }
        }
        let target = unique_local_path(local_parent.join(name));
        for d in &dirs {
            std::fs::create_dir_all(target.join(d))?;
        }
        let total: u64 = files.iter().map(|(_, f)| f.content.padded_size).sum();
        let mut base = 0u64;
        for (rel, f) in files {
            let progress = |done: u64, _| {
                if let Some(p) = opts.progress {
                    p(base + done, total);
                }
            };
            let sub = TransferOptions {
                progress: Some(&progress),
                ..opts
            };
            self.download_entry(&f, &target.join(rel), sub).await?;
            base += f.content.padded_size;
        }
        if let Some(p) = opts.progress {
            p(total, total);
        }
        Ok(target)
    }

    /// Decrypt a whole file into memory (for previews). Refuses files over `max_size`.
    pub async fn read_file(&self, remote: &str, max_size: u64) -> Result<Vec<u8>> {
        let f = self.file_entry(remote).await?;
        if f.content.size > max_size {
            return Err(Error::Invalid("file is too large to preview".into()));
        }
        self.fetch_into(
            &f,
            Vec::with_capacity(f.content.size as usize),
            TransferOptions::default(),
        )
        .await
    }

    /// Permanently remove a file, or a directory and everything under it.
    pub async fn remove(&self, path: &str) -> Result<()> {
        let (parent, name) = parent_and_name(path)?;
        let (parent, name) = (&parent, &name);
        self.commit_with_retry(|| {
            Box::pin(async move {
                let mut p = self.walk(parent).await?;
                let entry = p
                    .dir
                    .entries
                    .remove(name)
                    .ok_or_else(|| Error::NotFound(path.to_string()))?;
                let (mut ops, delete_blobs) = self.destroy_ops(entry).await?;
                ops.insert(0, put_op(&p)?);
                Ok(Plan {
                    ops,
                    delete_blobs,
                    value: (),
                })
            })
        })
        .await
    }

    /// Rename or move a file or directory.
    pub async fn rename(&self, from: &str, to: &str) -> Result<()> {
        let (src_parent, src_name) = parent_and_name(from)?;
        let (dst_parent, dst_name) = parent_and_name(to)?;
        if src_parent == dst_parent && src_name == dst_name {
            return Ok(());
        }
        if dst_parent.is_empty() && dst_name == TRASH_NAME {
            return Err(Error::Invalid(format!("{TRASH_NAME} is a reserved name")));
        }
        let mut src_full = src_parent.clone();
        src_full.push(src_name.clone());
        if dst_parent.starts_with(&src_full) {
            return Err(Error::Invalid("cannot move a folder into itself".into()));
        }
        let (src_parent, src_name, dst_parent, dst_name) =
            (&src_parent, &src_name, &dst_parent, &dst_name);
        self.commit_with_retry(|| {
            Box::pin(async move {
                let mut src = self.walk(src_parent).await?;
                let entry = src
                    .dir
                    .entries
                    .remove(src_name)
                    .ok_or_else(|| Error::NotFound(from.to_string()))?;
                if src_parent == dst_parent {
                    if src.dir.entries.contains_key(dst_name) {
                        return Err(Error::Exists(to.to_string()));
                    }
                    src.dir.entries.insert(dst_name.clone(), entry);
                    return Ok(Plan {
                        ops: vec![put_op(&src)?],
                        delete_blobs: vec![],
                        value: (),
                    });
                }
                let mut dst = self.walk(dst_parent).await?;
                if dst.dir.entries.contains_key(dst_name) {
                    return Err(Error::Exists(to.to_string()));
                }
                dst.dir.entries.insert(dst_name.clone(), entry);
                Ok(Plan {
                    ops: vec![put_op(&src)?, put_op(&dst)?],
                    delete_blobs: vec![],
                    value: (),
                })
            })
        })
        .await
    }

    /// Find entries whose name contains `query` (case-insensitive), anywhere in the drive
    /// except the trash. Everything is decrypted locally; the server only sees node fetches.
    pub async fn search(&self, query: &str) -> Result<Vec<SearchHit>> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Ok(vec![]);
        }
        let mut hits = Vec::new();
        let mut stack = vec![(Vec::<String>::new(), self.walk(&[]).await?)];
        while let Some((comps, d)) = stack.pop() {
            for (name, e) in &d.dir.entries {
                if comps.is_empty() && name == TRASH_NAME {
                    continue;
                }
                let mut child = comps.clone();
                child.push(name.clone());
                if name.to_lowercase().contains(&q) {
                    hits.push(SearchHit {
                        path: path_of(&child),
                        parent: path_of(&comps),
                        entry: list_entry(name, e),
                    });
                    if hits.len() >= MAX_SEARCH_RESULTS {
                        return Ok(hits);
                    }
                }
                if let Entry::Dir(r) = e {
                    if let Some(sub) = self.load(r.id, &r.key).await? {
                        stack.push((child, sub));
                    }
                }
            }
        }
        hits.sort_by_key(|h| h.entry.name.to_lowercase());
        Ok(hits)
    }

    /// The trash directory, optionally creating it (by adding it to `root`). Returns the
    /// loaded trash and whether `root` was modified.
    async fn trash_dir(&self, root: &mut Loaded, create: bool) -> Result<Option<(Loaded, bool)>> {
        match root.dir.entries.get(TRASH_NAME) {
            Some(Entry::Dir(r)) => {
                let t = self
                    .load(r.id, &r.key)
                    .await?
                    .ok_or_else(|| Error::NotFound("trash".into()))?;
                Ok(Some((t, false)))
            }
            Some(Entry::File(_)) => Err(Error::Invalid(format!("{TRASH_NAME} is a file"))),
            None if create => {
                let t = Loaded {
                    id: Id::random(),
                    key: Key::random(),
                    version: 0,
                    dir: Dir::default(),
                };
                root.dir.entries.insert(
                    TRASH_NAME.into(),
                    Entry::Dir(DirRef {
                        id: t.id,
                        key: t.key.clone(),
                        mtime: now_ms(),
                        trashed: None,
                    }),
                );
                Ok(Some((t, true)))
            }
            None => Ok(None),
        }
    }

    /// Move a file or folder to the trash. It keeps using quota until the trash is emptied.
    /// Returns its trash id (for [`Drive::restore`]).
    pub async fn trash(&self, path: &str) -> Result<String> {
        let (parent, name) = parent_and_name(path)?;
        let (parent, name) = (&parent, &name);
        self.commit_with_retry(|| {
            Box::pin(async move {
                let mut root = self.walk(&[]).await?;
                let mut sub = if parent.is_empty() {
                    None
                } else {
                    Some(self.walk(parent).await?)
                };
                let src = sub.as_mut().unwrap_or(&mut root);
                let mut entry = src
                    .dir
                    .entries
                    .remove(name)
                    .ok_or_else(|| Error::NotFound(path.to_string()))?;
                entry.set_trashed(Some(TrashInfo {
                    name: name.clone(),
                    parent: path_of(parent),
                    deleted_at: now_ms(),
                }));
                let (mut trash, created) = self
                    .trash_dir(&mut root, true)
                    .await?
                    .expect("created on demand");
                let trash_id = Id::random().to_string();
                trash.dir.entries.insert(trash_id.clone(), entry);
                let mut ops = vec![put_op(&trash)?];
                if sub.is_none() || created {
                    ops.push(put_op(&root)?);
                }
                if let Some(s) = &sub {
                    ops.push(put_op(s)?);
                }
                Ok(Plan {
                    ops,
                    delete_blobs: vec![],
                    value: trash_id,
                })
            })
        })
        .await
    }

    pub async fn list_trash(&self) -> Result<Vec<TrashEntry>> {
        let mut root = self.walk(&[]).await?;
        let Some((trash, _)) = self.trash_dir(&mut root, false).await? else {
            return Ok(vec![]);
        };
        let mut out: Vec<TrashEntry> = trash
            .dir
            .entries
            .iter()
            .map(|(id, e)| {
                let info = e.trashed();
                let le = list_entry(id, e);
                TrashEntry {
                    id: id.clone(),
                    name: info.map_or(id.clone(), |i| i.name.clone()),
                    parent: info.map_or("/".into(), |i| i.parent.clone()),
                    deleted_at: info.map_or(0, |i| i.deleted_at),
                    is_dir: le.is_dir,
                    size: le.size,
                }
            })
            .collect();
        out.sort_by_key(|t| std::cmp::Reverse(t.deleted_at));
        Ok(out)
    }

    /// Put a trashed item back where it came from (or in the root if that folder is gone),
    /// renaming it if the name has been taken since. Returns the restored path.
    pub async fn restore(&self, trash_id: &str) -> Result<String> {
        self.commit_with_retry(|| {
            Box::pin(async move {
                let mut root = self.walk(&[]).await?;
                let (mut trash, _) = self
                    .trash_dir(&mut root, false)
                    .await?
                    .ok_or_else(|| Error::NotFound("trash".into()))?;
                let mut entry = trash
                    .dir
                    .entries
                    .remove(trash_id)
                    .ok_or_else(|| Error::NotFound(trash_id.into()))?;
                let info = entry.trashed().cloned();
                entry.set_trashed(None);
                let name = info
                    .as_ref()
                    .map(|i| i.name.clone())
                    .filter(|n| node::validate_name(n).is_ok())
                    .unwrap_or_else(|| trash_id.to_string());
                let parent = info
                    .and_then(|i| components(&i.parent).ok())
                    .unwrap_or_default();
                let mut sub = if parent.is_empty() {
                    None
                } else {
                    match self.walk(&parent).await {
                        Ok(d) => Some(d),
                        Err(Error::NotFound(_) | Error::Invalid(_)) => None,
                        Err(e) => return Err(e),
                    }
                };
                let dst = sub.as_mut().unwrap_or(&mut root);
                let stored = unique_name(&dst.dir, &name);
                dst.dir.entries.insert(stored.clone(), entry);
                let restored = match &sub {
                    Some(_) => path_of(&[parent.clone(), vec![stored]].concat()),
                    None => path_of(&[stored]),
                };
                let ops = vec![put_op(&trash)?, put_op(sub.as_ref().unwrap_or(&root))?];
                Ok(Plan {
                    ops,
                    delete_blobs: vec![],
                    value: restored,
                })
            })
        })
        .await
    }

    /// Permanently delete one trashed item.
    pub async fn delete_from_trash(&self, trash_id: &str) -> Result<()> {
        self.commit_with_retry(|| {
            Box::pin(async move {
                let mut root = self.walk(&[]).await?;
                let (mut trash, _) = self
                    .trash_dir(&mut root, false)
                    .await?
                    .ok_or_else(|| Error::NotFound("trash".into()))?;
                let entry = trash
                    .dir
                    .entries
                    .remove(trash_id)
                    .ok_or_else(|| Error::NotFound(trash_id.into()))?;
                let (mut ops, delete_blobs) = self.destroy_ops(entry).await?;
                ops.insert(0, put_op(&trash)?);
                Ok(Plan {
                    ops,
                    delete_blobs,
                    value: (),
                })
            })
        })
        .await
    }

    /// Permanently delete everything in the trash. Returns how many items were removed.
    pub async fn empty_trash(&self) -> Result<usize> {
        let items = self.list_trash().await?;
        for item in &items {
            match self.delete_from_trash(&item.id).await {
                Ok(()) | Err(Error::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(items.len())
    }

    /// Delete blobs that no directory references (left behind by interrupted uploads). Do not
    /// run while another device is uploading: its not-yet-committed chunks look orphaned.
    pub async fn collect_garbage(&self) -> Result<usize> {
        let (root_id, root_key) = self.root()?;
        let (_, referenced) = self.subtree(root_id, root_key).await?;
        let referenced: std::collections::HashSet<Id> = referenced.into_iter().collect();
        let mut after = None;
        let mut removed = 0;
        loop {
            let page = self.api.list_blobs(after.as_ref()).await?;
            for b in &page.blobs {
                if !referenced.contains(&b.id) {
                    self.api.delete_blob(&b.id).await?;
                    removed += 1;
                }
            }
            match page.next {
                Some(n) => after = Some(n),
                None => return Ok(removed),
            }
        }
    }

    pub async fn usage(&self) -> Result<UsageResponse> {
        self.api.usage().await
    }

    /// The account's keyslots with their labels decrypted into `label`.
    pub async fn keyslots(&self) -> Result<Vec<Keyslot>> {
        let amk = self.amk()?;
        let mut slots = self.api.keyslots(&self.profile.username).await?;
        for s in &mut slots {
            s.label = s.label(&amk);
        }
        Ok(slots)
    }

    /// Enroll another security key (two touches on the new key).
    pub async fn add_security_key(
        &self,
        authn: Arc<dyn Authenticator>,
        label: String,
        password: Option<String>,
    ) -> Result<Keyslot> {
        let exclude = self
            .keyslots()
            .await?
            .iter()
            .filter_map(|s| s.credential_id().map(<[u8]>::to_vec))
            .collect();
        let slot = enroll_keyslot(
            authn,
            &self.profile.rp_id,
            &self.profile.username,
            label,
            password,
            exclude,
            &self.amk()?,
        )
        .await?;
        self.api.put_keyslot(&slot).await?;
        Ok(slot)
    }

    /// Create a new recovery code keyslot and return the code (show it once).
    pub async fn add_recovery_code(&self) -> Result<String> {
        let secret = recovery::generate();
        let slot = Keyslot::create(
            "Recovery code".into(),
            KeyslotKind::Recovery,
            &Unlock::Recovery { secret: &secret },
            &self.amk()?,
        )?;
        self.api.put_keyslot(&slot).await?;
        Ok(recovery::encode(&secret))
    }

    pub async fn remove_keyslot(&self, id: &Id) -> Result<()> {
        self.api.delete_keyslot(id).await
    }

    pub async fn logout(self) -> Result<()> {
        self.api.logout().await
    }

    /// Permanently delete this account on the server (all keyslots, files and the username).
    /// The caller must then wipe the drive and forget the local profile.
    pub async fn delete_account(&self) -> Result<()> {
        self.api.delete_account().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_local_names() {
        assert_eq!(local_safe_name("..\\..\\evil.txt"), ".._.._evil.txt");
        assert_eq!(local_safe_name("a:b*c?.txt"), "a_b_c_.txt");
        assert_eq!(local_safe_name("con.txt"), "_con.txt");
        assert_eq!(local_safe_name("COM1"), "_COM1");
        assert_eq!(local_safe_name("dots..."), "dots");
        assert_eq!(local_safe_name("..."), "_");
        assert_eq!(local_safe_name("report.pdf"), "report.pdf");
    }

    #[test]
    fn unique_names() {
        let mut d = Dir::default();
        assert_eq!(unique_name(&d, "a.txt"), "a.txt");
        let e = Entry::Dir(DirRef {
            id: Id::random(),
            key: Key::random(),
            mtime: 0,
            trashed: None,
        });
        d.entries.insert("a.txt".into(), e.clone());
        d.entries.insert("a (1).txt".into(), e.clone());
        assert_eq!(unique_name(&d, "a.txt"), "a (2).txt");
        d.entries.insert(".env".into(), e);
        assert_eq!(unique_name(&d, ".env"), ".env (1)");
    }
}
