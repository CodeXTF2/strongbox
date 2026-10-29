//! Sealed directory nodes.
//!
//! The server stores a flat set of `(node id, version, sealed bytes)`. All structure lives inside
//! the sealed bytes: names, timestamps, sizes, child directory ids and keys, and file content
//! references. A directory's key is held in its parent's sealed entry (the root's key is derived
//! from the account master key), so possession of a directory key grants exactly that subtree.
//!
//! Files are not separate nodes: their metadata and [`ContentRef`] are entries in the parent
//! directory. This keeps the number of server-visible objects down to "directories + chunks".

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::content::ContentRef;
use crate::{aead, padding, Error, Id, Key, Result};

const FORMAT_V1: u8 = 1;
const NODE_AAD: &str = "strongbox/node/v1";

/// Unix time in milliseconds.
pub type Timestamp = i64;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dir {
    pub entries: BTreeMap<String, Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Entry {
    File(FileEntry),
    Dir(DirRef),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub content: ContentRef,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    /// Set only on entries inside the trash directory. Optional so older nodes still decode
    /// and older clients ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed: Option<TrashInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirRef {
    pub id: Id,
    pub key: Key,
    pub mtime: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trashed: Option<TrashInfo>,
}

/// Where a trashed entry came from, so it can be restored. Sealed like everything else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrashInfo {
    /// Original name.
    pub name: String,
    /// Original parent directory path ("/" for the root).
    pub parent: String,
    pub deleted_at: Timestamp,
}

impl Entry {
    pub fn mtime(&self) -> Timestamp {
        match self {
            Entry::File(f) => f.mtime,
            Entry::Dir(d) => d.mtime,
        }
    }

    pub fn trashed(&self) -> Option<&TrashInfo> {
        match self {
            Entry::File(f) => f.trashed.as_ref(),
            Entry::Dir(d) => d.trashed.as_ref(),
        }
    }

    pub fn set_trashed(&mut self, info: Option<TrashInfo>) {
        match self {
            Entry::File(f) => f.trashed = info,
            Entry::Dir(d) => d.trashed = info,
        }
    }
}

fn node_aad(id: &Id, version: u64) -> Vec<u8> {
    aead::aad(NODE_AAD, &[id.as_bytes(), &version.to_be_bytes()])
}

/// Seal a directory for storage as `id` at `version`. Binding id and version into the AAD stops
/// the server from swapping nodes or presenting an old version under a new version number.
pub fn seal_dir(key: &Key, id: &Id, version: u64, dir: &Dir) -> Result<Vec<u8>> {
    let mut cbor = Vec::new();
    ciborium::into_writer(dir, &mut cbor).map_err(|e| Error::Encoding(e.to_string()))?;
    let padded = padding::pad_message(&cbor);
    let mut out = vec![FORMAT_V1];
    out.extend(aead::seal(key, &node_aad(id, version), &padded));
    Ok(out)
}

pub fn open_dir(key: &Key, id: &Id, version: u64, sealed: &[u8]) -> Result<Dir> {
    let (&format, body) = sealed.split_first().ok_or(Error::Malformed("empty node"))?;
    if format != FORMAT_V1 {
        return Err(Error::Version(format));
    }
    let padded = aead::open(key, &node_aad(id, version), body)?;
    let cbor = padding::unpad_message(&padded)?;
    ciborium::from_reader(cbor).map_err(|e| Error::Encoding(e.to_string()))
}

/// Validate a single path component.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(Error::Malformed("invalid file name"));
    }
    if name.len() > 1024 {
        return Err(Error::Malformed("file name too long"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::Encryptor;

    #[test]
    fn seal_open_and_binding() {
        let mut enc = Encryptor::new(&b"hi"[..]);
        while enc.next_chunk().unwrap().is_some() {}
        let mut dir = Dir::default();
        dir.entries.insert(
            "secret-plans.txt".into(),
            Entry::File(FileEntry {
                content: enc.finish().unwrap(),
                mtime: 1,
                ctime: 1,
                trashed: None,
            }),
        );
        dir.entries.insert(
            "sub".into(),
            Entry::Dir(DirRef {
                id: Id::random(),
                key: Key::random(),
                mtime: 2,
                trashed: Some(TrashInfo {
                    name: "old".into(),
                    parent: "/".into(),
                    deleted_at: 3,
                }),
            }),
        );
        let key = Key::random();
        let id = Id::random();
        let sealed = seal_dir(&key, &id, 3, &dir).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        assert_eq!(open_dir(&key, &id, 3, &sealed).unwrap(), dir);
        assert!(open_dir(&key, &id, 2, &sealed).is_err());
        assert!(open_dir(&key, &Id::random(), 3, &sealed).is_err());
    }

    #[test]
    fn entries_without_trash_field_still_decode() {
        // The CBOR an older client wrote: DirRef without the `trashed` key.
        #[derive(Serialize)]
        struct OldDirRef {
            id: Id,
            key: Key,
            mtime: Timestamp,
        }
        #[derive(Serialize)]
        enum OldEntry {
            Dir(OldDirRef),
        }
        let mut cbor = Vec::new();
        ciborium::into_writer(
            &OldEntry::Dir(OldDirRef {
                id: Id::random(),
                key: Key::random(),
                mtime: 5,
            }),
            &mut cbor,
        )
        .unwrap();
        let e: Entry = ciborium::from_reader(cbor.as_slice()).unwrap();
        assert_eq!(e.mtime(), 5);
        assert!(e.trashed().is_none());
    }
}
