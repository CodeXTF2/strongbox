//! Deniable vaults (docs/deniable-drives.md): log in with the security key, open a drive by
//! (slot, drive PIN), and work with its files.
//!
//! Nothing here touches the local disk except files the user explicitly uploads or
//! downloads: no profile, no credential id, no caches.

use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use strongbox_core::names::validate_name;
use strongbox_core::vault::{
    self as v, check_drive_pin, drive_salt, entry_key, header_entries, open_header,
    open_header_body, Entry, EntryKind, HeaderBody, MemberCreds, RecoveryCode, UsernameKeys, VDir,
    VFile, VNode, VaultGrant, VaultMemberLabel, BLOCK_PAYLOAD, ENTRIES_LEN, HEADER_BLOCKS,
    HEADER_LEN, KEY_ENTRIES, RECOVERY_ENTRY,
};
use strongbox_core::Key;
use strongbox_fido::{Authenticator, VAULT_USER_NAME};
use strongbox_proto::{
    AddMemberRequest, CreateVaultRequest, MemberInfo, UpdateRecordRequest, VaultLayout,
    VaultSessionRequest, MAX_BLOCKS_PER_REQUEST,
};

use crate::api::Api;
use crate::transfer::{ListEntry, OnConflict, TransferOptions};
use crate::{Error, Result};

/// WebAuthn relying party id for every credential Strongbox creates.
pub const DEFAULT_RP_ID: &str = "strongbox.app";

struct Inner {
    api: Api,
    layout: VaultLayout,
    username: UsernameKeys,
    /// Credential ids of this username's security keys (from the decrypted record).
    credentials: std::sync::Mutex<Vec<Vec<u8>>>,
    members: std::sync::Mutex<Vec<VaultMemberLabel>>,
}

/// A logged-in vault session. It knows nothing about which drives exist.
#[derive(Clone)]
pub struct VaultClient {
    inner: Arc<Inner>,
}

/// Keys that may open one slot: a security key's entry key, or a recovery code's.
pub struct SlotKey {
    slot: u32,
    key: Key,
    kind: EntryKind,
    member_id: String,
}

impl SlotKey {
    pub fn slot(&self) -> u32 {
        self.slot
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking task panicked")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

async fn server(server_url: &str) -> Result<(Api, String, VaultLayout)> {
    let api = Api::new(server_url)?;
    let info = api.info().await?;
    let layout = info.vault;
    if layout.block_size as usize != v::BLOCK_SIZE
        || layout.blocks_per_slot <= HEADER_BLOCKS
        || layout.slots == 0
    {
        return Err(Error::Invalid("unsupported vault layout".into()));
    }
    Ok((api, info.server_id, layout))
}

/// Query the server's configured vault layout without logging in.
pub async fn vault_layout(server_url: &str) -> Result<VaultLayout> {
    let (_, _, layout) = server(server_url).await?;
    Ok(layout)
}

async fn username_keys(username: &str, server_id: &str) -> Result<UsernameKeys> {
    if username.trim().is_empty() {
        return Err(Error::Invalid("enter a username".into()));
    }
    let (u, s) = (username.to_string(), server_id.to_string());
    Ok(blocking(move || UsernameKeys::derive(&u, &s)).await?)
}

/// Fetch and decrypt a username's credential record. A wrong username gets the server's
/// decoy, which does not decrypt; the server cannot tell the difference.
async fn credentials(
    api: &Api,
    keys: &UsernameKeys,
) -> Result<(Vec<Vec<u8>>, Vec<VaultMemberLabel>)> {
    let record = api.vault_record(&keys.lookup).await?;
    keys.open_record(&record)
        .ok_or_else(|| Error::Invalid("unknown username on this server".into()))
}

fn member_id(locator: &[u8]) -> String {
    hex::encode(v::locator_hash(locator))
}

async fn login(
    mut api: Api,
    server_id: &str,
    layout: VaultLayout,
    username: UsernameKeys,
    credentials: Vec<Vec<u8>>,
    members: Vec<VaultMemberLabel>,
    creds: &MemberCreds,
) -> Result<VaultClient> {
    // From here on everything is sealed under the member's transport key, which the server must
    // prove it holds: a proxy that cannot do that never sees the challenge, signature or token.
    api.open_channel(&v::locator_hash(&creds.locator), &creds.transport)
        .await?;
    // The server id and layout came from the clear-text `/v1/info`, and the client has
    // acted on them (key derivation, slot checks, block placement). Confirm them now that
    // they can be fetched authenticated.
    let sealed = api.sealed_info().await?;
    if sealed.server_id != server_id || sealed.vault != layout {
        return Err(Error::Invalid(
            "the server's details differ from what the network showed; refusing to continue".into(),
        ));
    }
    let mut session = None;
    for attempt in 0..3 {
        let challenge = api.vault_challenge(&creds.locator).await?;
        let signature = creds.sign_challenge(server_id, &challenge).to_vec();
        match api
            .vault_session(&VaultSessionRequest {
                locator: creds.locator.to_vec(),
                challenge,
                signature,
            })
            .await
        {
            Ok(s) => {
                session = Some(s);
                break;
            }
            Err(Error::Api { status: 401, .. }) if attempt < 2 => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(Error::Api { status: 401, .. }) => {
                return Err(Error::Invalid(
                    "this security key could not authenticate to the vault on this server".into(),
                ));
            }
            Err(e) => return Err(e),
        }
    }
    let session = session.expect("successful vault session after retry loop");
    api.set_token(session.token);
    Ok(VaultClient {
        inner: Arc::new(Inner {
            api,
            layout,
            username,
            credentials: std::sync::Mutex::new(credentials),
            members: std::sync::Mutex::new(members),
        }),
    })
}

fn check_slot(layout: &VaultLayout, slot: u32) -> Result<()> {
    if slot >= layout.slots {
        return Err(Error::Invalid(format!(
            "slot must be 0–{}",
            layout.slots - 1
        )));
    }
    Ok(())
}

/// Authenticate to a vault account without deriving or opening any drive key.
pub async fn connect_account(
    server_url: &str,
    username: &str,
    authn: Arc<dyn Authenticator>,
) -> Result<VaultClient> {
    let (api, server_id, layout) = server(server_url).await?;
    let keys = username_keys(username, &server_id).await?;
    let (credentials, members) = credentials(&api, &keys).await?;
    let allow = credentials.clone();
    let vsalt = keys.vault_salt()?;
    let pair = blocking(move || authn.prf2(DEFAULT_RP_ID, &allow, &vsalt, None)).await?;
    login(
        api,
        &server_id,
        layout,
        keys,
        credentials,
        members,
        &MemberCreds::from_prf(&pair.first),
    )
    .await
}

/// Authenticate to an account with an account-scoped recovery code, without opening a drive.
pub async fn connect_account_with_recovery(
    server_url: &str,
    username: &str,
    code: &str,
) -> Result<VaultClient> {
    let code = RecoveryCode::decode(code)?;
    let (api, server_id, layout) = server(server_url).await?;
    let keys = username_keys(username, &server_id).await?;
    let (credentials, members) = credentials(&api, &keys).await?;
    let creds = code.member_creds();
    let id = member_id(&creds.locator);
    if !members
        .iter()
        .any(|member| member.id == id && member.kind == "recovery_code" && member.slot.is_none())
    {
        return Err(Error::Invalid(
            "this is not an account recovery code".into(),
        ));
    }
    login(api, &server_id, layout, keys, credentials, members, &creds).await
}

/// Enroll a credential and get its vault-login PRF output: one touch when the key can evaluate
/// the PRF while enrolling, otherwise two (enroll, then assert).
async fn enroll_with_vault_secret(
    authn: Arc<dyn Authenticator>,
    exclude: &[Vec<u8>],
    vault_salt: &[u8],
) -> Result<(Vec<u8>, zeroize::Zeroizing<[u8; 32]>)> {
    let (a, exclude, salt) = (authn.clone(), exclude.to_vec(), vault_salt.to_vec());
    let enrolled =
        blocking(move || a.enroll_prf(DEFAULT_RP_ID, VAULT_USER_NAME, &exclude, &salt)).await?;
    if let Some(first) = enrolled.first {
        return Ok((enrolled.credential_id, first));
    }
    let allow = vec![enrolled.credential_id.clone()];
    let salt = vault_salt.to_vec();
    let pair = blocking(move || authn.prf2(DEFAULT_RP_ID, &allow, &salt, None)).await?;
    Ok((enrolled.credential_id, pair.first))
}

/// Create a vault under `username`: enroll a new (non-discoverable) credential on the
/// security key and register it. One touch if the key supports it, otherwise two. One key can hold any number of usernames;
/// nothing about them is stored on the key or this computer.
pub async fn create_vault(
    server_url: &str,
    username: &str,
    invite: Option<String>,
    authn: Arc<dyn Authenticator>,
) -> Result<VaultClient> {
    create_vault_named(server_url, username, invite, authn, "Security key 1").await
}

pub async fn create_vault_named(
    server_url: &str,
    username: &str,
    invite: Option<String>,
    authn: Arc<dyn Authenticator>,
    label: &str,
) -> Result<VaultClient> {
    let (api, server_id, layout) = server(server_url).await?;
    let keys = username_keys(username, &server_id).await?;
    let retry_authn = authn.clone();
    // A fresh random seed in the account record makes this account's login secrets unrelated
    // to those of any other server, even for the same credential.
    keys.new_seed();
    let (cred, first) = enroll_with_vault_secret(authn, &[], &keys.vault_salt()?).await?;
    let creds = MemberCreds::from_prf(&first);
    let credentials = vec![cred];
    let members = vec![VaultMemberLabel {
        id: member_id(&creds.locator),
        label: label.into(),
        kind: "security_key".into(),
        slot: None,
    }];
    api.create_vault(&CreateVaultRequest {
        lookup: keys.lookup.to_vec(),
        record: keys.seal_record(&credentials, &members)?,
        locator: creds.locator.to_vec(),
        auth_public_key: creds.public_key().to_vec(),
        transport_key: creds.transport.as_bytes().to_vec(),
        invite,
    })
    .await?;
    match login(api, &server_id, layout, keys, credentials, members, &creds).await {
        Ok(client) => Ok(client),
        Err(Error::Invalid(message)) if message.contains("could not authenticate") => {
            connect_account(server_url, username, retry_authn)
                .await
                .map_err(|_| {
                    Error::Invalid(
                        "the account was created, but the security key could not complete sign-in; try signing in again instead of creating the account again".into(),
                    )
                })
        }
        Err(e) => Err(e),
    }
}

/// Log in as `username` and derive the key for one slot with a single touch.
pub async fn connect(
    server_url: &str,
    username: &str,
    authn: Arc<dyn Authenticator>,
    slot: u32,
    pin: &str,
) -> Result<(VaultClient, SlotKey)> {
    check_drive_pin(pin)?;
    let (api, server_id, layout) = server(server_url).await?;
    check_slot(&layout, slot)?;
    let keys = username_keys(username, &server_id).await?;
    let (credentials, members) = credentials(&api, &keys).await?;
    let salt = drive_salt(slot, pin);
    let allow = credentials.clone();
    let vsalt = keys.vault_salt()?;
    let pair = blocking(move || authn.prf2(DEFAULT_RP_ID, &allow, &vsalt, Some(&salt))).await?;
    let second = pair.second.ok_or(strongbox_fido::Error::PrfUnsupported)?;
    let member = MemberCreds::from_prf(&pair.first);
    let member_id = member_id(&member.locator);
    let client = login(api, &server_id, layout, keys, credentials, members, &member).await?;
    Ok((
        client,
        SlotKey {
            slot,
            key: entry_key(&second),
            kind: EntryKind::Key,
            member_id,
        },
    ))
}

/// Log in with a drive recovery code and find the drive it opens.
pub async fn connect_with_recovery(
    server_url: &str,
    username: &str,
    code: &str,
) -> Result<(VaultClient, SlotKey)> {
    let code = RecoveryCode::decode(code)?;
    let (api, server_id, layout) = server(server_url).await?;
    let keys = username_keys(username, &server_id).await?;
    let (credentials, members) = credentials(&api, &keys).await?;
    let client = login(
        api,
        &server_id,
        layout,
        keys,
        credentials,
        members,
        &code.member_creds(),
    )
    .await?;
    // One request for every slot's entry table, then open only the slots whose recovery entry
    // this code unlocks, instead of fetching the headers of every slot in turn.
    let per_slot = HEADER_BLOCKS as usize * ENTRIES_LEN;
    let all = client.api().read_all_entries(layout.slots).await?;
    let candidates = (0..layout.slots).filter(|&slot| {
        let keys = [(code.entry_key(slot), EntryKind::Recovery)];
        all[slot as usize * per_slot..(slot as usize + 1) * per_slot]
            .chunks(ENTRIES_LEN)
            .any(|p| v::entries_open(slot, p, &keys))
    });
    for slot in candidates {
        let k = SlotKey {
            slot,
            key: code.entry_key(slot),
            kind: EntryKind::Recovery,
            member_id: member_id(&code.member_creds().locator),
        };
        if client.open(&k).await?.is_some() {
            return Ok((client, k));
        }
    }
    Err(Error::Invalid(
        "this recovery code does not open any drive".into(),
    ))
}

impl VaultClient {
    pub fn layout(&self) -> VaultLayout {
        self.inner.layout
    }

    fn api(&self) -> &Api {
        &self.inner.api
    }

    /// Derive the key for another slot (one touch).
    pub async fn slot_key(
        &self,
        authn: Arc<dyn Authenticator>,
        slot: u32,
        pin: &str,
    ) -> Result<SlotKey> {
        check_drive_pin(pin)?;
        check_slot(&self.inner.layout, slot)?;
        let salt = drive_salt(slot, pin);
        let allow = self.inner.credentials.lock().unwrap().clone();
        let vsalt = self.inner.username.vault_salt()?;
        let pair = blocking(move || authn.prf2(DEFAULT_RP_ID, &allow, &vsalt, Some(&salt))).await?;
        let second = pair.second.ok_or(strongbox_fido::Error::PrfUnsupported)?;
        let member = MemberCreds::from_prf(&pair.first);
        Ok(SlotKey {
            slot,
            key: entry_key(&second),
            kind: EntryKind::Key,
            member_id: member_id(&member.locator),
        })
    }

    /// Open the drive in a slot. `None` means "no drive for this slot and PIN", which is
    /// deliberately the same answer for a wrong PIN and a slot that was never used.
    pub async fn open(&self, k: &SlotKey) -> Result<Option<VaultDrive>> {
        let headers = self.api().read_headers(k.slot).await?;
        let keys = [(k.key.clone(), k.kind)];
        let best = headers
            .chunks(HEADER_LEN)
            .zip(0u8..)
            .filter_map(|(header, c)| open_header(k.slot, c, header, &keys).map(|h| (c, h)))
            .max_by_key(|(_, h)| h.body.generation);
        let Some((copy, opened)) = best else {
            return Ok(None);
        };
        let header = headers
            .chunks(HEADER_LEN)
            .nth(copy as usize)
            .expect("two copies");
        let mut drive = VaultDrive {
            client: self.clone(),
            slot: k.slot,
            drive_key: Arc::new(std::sync::RwLock::new(Some(opened.drive_key))),
            entries: header_entries(header),
            body: opened.body,
            copy,
            tree: VDir::default(),
        };
        drive.tree = drive.read_meta().await?;
        Ok(Some(drive))
    }

    /// Create a new, empty drive in the slot, destroying whatever was there (which nobody,
    /// including this client, can know). Only a security-key slot key can create drives.
    pub async fn create(&self, k: &SlotKey) -> Result<VaultDrive> {
        if k.kind != EntryKind::Key {
            return Err(Error::Invalid(
                "a recovery code cannot create drives".into(),
            ));
        }
        let drive_key = Key::random();
        let mut entries: [Entry; KEY_ENTRIES + 1] = std::array::from_fn(|_| v::random_entry());
        entries[0] = v::wrap_entry(k.slot, 0, &k.key, &drive_key);
        let mut drive = VaultDrive {
            client: self.clone(),
            slot: k.slot,
            drive_key: Arc::new(std::sync::RwLock::new(Some(drive_key))),
            entries,
            body: HeaderBody {
                generation: 0,
                used_entries: 1,
                meta_blocks: vec![],
                meta_len: 0,
                grants: vec![VaultGrant {
                    entry: 0,
                    member_id: k.member_id.clone(),
                }],
            },
            copy: 1,
            tree: VDir {
                entries: Default::default(),
                mtime: now_ms(),
            },
        };
        // Copy 1 becomes filler: an old header there could still open with the same PIN
        // and must not outrank the new drive. Then the first commit writes copy 0.
        self.api()
            .write_header(k.slot, 1, v::random_header())
            .await?;
        let tree = drive.tree.clone();
        drive.write_commit(tree).await?;
        Ok(drive)
    }

    /// Security keys and recovery codes that can log in to this vault.
    pub async fn members(&self) -> Result<(Vec<MemberInfo>, String)> {
        let r = self.api().vault_members().await?;
        Ok((r.members, r.current))
    }

    pub async fn remove_member(&self, id: &str) -> Result<()> {
        let mut members = self.inner.members.lock().unwrap().clone();
        let removed = members
            .iter()
            .find(|member| member.id == id)
            .cloned()
            .ok_or_else(|| Error::Invalid("account key or recovery code not found".into()))?;
        members.retain(|member| member.id != id);
        let mut credentials = self.inner.credentials.lock().unwrap().clone();
        if removed.kind == "security_key" {
            let index = self
                .inner
                .members
                .lock()
                .unwrap()
                .iter()
                .filter(|member| member.kind == "security_key")
                .position(|member| member.id == id)
                .ok_or_else(|| Error::Invalid("account key record is incomplete".into()))?;
            if index < credentials.len() {
                credentials.remove(index);
            }
        }
        self.api().remove_vault_member(id).await?;
        let record = self.inner.username.seal_record(&credentials, &members)?;
        self.api()
            .update_vault_record(&UpdateRecordRequest {
                lookup: self.inner.username.lookup.to_vec(),
                record,
            })
            .await?;
        *self.inner.credentials.lock().unwrap() = credentials;
        *self.inner.members.lock().unwrap() = members;
        Ok(())
    }

    pub fn member_labels(&self) -> Vec<VaultMemberLabel> {
        self.inner.members.lock().unwrap().clone()
    }

    /// Rename a security key or recovery code. Labels live only in the encrypted record.
    pub async fn rename_member(&self, id: &str, label: &str) -> Result<()> {
        let label = self.clean_label(label, &[id.to_string()])?;
        let mut members = self.inner.members.lock().unwrap().clone();
        members
            .iter_mut()
            .find(|member| member.id == id)
            .ok_or_else(|| Error::Invalid("account key or recovery code not found".into()))?
            .label = label;
        let credentials = self.inner.credentials.lock().unwrap().clone();
        let record = self.inner.username.seal_record(&credentials, &members)?;
        self.api()
            .update_vault_record(&UpdateRecordRequest {
                lookup: self.inner.username.lookup.to_vec(),
                record,
            })
            .await?;
        *self.inner.members.lock().unwrap() = members;
        Ok(())
    }

    /// Trim a key or recovery-code name and refuse empty, over-long or duplicate ones. Names
    /// are compared ignoring case and surrounding spaces; `ignore` lists members being replaced.
    fn clean_label(&self, label: &str, ignore: &[String]) -> Result<String> {
        let label = label.trim();
        if label.is_empty() || label.chars().count() > 80 {
            return Err(Error::Invalid("enter a name up to 80 characters".into()));
        }
        if self.label_taken(label, ignore) {
            return Err(Error::Invalid(format!(
                "a key or recovery code is already named “{label}”; choose another name"
            )));
        }
        Ok(label.to_string())
    }

    fn label_taken(&self, label: &str, ignore: &[String]) -> bool {
        let key = label.trim().to_lowercase();
        self.inner
            .members
            .lock()
            .unwrap()
            .iter()
            .any(|m| !ignore.contains(&m.id) && m.label.trim().to_lowercase() == key)
    }

    /// `base`, or `base` with the lowest free number after it ("Recovery code 2"), to prefill
    /// the name prompt. `ignore` lists members that are about to be replaced.
    pub fn suggest_label(&self, base: &str, ignore: &[String]) -> String {
        if !self.label_taken(base, ignore) {
            return base.to_string();
        }
        let stem = base
            .trim_end_matches(|c: char| c.is_ascii_digit())
            .trim_end();
        let stem = if stem.is_empty() { base } else { stem };
        (2..)
            .map(|n| format!("{stem} {n}"))
            .find(|c| !self.label_taken(c, ignore))
            .unwrap()
    }

    /// Copy the decrypted account member record to another open session for this account.
    pub fn sync_account_record_from(&self, source: &Self) {
        if Arc::ptr_eq(&self.inner, &source.inner) {
            return;
        }
        let credentials = source.inner.credentials.lock().unwrap().clone();
        let members = source.inner.members.lock().unwrap().clone();
        *self.inner.credentials.lock().unwrap() = credentials;
        *self.inner.members.lock().unwrap() = members;
    }

    /// Add an account sign-in key without granting it access to any drive.
    pub async fn add_account_key_named(
        &self,
        authn: Arc<dyn Authenticator>,
        label: &str,
    ) -> Result<()> {
        let label = self.clean_label(label, &[])?;
        let mut credentials = self.inner.credentials.lock().unwrap().clone();
        if credentials.len() >= v::MAX_RECORD_CREDENTIALS {
            return Err(Error::Invalid(format!(
                "this username already has {} keys",
                v::MAX_RECORD_CREDENTIALS
            )));
        }
        let vsalt = self.inner.username.vault_salt()?;
        let (credential, first) = enroll_with_vault_secret(authn, &credentials, &vsalt).await?;
        let member = MemberCreds::from_prf(&first);
        self.add_member(&member).await?;
        credentials.push(credential);
        let mut members = self.inner.members.lock().unwrap().clone();
        members.push(VaultMemberLabel {
            id: member_id(&member.locator),
            label: label.clone(),
            kind: "security_key".into(),
            slot: None,
        });
        let record = self.inner.username.seal_record(&credentials, &members)?;
        self.api()
            .update_vault_record(&UpdateRecordRequest {
                lookup: self.inner.username.lookup.to_vec(),
                record,
            })
            .await?;
        *self.inner.credentials.lock().unwrap() = credentials;
        *self.inner.members.lock().unwrap() = members;
        Ok(())
    }

    /// Add an account recovery code. It authenticates the account but cannot open drives.
    pub async fn new_account_recovery_code_named(&self, label: &str) -> Result<String> {
        let label = self.clean_label(label, &[])?;
        let code = RecoveryCode::generate();
        let member = code.member_creds();
        self.add_member(&member).await?;
        let mut members = self.inner.members.lock().unwrap().clone();
        members.push(VaultMemberLabel {
            id: member_id(&member.locator),
            label: label.clone(),
            kind: "recovery_code".into(),
            slot: None,
        });
        let credentials = self.inner.credentials.lock().unwrap().clone();
        let record = self.inner.username.seal_record(&credentials, &members)?;
        self.api()
            .update_vault_record(&UpdateRecordRequest {
                lookup: self.inner.username.lookup.to_vec(),
                record,
            })
            .await?;
        *self.inner.members.lock().unwrap() = members;
        Ok(code.encode())
    }

    async fn add_member(&self, creds: &MemberCreds) -> Result<()> {
        let req = AddMemberRequest {
            locator: creds.locator.to_vec(),
            auth_public_key: creds.public_key().to_vec(),
            transport_key: creds.transport.as_bytes().to_vec(),
        };
        match self.api().add_vault_member(&req).await {
            Ok(()) | Err(Error::Api { status: 409, .. }) => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub async fn logout(self) -> Result<()> {
        self.end_session().await
    }

    /// End the server session without consuming the client.
    pub async fn end_session(&self) -> Result<()> {
        self.inner.api.vault_logout().await
    }

    /// Permanently delete the signed-in account and everything stored under it.
    pub async fn delete_account(&self) -> Result<()> {
        self.inner.api.delete_account().await
    }
}

/// Wipes a [`VaultDrive`]'s key without needing the drive itself (see [`VaultDrive::wipe`]).
#[derive(Clone)]
pub struct WipeHandle(Arc<std::sync::RwLock<Option<Key>>>);

impl WipeHandle {
    pub fn wipe(&self) {
        drop(self.0.write().unwrap_or_else(|e| e.into_inner()).take());
    }
}

/// An open drive. Every change is one copy-on-write commit (docs/deniable-drives.md §6).
pub struct VaultDrive {
    client: VaultClient,
    slot: u32,
    /// `None` once wiped (lock / panic): every later operation fails.
    drive_key: Arc<std::sync::RwLock<Option<Key>>>,
    entries: [Entry; KEY_ENTRIES + 1],
    body: HeaderBody,
    /// Header copy holding `body`.
    copy: u8,
    tree: VDir,
}

fn comps(path: &str) -> Result<Vec<String>> {
    path.split('/')
        .filter(|c| !c.is_empty())
        .map(|c| validate_name(c).map(|_| c.to_string()).map_err(Error::from))
        .collect()
}

fn split(path: &str) -> Result<(Vec<String>, String)> {
    let mut c = comps(path)?;
    let name = c
        .pop()
        .ok_or_else(|| Error::Invalid("path refers to the root directory".into()))?;
    Ok((c, name))
}

fn dir<'a>(root: &'a VDir, comps: &[String]) -> Result<&'a VDir> {
    let mut cur = root;
    for (i, c) in comps.iter().enumerate() {
        cur = match cur.entries.get(c) {
            Some(VNode::Dir(d)) => d,
            Some(VNode::File(_)) => {
                return Err(Error::Invalid(format!(
                    "/{} is a file",
                    comps[..=i].join("/")
                )))
            }
            None => return Err(Error::NotFound(format!("/{}", comps[..=i].join("/")))),
        };
    }
    Ok(cur)
}

fn dir_mut<'a>(root: &'a mut VDir, comps: &[String]) -> Result<&'a mut VDir> {
    let mut cur = root;
    for (i, c) in comps.iter().enumerate() {
        cur = match cur.entries.get_mut(c) {
            Some(VNode::Dir(d)) => d,
            Some(VNode::File(_)) => {
                return Err(Error::Invalid(format!(
                    "/{} is a file",
                    comps[..=i].join("/")
                )))
            }
            None => return Err(Error::NotFound(format!("/{}", comps[..=i].join("/")))),
        };
    }
    Ok(cur)
}

fn unique_name(d: &VDir, name: &str) -> String {
    if !d.entries.contains_key(name) {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name, ""),
    };
    (1..)
        .map(|n| format!("{stem} ({n}){ext}"))
        .find(|c| !d.entries.contains_key(c))
        .unwrap()
}

/// Group (block index, data) pairs into runs of consecutive blocks, each at most
/// `MAX_BLOCKS_PER_REQUEST` long.
fn runs(mut blocks: Vec<(u32, Vec<u8>)>) -> Vec<(u32, Vec<u8>)> {
    blocks.sort_by_key(|(b, _)| *b);
    let mut out: Vec<(u32, Vec<u8>, u32)> = Vec::new();
    for (b, data) in blocks {
        match out.last_mut() {
            Some((start, buf, n)) if *start + *n == b && *n < MAX_BLOCKS_PER_REQUEST => {
                buf.extend_from_slice(&data);
                *n += 1;
            }
            _ => out.push((b, data, 1)),
        }
    }
    out.into_iter().map(|(s, d, _)| (s, d)).collect()
}

/// Requests kept in flight during a file transfer, so the network is not idle while the next
/// batch is read and encrypted (or the last one decrypted and written out). The server sees
/// the same requests as with one at a time, only overlapped.
const IN_FLIGHT: usize = 3;

/// Commit staged uploads once this many files are waiting...
const STAGE_MAX_FILES: usize = 64;
/// ...or this long after the first, so an interrupted batch loses little work.
const STAGE_MAX_AGE: Duration = Duration::from_secs(10);

/// Write (block, sealed data) pairs, one request per run of consecutive blocks.
async fn write_runs(api: &Api, slot: u32, blocks: Vec<(u32, Vec<u8>)>) -> Result<()> {
    for (start, data) in runs(blocks) {
        api.write_blocks(slot, start, data).await?;
    }
    Ok(())
}

/// Read blocks (any order); returns them in the order asked.
async fn read_runs(api: &Api, slot: u32, which: &[u32]) -> Result<Vec<Vec<u8>>> {
    let bs = v::BLOCK_SIZE;
    let mut out = Vec::with_capacity(which.len());
    let mut i = 0;
    while i < which.len() {
        let mut n = 1;
        while i + n < which.len()
            && which[i + n] == which[i] + n as u32
            && (n as u32) < MAX_BLOCKS_PER_REQUEST
        {
            n += 1;
        }
        let data = api.read_blocks(slot, which[i], n as u32, bs).await?;
        out.extend(data.chunks(bs).map(<[u8]>::to_vec));
        i += n;
    }
    Ok(out)
}

fn join_error(e: tokio::task::JoinError) -> Error {
    if e.is_panic() {
        std::panic::resume_unwind(e.into_panic());
    }
    Error::Cancelled
}

/// Transfer tasks that are aborted if the transfer ends early (error, cancel, wipe).
struct InFlight<T>(VecDeque<tokio::task::JoinHandle<T>>);

impl<T> Drop for InFlight<T> {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

/// Create the folder `c` and any missing parents in `tree`. True if anything was created.
fn mkdir_in(tree: &mut VDir, c: &[String]) -> Result<bool> {
    let mut cur = tree;
    let mut changed = false;
    for (i, name) in c.iter().enumerate() {
        let next = cur.entries.entry(name.clone()).or_insert_with(|| {
            changed = true;
            VNode::Dir(VDir {
                entries: Default::default(),
                mtime: now_ms(),
            })
        });
        cur = match next {
            VNode::Dir(d) => d,
            VNode::File(_) => {
                return Err(Error::Invalid(format!("/{} is a file", c[..=i].join("/"))))
            }
        };
    }
    Ok(changed)
}

/// Changes (uploads, new folders) waiting to be committed together: one metadata commit for
/// a batch instead of one per file. Data blocks are written as each file is uploaded; until
/// the commit they are indistinguishable from filler, exactly as during a single upload.
pub struct Staged {
    tree: VDir,
    /// Drive generation the staged tree is based on; the commit refuses if it moved.
    generation: u64,
    changed: bool,
    files: usize,
    since: Option<Instant>,
    /// A committed file was replaced: commit now, so its key is wiped as promptly as by an
    /// unbatched upload.
    replaced: bool,
}

impl VaultDrive {
    pub fn slot(&self) -> u32 {
        self.slot
    }

    pub fn access_grants(&self) -> Vec<VaultGrant> {
        self.body.grants.clone()
    }

    /// Grant an existing account key access to this drive only.
    pub async fn grant_account_key(
        &mut self,
        authn: Arc<dyn Authenticator>,
        pin: &str,
        target_id: &str,
    ) -> Result<()> {
        check_drive_pin(pin)?;
        let index = (0..KEY_ENTRIES)
            .find(|i| self.body.used_entries & (1 << i) == 0)
            .ok_or_else(|| {
                Error::Invalid(format!("this drive already has {KEY_ENTRIES} key slots"))
            })?;
        if self.body.grants.iter().any(|g| g.member_id == target_id) {
            return Err(Error::Invalid("this key already opens this vault".into()));
        }
        let (credential, known_id) = {
            let members = self.client.inner.members.lock().unwrap();
            let keys: Vec<_> = members
                .iter()
                .filter(|m| m.kind == "security_key")
                .collect();
            let key_index = keys
                .iter()
                .position(|m| m.id == target_id)
                .ok_or_else(|| Error::Invalid("account security key not found".into()))?;
            let credentials = self.client.inner.credentials.lock().unwrap();
            (
                credentials.get(key_index).cloned().ok_or_else(|| {
                    Error::Invalid("account security key record is incomplete".into())
                })?,
                keys[key_index].id.clone(),
            )
        };
        let salt = drive_salt(self.slot, pin);
        let allow = vec![credential];
        let vsalt = self.client.inner.username.vault_salt()?;
        let pair = blocking(move || authn.prf2(DEFAULT_RP_ID, &allow, &vsalt, Some(&salt))).await?;
        let second = pair.second.ok_or(strongbox_fido::Error::PrfUnsupported)?;
        let member = MemberCreds::from_prf(&pair.first);
        if member_id(&member.locator) != known_id {
            return Err(Error::Invalid(
                "insert the selected account security key".into(),
            ));
        }
        self.entries[index] = v::wrap_entry(self.slot, index, &entry_key(&second), &self.dk()?);
        self.body.used_entries |= 1u16 << index;
        self.body.grants.push(VaultGrant {
            entry: index as u8,
            member_id: known_id,
        });
        self.commit(self.tree.clone()).await
    }

    /// Change this drive's PIN for the security key that opened it (one touch). Other keys'
    /// entries were derived from the old PIN, so they are revoked and can be granted again
    /// with the new one. Returns how many were revoked. Recovery codes are unaffected.
    pub async fn change_pin(
        &mut self,
        authn: Arc<dyn Authenticator>,
        new_pin: &str,
    ) -> Result<usize> {
        check_drive_pin(new_pin)?;
        let (_, current) = self.client.members().await?;
        let mine = self
            .body
            .grants
            .iter()
            .find(|g| g.member_id == current && (g.entry as usize) < KEY_ENTRIES)
            .cloned()
            .ok_or_else(|| {
                Error::Invalid(
                    "only a security key that opens this vault can change its PIN".into(),
                )
            })?;
        let credential = {
            let members = self.client.inner.members.lock().unwrap();
            let credentials = self.client.inner.credentials.lock().unwrap();
            let index = members
                .iter()
                .filter(|m| m.kind == "security_key")
                .position(|m| m.id == current)
                .ok_or_else(|| Error::Invalid("account security key not found".into()))?;
            credentials
                .get(index)
                .cloned()
                .ok_or_else(|| Error::Invalid("account security key record is incomplete".into()))?
        };
        let salt = drive_salt(self.slot, new_pin);
        let allow = vec![credential];
        let vsalt = self.client.inner.username.vault_salt()?;
        let pair = blocking(move || authn.prf2(DEFAULT_RP_ID, &allow, &vsalt, Some(&salt))).await?;
        let second = pair.second.ok_or(strongbox_fido::Error::PrfUnsupported)?;
        if member_id(&MemberCreds::from_prf(&pair.first).locator) != current {
            return Err(Error::Invalid(
                "touch the security key you unlocked this vault with".into(),
            ));
        }
        let dk = self.dk()?;
        let mut revoked = 0;
        let others: Vec<VaultGrant> = self
            .body
            .grants
            .iter()
            .filter(|g| g.member_id != current && (g.entry as usize) < KEY_ENTRIES)
            .cloned()
            .collect();
        for grant in others {
            self.entries[grant.entry as usize] = v::random_entry();
            self.body.used_entries &= !(1u16 << grant.entry);
            self.body.grants.retain(|g| g.member_id != grant.member_id);
            revoked += 1;
        }
        let index = mine.entry as usize;
        self.entries[index] = v::wrap_entry(self.slot, index, &entry_key(&second), &dk);
        let tree = self.tree.clone();
        self.commit(tree.clone()).await?;
        // Rewrite both header copies so an older copy cannot keep an entry for the old PIN.
        self.commit(tree).await?;
        Ok(revoked)
    }

    /// Ids of this drive's recovery codes (a new one replaces them).
    pub fn recovery_ids(&self) -> Vec<String> {
        self.client
            .member_labels()
            .into_iter()
            .filter(|m| m.kind == "recovery_code" && m.slot == Some(self.slot))
            .map(|m| m.id)
            .collect()
    }

    /// Revoke one account key from this drive. The other account keys remain unaffected.
    pub async fn revoke_account_key(&mut self, member_id: &str) -> Result<()> {
        let grant = self
            .body
            .grants
            .iter()
            .find(|g| g.member_id == member_id)
            .cloned()
            .ok_or_else(|| Error::Invalid("key does not open this vault".into()))?;
        let index = grant.entry as usize;
        if index >= KEY_ENTRIES {
            return Err(Error::Invalid("invalid key access entry".into()));
        }
        self.entries[index] = v::random_entry();
        self.body.used_entries &= !(1u16 << index);
        self.body.grants.retain(|g| g.member_id != member_id);
        let tree = self.tree.clone();
        self.commit(tree.clone()).await?;
        // Rewrite both header copies so an older copy cannot retain the removed wrapper.
        self.commit(tree).await
    }

    /// Revoke a recovery code from this drive and remove its account sign-in member.
    pub async fn revoke_recovery_code(&mut self, member_id: &str) -> Result<()> {
        let member = self
            .client
            .member_labels()
            .into_iter()
            .find(|m| m.id == member_id && m.kind == "recovery_code" && m.slot == Some(self.slot))
            .ok_or_else(|| Error::Invalid("recovery code not found for this vault".into()))?;
        self.client.remove_member(&member.id).await?;
        self.entries[RECOVERY_ENTRY] = v::random_entry();
        self.body.used_entries &= !(1u16 << RECOVERY_ENTRY);
        self.body.grants.retain(|g| g.member_id != member_id);
        let tree = self.tree.clone();
        self.commit(tree.clone()).await?;
        self.commit(tree).await
    }

    fn dk(&self) -> Result<Key> {
        self.drive_key
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or_else(|| Error::Invalid("the drive is locked".into()))
    }

    /// Securely erase the drive key now (zeroized on drop), even while an operation holds this
    /// drive: it fails at its next step. File keys in the tree are dropped with the drive.
    pub fn wipe(&self) {
        self.wipe_handle().wipe();
    }

    /// A handle that can wipe this drive's key from elsewhere, e.g. while another task holds
    /// the drive for an upload.
    pub fn wipe_handle(&self) -> WipeHandle {
        WipeHandle(self.drive_key.clone())
    }

    /// The decrypted folder tree (for listing and search without the server).
    pub fn tree(&self) -> &VDir {
        &self.tree
    }

    /// Create a folder and any missing parents; existing folders are fine.
    pub async fn mkdir_p(&mut self, path: &str) -> Result<()> {
        let mut tree = self.tree.clone();
        if mkdir_in(&mut tree, &comps(path)?)? {
            self.commit(tree).await?;
        }
        Ok(())
    }

    /// Download a folder tree into a new folder inside `local_parent`. Returns the folder.
    pub async fn download_dir(
        &self,
        remote: &str,
        local_parent: &Path,
        opts: TransferOptions<'_>,
    ) -> Result<std::path::PathBuf> {
        let c = comps(remote)?;
        let root = dir(&self.tree, &c)?;
        let name = c
            .last()
            .map_or("Strongbox".to_string(), |n| crate::local_safe_name(n));
        let mut files = Vec::new();
        let mut dirs = vec![std::path::PathBuf::new()];
        let mut stack = vec![(std::path::PathBuf::new(), comps(remote)?, root)];
        while let Some((rel, rc, d)) = stack.pop() {
            crate::transfer::check_local_name_clashes(d.entries.keys())?;
            for (n, node) in &d.entries {
                let child = rel.join(crate::local_safe_name(n));
                let mut cc = rc.clone();
                cc.push(n.clone());
                match node {
                    VNode::Dir(sub) => {
                        dirs.push(child.clone());
                        stack.push((child, cc, sub));
                    }
                    VNode::File(f) => files.push((child, format!("/{}", cc.join("/")), f.size)),
                }
            }
        }
        let target = crate::unique_local_path(local_parent.join(name));
        for d in &dirs {
            std::fs::create_dir_all(target.join(d))?;
        }
        let total: u64 = files.iter().map(|f| f.2).sum();
        let mut base = 0u64;
        for (rel, path, size) in files {
            let progress = |done: u64, _| {
                if let Some(p) = opts.progress {
                    p(base + done, total);
                }
            };
            self.download(
                &path,
                &target.join(rel),
                TransferOptions {
                    progress: Some(&progress),
                    ..opts
                },
            )
            .await?;
            base += size;
        }
        Ok(target)
    }

    fn api(&self) -> &Api {
        self.client.api()
    }

    fn layout(&self) -> VaultLayout {
        self.client.inner.layout
    }

    async fn write_blocks(&self, blocks: Vec<(u32, Vec<u8>)>) -> Result<()> {
        write_runs(self.api(), self.slot, blocks).await
    }

    /// Read blocks (any order); returns them in the order asked.
    async fn read_blocks(&self, which: &[u32]) -> Result<Vec<Vec<u8>>> {
        read_runs(self.api(), self.slot, which).await
    }

    async fn read_meta(&self) -> Result<VDir> {
        if self.body.meta_blocks.is_empty() {
            return Ok(VDir::default());
        }
        let sealed = self.read_blocks(&self.body.meta_blocks).await?;
        Ok(v::open_meta(&self.dk()?, self.slot, &self.body, &sealed)?)
    }

    /// Blocks in use by the committed state plus `tree`'s files.
    fn used(&self, tree: &VDir) -> BTreeSet<u32> {
        let mut files = Vec::new();
        tree.file_blocks(&mut files);
        self.tree.file_blocks(&mut files);
        (0..HEADER_BLOCKS)
            .chain(self.body.meta_blocks.iter().copied())
            .chain(files)
            .collect()
    }

    fn allocate(&self, n: usize, used: &BTreeSet<u32>) -> Result<Vec<u32>> {
        let free: Vec<u32> = (HEADER_BLOCKS..self.layout().blocks_per_slot)
            .filter(|b| !used.contains(b))
            .take(n)
            .collect();
        if free.len() < n {
            return Err(Error::Invalid("this drive is full".into()));
        }
        Ok(free)
    }

    /// Capacity in bytes: (used, total).
    pub fn usage(&self) -> (u64, u64) {
        let total = (self.layout().blocks_per_slot - HEADER_BLOCKS) as u64 * BLOCK_PAYLOAD as u64;
        let mut files = Vec::new();
        self.tree.file_blocks(&mut files);
        let used = (files.len() + self.body.meta_blocks.len()) as u64 * BLOCK_PAYLOAD as u64;
        (used.min(total), total)
    }

    /// Commit a new tree: metadata to free blocks, then the older header copy, then wipe the
    /// previous metadata (it holds the keys of anything just deleted).
    async fn commit(&mut self, tree: VDir) -> Result<()> {
        // Refuse to overwrite a commit made elsewhere since we opened the drive.
        let headers = self.api().read_headers(self.slot).await?;
        let dk = self.dk()?;
        let latest = headers
            .chunks(HEADER_LEN)
            .zip(0u8..)
            .filter_map(|(header, c)| open_header_body(self.slot, c, header, &dk))
            .map(|b| b.generation)
            .max()
            .unwrap_or(0);
        if latest != self.body.generation {
            return Err(Error::Invalid(
                "this drive was changed on another device; close and reopen it".into(),
            ));
        }
        self.write_commit(tree).await
    }

    async fn write_commit(&mut self, tree: VDir) -> Result<()> {
        let cbor = v::encode_meta(&tree)?;
        let mut used = self.used(&tree);
        used.extend(self.body.meta_blocks.iter().copied());
        let meta_blocks = self.allocate(v::meta_block_count(cbor.len()), &used)?;
        let sealed = v::seal_meta(&self.dk()?, self.slot, &meta_blocks, &cbor);
        self.write_blocks(meta_blocks.iter().copied().zip(sealed).collect())
            .await?;

        let body = HeaderBody {
            generation: self.body.generation + 1,
            used_entries: self.body.used_entries,
            meta_blocks: meta_blocks.clone(),
            meta_len: cbor.len() as u64,
            grants: self.body.grants.clone(),
        };
        let copy = 1 - self.copy;
        let header = v::seal_header(self.slot, copy, &self.dk()?, &self.entries, &body)?;
        self.api().write_header(self.slot, copy, header).await?;

        let old_meta = std::mem::replace(&mut self.body, body).meta_blocks;
        self.copy = copy;
        self.tree = tree;
        let wipe = old_meta
            .into_iter()
            .filter(|b| !self.body.meta_blocks.contains(b))
            .map(|b| (b, v::random_block()))
            .collect();
        self.write_blocks(wipe).await
    }

    pub fn list(&self, path: &str) -> Result<Vec<ListEntry>> {
        let d = dir(&self.tree, &comps(path)?)?;
        Ok(d.entries
            .iter()
            .map(|(name, n)| match n {
                VNode::Dir(d) => ListEntry {
                    name: name.clone(),
                    is_dir: true,
                    size: 0,
                    mtime: d.mtime,
                },
                VNode::File(f) => ListEntry {
                    name: name.clone(),
                    is_dir: false,
                    size: f.size,
                    mtime: f.mtime,
                },
            })
            .collect())
    }

    pub async fn mkdir(&mut self, path: &str) -> Result<()> {
        let (parent, name) = split(path)?;
        let mut tree = self.tree.clone();
        let p = dir_mut(&mut tree, &parent)?;
        if p.entries.contains_key(&name) {
            return Err(Error::Exists(path.to_string()));
        }
        p.entries.insert(
            name,
            VNode::Dir(VDir {
                entries: Default::default(),
                mtime: now_ms(),
            }),
        );
        self.commit(tree).await
    }

    pub async fn remove(&mut self, path: &str) -> Result<()> {
        let (parent, name) = split(path)?;
        let mut tree = self.tree.clone();
        dir_mut(&mut tree, &parent)?
            .entries
            .remove(&name)
            .ok_or_else(|| Error::NotFound(path.to_string()))?;
        self.commit(tree).await
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let (sp, sn) = split(from)?;
        let (dp, dn) = split(to)?;
        if sp == dp && sn == dn {
            return Ok(());
        }
        let mut src_full = sp.clone();
        src_full.push(sn.clone());
        if dp.starts_with(&src_full) {
            return Err(Error::Invalid("cannot move a folder into itself".into()));
        }
        let mut tree = self.tree.clone();
        let node = dir_mut(&mut tree, &sp)?
            .entries
            .remove(&sn)
            .ok_or_else(|| Error::NotFound(from.to_string()))?;
        let d = dir_mut(&mut tree, &dp)?;
        if d.entries.contains_key(&dn) {
            return Err(Error::Exists(to.to_string()));
        }
        d.entries.insert(dn, node);
        self.commit(tree).await
    }

    /// Encrypt and upload a local file into `remote_dir`. Returns the stored name.
    pub async fn upload(
        &mut self,
        local: &Path,
        remote_dir: &str,
        opts: TransferOptions<'_>,
    ) -> Result<String> {
        let mut staged = self.stage();
        let stored = self
            .upload_staged(&mut staged, local, remote_dir, opts)
            .await?;
        self.commit_staged(&mut staged).await?;
        Ok(stored)
    }

    /// Start a batch of changes to commit together (see [`Staged`]). Make no other changes to
    /// the drive until [`commit_staged`](Self::commit_staged); that commit refuses if any were.
    pub fn stage(&self) -> Staged {
        Staged {
            tree: self.tree.clone(),
            generation: self.body.generation,
            changed: false,
            files: 0,
            since: None,
            replaced: false,
        }
    }

    /// Whether the batch should be committed now (many files, a while since the first, or a
    /// replaced file whose old content should be wiped without delay).
    pub fn staged_due(&self, staged: &Staged) -> bool {
        staged.replaced
            || staged.files >= STAGE_MAX_FILES
            || staged.since.is_some_and(|t| t.elapsed() >= STAGE_MAX_AGE)
    }

    /// Commit the batch (nothing to do if it is empty) and start a new one, which is based on
    /// the drive as it then is whether or not the commit succeeded (a failed batch's files are
    /// left out; their blocks stay unreferenced filler).
    pub async fn commit_staged(&mut self, staged: &mut Staged) -> Result<()> {
        let result = if staged.generation != self.body.generation {
            Err(Error::Invalid(
                "the drive changed while uploads were waiting to be saved".into(),
            ))
        } else if staged.changed {
            self.commit(staged.tree.clone()).await
        } else {
            Ok(())
        };
        *staged = self.stage();
        result
    }

    /// [`mkdir_p`](Self::mkdir_p) into a batch.
    pub fn mkdir_p_staged(&self, staged: &mut Staged, path: &str) -> Result<()> {
        if mkdir_in(&mut staged.tree, &comps(path)?)? {
            staged.changed = true;
        }
        Ok(())
    }

    /// Encrypt and upload a local file into `remote_dir` of a batch. Its data is written now;
    /// it appears in the drive when the batch is committed. Returns the stored name.
    pub async fn upload_staged(
        &mut self,
        staged: &mut Staged,
        local: &Path,
        remote_dir: &str,
        opts: TransferOptions<'_>,
    ) -> Result<String> {
        let name = local
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::Invalid("local path has no usable file name".into()))?
            .to_string();
        validate_name(&name)?;
        let parent = comps(remote_dir)?;
        let meta = std::fs::metadata(local)?;
        if !meta.is_file() {
            return Err(Error::Invalid(format!(
                "{} is not a regular file",
                local.display()
            )));
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or_else(now_ms, |d| d.as_millis() as i64);
        let size = meta.len();
        let stored = {
            let d = dir(&staged.tree, &parent)?;
            match (d.entries.get(&name), opts.on_conflict) {
                (None, _) => name.clone(),
                (Some(_), OnConflict::KeepBoth) => unique_name(d, &name),
                (Some(VNode::File(_)), OnConflict::Replace) => name.clone(),
                (Some(VNode::Dir(_)), OnConflict::Replace) => {
                    return Err(Error::Exists(format!("a folder named {name}")))
                }
                (Some(_), OnConflict::Fail) => return Err(Error::Exists(name.clone())),
            }
        };

        let n = v::file_block_count(size);
        // Files replaced by this batch keep their blocks until the commit (they are still in
        // the committed tree), and other staged files keep theirs: allocate around both.
        let blocks = self.allocate(n, &self.used(&staged.tree))?;
        // A fresh key for every upload: each block is sealed under it with its slot, block and
        // index as associated data, so blocks cannot be swapped, reordered or rolled back
        // (whatever was stored there before was sealed under another key), and the metadata
        // fixes the size. That authenticates the whole file without a separate hash.
        let key = Key::random();
        let mut reader = BufReader::new(File::open(local)?);
        let mut batch = Vec::new();
        let mut queued = 0u64;
        let mut writes = InFlight(VecDeque::new());
        for (k, b) in blocks.iter().enumerate() {
            opts.check_cancel()?;
            self.dk()?;
            let mut buf = vec![0u8; BLOCK_PAYLOAD.min((size - queued) as usize)];
            let sealed = tokio::task::block_in_place(|| -> Result<Vec<u8>> {
                reader.read_exact(&mut buf)?;
                Ok(v::seal_file_block(&key, self.slot, *b, k as u32, &buf))
            })?;
            queued += buf.len() as u64;
            batch.push((*b, sealed));
            if batch.len() == MAX_BLOCKS_PER_REQUEST as usize || k + 1 == n {
                if writes.0.len() >= IN_FLIGHT {
                    let h = writes.0.pop_front().expect("non-empty");
                    let done = h.await.map_err(join_error)??;
                    if let Some(p) = opts.progress {
                        p(done, size);
                    }
                }
                let (api, slot, data) = (self.api().clone(), self.slot, std::mem::take(&mut batch));
                let upto = queued;
                writes.0.push_back(tokio::spawn(async move {
                    write_runs(&api, slot, data).await.map(|()| upto)
                }));
            }
        }
        while let Some(h) = writes.0.pop_front() {
            let done = h.await.map_err(join_error)??;
            if let Some(p) = opts.progress {
                p(done, size);
            }
        }
        if queued != size {
            return Err(Error::Invalid("file changed while uploading".into()));
        }
        let file = VFile {
            size,
            mtime,
            key,
            blocks,
        };
        if matches!(
            dir(&self.tree, &parent)
                .ok()
                .and_then(|d| d.entries.get(&stored)),
            Some(VNode::File(_))
        ) {
            staged.replaced = true;
        }
        dir_mut(&mut staged.tree, &parent)?
            .entries
            .insert(stored.clone(), VNode::File(file));
        staged.changed = true;
        staged.files += 1;
        staged.since.get_or_insert_with(Instant::now);
        Ok(stored)
    }

    fn file(&self, remote: &str) -> Result<VFile> {
        let (parent, name) = split(remote)?;
        match dir(&self.tree, &parent)?.entries.get(&name) {
            Some(VNode::File(f)) => Ok(f.clone()),
            Some(VNode::Dir(_)) => Err(Error::Invalid(format!("{remote} is a folder"))),
            None => Err(Error::NotFound(remote.to_string())),
        }
    }

    async fn fetch<W: Write>(&self, f: &VFile, mut out: W, opts: TransferOptions<'_>) -> Result<W> {
        let mut left = f.size;
        self.dk()?; // a wiped drive must not keep decrypting with the file keys it still holds
        let chunks: Vec<Vec<u32>> = f
            .blocks
            .chunks(MAX_BLOCKS_PER_REQUEST as usize)
            .map(<[u32]>::to_vec)
            .collect();
        // Reads run ahead of decryption; only ciphertext is fetched early.
        let mut reads = InFlight(VecDeque::new());
        let mut next = 0;
        for (ci, chunk) in chunks.iter().enumerate() {
            while next < chunks.len() && reads.0.len() < IN_FLIGHT {
                let (api, slot, which) = (self.api().clone(), self.slot, chunks[next].clone());
                reads.0.push_back(tokio::spawn(
                    async move { read_runs(&api, slot, &which).await },
                ));
                next += 1;
            }
            opts.check_cancel()?;
            self.dk()?;
            let h = reads.0.pop_front().expect("a read per chunk");
            let data = h.await.map_err(join_error)??;
            for (j, (b, sealed)) in chunk.iter().zip(data).enumerate() {
                let k = (ci * MAX_BLOCKS_PER_REQUEST as usize + j) as u32;
                let plain = v::open_file_block(&f.key, self.slot, *b, k, &sealed)?;
                let take = (left as usize).min(plain.len());
                tokio::task::block_in_place(|| out.write_all(&plain[..take]))?;
                left -= take as u64;
            }
            if let Some(p) = opts.progress {
                p(f.size - left, f.size);
            }
        }
        if left != 0 {
            return Err(strongbox_core::Error::Integrity.into());
        }
        out.flush()?;
        Ok(out)
    }

    /// Download and verify a file. It appears at `local` only once fully verified.
    pub async fn download(
        &self,
        remote: &str,
        local: &Path,
        opts: TransferOptions<'_>,
    ) -> Result<()> {
        let f = self.file(remote)?;
        let tmp = local.with_file_name(format!(
            ".{}.fdpart",
            local
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("download")
        ));
        let result: Result<()> = async {
            let w = self
                .fetch(&f, BufWriter::new(File::create(&tmp)?), opts)
                .await?;
            let file = w.into_inner().map_err(|e| e.into_error())?;
            let _ = file.set_modified(UNIX_EPOCH + Duration::from_millis(f.mtime.max(0) as u64));
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

    /// Decrypt a whole file into memory (previews). Refuses files over `max_size`.
    pub async fn read_file(&self, remote: &str, max_size: u64) -> Result<Vec<u8>> {
        let f = self.file(remote)?;
        if f.size > max_size {
            return Err(Error::Invalid("file is too large to preview".into()));
        }
        self.fetch(
            &f,
            Vec::with_capacity(f.size as usize),
            TransferOptions::default(),
        )
        .await
    }

    /// Let another security key open this drive (and log in to the vault). `pin` is this
    /// drive's PIN; one touch on the new key.
    pub async fn add_key(&mut self, authn: Arc<dyn Authenticator>, pin: &str) -> Result<()> {
        self.add_key_named(authn, pin, "Security key").await
    }

    pub async fn add_key_named(
        &mut self,
        authn: Arc<dyn Authenticator>,
        pin: &str,
        label: &str,
    ) -> Result<()> {
        let label = self.client.clean_label(label, &[])?;
        let index = (0..KEY_ENTRIES)
            .find(|i| self.body.used_entries & (1 << i) == 0)
            .ok_or_else(|| Error::Invalid(format!("this drive already has {KEY_ENTRIES} keys")))?;
        let salt = drive_salt(self.slot, pin);
        let inner = self.client.inner.clone();
        let existing = inner.credentials.lock().unwrap().clone();
        if existing.len() >= v::MAX_RECORD_CREDENTIALS {
            return Err(Error::Invalid(format!(
                "this username already has {} keys",
                v::MAX_RECORD_CREDENTIALS
            )));
        }
        // A new credential for this username on the new key (the exclude list makes the key
        // refuse if it is already one of this username's keys), then its PRF: two touches.
        let (a, ex) = (authn.clone(), existing.clone());
        let cred = blocking(move || a.enroll(DEFAULT_RP_ID, VAULT_USER_NAME, &ex)).await?;
        let allow = vec![cred.clone()];
        let vsalt = inner.username.vault_salt()?;
        let pair = blocking(move || authn.prf2(DEFAULT_RP_ID, &allow, &vsalt, Some(&salt))).await?;
        let second = pair.second.ok_or(strongbox_fido::Error::PrfUnsupported)?;
        let ek = entry_key(&second);
        let member_creds = MemberCreds::from_prf(&pair.first);
        let added_member_id = member_id(&member_creds.locator);
        self.client.add_member(&member_creds).await?;
        let mut credentials = existing;
        credentials.push(cred);
        let mut members = inner.members.lock().unwrap().clone();
        members.push(VaultMemberLabel {
            id: added_member_id.clone(),
            label: label.clone(),
            kind: "security_key".into(),
            slot: None,
        });
        let record = inner.username.seal_record(&credentials, &members)?;
        inner
            .api
            .update_vault_record(&UpdateRecordRequest {
                lookup: inner.username.lookup.to_vec(),
                record,
            })
            .await?;
        *inner.credentials.lock().unwrap() = credentials;
        *inner.members.lock().unwrap() = members;
        self.entries[index] = v::wrap_entry(self.slot, index, &ek, &self.dk()?);
        self.body.used_entries |= 1 << index;
        self.body.grants.push(VaultGrant {
            entry: index as u8,
            member_id: added_member_id,
        });
        let tree = self.tree.clone();
        self.commit(tree).await
    }

    /// Create (or replace) this drive's recovery code. Show it once; it opens only this drive.
    pub async fn new_recovery_code(&mut self) -> Result<String> {
        self.new_recovery_code_named("Recovery code").await
    }

    pub async fn new_recovery_code_named(&mut self, label: &str) -> Result<String> {
        let old_ids = self.recovery_ids();
        let label = self.client.clean_label(label, &old_ids)?;
        let code = RecoveryCode::generate();
        let creds = code.member_creds();
        let old_ids: Vec<String> = self
            .client
            .inner
            .members
            .lock()
            .unwrap()
            .iter()
            .filter(|m| m.kind == "recovery_code" && m.slot == Some(self.slot))
            .map(|m| m.id.clone())
            .collect();
        for id in old_ids {
            self.client.remove_member(&id).await?;
        }
        self.client.add_member(&creds).await?;
        let mut members = self.client.inner.members.lock().unwrap().clone();
        members.push(VaultMemberLabel {
            id: member_id(&creds.locator),
            label: label.clone(),
            kind: "recovery_code".into(),
            slot: Some(self.slot),
        });
        let ids = self.client.inner.credentials.lock().unwrap().clone();
        let record = self.client.inner.username.seal_record(&ids, &members)?;
        self.client
            .inner
            .api
            .update_vault_record(&UpdateRecordRequest {
                lookup: self.client.inner.username.lookup.to_vec(),
                record,
            })
            .await?;
        *self.client.inner.members.lock().unwrap() = members;
        self.entries[RECOVERY_ENTRY] = v::wrap_entry(
            self.slot,
            RECOVERY_ENTRY,
            &code.entry_key(self.slot),
            &self.dk()?,
        );
        self.body.used_entries |= 1 << RECOVERY_ENTRY;
        let recovery_id = member_id(&creds.locator);
        self.body
            .grants
            .retain(|grant| grant.entry as usize != RECOVERY_ENTRY);
        self.body.grants.push(VaultGrant {
            entry: RECOVERY_ENTRY as u8,
            member_id: recovery_id,
        });
        let tree = self.tree.clone();
        self.commit(tree).await?;
        Ok(code.encode())
    }

    pub fn client(&self) -> &VaultClient {
        &self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_runs() {
        let r = runs(vec![(5, vec![1]), (3, vec![2]), (4, vec![3]), (9, vec![4])]);
        assert_eq!(r, vec![(3, vec![2, 3, 1]), (9, vec![4])]);
        let many: Vec<_> = (0..MAX_BLOCKS_PER_REQUEST + 1)
            .map(|b| (b, vec![0u8]))
            .collect();
        assert_eq!(runs(many).len(), 2);
    }
}

/// List a folder of a decrypted tree (see [`VaultDrive::tree`]).
pub fn list_in(tree: &VDir, path: &str) -> Result<Vec<ListEntry>> {
    let d = dir(tree, &comps(path)?)?;
    Ok(d.entries
        .iter()
        .map(|(name, n)| match n {
            VNode::Dir(d) => ListEntry {
                name: name.clone(),
                is_dir: true,
                size: 0,
                mtime: d.mtime,
            },
            VNode::File(f) => ListEntry {
                name: name.clone(),
                is_dir: false,
                size: f.size,
                mtime: f.mtime,
            },
        })
        .collect())
}

/// Case-insensitive name search over a decrypted tree.
pub fn search_in(tree: &VDir, query: &str) -> Vec<crate::SearchHit> {
    let q = query.trim().to_lowercase();
    let mut hits = Vec::new();
    if q.is_empty() {
        return hits;
    }
    let mut stack: Vec<(Vec<String>, &VDir)> = vec![(vec![], tree)];
    while let Some((c, d)) = stack.pop() {
        for (name, n) in &d.entries {
            let mut cc = c.clone();
            cc.push(name.clone());
            if name.to_lowercase().contains(&q) {
                let entry = match n {
                    VNode::Dir(d) => ListEntry {
                        name: name.clone(),
                        is_dir: true,
                        size: 0,
                        mtime: d.mtime,
                    },
                    VNode::File(f) => ListEntry {
                        name: name.clone(),
                        is_dir: false,
                        size: f.size,
                        mtime: f.mtime,
                    },
                };
                hits.push(crate::SearchHit {
                    path: format!("/{}", cc.join("/")),
                    parent: format!("/{}", c.join("/")),
                    entry,
                });
            }
            if let VNode::Dir(sub) = n {
                stack.push((cc, sub));
            }
        }
    }
    hits.sort_by_key(|h| h.entry.name.to_lowercase());
    hits.truncate(500);
    hits
}
