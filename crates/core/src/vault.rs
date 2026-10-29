//! Deniable vaults (format v1, see `docs/deniable-drives.md`).
//!
//! A vault is a fixed grid of slots × blocks on the server, all random from creation. A
//! drive lives in one slot and is opened by (slot, drive PIN) through the security key's
//! hmac-secret. Everything here is pure crypto and formats: no I/O.
//!
//! Every stored unit is exactly [`BLOCK_SIZE`] bytes and indistinguishable from random
//! filler without the right key, which is what makes unused slots and wrong PINs look alike.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{aead, kdf, Error, Key, Result};

pub const BLOCK_SIZE: usize = 256 * 1024;
/// Plaintext bytes per sealed block (nonce and tag take 40).
pub const BLOCK_PAYLOAD: usize = BLOCK_SIZE - aead::NONCE_LEN - aead::TAG_LEN;
/// Key entries per header (one per security key that can open the drive).
pub const KEY_ENTRIES: usize = 8;
/// Index of the recovery-code entry.
pub const RECOVERY_ENTRY: usize = KEY_ENTRIES;
const ENTRIES: usize = KEY_ENTRIES + 1;
pub const ENTRY_LEN: usize = aead::NONCE_LEN + 32 + aead::TAG_LEN;
const ENTRIES_LEN: usize = ENTRIES * ENTRY_LEN;
const HEADER_BODY_PLAIN: usize = BLOCK_SIZE - ENTRIES_LEN - aead::NONCE_LEN - aead::TAG_LEN;
/// Blocks 0 and 1 of every slot are the two header copies.
pub const HEADER_BLOCKS: u32 = 2;
/// Shortest drive PIN the client accepts (see the spec's guessing-cost table).
pub const MIN_DRIVE_PIN_LEN: usize = 8;

/// PRF input that yields the vault secret (login), the same for every vault.
pub const VAULT_SALT: &[u8] = b"strongbox/vault-salt/v1";

const L_DRIVE_SALT: &str = "strongbox/drive-salt/v1";
const L_LOCATOR: &str = "strongbox/vault/locator/v1";
const L_AUTH: &str = "strongbox/vault/auth/v1";
const L_REC_LOCATOR: &str = "strongbox/vault/recovery-locator/v1";
const L_REC_AUTH: &str = "strongbox/vault/recovery-auth/v1";
const L_ENTRY: &str = "strongbox/drive/entry/v1";
const L_REC_ENTRY: &str = "strongbox/drive/recovery-entry/v1";
const L_HEADER: &str = "strongbox/drive/header/v1";
const L_META: &str = "strongbox/drive/meta/v1";
const L_FILE: &str = "strongbox/drive/file/v1";
const L_CHALLENGE: &str = "strongbox/vault-auth-challenge/v1";

/// PRF input for drive `slot` with `pin`. The PIN goes into the salt so that every guess
/// needs the physical key (one touch per two guesses).
pub fn drive_salt(slot: u32, pin: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(kdf::info(
        L_DRIVE_SALT,
        &[&slot.to_be_bytes(), pin.as_bytes()],
    ));
    h.finalize().into()
}

/// Check a drive PIN against the minimum length (digits or a passphrase).
pub fn check_drive_pin(pin: &str) -> Result<()> {
    if pin.chars().count() < MIN_DRIVE_PIN_LEN {
        return Err(Error::Malformed(
            "drive PIN too short (at least 8 characters)",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- login credentials

/// What a vault member (security key or recovery code) uses to log in.
pub struct MemberCreds {
    /// Sent at login; the server stores only its SHA-256.
    pub locator: [u8; 32],
    pub auth: SigningKey,
}

impl MemberCreds {
    /// From the hmac-secret output for [`VAULT_SALT`].
    pub fn from_prf(prf_vault: &[u8; 32]) -> Self {
        Self::derive(prf_vault, L_LOCATOR, L_AUTH)
    }

    fn derive(ikm: &[u8], locator: &str, auth: &str) -> Self {
        MemberCreds {
            locator: *kdf::derive(ikm, None, locator, &[]).as_bytes(),
            auth: SigningKey::from_bytes(kdf::derive(ikm, None, auth, &[]).as_bytes()),
        }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.auth.verifying_key().to_bytes()
    }

    pub fn sign_challenge(&self, server_id: &str, challenge: &[u8]) -> [u8; 64] {
        self.auth
            .sign(&challenge_message(server_id, &self.locator, challenge))
            .to_bytes()
    }
}

pub fn locator_hash(locator: &[u8]) -> [u8; 32] {
    Sha256::digest(locator).into()
}

fn challenge_message(server_id: &str, locator: &[u8], challenge: &[u8]) -> Vec<u8> {
    kdf::info(
        L_CHALLENGE,
        &[server_id.as_bytes(), &locator_hash(locator), challenge],
    )
}

/// Server side of the login check.
pub fn verify_challenge(
    public_key: &[u8; 32],
    server_id: &str,
    locator: &[u8],
    challenge: &[u8],
    sig: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    vk.verify_strict(
        &challenge_message(server_id, locator, challenge),
        &ed25519_dalek::Signature::from_bytes(sig),
    )
    .is_ok()
}

// ---------------------------------------------------------------- usernames

const L_USERNAME_SALT: &str = "strongbox/vault/username/v1";
const L_LOOKUP: &str = "strongbox/vault/lookup/v1";
const L_RECORD: &str = "strongbox/vault/record/v1";
/// Plaintext size of a credential record: fixed, so the record does not reveal how many
/// keys a username has.
const RECORD_PLAIN: usize = 8192;
/// Stored size of a credential record (also the size of decoys for unknown usernames).
pub const RECORD_LEN: usize = aead::NONCE_LEN + RECORD_PLAIN + aead::TAG_LEN;
/// Most security keys per username (each has its own credential id in the record).
pub const MAX_RECORD_CREDENTIALS: usize = KEY_ENTRIES;

/// Keys derived from a username. Argon2id makes offline username guessing against a seized
/// database expensive; the server id as salt stops precomputation across servers.
pub struct UsernameKeys {
    /// The server's index for this username's record (sent in the clear).
    pub lookup: [u8; 32],
    record_key: Key,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultMemberLabel {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub slot: Option<u32>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CredentialRecord {
    credential_ids: Vec<serde_bytes::ByteBuf>,
    members: Vec<VaultMemberLabel>,
}

impl UsernameKeys {
    pub fn derive(username: &str, server_id: &str) -> Result<Self> {
        let salt = Sha256::digest(kdf::info(L_USERNAME_SALT, &[server_id.as_bytes()]));
        let params = argon2::Params::new(64 * 1024, 3, 4, Some(32))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        let mut out = zeroize::Zeroizing::new([0u8; 32]);
        argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(username.as_bytes(), &salt, out.as_mut())
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(UsernameKeys {
            lookup: *kdf::derive(out.as_ref(), None, L_LOOKUP, &[]).as_bytes(),
            record_key: kdf::derive(out.as_ref(), None, L_RECORD, &[]),
        })
    }

    /// Encrypt the credential ids of this username's security keys.
    pub fn seal_record(
        &self,
        credential_ids: &[Vec<u8>],
        members: &[VaultMemberLabel],
    ) -> Result<Vec<u8>> {
        if credential_ids.is_empty() || credential_ids.len() > MAX_RECORD_CREDENTIALS {
            return Err(Error::Malformed(
                "credential record must hold 1-8 credentials",
            ));
        }
        let mut cbor = Vec::new();
        let record = CredentialRecord {
            credential_ids: credential_ids
                .iter()
                .map(|c| serde_bytes::ByteBuf::from(c.clone()))
                .collect(),
            members: members.to_vec(),
        };
        ciborium::into_writer(&record, &mut cbor).map_err(|e| Error::Encoding(e.to_string()))?;
        if cbor.len() + 4 > RECORD_PLAIN {
            return Err(Error::Malformed("credential ids too long"));
        }
        let mut plain = (cbor.len() as u32).to_be_bytes().to_vec();
        plain.extend_from_slice(&cbor);
        plain.resize(RECORD_PLAIN, 0);
        Ok(aead::seal(
            &self.record_key,
            &aead::aad(L_RECORD, &[&self.lookup]),
            &plain,
        ))
    }

    /// `None` for a record this username's key does not open, which includes the server's
    /// decoys for unknown usernames.
    pub fn open_record(&self, record: &[u8]) -> Option<(Vec<Vec<u8>>, Vec<VaultMemberLabel>)> {
        let plain = aead::open(
            &self.record_key,
            &aead::aad(L_RECORD, &[&self.lookup]),
            record,
        )
        .ok()?;
        let len = u32::from_be_bytes(plain.get(..4)?.try_into().ok()?) as usize;
        let record: CredentialRecord = ciborium::from_reader(plain.get(4..4 + len)?).ok()?;
        Some((
            record
                .credential_ids
                .into_iter()
                .map(|b| b.into_vec())
                .collect(),
            record.members,
        ))
    }
}

// ---------------------------------------------------------------- recovery codes

/// A recovery code: one 256-bit secret. Its vault login credentials and per-drive entry keys
/// are derived from the whole secret under separate labels, so each keeps the full 256-bit
/// strength against offline guessing, including Grover-style quantum search.
pub struct RecoveryCode {
    secret: zeroize::Zeroizing<[u8; 32]>,
}

impl RecoveryCode {
    pub fn generate() -> Self {
        RecoveryCode {
            secret: crate::recovery::generate(),
        }
    }

    pub fn encode(&self) -> String {
        crate::recovery::encode(&self.secret)
    }

    pub fn decode(code: &str) -> Result<Self> {
        Ok(RecoveryCode {
            secret: crate::recovery::decode(code)?,
        })
    }

    /// Credentials to log in to the vault as this recovery code's member.
    pub fn member_creds(&self) -> MemberCreds {
        MemberCreds::derive(self.secret.as_ref(), L_REC_LOCATOR, L_REC_AUTH)
    }

    pub fn entry_key(&self, slot: u32) -> Key {
        kdf::derive(
            self.secret.as_ref(),
            None,
            L_REC_ENTRY,
            &[&slot.to_be_bytes()],
        )
    }
}

/// Entry key from the hmac-secret output for [`drive_salt`].
pub fn entry_key(prf_drive: &[u8; 32]) -> Key {
    kdf::derive(prf_drive, None, L_ENTRY, &[])
}

// ---------------------------------------------------------------- blocks

/// A block of fresh random bytes (filler, wiping).
pub fn random_block() -> Vec<u8> {
    let mut b = vec![0u8; BLOCK_SIZE];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn seal_block(key: &Key, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    assert!(plaintext.len() <= BLOCK_PAYLOAD);
    let mut padded = plaintext.to_vec();
    padded.resize(BLOCK_PAYLOAD, 0);
    let out = aead::seal(key, aad, &padded);
    debug_assert_eq!(out.len(), BLOCK_SIZE);
    out
}

fn open_block(key: &Key, aad: &[u8], block: &[u8]) -> Result<Vec<u8>> {
    if block.len() != BLOCK_SIZE {
        return Err(Error::Malformed("block size"));
    }
    aead::open(key, aad, block)
}

// ---------------------------------------------------------------- header

/// Decrypted header body.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderBody {
    pub generation: u64,
    /// Bit i set: entry i is in use (so adding a key never overwrites another key's entry).
    pub used_entries: u16,
    pub meta_blocks: Vec<u32>,
    pub meta_len: u64,
    /// Which account credentials can open this drive; encrypted with the drive header.
    #[serde(default)]
    pub grants: Vec<VaultGrant>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultGrant {
    pub entry: u8,
    pub member_id: String,
}

/// A raw header entry (always [`ENTRY_LEN`] bytes).
pub type Entry = [u8; ENTRY_LEN];

pub fn random_entry() -> Entry {
    let mut e = [0u8; ENTRY_LEN];
    rand::thread_rng().fill_bytes(&mut e);
    e
}

fn entry_aad(slot: u32, index: usize) -> Vec<u8> {
    aead::aad(L_ENTRY, &[&slot.to_be_bytes(), &[index as u8]])
}

/// Wrap the drive key for entry `index` of `slot`.
pub fn wrap_entry(slot: u32, index: usize, entry_key: &Key, drive_key: &Key) -> Entry {
    aead::seal(entry_key, &entry_aad(slot, index), drive_key.as_bytes())
        .try_into()
        .expect("entry length")
}

fn header_key(drive_key: &Key) -> Key {
    kdf::subkey(drive_key, L_HEADER, &[])
}

fn header_aad(slot: u32, copy: u8) -> Vec<u8> {
    aead::aad(L_HEADER, &[&slot.to_be_bytes(), &[copy]])
}

/// The entries of a header block (valid or random), to carry over when rewriting it.
pub fn header_entries(block: &[u8]) -> [Entry; ENTRIES] {
    std::array::from_fn(|i| {
        block[i * ENTRY_LEN..(i + 1) * ENTRY_LEN]
            .try_into()
            .unwrap()
    })
}

pub fn seal_header(
    slot: u32,
    copy: u8,
    drive_key: &Key,
    entries: &[Entry; ENTRIES],
    body: &HeaderBody,
) -> Result<Vec<u8>> {
    let mut cbor = Vec::new();
    ciborium::into_writer(body, &mut cbor).map_err(|e| Error::Encoding(e.to_string()))?;
    if cbor.len() + 4 > HEADER_BODY_PLAIN {
        return Err(Error::Malformed("header body too large"));
    }
    let mut plain = Vec::with_capacity(HEADER_BODY_PLAIN);
    plain.extend_from_slice(&(cbor.len() as u32).to_be_bytes());
    plain.extend_from_slice(&cbor);
    plain.resize(HEADER_BODY_PLAIN, 0);
    let mut out = Vec::with_capacity(BLOCK_SIZE);
    for e in entries {
        out.extend_from_slice(e);
    }
    out.extend(aead::seal(
        &header_key(drive_key),
        &header_aad(slot, copy),
        &plain,
    ));
    debug_assert_eq!(out.len(), BLOCK_SIZE);
    Ok(out)
}

/// An opened header: the drive key, which entry opened it, and the body.
pub struct OpenedHeader {
    pub drive_key: Key,
    pub entry: usize,
    pub body: HeaderBody,
}

/// Try to open one header copy with any of `keys` (each tried against its entries: key
/// entries for security keys, the recovery entry for a recovery code). `None` means nothing
/// opened it, which is deliberately the same for a wrong PIN and an unused slot.
pub fn open_header(
    slot: u32,
    copy: u8,
    block: &[u8],
    keys: &[(Key, EntryKind)],
) -> Option<OpenedHeader> {
    if block.len() != BLOCK_SIZE {
        return None;
    }
    let entries = header_entries(block);
    for (key, kind) in keys {
        let range = match kind {
            EntryKind::Key => 0..KEY_ENTRIES,
            EntryKind::Recovery => RECOVERY_ENTRY..RECOVERY_ENTRY + 1,
        };
        for i in range {
            let Ok(dk) = aead::open(key, &entry_aad(slot, i), &entries[i]) else {
                continue;
            };
            let Ok(dk) = <[u8; 32]>::try_from(dk.as_slice()) else {
                continue;
            };
            let drive_key = Key::from_bytes(dk);
            let Some(body) = open_header_body(slot, copy, block, &drive_key) else {
                continue;
            };
            return Some(OpenedHeader {
                drive_key,
                entry: i,
                body,
            });
        }
    }
    None
}

/// Decrypt a header copy's body with a known drive key (`None` if it does not authenticate,
/// e.g. the copy was never written or belongs to an older drive in this slot).
pub fn open_header_body(slot: u32, copy: u8, block: &[u8], drive_key: &Key) -> Option<HeaderBody> {
    if block.len() != BLOCK_SIZE {
        return None;
    }
    let plain = aead::open(
        &header_key(drive_key),
        &header_aad(slot, copy),
        &block[ENTRIES_LEN..],
    )
    .ok()?;
    let len = u32::from_be_bytes(plain[..4].try_into().unwrap()) as usize;
    ciborium::from_reader(plain.get(4..4 + len)?).ok()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Key,
    Recovery,
}

// ---------------------------------------------------------------- metadata

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VDir {
    pub entries: BTreeMap<String, VNode>,
    pub mtime: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VNode {
    Dir(VDir),
    File(VFile),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VFile {
    pub size: u64,
    pub mtime: i64,
    #[serde(with = "serde_bytes")]
    pub sha256: Vec<u8>,
    pub key: Key,
    pub blocks: Vec<u32>,
}

impl VDir {
    /// Every block referenced by files under this directory.
    pub fn file_blocks(&self, out: &mut Vec<u32>) {
        for n in self.entries.values() {
            match n {
                VNode::Dir(d) => d.file_blocks(out),
                VNode::File(f) => out.extend_from_slice(&f.blocks),
            }
        }
    }
}

fn meta_key(drive_key: &Key) -> Key {
    kdf::subkey(drive_key, L_META, &[])
}

fn meta_aad(slot: u32, block: u32) -> Vec<u8> {
    aead::aad(L_META, &[&slot.to_be_bytes(), &block.to_be_bytes()])
}

pub fn encode_meta(root: &VDir) -> Result<Vec<u8>> {
    let mut cbor = Vec::new();
    ciborium::into_writer(root, &mut cbor).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(cbor)
}

/// Blocks needed to store `len` bytes of metadata.
pub fn meta_block_count(len: usize) -> usize {
    len.div_ceil(BLOCK_PAYLOAD).max(1)
}

/// Seal encoded metadata into the given blocks (`blocks.len() == meta_block_count(len)`).
pub fn seal_meta(drive_key: &Key, slot: u32, blocks: &[u32], cbor: &[u8]) -> Vec<Vec<u8>> {
    let key = meta_key(drive_key);
    let mut chunks: Vec<&[u8]> = cbor.chunks(BLOCK_PAYLOAD).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    assert_eq!(chunks.len(), blocks.len());
    blocks
        .iter()
        .zip(chunks)
        .map(|(b, c)| seal_block(&key, &meta_aad(slot, *b), c))
        .collect()
}

pub fn open_meta(
    drive_key: &Key,
    slot: u32,
    body: &HeaderBody,
    sealed: &[Vec<u8>],
) -> Result<VDir> {
    if sealed.len() != body.meta_blocks.len() {
        return Err(Error::Malformed("metadata block count"));
    }
    let key = meta_key(drive_key);
    let mut cbor = Vec::with_capacity(sealed.len() * BLOCK_PAYLOAD);
    for (b, data) in body.meta_blocks.iter().zip(sealed) {
        cbor.extend(open_block(&key, &meta_aad(slot, *b), data)?);
    }
    cbor.truncate(body.meta_len as usize);
    ciborium::from_reader(cbor.as_slice()).map_err(|e| Error::Encoding(e.to_string()))
}

// ---------------------------------------------------------------- file content

fn file_aad(slot: u32, block: u32, index: u32) -> Vec<u8> {
    aead::aad(
        L_FILE,
        &[
            &slot.to_be_bytes(),
            &block.to_be_bytes(),
            &index.to_be_bytes(),
        ],
    )
}

/// Blocks needed for a file of `size` bytes (empty files take none).
pub fn file_block_count(size: u64) -> usize {
    size.div_ceil(BLOCK_PAYLOAD as u64) as usize
}

/// Seal the `index`-th piece of a file (≤ [`BLOCK_PAYLOAD`] bytes) for storage at `block`.
pub fn seal_file_block(file_key: &Key, slot: u32, block: u32, index: u32, data: &[u8]) -> Vec<u8> {
    seal_block(file_key, &file_aad(slot, block, index), data)
}

pub fn open_file_block(
    file_key: &Key,
    slot: u32,
    block: u32,
    index: u32,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    open_block(file_key, &file_aad(slot, block, index), sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prf(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn salts_and_creds() {
        assert_ne!(drive_salt(1, "12345678"), drive_salt(2, "12345678"));
        assert_ne!(drive_salt(1, "12345678"), drive_salt(1, "12345679"));
        let a = MemberCreds::from_prf(&prf(1));
        let b = MemberCreds::from_prf(&prf(2));
        assert_ne!(a.locator, b.locator);
        let sig = a.sign_challenge("srv", b"chal");
        assert!(verify_challenge(
            &a.public_key(),
            "srv",
            &a.locator,
            b"chal",
            &sig
        ));
        assert!(!verify_challenge(
            &a.public_key(),
            "other",
            &a.locator,
            b"chal",
            &sig
        ));
        assert!(!verify_challenge(
            &b.public_key(),
            "srv",
            &a.locator,
            b"chal",
            &sig
        ));
        assert!(check_drive_pin("1234567").is_err());
        assert!(check_drive_pin("12345678").is_ok());
    }

    #[test]
    fn username_records() {
        let a = UsernameKeys::derive("quiet-river-lantern", "srv").unwrap();
        let a2 = UsernameKeys::derive("quiet-river-lantern", "srv").unwrap();
        let other_server = UsernameKeys::derive("quiet-river-lantern", "srv2").unwrap();
        let b = UsernameKeys::derive("someone-else", "srv").unwrap();
        assert_eq!(a.lookup, a2.lookup);
        assert_ne!(a.lookup, other_server.lookup);
        assert_ne!(a.lookup, b.lookup);
        let one = a.seal_record(&[vec![1; 64]], &[]).unwrap();
        let five = a.seal_record(&vec![vec![2; 64]; 5], &[]).unwrap();
        assert_eq!(one.len(), RECORD_LEN);
        assert_eq!(
            five.len(),
            RECORD_LEN,
            "record size hides the number of keys"
        );
        assert_eq!(a2.open_record(&five).unwrap().0, vec![vec![2u8; 64]; 5]);
        assert!(b.open_record(&one).is_none());
        let mut decoy = vec![0u8; RECORD_LEN];
        rand::thread_rng().fill_bytes(&mut decoy);
        assert!(a.open_record(&decoy).is_none());
        assert!(a.seal_record(&[], &[]).is_err());
        assert!(a.seal_record(&vec![vec![0; 64]; 9], &[]).is_err());
    }

    #[test]
    fn header_roundtrip_and_deniability() {
        let slot = 7;
        let drive_key = Key::random();
        let good = entry_key(&prf(3));
        let wrong = entry_key(&prf(4));
        let mut entries: [Entry; ENTRIES] = std::array::from_fn(|_| random_entry());
        entries[2] = wrap_entry(slot, 2, &good, &drive_key);
        let body = HeaderBody {
            generation: 5,
            used_entries: 1 << 2,
            meta_blocks: vec![2, 3],
            meta_len: 10,
            grants: vec![],
        };
        let block = seal_header(slot, 0, &drive_key, &entries, &body).unwrap();
        assert_eq!(block.len(), BLOCK_SIZE);

        let opened = open_header(slot, 0, &block, &[(good.clone(), EntryKind::Key)]).unwrap();
        assert_eq!((opened.entry, &opened.body), (2, &body));
        assert_eq!(opened.drive_key, drive_key);
        // Wrong PIN, wrong slot, wrong copy and pure filler all fail the same way.
        assert!(open_header(slot, 0, &block, &[(wrong, EntryKind::Key)]).is_none());
        assert!(open_header(slot + 1, 0, &block, &[(good.clone(), EntryKind::Key)]).is_none());
        assert!(open_header(slot, 1, &block, &[(good.clone(), EntryKind::Key)]).is_none());
        assert!(open_header(slot, 0, &random_block(), &[(good.clone(), EntryKind::Key)]).is_none());
        // A key entry is not accepted as the recovery entry.
        assert!(open_header(slot, 0, &block, &[(good, EntryKind::Recovery)]).is_none());
        // Entries carry over byte for byte.
        assert_eq!(header_entries(&block), entries);
    }

    #[test]
    fn recovery_entry() {
        let slot = 3;
        let code = RecoveryCode::generate();
        let back = RecoveryCode::decode(&code.encode()).unwrap();
        assert_eq!(back.encode(), code.encode());
        assert_eq!(back.member_creds().locator, code.member_creds().locator);
        // Login and drive keys are independent derivations of the same secret.
        assert_ne!(
            &code.member_creds().locator[..],
            code.entry_key(slot).as_bytes()
        );
        let drive_key = Key::random();
        let mut entries: [Entry; ENTRIES] = std::array::from_fn(|_| random_entry());
        entries[RECOVERY_ENTRY] =
            wrap_entry(slot, RECOVERY_ENTRY, &code.entry_key(slot), &drive_key);
        let block = seal_header(slot, 1, &drive_key, &entries, &HeaderBody::default()).unwrap();
        let o = open_header(
            slot,
            1,
            &block,
            &[(back.entry_key(slot), EntryKind::Recovery)],
        )
        .unwrap();
        assert_eq!(o.entry, RECOVERY_ENTRY);
        assert!(open_header(
            slot,
            1,
            &block,
            &[(back.entry_key(slot + 1), EntryKind::Recovery)]
        )
        .is_none());
        assert_ne!(
            code.member_creds().locator,
            MemberCreds::from_prf(&prf(1)).locator
        );
    }

    #[test]
    fn meta_and_file_blocks() {
        let slot = 1;
        let dk = Key::random();
        let mut root = VDir::default();
        for i in 0..2000 {
            root.entries.insert(
                format!("file-{i:05}-with-a-longish-name.txt"),
                VNode::File(VFile {
                    size: 1,
                    mtime: 2,
                    sha256: vec![0; 32],
                    key: Key::random(),
                    blocks: vec![i],
                }),
            );
        }
        let cbor = encode_meta(&root).unwrap();
        let n = meta_block_count(cbor.len());
        let blocks: Vec<u32> = (10..10 + n as u32).collect();
        let sealed = seal_meta(&dk, slot, &blocks, &cbor);
        assert!(sealed.iter().all(|b| b.len() == BLOCK_SIZE));
        let body = HeaderBody {
            meta_blocks: blocks.clone(),
            meta_len: cbor.len() as u64,
            ..Default::default()
        };
        assert_eq!(open_meta(&dk, slot, &body, &sealed).unwrap(), root);
        // Swapped block positions fail.
        let mut swapped = body.clone();
        swapped.meta_blocks[0] += 100;
        assert!(open_meta(&dk, slot, &swapped, &sealed).is_err());

        let fk = Key::random();
        let b = seal_file_block(&fk, slot, 42, 0, b"hello");
        let mut want = b"hello".to_vec();
        want.resize(BLOCK_PAYLOAD, 0);
        assert_eq!(open_file_block(&fk, slot, 42, 0, &b).unwrap(), want);
        assert!(open_file_block(&fk, slot, 43, 0, &b).is_err());
        assert!(open_file_block(&fk, slot, 42, 1, &b).is_err());
        assert_eq!(file_block_count(0), 0);
        assert_eq!(file_block_count(BLOCK_PAYLOAD as u64 + 1), 2);
    }
}
