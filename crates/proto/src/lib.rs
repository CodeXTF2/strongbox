//! Wire types for the Strongbox HTTP API (`/v1`). JSON bodies; byte fields are base64.
//!
//! Everything the server sees is listed here. Note what is absent: names, paths, timestamps,
//! tree structure and exact sizes all live inside sealed nodes.

use serde::{Deserialize, Serialize};
use strongbox_core::keyslot::Keyslot;
use strongbox_core::serde_b64;
use strongbox_core::Id;

pub const API_PREFIX: &str = "/v1";
/// Header carrying a node's version on `GET /v1/nodes/{id}`.
pub const NODE_VERSION_HEADER: &str = "x-node-version";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Random per-installation id. Clients pin it at sign-up and bind it into login signatures.
    pub server_id: String,
    pub software_version: String,
    pub registration: RegistrationMode,
    pub max_blob_size: u64,
    pub max_node_size: u64,
    /// Deniable vault layout (`/v2`), identical for every vault on this server.
    #[serde(default)]
    pub vault: Option<VaultLayout>,
}

// ---------------------------------------------------------------- /v2 deniable vaults
// See docs/deniable-drives.md. The server sees vault ids, member locator hashes and public
// keys, and whole fixed-size blocks; never which slots are in use.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultLayout {
    pub slots: u32,
    pub blocks_per_slot: u32,
    pub block_size: u32,
}

/// Most blocks one `/v2/slots/{slot}/blocks` request may read or write.
pub const MAX_BLOCKS_PER_REQUEST: u32 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateVaultRequest {
    /// Username lookup id (derived from the username with Argon2id, client side).
    #[serde(with = "serde_b64")]
    pub lookup: Vec<u8>,
    /// Encrypted credential record, fixed size.
    #[serde(with = "serde_b64")]
    pub record: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub locator: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub auth_public_key: Vec<u8>,
    pub invite: Option<String>,
}

/// `GET /v2/lookup/{hex lookup id}`. Unknown ids get a stable decoy of the same size.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordResponse {
    #[serde(with = "serde_b64")]
    pub record: Vec<u8>,
}

/// `PUT /v2/record` (authenticated): replace this vault's credential record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateRecordRequest {
    #[serde(with = "serde_b64")]
    pub lookup: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub record: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultChallengeRequest {
    #[serde(with = "serde_b64")]
    pub locator: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultSessionRequest {
    #[serde(with = "serde_b64")]
    pub locator: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub challenge: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddMemberRequest {
    #[serde(with = "serde_b64")]
    pub locator: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub auth_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberInfo {
    /// Hex SHA-256 of the member's locator.
    pub id: String,
    #[serde(with = "serde_b64")]
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembersResponse {
    pub members: Vec<MemberInfo>,
    /// Which member this session logged in as.
    pub current: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    Open,
    Invite,
    Closed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    #[serde(with = "serde_b64")]
    pub auth_public_key: Vec<u8>,
    pub keyslots: Vec<Keyslot>,
    pub invite: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyslotsResponse {
    pub keyslots: Vec<Keyslot>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub username: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChallengeResponse {
    #[serde(with = "serde_b64")]
    pub challenge: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionRequest {
    pub username: String,
    #[serde(with = "serde_b64")]
    pub challenge: Vec<u8>,
    #[serde(with = "serde_b64")]
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: String,
    /// Unix seconds.
    pub expires_at: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeMeta {
    pub id: Id,
    pub version: u64,
    /// Per-account change sequence number, for incremental sync.
    pub seq: u64,
    pub size: u64,
    pub deleted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub changes: Vec<NodeMeta>,
    /// Pass back as `?since=` to continue.
    pub cursor: u64,
    pub more: bool,
}

/// Atomically apply node writes and blob deletions. Every op names the version it expects
/// (0 = node must not exist); if any expectation fails nothing is applied and the server
/// answers 409 with [`ApiError::conflicts`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CommitRequest {
    pub ops: Vec<CommitOp>,
    #[serde(default)]
    pub delete_blobs: Vec<Id>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitOp {
    pub id: Id,
    pub expect_version: u64,
    pub action: CommitAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommitAction {
    /// Store sealed bytes as version `expect_version + 1`.
    Put {
        #[serde(with = "serde_b64")]
        data: Vec<u8>,
    },
    Delete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitResponse {
    pub versions: Vec<NodeVersion>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeVersion {
    pub id: Id,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobListResponse {
    pub blobs: Vec<BlobMeta>,
    pub next: Option<Id>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobMeta {
    pub id: Id,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageResponse {
    pub used_bytes: u64,
    pub quota_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<NodeVersion>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    UsernameTaken,
    QuotaExceeded,
    TooLarge,
    RateLimited,
    Internal,
}
