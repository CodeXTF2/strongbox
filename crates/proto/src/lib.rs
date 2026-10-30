//! Wire types for the Strongbox HTTP API (`/v1/info`, `/v2/...`). JSON bodies; byte fields are base64.
//!
//! Everything the server sees is listed here. Note what is absent: names, paths, timestamps,
//! tree structure and which drive slots are in use.

use serde::{Deserialize, Serialize};
use strongbox_core::serde_b64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Random per-installation id. Clients pin it at sign-up and bind it into login signatures.
    pub server_id: String,
    pub software_version: String,
    pub registration: RegistrationMode,
    /// Vault layout (`/v2`), identical for every vault on this server.
    pub vault: VaultLayout,
}

// ---------------------------------------------------------------- sealed channel
// Only `GET /v1/info`, `GET /v2/lookup/{id}`, `POST /v2/vaults` (sign-up), `POST /v2/channel`
// and `POST /v2/rpc` are served in the clear; every other route is reachable only inside the
// sealed channel (`strongbox_core::channel`), as a request carried by `POST /v2/rpc`.
//
// `POST /v2/channel` (hello): body = member id (SHA-256 of the locator, 32 bytes) || client
// nonce (32 bytes). Reply = server nonce (32) || session id (16) || confirm tag (32).
//
// `POST /v2/rpc`: body = session id (16) || counter (8, big endian) || sealed request; the
// reply body is the sealed response. Failures at the channel level are a plain `ApiError`.

pub const CHANNEL_HELLO_PATH: &str = "/v2/channel";
pub const CHANNEL_RPC_PATH: &str = "/v2/rpc";

// ---------------------------------------------------------------- /v2 vaults
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
    /// The member's sealed-channel key (see `strongbox_core::channel`). Sent once, at sign-up,
    /// which must happen on a network the client trusts.
    #[serde(with = "serde_b64")]
    pub transport_key: Vec<u8>,
    pub invite: Option<String>,
}

/// `POST /v2/invite/check`: whether sign-up would accept this invite code right now (nothing is
/// spent), so the client can ask for it before the user touches their security key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckInviteRequest {
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
    #[serde(with = "serde_b64")]
    pub transport_key: Vec<u8>,
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
pub struct ChallengeResponse {
    #[serde(with = "serde_b64")]
    pub challenge: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionResponse {
    pub token: String,
    /// Unix seconds.
    pub expires_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
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
    RateLimited,
    Internal,
}
