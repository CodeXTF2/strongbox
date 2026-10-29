//! `/v2` deniable vault routes (docs/deniable-drives.md §8).
//!
//! Sessions and challenges live in memory only: the database must not record when anyone
//! logged in. Unknown locators get a random challenge exactly like known ones.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use strongbox_core::vault::{locator_hash, verify_challenge, RECORD_LEN};
use strongbox_proto::*;

use crate::api::{check_registration, decoy_bytes, invalid_invite, rate_limit, ClientIp};
use crate::db::{CreateVault, MemberAdd, MemberDelete};
use crate::error::{AppError, AppResult};
use crate::AppState;

type St = State<Arc<AppState>>;

const CHALLENGE_TTL: Duration = Duration::from_secs(120);
const MAX_PENDING_CHALLENGES: usize = 100_000;
const MAX_MEMBERS: usize = 32;

/// SHA-256(token) → (vault id, member id, expiry)
type SessionMap = HashMap<[u8; 32], (String, [u8; 32], Instant)>;
/// challenge → (locator hash, expiry)
type ChallengeMap = HashMap<Vec<u8>, ([u8; 32], Instant)>;

/// In-memory vault sessions and challenges.
#[derive(Default)]
pub struct VaultSessions {
    sessions: Mutex<SessionMap>,
    challenges: Mutex<ChallengeMap>,
}

impl VaultSessions {
    /// Unexpired sessions (each is one signed-in member key).
    pub fn active_count(&self) -> usize {
        let now = Instant::now();
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|(_, _, exp)| *exp > now)
            .count()
    }

    pub fn vault_for_token(&self, token_hash: &[u8; 32]) -> Option<String> {
        let sessions = self.sessions.lock().unwrap();
        match sessions.get(token_hash) {
            Some((vault, _, exp)) if *exp > Instant::now() => Some(vault.clone()),
            _ => None,
        }
    }

    pub fn remove_vault_sessions(&self, vault: &str) {
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, (session_vault, _, _)| session_vault != vault);
    }

    pub fn purge(&self) {
        let now = Instant::now();
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, (_, _, exp)| *exp > now);
        self.challenges
            .lock()
            .unwrap()
            .retain(|_, (_, exp)| *exp > now);
    }
}

/// Routes served in the clear: sign-up and the username record lookup (needed before the
/// client has touched its key, so before a channel can exist).
pub fn plain_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/v2/vaults", post(create_vault))
        .route("/v2/lookup/{lookup}", get(lookup))
}

/// Routes reachable only inside the sealed channel (`channel_api::rpc`).
pub fn sealed_routes(state: &AppState) -> Router<Arc<AppState>> {
    let bs = state.vaults.layout.block_size as usize;
    Router::new()
        .route("/v2/vaults", delete(delete_account))
        // `/v1/info` again, but authenticated: the client compares the two.
        .route("/v2/info", get(crate::api::info))
        .route("/v2/record", put(update_record))
        .route("/v2/auth/challenge", post(challenge))
        .route("/v2/auth/session", post(create_session).delete(logout))
        .route("/v2/members", get(list_members).post(add_member))
        .route("/v2/members/{id}", delete(remove_member))
        .route(
            "/v2/slots/{slot}/blocks",
            get(read_blocks)
                .put(write_blocks)
                .layer(DefaultBodyLimit::max(MAX_BLOCKS_PER_REQUEST as usize * bs)),
        )
}

pub struct VaultAuthed {
    pub vault: String,
    pub member: [u8; 32],
    token_hash: [u8; 32],
}

impl FromRequestParts<Arc<AppState>> for VaultAuthed {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(AppError::unauthorized)?;
        let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let sessions = state.vault_sessions.sessions.lock().unwrap();
        match sessions.get(&token_hash) {
            Some((vault, member, exp)) if *exp > Instant::now() => Ok(VaultAuthed {
                vault: vault.clone(),
                member: *member,
                token_hash,
            }),
            _ => Err(AppError::unauthorized()),
        }
    }
}

fn locator_of(v: &[u8]) -> AppResult<[u8; 32]> {
    if v.len() != 32 {
        return Err(AppError::bad_request("locator must be 32 bytes"));
    }
    Ok(locator_hash(v))
}

async fn create_vault(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<CreateVaultRequest>,
) -> AppResult<(StatusCode, Json<VaultLayout>)> {
    rate_limit(&s, &ip)?;
    let spend_invite = check_registration(&s, req.invite.as_deref()).await?;
    let lh = locator_of(&req.locator)?;
    if req.auth_public_key.len() != 32 || req.transport_key.len() != 32 {
        return Err(AppError::bad_request(
            "auth_public_key and transport_key must be 32 bytes",
        ));
    }
    check_record(&req.lookup, &req.record)?;
    if s.db.vault_record(&req.lookup).await?.is_some() || s.db.vault_member(&lh).await?.is_some() {
        return Err(taken());
    }
    let vault_id = strongbox_core::Id::random().to_string();
    let st = s.clone();
    let vid = vault_id.clone();
    tokio::task::spawn_blocking(move || st.vaults.create(&vid))
        .await
        .map_err(|_| AppError::from(std::io::Error::other("fill task")))?
        .map_err(|e| {
            // Creating the vault's directory can't be "not found" in the user's sense; a missing
            // data directory is a server fault, not a missing account.
            if e.kind() == std::io::ErrorKind::NotFound {
                AppError::from(std::io::Error::other(e))
            } else {
                AppError::from(e)
            }
        })?;
    match s
        .db
        .create_vault(
            &vault_id,
            &req.lookup,
            &req.record,
            &lh,
            &req.auth_public_key,
            &req.transport_key,
            spend_invite,
        )
        .await?
    {
        CreateVault::Created => {}
        CreateVault::Taken => {
            let _ = s.vaults.delete(&vault_id);
            return Err(taken());
        }
        CreateVault::InvalidInvite => {
            let _ = s.vaults.delete(&vault_id);
            return Err(invalid_invite());
        }
    }
    Ok((StatusCode::CREATED, Json(s.vaults.layout)))
}

fn taken() -> AppError {
    AppError::new(
        StatusCode::CONFLICT,
        ErrorCode::UsernameTaken,
        "username taken",
    )
}

fn check_record(lookup: &[u8], record: &[u8]) -> AppResult<()> {
    if lookup.len() != 32 || record.len() != RECORD_LEN {
        return Err(AppError::bad_request("malformed username record"));
    }
    Ok(())
}

/// The encrypted credential record for a username. Unknown usernames get a decoy that is
/// stable across requests and the same size, so this does not reveal which usernames exist.
async fn lookup(
    State(s): St,
    ip: ClientIp,
    Path(lookup): Path<String>,
) -> AppResult<Json<RecordResponse>> {
    rate_limit(&s, &ip)?;
    let id = hex::decode(&lookup)
        .ok()
        .filter(|b| b.len() == 32)
        .ok_or_else(|| AppError::bad_request("invalid lookup id"))?;
    let record = match s.db.vault_record(&id).await? {
        Some(r) => r,
        // Keyed on the canonical hex: hex::decode also accepts upper case, and a decoy keyed on the
        // raw string would differ between spellings of one id, unlike a real record.
        None => decoy_bytes(
            &s.decoy_secret,
            &hex::encode(&id),
            "vault-record",
            RECORD_LEN,
        ),
    };
    Ok(Json(RecordResponse { record }))
}

async fn update_record(
    State(s): St,
    auth: VaultAuthed,
    Json(req): Json<UpdateRecordRequest>,
) -> AppResult<StatusCode> {
    check_record(&req.lookup, &req.record)?;
    if s.db
        .update_vault_record(&auth.vault, &req.lookup, &req.record)
        .await?
    {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::not_found())
    }
}

async fn challenge(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<VaultChallengeRequest>,
) -> AppResult<Json<ChallengeResponse>> {
    rate_limit(&s, &ip)?;
    let lh = locator_of(&req.locator)?;
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    if s.db.vault_member(&lh).await?.is_some() {
        let mut ch = s.vault_sessions.challenges.lock().unwrap();
        if ch.len() >= MAX_PENDING_CHALLENGES {
            let now = Instant::now();
            ch.retain(|_, (_, exp)| *exp > now);
        }
        if ch.len() < MAX_PENDING_CHALLENGES {
            ch.insert(challenge.clone(), (lh, Instant::now() + CHALLENGE_TTL));
        }
    }
    Ok(Json(ChallengeResponse { challenge }))
}

async fn create_session(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<VaultSessionRequest>,
) -> AppResult<Json<SessionResponse>> {
    rate_limit(&s, &ip)?;
    let lh = locator_of(&req.locator)?;
    let taken = s
        .vault_sessions
        .challenges
        .lock()
        .unwrap()
        .remove(&req.challenge);
    if !taken.is_some_and(|(want, exp)| want == lh && exp > Instant::now()) {
        return Err(AppError::unauthorized());
    }
    let (vault, pk) =
        s.db.vault_member(&lh)
            .await?
            .ok_or_else(AppError::unauthorized)?;
    let (Ok(pk), Ok(sig)) = (
        <[u8; 32]>::try_from(pk.as_slice()),
        <[u8; 64]>::try_from(req.signature.as_slice()),
    ) else {
        return Err(AppError::unauthorized());
    };
    if !verify_challenge(&pk, &s.server_id, &req.locator, &req.challenge, &sig) {
        return Err(AppError::unauthorized());
    }
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let ttl = Duration::from_secs(s.config.session_ttl_secs.max(60) as u64);
    s.vault_sessions.sessions.lock().unwrap().insert(
        Sha256::digest(token.as_bytes()).into(),
        (vault, lh, Instant::now() + ttl),
    );
    // Report expiry as a relative lifetime: the server keeps no wall-clock login record.
    Ok(Json(SessionResponse {
        token,
        expires_at: ttl.as_secs() as i64,
    }))
}

/// Permanently delete the signed-in account: its lookup record, members and every drive.
async fn delete_account(State(s): St, auth: VaultAuthed) -> AppResult<StatusCode> {
    s.db.delete_vault(&auth.vault).await?;
    match s.vaults.delete(&auth.vault) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    s.vault_sessions.remove_vault_sessions(&auth.vault);
    Ok(StatusCode::NO_CONTENT)
}

async fn logout(State(s): St, auth: VaultAuthed) -> StatusCode {
    s.vault_sessions
        .sessions
        .lock()
        .unwrap()
        .remove(&auth.token_hash);
    StatusCode::NO_CONTENT
}

async fn list_members(State(s): St, auth: VaultAuthed) -> AppResult<Json<MembersResponse>> {
    let members =
        s.db.vault_members(&auth.vault)
            .await?
            .into_iter()
            .map(|(lh, pk)| MemberInfo {
                id: hex::encode(lh),
                public_key: pk,
            })
            .collect();
    Ok(Json(MembersResponse {
        members,
        current: hex::encode(auth.member),
    }))
}

async fn add_member(
    State(s): St,
    auth: VaultAuthed,
    Json(req): Json<AddMemberRequest>,
) -> AppResult<StatusCode> {
    let lh = locator_of(&req.locator)?;
    if req.auth_public_key.len() != 32 || req.transport_key.len() != 32 {
        return Err(AppError::bad_request(
            "auth_public_key and transport_key must be 32 bytes",
        ));
    }
    match s
        .db
        .add_vault_member(
            &auth.vault,
            &lh,
            &req.auth_public_key,
            &req.transport_key,
            MAX_MEMBERS,
        )
        .await?
    {
        MemberAdd::Added => Ok(StatusCode::NO_CONTENT),
        MemberAdd::Exists => Err(AppError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "already a member",
        )),
        MemberAdd::TooMany => Err(AppError::bad_request("too many members")),
    }
}

async fn remove_member(
    State(s): St,
    auth: VaultAuthed,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let lh = hex::decode(&id).map_err(|_| AppError::bad_request("invalid member id"))?;
    match s.db.remove_vault_member(&auth.vault, &lh).await? {
        MemberDelete::Deleted => Ok(StatusCode::NO_CONTENT),
        MemberDelete::NotFound => Err(AppError::not_found()),
        MemberDelete::LastMember => Err(AppError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "refusing to remove the last member (the vault would become unreachable)",
        )),
    }
}

#[derive(Deserialize)]
struct BlockQuery {
    start: u32,
    count: Option<u32>,
}

fn io_bad_request(e: std::io::Error) -> AppError {
    if e.kind() == std::io::ErrorKind::InvalidInput {
        AppError::bad_request(e.to_string())
    } else {
        e.into()
    }
}

async fn read_blocks(
    State(s): St,
    auth: VaultAuthed,
    Path(slot): Path<u32>,
    Query(q): Query<BlockQuery>,
) -> AppResult<Bytes> {
    let count = q.count.unwrap_or(1);
    if count > MAX_BLOCKS_PER_REQUEST {
        return Err(AppError::bad_request("too many blocks in one request"));
    }
    let st = s.clone();
    let data =
        tokio::task::spawn_blocking(move || st.vaults.read(&auth.vault, slot, q.start, count))
            .await
            .map_err(|_| AppError::from(std::io::Error::other("read task")))?
            .map_err(io_bad_request)?;
    Ok(Bytes::from(data))
}

async fn write_blocks(
    State(s): St,
    auth: VaultAuthed,
    Path(slot): Path<u32>,
    Query(q): Query<BlockQuery>,
    body: Bytes,
) -> AppResult<StatusCode> {
    let st = s.clone();
    tokio::task::spawn_blocking(move || st.vaults.write(&auth.vault, slot, q.start, &body))
        .await
        .map_err(|_| AppError::from(std::io::Error::other("write task")))?
        .map_err(io_bad_request)?;
    Ok(StatusCode::NO_CONTENT)
}
