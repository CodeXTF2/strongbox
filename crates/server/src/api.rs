use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRequestParts, Path, Query, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, X_CONTENT_TYPE_OPTIONS};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post, put};
use axum::{middleware, Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use strongbox_core::account::verify_auth;
use strongbox_core::keyslot::{Keyslot, KeyslotKind, SEALED_LABEL_LEN};
use strongbox_core::{kdf, Id};
use strongbox_proto::*;
use tower_http::trace::TraceLayer;

use crate::db::{now, CommitOutcome, KeyslotAdd, KeyslotDelete};
use crate::error::{AppError, AppResult};
use crate::AppState;

type St = State<Arc<AppState>>;

const MAX_KEYSLOTS: usize = 32;
const MAX_KEYSLOT_JSON: usize = 8 * 1024;
const MAX_COMMIT_OPS: usize = 1000;
const CHALLENGE_TTL_SECS: i64 = 120;

pub fn router(state: Arc<AppState>) -> Router {
    let max_blob = state.config.max_blob_size as usize;
    // Commit bodies are JSON with base64 nodes: allow for the 4/3 expansion plus a few nodes.
    let max_commit = (state.config.max_node_size as usize) * 3;
    let debug = state.config.debug;
    let router = Router::new()
        .route("/v1/info", get(info))
        .route("/v1/accounts", post(register).delete(delete_account))
        .route("/v1/accounts/{username}/keyslots", get(prelogin_keyslots))
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/session", post(create_session).delete(logout))
        .route("/v1/keyslots/{id}", put(put_keyslot).delete(delete_keyslot))
        .route("/v1/nodes/{id}", get(get_node))
        .route("/v1/changes", get(changes))
        .route(
            "/v1/commit",
            post(commit).layer(DefaultBodyLimit::max(max_commit)),
        )
        .route("/v1/blobs", get(list_blobs))
        .route(
            "/v1/blobs/{id}",
            put(put_blob)
                .get(get_blob)
                .delete(delete_blob)
                .layer(DefaultBodyLimit::max(max_blob)),
        )
        .route("/v1/usage", get(usage))
        .merge(crate::vault_api::routes(&state))
        .layer(middleware::map_response(security_headers));
    // Request traces record paths, which contain usernames and node/blob ids: debug only.
    let router = if debug {
        router.layer(TraceLayer::new_for_http())
    } else {
        router
    };
    router.with_state(state)
}

/// Nothing the API returns should be cached by intermediaries or sniffed into something
/// renderable (blobs are served as raw bytes).
async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    res
}

// ---------- extractors ----------

/// An authenticated session (bearer token).
pub struct Authed {
    pub account: i64,
    pub token_hash: Vec<u8>,
}

impl FromRequestParts<Arc<AppState>> for Authed {
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
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        let account = state
            .db
            .session_account(&token_hash)
            .await?
            .ok_or_else(AppError::unauthorized)?;
        Ok(Authed {
            account,
            token_hash,
        })
    }
}

/// Client IP if known (absent when the router is driven without a socket, e.g. in tests).
/// With `--trust-proxy`, a loopback peer is taken to be the local TLS proxy and the last
/// `X-Forwarded-For` hop (the one that proxy appended) is used instead.
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<Arc<AppState>> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip());
        if state.config.trust_proxy && peer.is_some_and(|p| p.is_loopback()) {
            let forwarded = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .next_back()
                .and_then(|v| v.trim().parse().ok());
            if forwarded.is_some() {
                return Ok(ClientIp(forwarded));
            }
        }
        Ok(ClientIp(peer))
    }
}

pub(crate) fn rate_limit(state: &AppState, ip: &ClientIp) -> AppResult<()> {
    match ip.0 {
        Some(ip) if !state.prelogin_limiter.check(ip) => Err(AppError::new(
            StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::RateLimited,
            "slow down",
        )),
        _ => Ok(()),
    }
}

fn parse_id(s: &str) -> AppResult<Id> {
    s.parse().map_err(|_| AppError::bad_request("invalid id"))
}

fn validate_username(u: &str) -> AppResult<()> {
    let ok = (3..=64).contains(&u.len())
        && u.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && u.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "username must be 3-64 chars of a-z 0-9 . _ - (starting alphanumeric)",
        ))
    }
}

fn keyslot_json(slot: &Keyslot) -> AppResult<String> {
    let json = serde_json::to_string(slot).map_err(|_| AppError::bad_request("invalid keyslot"))?;
    if json.len() > MAX_KEYSLOT_JSON {
        return Err(AppError::bad_request("keyslot too large"));
    }
    Ok(json)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Deterministic pseudo-random bytes for decoys, keyed by the server's decoy secret.
pub(crate) fn decoy_bytes(secret: &[u8], username: &str, what: &str, len: usize) -> Vec<u8> {
    (0u32..)
        .flat_map(|i| {
            *kdf::derive(
                secret,
                None,
                "strongbox/decoy/v1",
                &[username.as_bytes(), what.as_bytes(), &i.to_be_bytes()],
            )
            .as_bytes()
        })
        .take(len)
        .collect()
}

/// Keyslots for a username that does not exist. They look like a freshly registered account
/// (one security key plus a recovery code) and are stable across requests, so the pre-login
/// endpoints do not reveal which usernames are registered. Nothing can unlock them, and
/// `create_session` rejects unknown usernames like a bad signature.
fn decoy_keyslots(secret: &[u8], username: &str) -> Vec<Keyslot> {
    let id = |what| Id(decoy_bytes(secret, username, what, 16).try_into().unwrap());
    // nonce (24) + AMK (32) + tag (16)
    let wrapped = |what| decoy_bytes(secret, username, what, 24 + 32 + 16);
    let mut slots = vec![
        Keyslot {
            id: id("fido-id"),
            label: String::new(),
            sealed_label: Some(decoy_bytes(secret, username, "fido-label", SEALED_LABEL_LEN)),
            kind: KeyslotKind::Fido {
                rp_id: "strongbox.app".into(),
                credential_id: decoy_bytes(secret, username, "credential", 64),
                prf_salt: decoy_bytes(secret, username, "prf-salt", 32),
                password: None,
            },
            wrapped_amk: wrapped("fido-amk"),
        },
        Keyslot {
            id: id("recovery-id"),
            label: String::new(),
            sealed_label: Some(decoy_bytes(secret, username, "recovery-label", SEALED_LABEL_LEN)),
            kind: KeyslotKind::Recovery,
            wrapped_amk: wrapped("recovery-amk"),
        },
    ];
    // Real keyslots are returned ordered by id.
    slots.sort_by_key(|s| s.id);
    slots
}

// ---------- handlers ----------

async fn info(State(s): St) -> Json<ServerInfo> {
    Json(ServerInfo {
        server_id: s.server_id.clone(),
        software_version: env!("CARGO_PKG_VERSION").into(),
        registration: s.config.registration,
        max_blob_size: s.config.max_blob_size,
        max_node_size: s.config.max_node_size,
        vault: Some(s.vaults.layout),
    })
}

/// Registration policy shared by accounts and vaults.
pub(crate) fn check_registration(s: &AppState, invite: Option<&str>) -> AppResult<()> {
    match s.config.registration {
        RegistrationMode::Open => Ok(()),
        RegistrationMode::Closed => Err(AppError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "registration is closed",
        )),
        RegistrationMode::Invite => {
            let ok = matches!((&s.config.invite_token, invite),
                (Some(want), Some(got)) if constant_time_eq(want.as_bytes(), got.as_bytes()));
            if ok {
                Ok(())
            } else {
                Err(AppError::new(
                    StatusCode::FORBIDDEN,
                    ErrorCode::Forbidden,
                    "invalid invite token",
                ))
            }
        }
    }
}

async fn register(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<RegisterRequest>,
) -> AppResult<StatusCode> {
    rate_limit(&s, &ip)?;
    check_registration(&s, req.invite.as_deref())?;
    validate_username(&req.username)?;
    if req.auth_public_key.len() != 32 {
        return Err(AppError::bad_request("auth_public_key must be 32 bytes"));
    }
    if req.keyslots.is_empty() || req.keyslots.len() > MAX_KEYSLOTS {
        return Err(AppError::bad_request("need 1-32 keyslots"));
    }
    let mut ids = std::collections::HashSet::new();
    if !req.keyslots.iter().all(|k| ids.insert(k.id)) {
        return Err(AppError::bad_request("duplicate keyslot id"));
    }
    let slots = req
        .keyslots
        .iter()
        .map(|k| Ok((k.id.to_string(), keyslot_json(k)?)))
        .collect::<AppResult<Vec<_>>>()?;
    match s
        .db
        .create_account(
            &req.username,
            &req.auth_public_key,
            &slots,
            s.config.quota_bytes,
        )
        .await?
    {
        Some(_) => Ok(StatusCode::CREATED),
        None => Err(AppError::new(
            StatusCode::CONFLICT,
            ErrorCode::UsernameTaken,
            "username taken",
        )),
    }
}

async fn prelogin_keyslots(
    State(s): St,
    ip: ClientIp,
    Path(username): Path<String>,
) -> AppResult<Json<KeyslotsResponse>> {
    rate_limit(&s, &ip)?;
    validate_username(&username)?;
    let Some(acct) = s.db.account_by_username(&username).await? else {
        return Ok(Json(KeyslotsResponse {
            keyslots: decoy_keyslots(&s.decoy_secret, &username),
        }));
    };
    let keyslots =
        s.db.keyslots(acct.id)
            .await?
            .iter()
            .filter_map(|b| serde_json::from_str(b).ok())
            .collect();
    Ok(Json(KeyslotsResponse { keyslots }))
}

async fn challenge(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<ChallengeRequest>,
) -> AppResult<Json<ChallengeResponse>> {
    rate_limit(&s, &ip)?;
    let mut challenge = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    // Unknown usernames get an unusable challenge rather than a 404 (no enumeration).
    if let Some(acct) = s.db.account_by_username(&req.username).await? {
        s.db.create_challenge(acct.id, &challenge, now() + CHALLENGE_TTL_SECS)
            .await?;
    }
    Ok(Json(ChallengeResponse { challenge }))
}

async fn create_session(
    State(s): St,
    ip: ClientIp,
    Json(req): Json<SessionRequest>,
) -> AppResult<Json<SessionResponse>> {
    rate_limit(&s, &ip)?;
    let acct =
        s.db.account_by_username(&req.username)
            .await?
            .ok_or_else(AppError::unauthorized)?;
    if !s.db.take_challenge(acct.id, &req.challenge).await? {
        return Err(AppError::unauthorized());
    }
    let (Ok(pk), Ok(sig)) = (
        <[u8; 32]>::try_from(acct.auth_public_key.as_slice()),
        <[u8; 64]>::try_from(req.signature.as_slice()),
    ) else {
        return Err(AppError::unauthorized());
    };
    if !verify_auth(&pk, &s.server_id, &req.username, &req.challenge, &sig) {
        return Err(AppError::unauthorized());
    }
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = URL_SAFE_NO_PAD.encode(raw);
    let expires_at = now() + s.config.session_ttl_secs;
    s.db.create_session(&Sha256::digest(token.as_bytes()), acct.id, expires_at)
        .await?;
    Ok(Json(SessionResponse { token, expires_at }))
}

async fn logout(State(s): St, auth: Authed) -> AppResult<StatusCode> {
    s.db.delete_session(&auth.token_hash).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Permanently delete the signed-in account: keys, metadata and blobs. The username is freed.
async fn delete_account(State(s): St, headers: HeaderMap) -> AppResult<StatusCode> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(AppError::unauthorized)?;
    let token_hash = Sha256::digest(token.as_bytes()).to_vec();

    if let Some(account) = s.db.session_account(&token_hash).await? {
        if !s.db.delete_account(account).await? {
            return Err(AppError::not_found());
        }
        // The account is already gone from the database; a failed unlink leaves orphaned
        // ciphertext only, which no key can decrypt any more.
        if let Err(e) = s.blobs.delete_account(account).await {
            tracing::warn!(
                "failed to remove blobs of a deleted account ({:?})",
                e.kind()
            );
        }
        return Ok(StatusCode::NO_CONTENT);
    }

    let vault_hash: [u8; 32] = token_hash.as_slice().try_into().unwrap();
    let vault = s
        .vault_sessions
        .vault_for_token(&vault_hash)
        .ok_or_else(AppError::unauthorized)?;
    if !s.db.delete_vault(&vault).await? {
        return Err(AppError::not_found());
    }
    s.vault_sessions.remove_vault_sessions(&vault);
    // Metadata and members are gone; a failed unlink leaves only undecryptable ciphertext.
    if let Err(e) = s.vaults.delete(&vault) {
        tracing::warn!("failed to remove files of a deleted vault ({:?})", e.kind());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn put_keyslot(
    State(s): St,
    auth: Authed,
    Path(id): Path<String>,
    Json(slot): Json<Keyslot>,
) -> AppResult<StatusCode> {
    let id = parse_id(&id)?;
    if id != slot.id {
        return Err(AppError::bad_request("keyslot id mismatch"));
    }
    match s
        .db
        .add_keyslot(
            auth.account,
            &id.to_string(),
            &keyslot_json(&slot)?,
            MAX_KEYSLOTS,
        )
        .await?
    {
        KeyslotAdd::Added => Ok(StatusCode::NO_CONTENT),
        KeyslotAdd::Exists => Err(AppError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "keyslot already exists",
        )),
        KeyslotAdd::TooMany => Err(AppError::bad_request("too many keyslots")),
    }
}

async fn delete_keyslot(
    State(s): St,
    auth: Authed,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    match s
        .db
        .delete_keyslot(auth.account, &parse_id(&id)?.to_string())
        .await?
    {
        KeyslotDelete::Deleted => Ok(StatusCode::NO_CONTENT),
        KeyslotDelete::NotFound => Err(AppError::not_found()),
        KeyslotDelete::LastKeyslot => Err(AppError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "refusing to delete the last keyslot (the account would become unrecoverable)",
        )),
    }
}

async fn get_node(
    State(s): St,
    auth: Authed,
    Path(id): Path<String>,
) -> AppResult<(HeaderMap, Bytes)> {
    let (version, data) =
        s.db.get_node(auth.account, &parse_id(&id)?)
            .await?
            .ok_or_else(AppError::not_found)?;
    let mut headers = HeaderMap::new();
    headers.insert(NODE_VERSION_HEADER, HeaderValue::from(version));
    Ok((headers, Bytes::from(data)))
}

#[derive(Deserialize)]
struct ChangesQuery {
    #[serde(default)]
    since: u64,
    limit: Option<u32>,
}

async fn changes(
    State(s): St,
    auth: Authed,
    Query(q): Query<ChangesQuery>,
) -> AppResult<Json<ChangesResponse>> {
    let limit = q.limit.unwrap_or(1000).clamp(1, 5000);
    let changes = s.db.changes(auth.account, q.since, limit + 1).await?;
    let more = changes.len() > limit as usize;
    let changes: Vec<_> = changes.into_iter().take(limit as usize).collect();
    let cursor = changes.last().map_or(q.since, |c| c.seq);
    Ok(Json(ChangesResponse {
        changes,
        cursor,
        more,
    }))
}

async fn commit(
    State(s): St,
    auth: Authed,
    Json(req): Json<CommitRequest>,
) -> AppResult<Json<CommitResponse>> {
    if req.ops.len() > MAX_COMMIT_OPS || req.delete_blobs.len() > 100_000 {
        return Err(AppError::bad_request("commit too large"));
    }
    let mut seen = std::collections::HashSet::new();
    for op in &req.ops {
        if !seen.insert(op.id) {
            return Err(AppError::bad_request("duplicate node id in commit"));
        }
        if let CommitAction::Put { data } = &op.action {
            if data.len() as u64 > s.config.max_node_size {
                return Err(AppError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    ErrorCode::TooLarge,
                    "node too large",
                ));
            }
        }
    }
    match s
        .db
        .commit(auth.account, &req.ops, &req.delete_blobs)
        .await?
    {
        CommitOutcome::Ok {
            versions,
            deleted_blobs,
        } => {
            for id in deleted_blobs {
                // Metadata is already gone; a failed unlink just leaves garbage for a sweep.
                if let Err(e) = s.blobs.delete(auth.account, &id).await {
                    if crate::debug_logging() {
                        tracing::warn!("failed to delete blob {id}: {e}");
                    } else {
                        tracing::warn!(
                            "failed to delete a blob ({:?}); a sweep will reclaim it",
                            e.kind()
                        );
                    }
                }
            }
            Ok(Json(CommitResponse { versions }))
        }
        CommitOutcome::Conflict(c) => Err(AppError::conflict(c)),
        CommitOutcome::QuotaExceeded => Err(quota_exceeded()),
    }
}

fn quota_exceeded() -> AppError {
    AppError::new(
        StatusCode::INSUFFICIENT_STORAGE,
        ErrorCode::QuotaExceeded,
        "quota exceeded",
    )
}

#[derive(Deserialize)]
struct BlobListQuery {
    after: Option<String>,
    limit: Option<u32>,
}

async fn list_blobs(
    State(s): St,
    auth: Authed,
    Query(q): Query<BlobListQuery>,
) -> AppResult<Json<BlobListResponse>> {
    let after = q.after.as_deref().map(parse_id).transpose()?;
    let limit = q.limit.unwrap_or(1000).clamp(1, 10_000);
    let mut blobs =
        s.db.list_blobs(auth.account, after.as_ref(), limit + 1)
            .await?;
    let next = (blobs.len() > limit as usize).then(|| {
        blobs.truncate(limit as usize);
        blobs.last().unwrap().id
    });
    Ok(Json(BlobListResponse { blobs, next }))
}

async fn put_blob(
    State(s): St,
    auth: Authed,
    Path(id): Path<String>,
    body: Bytes,
) -> AppResult<StatusCode> {
    let id = parse_id(&id)?;
    if body.len() < strongbox_core::aead::TAG_LEN {
        return Err(AppError::bad_request("blob too small"));
    }
    if !s
        .db
        .reserve_blob(auth.account, &id, body.len() as u64)
        .await?
    {
        return Err(quota_exceeded());
    }
    if let Err(e) = s.blobs.put(auth.account, &id, &body).await {
        let _ = s.db.delete_blob(auth.account, &id).await;
        return Err(e.into());
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn get_blob(State(s): St, auth: Authed, Path(id): Path<String>) -> AppResult<Bytes> {
    let id = parse_id(&id)?;
    if !s.db.blob_exists(auth.account, &id).await? {
        return Err(AppError::not_found());
    }
    s.blobs
        .get(auth.account, &id)
        .await?
        .map(Bytes::from)
        .ok_or_else(AppError::not_found)
}

async fn delete_blob(State(s): St, auth: Authed, Path(id): Path<String>) -> AppResult<StatusCode> {
    let id = parse_id(&id)?;
    if !s.db.delete_blob(auth.account, &id).await? {
        return Err(AppError::not_found());
    }
    s.blobs.delete(auth.account, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn usage(State(s): St, auth: Authed) -> AppResult<Json<UsageResponse>> {
    let (used_bytes, quota_bytes) = s.db.usage(auth.account).await?;
    Ok(Json(UsageResponse {
        used_bytes,
        quota_bytes,
    }))
}
