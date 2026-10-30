//! Operator admin page: a small website for managing invite codes and checking the server's
//! health, capacity and configuration. It has its own loopback-only listener (`--admin-listen`), is only served to a browser on
//! the same machine (see `local_only`), never through the TLS proxy, and has no login of its own.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, put};
use axum::{Json, Router};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use strongbox_proto::{ErrorCode, RegistrationMode};

use crate::db::{InviteAdd, InviteCode};
use crate::error::{AppError, AppResult};
use crate::AppState;

type St = State<Arc<AppState>>;

/// The page sends this header with every request. A web page on another site cannot add it to a
/// cross-origin request without a preflight, which the server never answers.
const ADMIN_HEADER: &str = "x-strongbox-admin";

const PAGE: &str = include_str!("admin.html");
/// The desktop app's logo, so the page looks like the rest of Strongbox.
const LOGO: &[u8] = include_bytes!("../../../apps/desktop/ui/logo.png");

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/logo.png", get(logo))
        .route("/admin/stats", get(stats))
        .route("/admin/registration", put(set_registration))
        .route("/admin/codes", get(list_codes).post(create_code))
        .route("/admin/codes/{id}", delete(delete_code))
        .route_layer(middleware::from_fn(local_only))
        .layer(middleware::map_response(crate::api::security_headers))
        .with_state(state)
}

/// Admin routes answer only a direct local browser: a loopback peer, no proxy headers (the
/// TLS proxy runs on loopback too, and always adds them), a loopback `Host` (blocks DNS
/// rebinding from web pages) and, for changes, the custom header. Anything else sees a 404.
async fn local_only(req: Request, next: Next) -> Response {
    if !is_local(&req) {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

fn is_local(req: &Request) -> bool {
    let peer_is_local = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|c| c.0.ip().is_loopback());
    let h = req.headers();
    let proxied = [
        "x-forwarded-for",
        "x-forwarded-host",
        "x-real-ip",
        "forwarded",
    ]
    .iter()
    .any(|name| h.contains_key(*name));
    let host_is_local = h
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|host| {
            let name = match host.strip_prefix('[') {
                Some(v6) => v6.split(']').next().unwrap_or_default(),
                None => host.rsplit_once(':').map_or(host, |(n, _)| n),
            };
            matches!(name, "localhost" | "127.0.0.1" | "::1")
        });
    let header_ok = req.method() == Method::GET || h.contains_key(ADMIN_HEADER);
    peer_is_local && !proxied && host_is_local && header_ok
}

async fn page() -> Response {
    let mut res = Html(PAGE).into_response();
    res.headers_mut().insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
             img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; \
             frame-ancestors 'none'",
        ),
    );
    res
}

async fn logo() -> Response {
    (
        [(CONTENT_TYPE, HeaderValue::from_static("image/png"))],
        LOGO,
    )
        .into_response()
}

#[derive(Serialize)]
struct Stats {
    server_id: String,
    version: &'static str,
    uptime_secs: u64,
    accounts: i64,
    /// Security keys, across all accounts.
    member_keys: i64,
    active_sessions: usize,
    /// Accounts in the database whose vault files are gone.
    missing_storage: usize,
    drives_per_vault: u32,
    drive_bytes: u64,
    /// Disk every account reserves (all its drives), whether or not it holds data.
    vault_bytes: u64,
    /// `accounts × vault_bytes`.
    allocated_bytes: u64,
    spares_ready: usize,
    spares_filling: usize,
    spares_target: usize,
    /// Free and total space of the volume holding the data directory (`None` if unknown).
    disk_free: Option<u64>,
    disk_total: Option<u64>,
    /// Size of the database file (the rollback journal is transient).
    db_bytes: u64,
    config: ConfigView,
    metrics: crate::metrics::Snapshot,
}

/// The settings an operator may want to check or change (all from flags or the environment).
#[derive(Serialize)]
struct ConfigView {
    registration: &'static str,
    invite_token_set: bool,
    listen: String,
    data_dir: String,
    session_ttl_secs: i64,
    prelogin_rate_per_minute: u32,
    trust_proxy: bool,
    debug: bool,
}

/// Counts of rows the server holds anyway, the fixed allocation per account, and the machine's
/// disk, CPU, memory and network. File contents, names and per-account usage are unknown to the server, so they are
/// not (and cannot be) shown.
async fn stats(State(s): St) -> AppResult<Json<Stats>> {
    let (accounts, member_keys) = s.db.user_counts().await?;
    let missing_storage =
        s.db.vault_ids()
            .await?
            .iter()
            .filter(|id| !s.vaults.exists(id))
            .count();
    let layout = s.vaults.layout;
    let drive_bytes = layout.blocks_per_slot as u64 * layout.block_size as u64;
    let vault_bytes = drive_bytes * layout.slots as u64;
    let (spares_ready, spares_filling) = s.vaults.spare_counts().unwrap_or((0, 0));
    let dir = s.config.data_dir.clone();
    let (disk_free, disk_total, db_bytes) = tokio::task::spawn_blocking(move || {
        let db_bytes = std::fs::metadata(dir.join("strongbox.sqlite3"))
            .map(|m| m.len())
            .unwrap_or(0);
        (
            fs2::available_space(&dir).ok(),
            fs2::total_space(&dir).ok(),
            db_bytes,
        )
    })
    .await
    .unwrap_or((None, None, 0));
    let c = &s.config;
    Ok(Json(Stats {
        server_id: s.server_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: s.started.elapsed().as_secs(),
        accounts,
        member_keys,
        active_sessions: s.vault_sessions.active_count(),
        missing_storage,
        drives_per_vault: layout.slots,
        drive_bytes,
        vault_bytes,
        allocated_bytes: vault_bytes * accounts as u64,
        spares_ready,
        spares_filling,
        spares_target: c.spare_vaults,
        disk_free,
        disk_total,
        db_bytes,
        metrics: s.metrics.snapshot(),
        config: ConfigView {
            registration: match s.registration_mode() {
                RegistrationMode::Open => "open",
                RegistrationMode::Invite => "invite",
                RegistrationMode::Closed => "closed",
            },
            invite_token_set: c.invite_token.is_some(),
            listen: c.listen.to_string(),
            data_dir: std::path::absolute(&c.data_dir)
                .unwrap_or_else(|_| c.data_dir.clone())
                .display()
                .to_string(),
            session_ttl_secs: c.session_ttl_secs,
            prelogin_rate_per_minute: c.prelogin_rate_per_minute,
            trust_proxy: c.trust_proxy,
            debug: c.debug,
        },
    }))
}

#[derive(Deserialize)]
struct SetRegistration {
    /// `"open"` or `"invite"`.
    mode: String,
}

/// Switch sign-ups between open and invite-only, effective immediately, until restart.
async fn set_registration(State(s): St, Json(req): Json<SetRegistration>) -> AppResult<StatusCode> {
    let mode = match req.mode.as_str() {
        "open" => RegistrationMode::Open,
        "invite" => RegistrationMode::Invite,
        _ => return Err(AppError::bad_request("mode must be open or invite")),
    };
    *s.registration.write().unwrap_or_else(|e| e.into_inner()) = mode;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct CodeView {
    id: i64,
    code: String,
    single_use: bool,
    created_at: i64,
}

impl From<InviteCode> for CodeView {
    fn from(c: InviteCode) -> Self {
        CodeView {
            id: c.id,
            code: c.code,
            single_use: c.single_use,
            created_at: c.created_at,
        }
    }
}

async fn list_codes(State(s): St) -> AppResult<Json<Vec<CodeView>>> {
    Ok(Json(
        s.db.invite_codes()
            .await?
            .into_iter()
            .map(Into::into)
            .collect(),
    ))
}

#[derive(Deserialize)]
struct NewCode {
    single_use: bool,
    /// Only for standard codes; a random one is generated when absent or empty.
    code: Option<String>,
}

/// 20 characters from an alphabet without look-alikes (100 bits), in groups of five.
fn random_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(23);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && i % 5 == 0 {
            out.push('-');
        }
        out.push(ALPHABET[*b as usize % ALPHABET.len()] as char);
    }
    out
}

async fn create_code(
    State(s): St,
    Json(req): Json<NewCode>,
) -> AppResult<(StatusCode, Json<CodeView>)> {
    let custom = req.code.as_deref().map(str::trim).filter(|c| !c.is_empty());
    let code = match custom {
        Some(_) if req.single_use => {
            return Err(AppError::bad_request(
                "single-use codes are always generated",
            ))
        }
        Some(c) => {
            if !(8..=64).contains(&c.len()) || !c.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(AppError::bad_request(
                    "a custom code needs 8-64 visible characters, no spaces",
                ));
            }
            c.to_string()
        }
        None => random_code(),
    };
    match s.db.add_invite(&code, req.single_use).await? {
        InviteAdd::Added(c) => Ok((StatusCode::CREATED, Json(c.into()))),
        InviteAdd::Exists => Err(AppError::new(
            StatusCode::CONFLICT,
            ErrorCode::BadRequest,
            "that code already exists",
        )),
    }
}

async fn delete_code(State(s): St, Path(id): Path<i64>) -> AppResult<StatusCode> {
    if s.db.delete_invite(id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::not_found())
    }
}
