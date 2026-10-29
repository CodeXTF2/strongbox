//! Operator admin page: a small website for managing invite codes and seeing what the server can
//! know. It has its own loopback-only listener (`--admin-listen`), is only served to a browser on
//! the same machine (see `local_only`), never through the TLS proxy, and has no login of its own.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::header::{CONTENT_SECURITY_POLICY, HOST};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get};
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

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(page))
        .route("/admin/stats", get(stats))
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
    let proxied = ["x-forwarded-for", "x-forwarded-host", "x-real-ip", "forwarded"]
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
             connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    res
}

#[derive(Serialize)]
struct Stats {
    server_id: String,
    version: &'static str,
    uptime_secs: u64,
    registration: &'static str,
    shared_token_set: bool,
    accounts: i64,
    member_keys: i64,
    active_sessions: usize,
    drives_per_vault: u32,
    drive_bytes: u64,
    vault_bytes: u64,
    allocated_bytes: u64,
    missing_storage: usize,
    standard_codes: usize,
    single_use_codes: usize,
}

/// Everything here is something the operator can already see on the machine: counts of rows,
/// and the fixed size every account is allocated. File contents, names and per-account usage
/// are not known to the server, so they are not (and cannot be) shown.
async fn stats(State(s): St) -> AppResult<Json<Stats>> {
    let (accounts, member_keys) = s.db.user_counts().await?;
    let codes = s.db.invite_codes().await?;
    let single_use_codes = codes.iter().filter(|c| c.single_use).count();
    let missing_storage = s
        .db
        .vault_ids()
        .await?
        .iter()
        .filter(|id| !s.vaults.exists(id))
        .count();
    let layout = s.vaults.layout;
    let drive_bytes = layout.blocks_per_slot as u64 * layout.block_size as u64;
    let vault_bytes = drive_bytes * layout.slots as u64;
    Ok(Json(Stats {
        server_id: s.server_id.clone(),
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: s.started.elapsed().as_secs(),
        registration: match s.config.registration {
            RegistrationMode::Open => "open",
            RegistrationMode::Invite => "invite",
            RegistrationMode::Closed => "closed",
        },
        shared_token_set: s.config.invite_token.is_some(),
        accounts,
        member_keys,
        active_sessions: s.vault_sessions.active_count(),
        drives_per_vault: layout.slots,
        drive_bytes,
        vault_bytes,
        allocated_bytes: vault_bytes * accounts as u64,
        missing_storage,
        standard_codes: codes.len() - single_use_codes,
        single_use_codes,
    }))
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
