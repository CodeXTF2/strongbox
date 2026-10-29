use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::header::{CACHE_CONTROL, X_CONTENT_TYPE_OPTIONS};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::{middleware, Json, Router};
use strongbox_core::kdf;
use strongbox_proto::*;
use tower_http::trace::TraceLayer;

use crate::error::{AppError, AppResult};
use crate::AppState;

type St = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    let debug = state.config.debug;
    let router = Router::new()
        .route("/v1/info", get(info))
        .merge(crate::vault_api::routes(&state))
        .layer(middleware::map_response(security_headers));
    // Request traces record paths, which contain lookup and member ids: debug only.
    let router = if debug {
        router.layer(TraceLayer::new_for_http())
    } else {
        router
    };
    router.with_state(state)
}

/// Nothing the API returns should be cached by intermediaries or sniffed into something
/// renderable (blobs are served as raw bytes).
pub(crate) async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    res
}

// ---------- extractors ----------

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

async fn info(State(s): St) -> Json<ServerInfo> {
    Json(ServerInfo {
        server_id: s.server_id.clone(),
        software_version: env!("CARGO_PKG_VERSION").into(),
        registration: s.config.registration,
        vault: s.vaults.layout,
    })
}

pub(crate) fn invalid_invite() -> AppError {
    AppError::new(
        StatusCode::FORBIDDEN,
        ErrorCode::Forbidden,
        "invalid invite token",
    )
}

/// Registration policy shared by accounts and vaults. In invite mode the code is the shared
/// `--invite-token` or one of the operator's stored codes. Returns the id of a single-use code,
/// which the caller must spend (atomically with creating the account).
pub(crate) async fn check_registration(
    s: &AppState,
    invite: Option<&str>,
) -> AppResult<Option<i64>> {
    match s.config.registration {
        RegistrationMode::Open => Ok(None),
        RegistrationMode::Closed => Err(AppError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "registration is closed",
        )),
        RegistrationMode::Invite => {
            if matches!((&s.config.invite_token, invite),
                (Some(want), Some(got)) if constant_time_eq(want.as_bytes(), got.as_bytes()))
            {
                return Ok(None);
            }
            match s.db.find_invite(invite.unwrap_or_default()).await? {
                Some((id, true)) => Ok(Some(id)),
                Some((_, false)) => Ok(None),
                None => Err(invalid_invite()),
            }
        }
    }
}
