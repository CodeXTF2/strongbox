//! The sealed channel (`strongbox_core::channel`): `POST /v2/channel` sets up a session keyed
//! by the member's transport key, and `POST /v2/rpc` carries every other API call as an
//! authenticated, encrypted message. The decrypted request is handed to the ordinary router,
//! so handlers are unchanged and a hostile proxy never sees (or can forge) a path, token or
//! body. Sessions live in memory only.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{Method as HttpMethod, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use rand::RngCore;
use strongbox_core::channel::{
    self as ch, Method, ReplayWindow, RequestHead, HELLO_NONCE_LEN, REQUEST_HEADER_LEN, SID_LEN,
};
use strongbox_core::vault::BLOCK_SIZE;
use strongbox_core::Key;
use strongbox_proto::{CHANNEL_HELLO_PATH, CHANNEL_RPC_PATH, MAX_BLOCKS_PER_REQUEST};

use crate::api::{rate_limit, ClientIp};
use crate::error::{AppError, AppResult};
use crate::AppState;

type St = State<Arc<AppState>>;

const MAX_CHANNELS: usize = 100_000;
/// Largest sealed message: a full block write plus its framing.
const MAX_MESSAGE: usize = MAX_BLOCKS_PER_REQUEST as usize * BLOCK_SIZE + 64 * 1024;

struct Channel {
    c2s: Key,
    s2c: Key,
    window: ReplayWindow,
    expires: Instant,
}

/// In-memory channel sessions.
#[derive(Default)]
pub struct Channels {
    map: Mutex<HashMap<[u8; SID_LEN], Channel>>,
}

impl Channels {
    pub fn purge(&self) {
        let now = Instant::now();
        self.map.lock().unwrap().retain(|_, c| c.expires > now);
    }
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route(CHANNEL_HELLO_PATH, post(hello)).route(
        CHANNEL_RPC_PATH,
        post(rpc).layer(DefaultBodyLimit::max(MAX_MESSAGE)),
    )
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Hello: member id || client nonce → server nonce || session id || confirm. An unknown
/// member (or one without a transport key) gets random bytes of the same size, so this does
/// not reveal which members exist; its channel simply never works.
async fn hello(State(s): St, ip: ClientIp, body: Bytes) -> AppResult<Response> {
    rate_limit(&s, &ip)?;
    if body.len() != 32 + HELLO_NONCE_LEN {
        return Err(AppError::bad_request("malformed hello"));
    }
    let (member, client_nonce) = body.split_at(32);
    let server_nonce = random::<HELLO_NONCE_LEN>();
    let sid = random::<SID_LEN>();
    let key =
        s.db.member_transport_key(member)
            .await?
            .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
            .map(Key::from_bytes);
    let confirm = match key {
        Some(tk) => {
            let (c2s, s2c) = ch::session_keys(&tk, client_nonce, &server_nonce, &sid);
            let ttl = Duration::from_secs(s.config.session_ttl_secs.max(60) as u64);
            let mut map = s.channels.map.lock().unwrap();
            if map.len() >= MAX_CHANNELS {
                let now = Instant::now();
                map.retain(|_, c| c.expires > now);
            }
            if map.len() >= MAX_CHANNELS {
                return Err(AppError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    strongbox_proto::ErrorCode::RateLimited,
                    "too many open channels",
                ));
            }
            map.insert(
                sid,
                Channel {
                    c2s,
                    s2c,
                    window: ReplayWindow::default(),
                    expires: Instant::now() + ttl,
                },
            );
            ch::confirm_tag(&tk, client_nonce, &server_nonce, &sid)
        }
        None => random::<32>(),
    };
    let mut out = Vec::with_capacity(HELLO_NONCE_LEN + SID_LEN + 32);
    out.extend_from_slice(&server_nonce);
    out.extend_from_slice(&sid);
    out.extend_from_slice(&confirm);
    Ok(octets(out))
}

fn octets(body: Vec<u8>) -> Response {
    ([(CONTENT_TYPE, "application/octet-stream")], body).into_response()
}

/// Open a sealed request, run it through the ordinary router, seal the answer.
async fn rpc(
    State(state): St,
    Extension(inner): Extension<Router>,
    req: Request,
) -> AppResult<Response> {
    let connect = req.extensions().get::<ConnectInfo<SocketAddr>>().cloned();
    let forwarded: Vec<_> = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .cloned()
        .collect();
    let body = to_bytes(req.into_body(), MAX_MESSAGE)
        .await
        .map_err(|_| AppError::bad_request("message too large"))?;
    if body.len() < REQUEST_HEADER_LEN {
        return Err(AppError::unauthorized());
    }
    let sid: [u8; SID_LEN] = body[..SID_LEN].try_into().unwrap();
    let counter = u64::from_be_bytes(body[SID_LEN..REQUEST_HEADER_LEN].try_into().unwrap());

    // Look at the window first, authenticate, and only then commit the counter: a forger
    // who cannot produce a valid tag must not be able to burn counters.
    let (c2s, s2c) = {
        let map = state.channels.map.lock().unwrap();
        match map.get(&sid) {
            Some(c) if c.expires > Instant::now() && c.window.would_accept(counter) => {
                (c.c2s.clone(), c.s2c.clone())
            }
            _ => return Err(AppError::unauthorized()),
        }
    };
    // Decrypt in place: a block write is megabytes, and this keeps one copy of it.
    let mut buf = Vec::from(body);
    ch::open_message_in_place(&c2s, &sid, counter, &mut buf, REQUEST_HEADER_LEN)
        .map_err(|_| AppError::unauthorized())?;
    {
        let mut map = state.channels.map.lock().unwrap();
        if !map.get_mut(&sid).is_some_and(|c| c.window.accept(counter)) {
            return Err(AppError::unauthorized());
        }
    }
    let (head, at) = ch::decode_request_head(&buf[REQUEST_HEADER_LEN..])
        .map_err(|_| AppError::bad_request("malformed request"))?;
    let inner_body = Bytes::from(buf).slice(REQUEST_HEADER_LEN + at..);

    let (status, out) = dispatch(inner, head, inner_body, connect, forwarded).await?;
    let mut sealed = Vec::with_capacity(2 + out.len() + 16);
    sealed.extend_from_slice(&status.to_be_bytes());
    sealed.extend_from_slice(&out);
    drop(out);
    ch::seal_message_in_place(&s2c, &sid, counter, &mut sealed, 0);
    Ok(octets(sealed))
}

async fn dispatch(
    inner: Router,
    ireq: RequestHead,
    body: Bytes,
    connect: Option<ConnectInfo<SocketAddr>>,
    forwarded: Vec<axum::http::HeaderValue>,
) -> AppResult<(u16, Bytes)> {
    use tower::ServiceExt;

    if !ireq.path.starts_with('/') {
        return Err(AppError::bad_request("malformed request"));
    }
    let method = match ireq.method {
        Method::Get => HttpMethod::GET,
        Method::Post => HttpMethod::POST,
        Method::Put => HttpMethod::PUT,
        Method::Delete => HttpMethod::DELETE,
    };
    let mut b = Request::builder().method(method).uri(&ireq.path);
    if !ireq.token.is_empty() {
        b = b.header(AUTHORIZATION, format!("Bearer {}", ireq.token));
    }
    if ireq.json {
        b = b.header(CONTENT_TYPE, "application/json");
    }
    for v in forwarded {
        b = b.header("x-forwarded-for", v);
    }
    let mut request = b
        .body(Body::from(body))
        .map_err(|_| AppError::bad_request("malformed request"))?;
    if let Some(c) = connect {
        request.extensions_mut().insert(c);
    }
    let response = match inner.oneshot(request).await {
        Ok(r) => r,
        Err(never) => match never {},
    };
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), MAX_MESSAGE)
        .await
        .map_err(|_| AppError::from(std::io::Error::other("response too large")))?;
    Ok((status, body))
}
