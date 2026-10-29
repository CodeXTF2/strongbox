//! A hostile HTTP proxy between client and server: everything after sign-up is sealed, so the
//! proxy sees no path, token or key material, cannot alter either direction, cannot replay a
//! request, and cannot stand in for the server.

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Router;
use strongbox_client::vault::{connect, create_vault};
use strongbox_client::Error;
use strongbox_fido::soft::SoftAuthenticator;
use strongbox_fido::Authenticator;
use strongbox_proto::RegistrationMode;
use strongbox_server::Config;

async fn start_server(data_dir: &Path) -> String {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        admin_listen: "127.0.0.1:1".parse().unwrap(),
        data_dir: data_dir.to_path_buf(),
        registration: RegistrationMode::Invite,
        invite_token: Some("letmein".into()),
        session_ttl_secs: 3600,
        prelogin_rate_per_minute: 1000,
        trust_proxy: false,
        debug: false,
        vault_slots: Some(2),
        vault_slot_blocks: Some(16),
        drive_size: None,
        spare_vaults: 0,
    };
    let app = strongbox_server::build(config).await.unwrap();
    serve(app).await
}

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    format!("http://{addr}")
}

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    request: Vec<u8>,
    response: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Forward faithfully, recording everything.
    Record,
    /// Flip a bit in every sealed reply.
    TamperReplies,
    /// Answer the channel hello with made-up bytes, as a server that lacks the key would.
    ForgeHello,
    /// Rewrite the clear-text `/v1/info` (vault layout).
    ForgeInfo,
}

struct Proxy {
    upstream: String,
    http: reqwest::Client,
    seen: Mutex<Vec<Seen>>,
    mode: Mutex<Mode>,
}

async fn forward(State(p): State<Arc<Proxy>>, req: Request) -> Response {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap();
    let body = to_bytes(req.into_body(), 64 << 20).await.unwrap();
    let mode = *p.mode.lock().unwrap();
    let mut reply = if mode == Mode::ForgeHello && path == "/v2/channel" {
        Bytes::from(vec![0x42; 32 + 16 + 32])
    } else {
        let upstream = p
            .http
            .request(method.clone(), format!("{}{}", p.upstream, path))
            .body(body.to_vec())
            .send()
            .await
            .unwrap();
        let status = upstream.status();
        let bytes = upstream.bytes().await.unwrap();
        if !status.is_success() {
            return Response::builder()
                .status(status.as_u16())
                .body(Body::from(bytes))
                .unwrap();
        }
        bytes
    };
    if mode == Mode::ForgeInfo && path == "/v1/info" {
        let mut info: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        let slots = info["vault"]["slots"].as_u64().unwrap();
        info["vault"]["slots"] = (slots + 1).into();
        reply = Bytes::from(serde_json::to_vec(&info).unwrap());
    }
    p.seen.lock().unwrap().push(Seen {
        method: method.to_string(),
        path: path.clone(),
        request: body.to_vec(),
        response: reply.to_vec(),
    });
    if mode == Mode::TamperReplies && path == "/v2/rpc" {
        let mut v = reply.to_vec();
        let last = v.len() - 1;
        v[last] ^= 1;
        reply = Bytes::from(v);
    }
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::from(reply))
        .unwrap()
}

async fn start_proxy(upstream: String) -> (String, Arc<Proxy>) {
    let proxy = Arc::new(Proxy {
        upstream,
        http: reqwest::Client::new(),
        seen: Mutex::new(Vec::new()),
        mode: Mutex::new(Mode::Record),
    });
    let app = Router::new().fallback(forward).with_state(proxy.clone());
    (serve(app).await, proxy)
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test(flavor = "multi_thread")]
async fn proxy_sees_only_ciphertext_and_cannot_tamper_replay_or_impersonate() {
    let tmp = tempfile::tempdir().unwrap();
    let server = start_server(&tmp.path().join("server")).await;
    let (url, proxy) = start_proxy(server.clone()).await;
    let key: Arc<dyn Authenticator> = Arc::new(SoftAuthenticator::new(tmp.path().join("key.json")));

    // Sign-up happens on a clean network (straight to the server); the proxy was not there.
    const USER: &str = "amber-falcon-orchard";
    create_vault(&server, USER, Some("letmein".into()), key.clone())
        .await
        .unwrap();

    // Everything afterwards goes through the hostile proxy and works.
    let (client, k) = connect(&url, USER, key.clone(), 0, "11111111")
        .await
        .unwrap();
    client.members().await.unwrap();
    client.create(&k).await.unwrap();

    // The proxy saw only the clear routes plus opaque rpc messages: no vault path, no token,
    // and nothing it recorded contains an API path or JSON field name.
    let seen = proxy.seen.lock().unwrap().clone();
    assert!(seen.iter().filter(|s| s.path == "/v2/rpc").count() > 5);
    for s in &seen {
        let clear = s.path == "/v1/info"
            || s.path.starts_with("/v2/lookup/")
            || s.path == "/v2/channel"
            || s.path == "/v2/rpc";
        assert!(clear, "{} {} must be sealed", s.method, s.path);
        for needle in [
            &b"/v2/"[..],
            b"Bearer",
            b"locator",
            b"challenge",
            b"signature",
            b"members",
            b"slots",
            b"auth_public_key",
        ] {
            if s.path == "/v2/rpc" {
                assert!(
                    !contains(&s.request, needle) && !contains(&s.response, needle),
                    "plaintext {:?} on the wire",
                    String::from_utf8_lossy(needle)
                );
            }
        }
    }

    // Replaying a captured request is refused (nothing is executed twice).
    let captured = seen
        .iter()
        .rfind(|s| s.path == "/v2/rpc")
        .expect("an rpc message")
        .request
        .clone();
    let replay = reqwest::Client::new()
        .post(format!("{server}/v2/rpc"))
        .body(captured.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 401, "replayed message must be refused");

    // A forged message (valid-looking framing, wrong key) is refused too.
    let mut forged = captured;
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let resp = reqwest::Client::new()
        .post(format!("{server}/v2/rpc"))
        .body(forged)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Authenticated routes do not exist outside the channel, whatever the token.
    let plain = reqwest::Client::new()
        .get(format!("{server}/v2/members"))
        .bearer_auth("anything")
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), 404);

    // A proxy that flips a bit in a reply is detected, not believed.
    *proxy.mode.lock().unwrap() = Mode::TamperReplies;
    assert!(client.members().await.is_err());

    // A proxy that rewrites the clear-text layout is caught once the channel can confirm it.
    *proxy.mode.lock().unwrap() = Mode::ForgeInfo;
    match connect(&url, USER, key.clone(), 0, "11111111").await {
        Err(Error::Invalid(m)) => assert!(m.contains("differ"), "{m}"),
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("a forged layout must not be accepted"),
    }

    // A proxy (or rogue server) that answers the hello without the key cannot get a session.
    *proxy.mode.lock().unwrap() = Mode::ForgeHello;
    match connect(&url, USER, key.clone(), 0, "11111111").await {
        Err(Error::Invalid(m)) => assert!(m.contains("could not prove"), "{m}"),
        Err(e) => panic!("unexpected error {e}"),
        Ok(_) => panic!("a forged hello must not log in"),
    }
}
