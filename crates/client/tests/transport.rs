//! Transport hardening: the client must not follow redirects (they could downgrade to
//! plain HTTP with the session token attached) and must refuse plain HTTP to remote hosts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::{header, StatusCode};
use axum::routing::any;
use axum::Router;
use strongbox_client::api::{check_server_url, Api};

async fn serve(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    let target = serve(Router::new().fallback(any(move || {
        h.fetch_add(1, Ordering::SeqCst);
        async { "{}" }
    })))
    .await;
    for status in [
        StatusCode::MOVED_PERMANENTLY,
        StatusCode::FOUND,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        let location = format!("{target}/v1/info");
        let redirector = serve(Router::new().fallback(any(move || {
            let location = location.clone();
            async move { (status, [(header::LOCATION, location)]) }
        })))
        .await;
        let mut api = Api::new(&redirector).unwrap();
        api.set_token("secret-session-token".into());
        assert!(api.info().await.is_err(), "{status} must not be followed");
        assert!(api.vault_members().await.is_err());
    }
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the redirect target must never be contacted"
    );
}

#[test]
fn plain_http_only_to_loopback() {
    for ok in [
        "https://drive.example.org",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://[::1]:8080",
    ] {
        assert!(check_server_url(ok).is_ok(), "{ok}");
    }
    for bad in [
        "http://drive.example.org",
        "http://192.168.1.10:8080",
        "ftp://drive.example.org",
        "drive.example.org",
    ] {
        assert!(check_server_url(bad).is_err(), "{bad}");
    }
}
