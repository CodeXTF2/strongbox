use std::net::SocketAddr;

use clap::Parser;
use strongbox_server::{build, log_filter, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    tracing_subscriber::fmt()
        .with_env_filter(log_filter(config.debug))
        .init();
    if config.debug {
        tracing::warn!(
            "DEBUG LOGGING IS ON: logs will contain request paths (usernames, object ids) and raw \
             error details. Do not run production servers like this."
        );
    }
    let listen = config.listen;
    if !listen.ip().is_loopback() {
        // The server itself speaks plain HTTP; TLS is the reverse proxy's job (deploy/).
        tracing::warn!(
            "listening on non-loopback address {listen} over plain HTTP: clients refuse http:// to remote \
             hosts, so put a TLS proxy in front and do not expose this port directly"
        );
    }
    let app = build(config).await?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!("listening on http://{listen}");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
