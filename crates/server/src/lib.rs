//! Strongbox server: a blind store for username-sealed account records and fixed-size vault blocks.
//!
//! The server never holds a key that decrypts user data. It authenticates vault members with
//! Ed25519 keys derived client-side from their security keys, and stores whole fixed-size blocks
//! without knowing which of them are in use.

pub mod admin;
pub mod api;
pub mod config;
pub mod db;
pub mod error;
pub mod ratelimit;
pub mod vault_api;
pub mod vaultstore;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;

pub use config::Config;

static DEBUG_LOGGING: AtomicBool = AtomicBool::new(false);

/// Whether logs may contain identifying details (usernames, ids, request paths, raw errors).
/// Only true with `--debug`; every log site that could identify a user checks this.
pub fn debug_logging() -> bool {
    DEBUG_LOGGING.load(Ordering::Relaxed)
}

/// The log filter for a mode. Default mode is fixed (it ignores `RUST_LOG`) so the privacy
/// guarantee cannot be undone by an environment variable: only this crate's own messages,
/// which are written to be non-identifying, plus warnings and errors from dependencies.
pub fn log_filter(debug: bool) -> String {
    if debug {
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info,sqlx=warn".into())
    } else {
        "warn,strongbox_server=info,sqlx=off,tower_http=off,hyper=off".into()
    }
}

pub struct AppState {
    pub config: Config,
    pub db: db::Db,
    pub server_id: String,
    /// Server-local secret for deterministic decoy records and blocks (see `api::decoy_bytes`).
    pub decoy_secret: Vec<u8>,
    pub prelogin_limiter: ratelimit::RateLimiter,
    pub vaults: vaultstore::VaultStore,
    pub vault_sessions: vault_api::VaultSessions,
    pub started: std::time::Instant,
}

const BLOCK: u64 = strongbox_core::vault::BLOCK_SIZE as u64;
const DEFAULT_DRIVES: u32 = 100;
const DEFAULT_DRIVE_SIZE: u64 = 256 << 20;

/// The deniable-vault layout. Existing vault files have the layout they were created with, and
/// every vault on a server must look the same, so it is fixed per data directory on first start.
async fn vault_layout(
    config: &Config,
    db: &db::Db,
) -> anyhow::Result<strongbox_proto::VaultLayout> {
    let blocks_for = |bytes: u64| -> anyhow::Result<u32> {
        let b = bytes.div_ceil(BLOCK);
        anyhow::ensure!(
            b > strongbox_core::vault::HEADER_BLOCKS as u64,
            "drive size must be at least 1 MiB"
        );
        u32::try_from(b).map_err(|_| anyhow::anyhow!("drive size too large"))
    };
    let want_blocks = match (config.drive_size, config.vault_slot_blocks) {
        (Some(bytes), _) => Some(blocks_for(bytes)?),
        (None, b) => b,
    };
    if let Some(n) = config.vault_slots {
        anyhow::ensure!(
            (1..=10_000).contains(&n),
            "drives per vault must be 1-10000"
        );
    }
    let (slots, blocks) = match db.meta("vault_layout").await? {
        Some(fixed) => {
            let (s, b) = fixed
                .split_once('x')
                .and_then(|(s, b)| Some((s.parse::<u32>().ok()?, b.parse::<u32>().ok()?)))
                .ok_or_else(|| anyhow::anyhow!("corrupt vault_layout {fixed:?}"))?;
            if config.vault_slots.is_some_and(|n| n != s) || want_blocks.is_some_and(|n| n != b) {
                anyhow::bail!(
                    "this data directory's vault layout is fixed at {s} drives of {} each; it cannot change once set. Omit --drives-per-vault/--drive-size, or use a new data directory",
                    human(b as u64 * BLOCK)
                );
            }
            (s, b)
        }
        None => {
            let s = config.vault_slots.unwrap_or(DEFAULT_DRIVES);
            let b = match want_blocks {
                Some(b) => b,
                None => blocks_for(DEFAULT_DRIVE_SIZE)?,
            };
            db.meta_or_init("vault_layout", || format!("{s}x{b}"))
                .await?;
            (s, b)
        }
    };
    let drive = blocks as u64 * BLOCK;
    tracing::info!(
        "vaults: {slots} drives of {} each ({} usable), {} of disk allocated per vault at creation",
        human(drive),
        human(
            (blocks as u64 - strongbox_core::vault::HEADER_BLOCKS as u64)
                * strongbox_core::vault::BLOCK_PAYLOAD as u64
        ),
        human(drive * slots as u64)
    );
    Ok(strongbox_proto::VaultLayout {
        slots,
        blocks_per_slot: blocks,
        block_size: BLOCK as u32,
    })
}

fn human(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let (mut v, mut u) = (n as f64, 0);
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if v.fract() == 0.0 {
        format!("{v} {}", units[u])
    } else {
        format!("{v:.1} {}", units[u])
    }
}

/// The service router (what clients talk to).
pub async fn build(config: Config) -> anyhow::Result<Router> {
    Ok(build_all(config).await?.0)
}

/// The service router and the admin page router, which belong on separate listeners.
pub async fn build_all(config: Config) -> anyhow::Result<(Router, Router)> {
    anyhow::ensure!(
        config.admin_listen.ip().is_loopback(),
        "--admin-listen must be a loopback address (the admin page has no login)"
    );
    anyhow::ensure!(
        config.admin_listen != config.listen,
        "--admin-listen and --listen must be different addresses"
    );
    DEBUG_LOGGING.store(config.debug, Ordering::Relaxed);
    std::fs::create_dir_all(&config.data_dir)?;
    // The database holds the decoy secret and account metadata: keep it private to the operator.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.data_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let db_path = config.data_dir.join("strongbox.sqlite3");
    let db = db::Db::open(&db_path).await?;
    let server_id = db
        .meta_or_init("server_id", || strongbox_core::Id::random().to_string())
        .await?;
    let decoy_secret = db
        .meta_or_init("decoy_secret", || {
            strongbox_core::Key::random()
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        })
        .await?;
    let decoy_secret = hex::decode(decoy_secret)?;
    let layout = vault_layout(&config, &db).await?;
    let vaults = vaultstore::VaultStore::new(config.data_dir.join("vaults"), layout)?;
    // Accounts whose files are gone (data deleted by hand, an incomplete restore) can still sign
    // in but can't open a drive. Say so at startup; the count identifies no one.
    let missing = db
        .vault_ids()
        .await?
        .iter()
        .filter(|id| !vaults.exists(id))
        .count();
    if missing > 0 {
        tracing::warn!(
            "{missing} account(s) have no vault storage on disk; their owners can sign in but not open drives, and can delete the account to start over"
        );
    }
    let state = Arc::new(AppState {
        vaults,
        vault_sessions: Default::default(),
        prelogin_limiter: ratelimit::RateLimiter::new(config.prelogin_rate_per_minute),
        config,
        db,
        server_id,
        decoy_secret,
        started: std::time::Instant::now(),
    });

    let janitor = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(600)).await;
            janitor.prelogin_limiter.purge();
            janitor.vault_sessions.purge();
        }
    });

    Ok((api::router(state.clone()), admin::router(state)))
}
