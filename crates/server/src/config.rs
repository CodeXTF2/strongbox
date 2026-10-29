use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use strongbox_proto::RegistrationMode;

#[derive(Clone, Debug, Parser)]
#[command(name = "strongbox-server", about = "Strongbox blind storage server")]
pub struct Config {
    /// Address to listen on. Put a TLS-terminating reverse proxy (e.g. Caddy) in front.
    #[arg(long, env = "STRONGBOX_LISTEN", default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Directory for the metadata database and vault block files.
    #[arg(long, env = "STRONGBOX_DATA_DIR", default_value = "./strongbox-data")]
    pub data_dir: PathBuf,

    /// Who may create accounts.
    #[arg(long, env = "STRONGBOX_REGISTRATION", value_parser = parse_registration, default_value = "invite")]
    pub registration: RegistrationMode,

    /// Shared invite token required when registration is `invite`.
    #[arg(long, env = "STRONGBOX_INVITE_TOKEN")]
    pub invite_token: Option<String>,

    /// Session lifetime in seconds.
    #[arg(long, env = "STRONGBOX_SESSION_TTL", default_value_t = 12 * 3600)]
    pub session_ttl_secs: i64,

    /// Pre-login requests (record lookup, challenge, session) allowed per IP per minute.
    #[arg(long, env = "STRONGBOX_PRELOGIN_RATE", default_value_t = 30)]
    pub prelogin_rate_per_minute: u32,

    /// Take the client IP (for rate limiting) from the last `X-Forwarded-For` hop when the
    /// direct peer is a loopback address, i.e. the local TLS proxy from `deploy/`. Without
    /// this, every request behind the proxy shares one rate-limit bucket.
    #[arg(long, env = "STRONGBOX_TRUST_PROXY")]
    pub trust_proxy: bool,

    /// Debug logging: per-request traces (method and path, which include usernames and object
    /// ids), detailed error messages, and `RUST_LOG` overrides. Off by default: the default mode
    /// logs nothing that identifies a user, an object or a request, and ignores `RUST_LOG`.
    #[arg(long, env = "STRONGBOX_DEBUG")]
    pub debug: bool,

    /// Drives per deniable vault (account). Set on the first start and fixed for this data
    /// directory afterwards (every vault on a server must look the same). Default 100.
    #[arg(
        long = "drives-per-vault",
        visible_alias = "vault-slots",
        env = "STRONGBOX_DRIVES_PER_VAULT"
    )]
    pub vault_slots: Option<u32>,

    /// Size of each drive, e.g. `256MiB`, `1GiB` (a bare number means MiB; rounded up to whole
    /// 256 KiB blocks, of which two hold the drive's headers). Set on the first start and
    /// fixed afterwards. Every vault is allocated in full when created: drives × size of disk.
    /// Default 256MiB.
    #[arg(long = "drive-size", env = "STRONGBOX_DRIVE_SIZE", value_parser = parse_size)]
    pub drive_size: Option<u64>,

    /// Drive size in 256 KiB blocks (alternative to --drive-size).
    #[arg(
        long,
        env = "STRONGBOX_VAULT_SLOT_BLOCKS",
        hide = true,
        conflicts_with = "drive_size"
    )]
    pub vault_slot_blocks: Option<u32>,
}

/// `16MiB`, `1 GiB`, `512k`, `2G`, `100` (MiB). Binary units.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: f64 = num.parse().map_err(|_| format!("invalid size {s:?}"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "k" | "kb" | "kib" => 1 << 10,
        "" | "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        "b" => 1,
        u => {
            return Err(format!(
                "unknown size unit {u:?} (use KiB, MiB, GiB or TiB)"
            ))
        }
    };
    let bytes = (n * mult as f64).ceil();
    if !(bytes >= 1.0 && bytes < u64::MAX as f64) {
        return Err(format!("invalid size {s:?}"));
    }
    Ok(bytes as u64)
}

fn parse_registration(s: &str) -> Result<RegistrationMode, String> {
    match s {
        "open" => Ok(RegistrationMode::Open),
        "invite" => Ok(RegistrationMode::Invite),
        "closed" => Ok(RegistrationMode::Closed),
        _ => Err("expected open, invite or closed".into()),
    }
}
