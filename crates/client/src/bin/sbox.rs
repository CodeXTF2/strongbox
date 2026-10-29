//! `sbox`: command-line Strongbox client.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::bail;
use clap::{Parser, Subcommand};
use strongbox_client::local_safe_name;
use strongbox_fido::Interaction;

#[derive(Parser)]
#[command(
    name = "sbox",
    version,
    about = "End-to-end encrypted cloud drive unlocked by a FIDO2 security key"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an account for the connected security key. Nothing is saved on this computer.
    Create {
        #[arg(long)]
        server: String,
        #[arg(long)]
        invite: Option<String>,
    },
    /// Open a drive by slot number and drive PIN (asked for), then run commands.
    Open {
        #[arg(long)]
        server: String,
        /// Slot number (0-99 on a default server).
        slot: u32,
    },
    /// Open the drive a recovery code belongs to.
    Recover {
        #[arg(long)]
        server: String,
    },
}

/// Commands inside `sbox open`.
#[derive(Parser)]
#[command(name = "", no_binary_name = true)]
enum VaultShellCmd {
    Ls {
        #[arg(default_value = "/")]
        path: String,
    },
    Mkdir {
        path: String,
    },
    Put {
        files: Vec<PathBuf>,
        #[arg(long, default_value = "/")]
        to: String,
    },
    Get {
        remote: String,
        local: Option<PathBuf>,
    },
    Rm {
        path: String,
    },
    Mv {
        from: String,
        to: String,
    },
    /// Space used in this drive.
    Usage,
    /// Let another security key open this drive (asks for this drive's PIN again).
    AddKey,
    /// Create or replace this drive's recovery code.
    RecoveryCode,
    Exit,
}

struct CliUi;

impl Interaction for CliUi {
    fn status(&self, message: &str) {
        eprintln!("{message}");
    }

    fn request_pin(&self, attempts_left: Option<u8>) -> Option<String> {
        if let Some(n) = attempts_left {
            eprintln!("Wrong PIN ({n} attempts left)");
        }
        rpassword::prompt_password("Security key PIN: ").ok()
    }
}

fn authenticator() -> Arc<dyn strongbox_fido::Authenticator> {
    strongbox_fido::platform(Arc::new(CliUi)).into()
}

fn show_recovery(code: &str) {
    eprintln!("\n================ RECOVERY CODE ================");
    eprintln!("{code}");
    eprintln!("===============================================");
    eprintln!("Write this down and store it offline. It unlocks your drive without a");
    eprintln!("security key. It will not be shown again.\n");
}

fn human(n: u64) -> String {
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < units.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", units[u])
    }
}

fn progress(done: u64, total: u64) {
    eprint!("\r  {} / {}   ", human(done), human(total));
    if done >= total {
        eprintln!();
    }
}

fn split_words(line: &str) -> Vec<String> {
    let (mut words, mut cur, mut quoted, mut any) = (Vec::new(), String::new(), false, false);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any {
                    words.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            c => {
                cur.push(c);
                any = true;
            }
        }
    }
    if any {
        words.push(cur);
    }
    words
}

/// Vault usernames are secrets (they locate the account), so they are typed hidden and never
/// taken from the command line, where they would end up in shell history.
fn ask_vault_username(new: bool) -> anyhow::Result<String> {
    if new {
        eprintln!("Choose a username nobody could guess (it works like a password: anyone who has");
        eprintln!("your key and its PIN can only find this account by guessing its username).");
    }
    let u = rpassword::prompt_password("Username: ")?;
    if new && rpassword::prompt_password("Repeat username: ")? != u {
        bail!("usernames do not match");
    }
    Ok(u)
}

fn ask_drive_pin(prompt: &str) -> anyhow::Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}

fn confirm(question: &str) -> anyhow::Result<bool> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

async fn run(cmd: Cmd) -> anyhow::Result<()> {
    use strongbox_client::vault;
    match cmd {
        Cmd::Create { server, invite } => {
            let username = ask_vault_username(true)?;
            eprintln!("Insert the security key. You will enter its PIN and touch it twice.");
            let v = vault::create_vault(&server, &username, invite, authenticator()).await?;
            eprintln!(
                "Account created with {} drive slots. Open one with `sbox open --server {server} <slot>`;\n\
                 choose a drive PIN of at least 8 characters (10+ digits or a passphrase recommended).",
                v.layout().slots
            );
            v.logout().await?;
        }
        Cmd::Open { server, slot } => {
            let username = ask_vault_username(false)?;
            let pin = ask_drive_pin(&format!("Drive PIN for slot {slot}: "))?;
            eprintln!("Insert your security key, enter its PIN and touch it.");
            let (v, key) = vault::connect(&server, &username, authenticator(), slot, &pin).await?;
            let drive = match v.open(&key).await? {
                Some(d) => d,
                None => {
                    eprintln!("No drive found for this slot and PIN.");
                    if !confirm(&format!("Create a new drive in slot {slot}? This erases slot {slot} if it holds anything."))? {
                        v.logout().await?;
                        return Ok(());
                    }
                    if ask_drive_pin("Repeat the drive PIN: ")? != pin {
                        bail!("PINs do not match");
                    }
                    v.create(&key).await?
                }
            };
            drop(pin);
            vault_shell(drive).await?;
            v.logout().await?;
        }
        Cmd::Recover { server } => {
            let username = ask_vault_username(false)?;
            let code = rpassword::prompt_password("Recovery code: ")?;
            let (v, key) = vault::connect_with_recovery(&server, &username, &code).await?;
            let drive = v.open(&key).await?.expect("recovery located this drive");
            eprintln!(
                "Opened slot {}. Add a security key with `add-key`.",
                key.slot()
            );
            vault_shell(drive).await?;
            v.logout().await?;
        }
    }
    Ok(())
}

async fn vault_shell(mut drive: strongbox_client::vault::VaultDrive) -> anyhow::Result<()> {
    use strongbox_client::TransferOptions;
    eprintln!(
        "Drive open. Commands: ls, mkdir, put, get, rm, mv, usage, add-key, recovery-code, exit"
    );
    let stdin = std::io::stdin();
    loop {
        eprint!("vault> ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            return Ok(());
        }
        let words = split_words(&line);
        if words.is_empty() {
            continue;
        }
        let cmd = match VaultShellCmd::try_parse_from(words) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("{e}");
                continue;
            }
        };
        let progress = |done: u64, total: u64| progress(done, total);
        let opts = TransferOptions {
            progress: Some(&progress),
            ..Default::default()
        };
        let r: anyhow::Result<()> = async {
            match cmd {
                VaultShellCmd::Ls { path } => {
                    for e in drive.list(&path)? {
                        let size = if e.is_dir { "-".to_string() } else { human(e.size) };
                        println!("{size:>10}  {}{}", e.name, if e.is_dir { "/" } else { "" });
                    }
                }
                VaultShellCmd::Mkdir { path } => drive.mkdir(&path).await?,
                VaultShellCmd::Put { files, to } => {
                    let mut staged = drive.stage();
                    for f in files {
                        eprintln!("{}", f.display());
                        drive.upload_staged(&mut staged, &f, &to, opts).await?;
                        if drive.staged_due(&staged) {
                            drive.commit_staged(&mut staged).await?;
                        }
                    }
                    drive.commit_staged(&mut staged).await?;
                }
                VaultShellCmd::Get { remote, local } => {
                    let local = local.unwrap_or_else(|| PathBuf::from(local_safe_name(remote.rsplit('/').next().unwrap_or("download"))));
                    drive.download(&remote, &local, opts).await?;
                    eprintln!("saved {}", local.display());
                }
                VaultShellCmd::Rm { path } => drive.remove(&path).await?,
                VaultShellCmd::Mv { from, to } => drive.rename(&from, &to).await?,
                VaultShellCmd::Usage => {
                    let (used, total) = drive.usage();
                    println!("{} of {} used", human(used), human(total));
                }
                VaultShellCmd::AddKey => {
                    let pin = ask_drive_pin("This drive's PIN: ")?;
                    eprintln!("Insert the OTHER security key (remove this one), enter its PIN and touch it.");
                    drive.add_key(authenticator(), &pin).await?;
                    eprintln!("Done: that key now opens this drive (same slot and drive PIN).");
                }
                VaultShellCmd::RecoveryCode => show_recovery(&drive.new_recovery_code().await?),
                VaultShellCmd::Exit => return Err(anyhow::anyhow!("exit")),
            }
            Ok(())
        }
        .await;
        match r {
            Err(e) if e.to_string() == "exit" => return Ok(()),
            Err(e) => eprintln!("error: {e}"),
            Ok(()) => {}
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run(Cli::parse().cmd).await
}
