//! `sbox`: command-line Strongbox client.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use strongbox_client::{
    local_safe_name, login, login_with_recovery, register, sign_in, sign_in_with_recovery, Drive,
    Profile, RegisterOptions, Ui,
};
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
    /// Create an account on a server, enrolling the connected security key.
    Register {
        #[arg(long)]
        server: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        invite: Option<String>,
        #[arg(long, default_value = "Security key 1")]
        label: String,
        /// Also require a password together with the security key.
        #[arg(long)]
        password: bool,
        /// Skip creating a printable recovery code (not recommended).
        #[arg(long)]
        no_recovery: bool,
        #[arg(long)]
        rp_id: Option<String>,
    },
    /// Sign in on this device to an existing account (enrolled from another device).
    Login {
        #[arg(long)]
        server: String,
        #[arg(long)]
        username: String,
        /// Use the recovery code instead of a security key.
        #[arg(long)]
        recovery: bool,
        #[arg(long)]
        rp_id: Option<String>,
    },
    /// Unlock and show account usage.
    Status,
    Ls {
        #[arg(default_value = "/")]
        path: String,
    },
    /// Search file and folder names everywhere in the drive.
    Find {
        query: String,
    },
    Mkdir {
        path: String,
    },
    /// Upload local files into a remote directory.
    Put {
        files: Vec<PathBuf>,
        #[arg(long, default_value = "/")]
        to: String,
    },
    /// Download a remote file.
    Get {
        remote: String,
        local: Option<PathBuf>,
    },
    /// Delete a file or folder (moves it to the trash unless --permanent).
    Rm {
        path: String,
        #[arg(long)]
        permanent: bool,
    },
    Mv {
        from: String,
        to: String,
    },
    /// List, restore or empty the trash.
    Trash {
        #[command(subcommand)]
        cmd: TrashCmd,
    },
    /// Manage security keys and recovery codes.
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Remove unreferenced blobs left by interrupted uploads.
    Gc,
    /// Unlock once and run commands interactively.
    Shell,
    /// Unlock with a recovery code and enroll a replacement security key.
    Recover {
        #[arg(long, default_value = "Replacement key")]
        label: String,
    },
    /// Deniable vaults (docs/deniable-drives.md). Nothing is saved on this computer.
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Create a vault for the connected security key.
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
        /// Slot number (0–99 on a default server).
        slot: u32,
    },
    /// Open the drive a recovery code belongs to.
    Recover {
        #[arg(long)]
        server: String,
    },
}

/// Commands inside `sbox vault open`.
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

#[derive(Subcommand)]
enum KeysCmd {
    List,
    /// Enroll an additional security key.
    Add {
        #[arg(long, default_value = "Security key")]
        label: String,
        #[arg(long)]
        password: bool,
    },
    /// Generate a new recovery code.
    Recovery,
    Remove {
        id: String,
    },
}

#[derive(Subcommand)]
enum TrashCmd {
    List,
    /// Restore an item by the id shown in `trash list`.
    Restore {
        id: String,
    },
    /// Permanently delete everything in the trash.
    Empty,
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

impl Ui for CliUi {
    fn request_password(&self) -> Option<String> {
        rpassword::prompt_password("Password: ").ok()
    }
}

fn ask_new_password() -> anyhow::Result<String> {
    let a = rpassword::prompt_password("New password: ")?;
    if a != rpassword::prompt_password("Confirm password: ")? {
        bail!("passwords do not match");
    }
    Ok(a)
}

fn authenticator() -> Arc<dyn strongbox_fido::Authenticator> {
    strongbox_fido::platform(Arc::new(CliUi)).into()
}

fn profile() -> anyhow::Result<Profile> {
    Profile::load()?.context("no account configured; run `sbox register` first")
}

async fn unlock() -> anyhow::Result<Drive> {
    Ok(login(profile()?, authenticator(), Arc::new(CliUi)).await?)
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

async fn run_drive_cmd(drive: &Drive, cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Status => {
            let u = drive.usage().await?;
            let p = drive.profile();
            println!("{}@{}", p.username, p.server_url);
            println!(
                "used: {} (padded){}",
                human(u.used_bytes),
                u.quota_bytes
                    .map(|q| format!(" of {}", human(q)))
                    .unwrap_or_default()
            );
        }
        Cmd::Ls { path } => {
            for e in drive.list(&path).await? {
                let size = if e.is_dir {
                    "-".to_string()
                } else {
                    human(e.size)
                };
                let name = if e.is_dir {
                    format!("{}/", e.name)
                } else {
                    e.name
                };
                println!("{size:>10}  {name}");
            }
        }
        Cmd::Find { query } => {
            for h in drive.search(&query).await? {
                println!("{}{}", h.path, if h.entry.is_dir { "/" } else { "" });
            }
        }
        Cmd::Mkdir { path } => drive.mkdir(&path).await?,
        Cmd::Put { files, to } => {
            for f in files {
                eprintln!("{}", f.display());
                drive.upload(&f, &to, Some(&progress)).await?;
            }
        }
        Cmd::Get { remote, local } => {
            // The remote name is not trusted as a path: it could contain `..\` on Windows.
            let local = local.unwrap_or_else(|| {
                PathBuf::from(local_safe_name(
                    remote.rsplit('/').next().unwrap_or("download"),
                ))
            });
            drive.download(&remote, &local, Some(&progress)).await?;
            eprintln!("saved {}", local.display());
        }
        Cmd::Rm {
            path,
            permanent: true,
        } => drive.remove(&path).await?,
        Cmd::Rm {
            path,
            permanent: false,
        } => {
            drive.trash(&path).await?;
        }
        Cmd::Mv { from, to } => drive.rename(&from, &to).await?,
        Cmd::Trash { cmd } => match cmd {
            TrashCmd::List => {
                for t in drive.list_trash().await? {
                    let p = if t.parent == "/" {
                        format!("/{}", t.name)
                    } else {
                        format!("{}/{}", t.parent, t.name)
                    };
                    println!("{}  {}{}", t.id, p, if t.is_dir { "/" } else { "" });
                }
            }
            TrashCmd::Restore { id } => eprintln!("restored to {}", drive.restore(&id).await?),
            TrashCmd::Empty => {
                eprintln!("permanently deleted {} items", drive.empty_trash().await?)
            }
        },
        Cmd::Keys { cmd } => match cmd {
            KeysCmd::List => {
                for s in drive.keyslots().await? {
                    let kind = match &s.kind {
                        strongbox_core::keyslot::KeyslotKind::Fido {
                            password: Some(_), ..
                        } => "security key + password",
                        strongbox_core::keyslot::KeyslotKind::Fido { .. } => "security key",
                        strongbox_core::keyslot::KeyslotKind::Recovery => "recovery code",
                    };
                    println!("{}  {:<24} {}", s.id, kind, s.label);
                }
            }
            KeysCmd::Add { label, password } => {
                let pw = if password {
                    Some(ask_new_password()?)
                } else {
                    None
                };
                eprintln!("Insert the NEW security key (you will be asked to touch it twice)");
                let slot = drive.add_security_key(authenticator(), label, pw).await?;
                eprintln!("added keyslot {}", slot.id);
            }
            KeysCmd::Recovery => show_recovery(&drive.add_recovery_code().await?),
            KeysCmd::Remove { id } => drive.remove_keyslot(&id.parse()?).await?,
        },
        Cmd::Gc => eprintln!("removed {} orphaned blobs", drive.collect_garbage().await?),
        Cmd::Register { .. }
        | Cmd::Login { .. }
        | Cmd::Shell
        | Cmd::Recover { .. }
        | Cmd::Vault { .. } => {
            bail!("not available here")
        }
    }
    Ok(())
}

/// Split a line into words, honouring double quotes.
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

async fn shell(drive: Drive) -> anyhow::Result<()> {
    eprintln!(
        "Unlocked. Commands: ls, find, mkdir, put, get, rm, mv, trash, keys, status, gc, exit"
    );
    let stdin = std::io::stdin();
    loop {
        eprint!("sbox> ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            break;
        }
        let mut words = split_words(&line);
        if words.is_empty() {
            continue;
        }
        if matches!(words[0].as_str(), "exit" | "quit") {
            break;
        }
        words.insert(0, "sbox".into());
        match Cli::try_parse_from(words) {
            Ok(Cli { cmd }) => {
                if let Err(e) = run_drive_cmd(&drive, cmd).await {
                    eprintln!("error: {e}");
                }
            }
            Err(e) => eprintln!("{e}"),
        }
    }
    drive.logout().await?;
    Ok(())
}

/// Vault usernames are secrets (they locate the account), so they are typed hidden and never
/// taken from the command line, where they would end up in shell history.
fn ask_vault_username(new: bool) -> anyhow::Result<String> {
    if new {
        eprintln!("Choose a username nobody could guess (it works like a password: anyone who has");
        eprintln!("your key and its PIN can only find this account by guessing its username).");
    }
    let u = rpassword::prompt_password("Vault username: ")?;
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

async fn vault(cmd: VaultCmd) -> anyhow::Result<()> {
    use strongbox_client::vault;
    match cmd {
        VaultCmd::Create { server, invite } => {
            let username = ask_vault_username(true)?;
            eprintln!("Insert the security key. You will enter its PIN and touch it twice.");
            let v = vault::create_vault(&server, &username, invite, authenticator()).await?;
            eprintln!(
                "Vault created with {} drive slots. Open one with `sbox vault open --server {server} <slot>`;\n\
                 choose a drive PIN of at least 8 characters (10+ digits or a passphrase recommended).",
                v.layout().slots
            );
            v.logout().await?;
        }
        VaultCmd::Open { server, slot } => {
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
        VaultCmd::Recover { server } => {
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
                    for f in files {
                        eprintln!("{}", f.display());
                        drive.upload(&f, &to, opts).await?;
                    }
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
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Register {
            server,
            username,
            invite,
            label,
            password,
            no_recovery,
            rp_id,
        } => {
            if Profile::load()?.is_some() {
                eprintln!("note: replacing the existing local profile");
            }
            let password = if password {
                Some(ask_new_password()?)
            } else {
                None
            };
            eprintln!(
                "Insert your security key. You will be asked for its PIN and to touch it twice."
            );
            let opts = RegisterOptions {
                server_url: server,
                username,
                invite,
                key_label: label,
                password,
                recovery_code: !no_recovery,
                rp_id,
            };
            let (drive, code) = register(opts, authenticator()).await?;
            if let Some(code) = code {
                show_recovery(&code);
            }
            eprintln!("Account created. Add a backup security key soon: `sbox keys add`.");
            drive.logout().await?;
        }
        Cmd::Login {
            server,
            username,
            recovery,
            rp_id,
        } => {
            let drive = if recovery {
                let code = rpassword::prompt_password("Recovery code: ")?;
                sign_in_with_recovery(&server, &username, &code).await?
            } else {
                eprintln!("Insert your security key, enter its PIN and touch it.");
                sign_in(&server, &username, rp_id, authenticator(), Arc::new(CliUi)).await?
            };
            eprintln!("Signed in as {username}. This device will now unlock this account.");
            drive.logout().await?;
        }
        Cmd::Shell => shell(unlock().await?).await?,
        Cmd::Vault { cmd } => vault(cmd).await?,
        Cmd::Recover { label } => {
            let code = rpassword::prompt_password("Recovery code: ")?;
            let drive = login_with_recovery(profile()?, &code).await?;
            eprintln!("Unlocked with recovery code. Insert the replacement security key.");
            let slot = drive.add_security_key(authenticator(), label, None).await?;
            eprintln!(
                "added keyslot {}; consider rotating your recovery code (`sbox keys recovery`)",
                slot.id
            );
            drive.logout().await?;
        }
        cmd => {
            let drive = unlock().await?;
            let r = run_drive_cmd(&drive, cmd).await;
            drive.logout().await?;
            r?;
        }
    }
    Ok(())
}
