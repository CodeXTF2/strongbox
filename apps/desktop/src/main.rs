//! Strongbox desktop app. The web UI only renders; every key, every byte of crypto and every
//! security key interaction stays in this Rust process (via `strongbox-client`).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use strongbox_client::{
    local_safe_name, unique_local_path, ListEntry, OnConflict, SearchHit, TransferOptions,
};
use strongbox_fido::{Authenticator, Interaction};
use tauri::ipc::Response;
use tauri::{AppHandle, Emitter, Manager, RunEvent, State};
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::RwLock;

/// Largest file the in-app preview will decrypt into memory.
const MAX_PREVIEW_BYTES: u64 = 256 * 1024 * 1024;
/// Prefix on errors that mean the server session is gone; the UI returns to the lock screen.
const SESSION_EXPIRED: &str = "SESSION_EXPIRED";

#[derive(Default)]
struct AppState {
    /// Open vaults, with one selected for file operations.
    vaults: RwLock<HashMap<String, VaultItem>>,
    active_vault: RwLock<Option<String>>,
    vault_account: RwLock<Option<VaultAccount>>,
    next_vault: AtomicU64,
    /// Pending answer channel for a PIN/password prompt shown in the UI.
    prompt: Arc<Mutex<Option<mpsc::Sender<Option<String>>>>>,
    transfers: Transfers,
}

struct VaultSession {
    drive: strongbox_client::vault::VaultDrive,
    server: String,
    username: String,
}

struct VaultItem {
    session: Arc<AsyncMutex<VaultSession>>,
    wipe: strongbox_client::vault::WipeHandle,
    client: strongbox_client::vault::VaultClient,
    slot: u32,
}

struct VaultAccount {
    client: strongbox_client::vault::VaultClient,
    server: String,
    username: String,
}

async fn install_vault(
    state: &AppState,
    client: strongbox_client::vault::VaultClient,
    drive: strongbox_client::vault::VaultDrive,
    server: String,
    username: String,
    slot: u32,
) -> String {
    let id = format!(
        "vault-{}",
        state.next_vault.fetch_add(1, Ordering::Relaxed) + 1
    );
    let wipe = drive.wipe_handle();
    let item = VaultItem {
        session: Arc::new(AsyncMutex::new(VaultSession {
            drive,
            server,
            username,
        })),
        wipe,
        client,
        slot,
    };
    state.vaults.write().await.insert(id.clone(), item);
    *state.active_vault.write().await = Some(id.clone());
    id
}

/// Make a freshly signed-in account the only unlocked thing: whatever was open before is
/// wiped and its server sessions ended.
async fn sign_in_account(
    state: &AppState,
    client: strongbox_client::vault::VaultClient,
    server: String,
    username: String,
) {
    for previous in wipe_vault(state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), previous.end_session()).await;
    }
    *state.vault_account.write().await = Some(VaultAccount {
        client,
        server,
        username,
    });
}

/// Cancellation flags for queued and running transfers, by transfer id.
#[derive(Default)]
struct Transfers {
    next: AtomicU64,
    flags: Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

impl Transfers {
    fn start(&self) -> (u64, Arc<AtomicBool>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let flag = Arc::new(AtomicBool::new(false));
        self.flags.lock().unwrap().insert(id, flag.clone());
        (id, flag)
    }

    fn finish(&self, id: u64) {
        self.flags.lock().unwrap().remove(&id);
    }

    fn cancel(&self, id: Option<u64>) {
        for (k, f) in self.flags.lock().unwrap().iter() {
            if id.is_none() || id == Some(*k) {
                f.store(true, Ordering::Relaxed);
            }
        }
    }
}

#[derive(Clone, Serialize)]
struct PromptEvent {
    kind: &'static str,
    attempts_left: Option<u8>,
}

#[derive(Clone, Serialize)]
struct TransferEvent {
    id: u64,
    kind: &'static str,
    name: String,
    /// Remote folder (uploads) or local destination (downloads), for display.
    target: String,
    done: u64,
    total: u64,
    /// queued | active | done | error | cancelled
    state: &'static str,
    error: Option<String>,
}

/// Bridges security-key prompts to the web UI: emits an event, then blocks (on the
/// authenticator's worker thread) until the UI answers via `answer_prompt`.
struct TauriUi {
    app: AppHandle,
    pending: Arc<Mutex<Option<mpsc::Sender<Option<String>>>>>,
}

impl TauriUi {
    fn ask(&self, kind: &'static str, attempts_left: Option<u8>) -> Option<String> {
        let (tx, rx) = mpsc::channel();
        *self.pending.lock().unwrap() = Some(tx);
        let _ = self.app.emit(
            "prompt",
            PromptEvent {
                kind,
                attempts_left,
            },
        );
        rx.recv().ok().flatten()
    }
}

impl Interaction for TauriUi {
    fn status(&self, message: &str) {
        let _ = self.app.emit("status", message);
    }

    fn request_pin(&self, attempts_left: Option<u8>) -> Option<String> {
        self.ask("pin", attempts_left)
    }
}

type CmdResult<T> = Result<T, String>;

/// Client errors for the UI. An expired or revoked session gets a fixed prefix.
fn cerr(e: strongbox_client::Error) -> String {
    match e {
        strongbox_client::Error::Api { status: 401, .. } => {
            format!("{SESSION_EXPIRED}: your session has expired; unlock the vault again")
        }
        e => e.to_string(),
    }
}

fn ui(app: &AppHandle, state: &AppState) -> Arc<TauriUi> {
    Arc::new(TauriUi {
        app: app.clone(),
        pending: state.prompt.clone(),
    })
}

fn authenticator(app: &AppHandle, state: &AppState) -> Arc<dyn Authenticator> {
    strongbox_fido::platform(ui(app, state)).into()
}

fn nonempty(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.is_empty())
}

#[tauri::command]
fn answer_prompt(state: State<'_, AppState>, value: Option<String>) {
    if let Some(tx) = state.prompt.lock().unwrap().take() {
        let _ = tx.send(value);
    }
}

#[tauri::command]
async fn vault_create_account(
    app: AppHandle,
    state: State<'_, AppState>,
    server: String,
    username: String,
    invite: Option<String>,
    label: String,
) -> CmdResult<()> {
    let client = strongbox_client::vault::create_vault_named(
        &server,
        &username,
        nonempty(invite),
        authenticator(&app, &state),
        &label,
    )
    .await
    .map_err(cerr)?;
    sign_in_account(&state, client, server, username).await;
    Ok(())
}

#[tauri::command]
async fn vault_slot_count(server: String) -> CmdResult<u32> {
    strongbox_client::vault::vault_layout(&server)
        .await
        .map(|layout| layout.slots)
        .map_err(cerr)
}

#[tauri::command]
async fn vault_sign_in(
    app: AppHandle,
    state: State<'_, AppState>,
    server: String,
    username: String,
) -> CmdResult<()> {
    let client =
        strongbox_client::vault::connect_account(&server, &username, authenticator(&app, &state))
            .await
            .map_err(cerr)?;
    sign_in_account(&state, client, server, username).await;
    Ok(())
}

#[tauri::command]
async fn vault_account_recover(
    state: State<'_, AppState>,
    server: String,
    username: String,
    code: String,
) -> CmdResult<()> {
    let client = strongbox_client::vault::connect_account_with_recovery(&server, &username, &code)
        .await
        .map_err(cerr)?;
    sign_in_account(&state, client, server, username).await;
    Ok(())
}

#[tauri::command]
async fn vault_open(
    app: AppHandle,
    state: State<'_, AppState>,
    server: String,
    username: String,
    slot: u32,
    pin: String,
    create: bool,
) -> CmdResult<()> {
    let (client, key) = strongbox_client::vault::connect(
        &server,
        &username,
        authenticator(&app, &state),
        slot,
        &pin,
    )
    .await
    .map_err(cerr)?;
    let drive = if create {
        client.create(&key).await.map_err(cerr)?
    } else {
        client
            .open(&key)
            .await
            .map_err(cerr)?
            .ok_or("No drive found for that slot and PIN")?
    };
    install_vault(&state, client, drive, server, username, slot).await;
    Ok(())
}

#[tauri::command]
async fn vault_recover(
    state: State<'_, AppState>,
    server: String,
    username: String,
    code: String,
) -> CmdResult<u32> {
    let (client, key) = strongbox_client::vault::connect_with_recovery(&server, &username, &code)
        .await
        .map_err(cerr)?;
    let slot = key.slot();
    let drive = client
        .open(&key)
        .await
        .map_err(cerr)?
        .ok_or("Recovery code did not open a drive")?;
    install_vault(&state, client, drive, server, username, slot).await;
    Ok(slot)
}

#[tauri::command]
async fn vault_add_account_key(
    app: AppHandle,
    state: State<'_, AppState>,
    label: String,
) -> CmdResult<()> {
    let client = current_vault_client(&state).await?;
    client
        .add_account_key_named(authenticator(&app, &state), &label)
        .await
        .map_err(cerr)?;
    sync_vault_clients(&state, &client).await;
    Ok(())
}

#[tauri::command]
async fn vault_add_key_to_current(
    app: AppHandle,
    state: State<'_, AppState>,
    label: String,
    pin: String,
) -> CmdResult<()> {
    let client = current_vault_client(&state).await?;
    let existing_ids: Vec<_> = client
        .member_labels()
        .into_iter()
        .map(|member| member.id)
        .collect();
    let authn = authenticator(&app, &state);
    client
        .add_account_key_named(authn.clone(), &label)
        .await
        .map_err(cerr)?;
    let member = client
        .member_labels()
        .into_iter()
        .find(|member| {
            member.kind == "security_key"
                && member.slot.is_none()
                && !existing_ids.contains(&member.id)
        })
        .ok_or("new security key was added but could not be identified")?;
    sync_vault_clients(&state, &client).await;
    let vault = current_vault(&state).await?;
    let result = vault
        .lock()
        .await
        .drive
        .grant_account_key(authn, &pin, &member.id)
        .await
        .map_err(cerr);
    result
}

#[tauri::command]
async fn vault_new_account_recovery(
    state: State<'_, AppState>,
    label: String,
) -> CmdResult<String> {
    let client = current_vault_client(&state).await?;
    let code = client
        .new_account_recovery_code_named(&label)
        .await
        .map_err(cerr)?;
    sync_vault_clients(&state, &client).await;
    Ok(code)
}

#[derive(Serialize)]
struct VaultAccessView {
    keys: Vec<VaultAccessKeyView>,
    recovery_codes: Vec<VaultAccessKeyView>,
}

#[derive(Serialize)]
struct VaultAccessKeyView {
    id: String,
    label: String,
    granted: bool,
    current: bool,
}

#[tauri::command]
async fn vault_drive_access(state: State<'_, AppState>) -> CmdResult<VaultAccessView> {
    let v = current_vault(&state).await?;
    let session = v.lock().await;
    let drive = &session.drive;
    let grants = drive.access_grants();
    let client = drive.client();
    let (_, current) = client.members().await.map_err(cerr)?;
    let members = client.member_labels();
    let keys = members
        .iter()
        .filter(|m| m.kind == "security_key" && m.slot.is_none())
        .map(|m| VaultAccessKeyView {
            id: m.id.clone(),
            label: m.label.clone(),
            granted: grants.iter().any(|g| g.member_id == m.id),
            current: m.id == current,
        })
        .collect();
    let recovery_codes = members
        .iter()
        .filter(|m| m.kind == "recovery_code" && m.slot == Some(drive.slot()))
        .map(|m| VaultAccessKeyView {
            id: m.id.clone(),
            label: m.label.clone(),
            granted: grants.iter().any(|g| g.member_id == m.id),
            current: m.id == current,
        })
        .collect();
    Ok(VaultAccessView {
        keys,
        recovery_codes,
    })
}

#[tauri::command]
async fn vault_grant_key(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    pin: String,
) -> CmdResult<()> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    session
        .drive
        .grant_account_key(authenticator(&app, &state), &pin, &id)
        .await
        .map_err(cerr)
}

#[tauri::command]
async fn vault_revoke_key(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    session.drive.revoke_account_key(&id).await.map_err(cerr)
}

#[tauri::command]
async fn vault_revoke_recovery(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    let client = session.drive.client().clone();
    session
        .drive
        .revoke_recovery_code(&id)
        .await
        .map_err(cerr)?;
    drop(session);
    sync_vault_clients(&state, &client).await;
    Ok(())
}

#[tauri::command]
async fn vault_new_recovery(state: State<'_, AppState>, label: String) -> CmdResult<String> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    let client = session.drive.client().clone();
    let code = session
        .drive
        .new_recovery_code_named(&label)
        .await
        .map_err(cerr)?;
    drop(session);
    sync_vault_clients(&state, &client).await;
    Ok(code)
}

#[tauri::command]
async fn vault_members(state: State<'_, AppState>) -> CmdResult<VaultMembersView> {
    let client = current_vault_client(&state).await?;
    let (_, current) = client.members().await.map_err(cerr)?;
    let members = client
        .member_labels()
        .into_iter()
        .map(|m| {
            let is_current = m.id == current;
            VaultMemberView {
                id: m.id,
                label: m.label,
                kind: m.kind,
                slot: m.slot,
                current: is_current,
            }
        })
        .collect();
    Ok(VaultMembersView { members })
}

#[derive(Serialize)]
struct VaultMembersView {
    members: Vec<VaultMemberView>,
}

#[derive(Serialize)]
struct VaultMemberView {
    id: String,
    label: String,
    kind: String,
    slot: Option<u32>,
    current: bool,
}

/// A free name to prefill a key or recovery-code name prompt: `base`, else `base 2`, `base 3`...
/// With `replaces_vault_recovery`, this vault's current recovery code does not count (a new
/// one replaces it).
#[tauri::command]
async fn vault_suggest_label(
    state: State<'_, AppState>,
    base: String,
    replaces_vault_recovery: bool,
) -> CmdResult<String> {
    let client = current_vault_client(&state).await?;
    let ignore = if replaces_vault_recovery {
        let v = current_vault(&state).await?;
        let session = v.lock().await;
        session.drive.recovery_ids()
    } else {
        Vec::new()
    };
    Ok(client.suggest_label(&base, &ignore))
}

#[tauri::command]
async fn vault_rename_member(
    state: State<'_, AppState>,
    id: String,
    label: String,
) -> CmdResult<()> {
    let client = current_vault_client(&state).await?;
    client.rename_member(&id, &label).await.map_err(cerr)?;
    sync_vault_clients(&state, &client).await;
    Ok(())
}

/// Returns how many other keys lost access to the vault (they used the old PIN).
#[tauri::command]
async fn vault_change_pin(
    app: AppHandle,
    state: State<'_, AppState>,
    new_pin: String,
) -> CmdResult<usize> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    session
        .drive
        .change_pin(authenticator(&app, &state), &new_pin)
        .await
        .map_err(cerr)
}

#[tauri::command]
async fn vault_remove_member(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let client = current_vault_client(&state).await?;
    client.remove_member(&id).await.map_err(cerr)?;
    sync_vault_clients(&state, &client).await;
    Ok(())
}

async fn current_vault(state: &AppState) -> Result<Arc<AsyncMutex<VaultSession>>, String> {
    let active = state
        .active_vault
        .read()
        .await
        .clone()
        .ok_or_else(|| "no vault unlocked".to_string())?;
    state
        .vaults
        .read()
        .await
        .get(&active)
        .map(|item| item.session.clone())
        .ok_or_else(|| "no vault unlocked".to_string())
}

async fn current_vault_client(
    state: &AppState,
) -> Result<strongbox_client::vault::VaultClient, String> {
    if let Some(active) = state.active_vault.read().await.clone() {
        if let Some(item) = state.vaults.read().await.get(&active) {
            return Ok(item.client.clone());
        }
    }
    state
        .vault_account
        .read()
        .await
        .as_ref()
        .map(|account| account.client.clone())
        .ok_or_else(|| "locked".to_string())
}

async fn sync_vault_clients(state: &AppState, source: &strongbox_client::vault::VaultClient) {
    let mut clients: Vec<_> = state
        .vaults
        .read()
        .await
        .values()
        .map(|item| item.client.clone())
        .collect();
    if let Some(account) = state.vault_account.read().await.as_ref() {
        clients.push(account.client.clone());
    }
    for client in clients {
        client.sync_account_record_from(source);
    }
}

#[derive(Serialize)]
struct VaultTab {
    id: String,
    slot: u32,
    active: bool,
}

#[tauri::command]
async fn vault_tabs(state: State<'_, AppState>) -> CmdResult<Vec<VaultTab>> {
    let active = state.active_vault.read().await.clone();
    let mut tabs: Vec<_> = state
        .vaults
        .read()
        .await
        .iter()
        .map(|(id, item)| VaultTab {
            id: id.clone(),
            slot: item.slot,
            active: active.as_ref() == Some(id),
        })
        .collect();
    tabs.sort_by_key(|tab| tab.id.clone());
    Ok(tabs)
}

#[tauri::command]
async fn vault_select(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    if !state.vaults.read().await.contains_key(&id) {
        return Err("vault is locked".into());
    }
    *state.active_vault.write().await = Some(id);
    Ok(())
}

#[tauri::command]
async fn vault_lock(state: State<'_, AppState>, id: String) -> CmdResult<bool> {
    let item = state
        .vaults
        .write()
        .await
        .remove(&id)
        .ok_or("vault is already locked")?;
    item.wipe.wipe();
    let remaining = {
        let vaults = state.vaults.read().await;
        if vaults.is_empty() {
            None
        } else {
            vaults.keys().next().cloned()
        }
    };
    let mut active = state.active_vault.write().await;
    if active.as_deref() == Some(&id) {
        *active = remaining.clone();
    }
    drop(active);
    let _ =
        tokio::time::timeout(std::time::Duration::from_secs(5), item.client.end_session()).await;
    Ok(remaining.is_some() || state.vault_account.read().await.is_some())
}

/// Stop everything using the keys, then wipe every open vault's keys and take the sessions out
/// of the app state. Returns the clients so the caller can end their server sessions.
async fn wipe_vault(state: &AppState) -> Vec<strongbox_client::vault::VaultClient> {
    state.transfers.cancel(None);
    // Unblock an authenticator thread waiting for a PIN from the UI.
    if let Some(tx) = state
        .prompt
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        let _ = tx.send(None);
    }
    *state.active_vault.write().await = None;
    let vaults = std::mem::take(&mut *state.vaults.write().await);
    let mut clients = Vec::with_capacity(vaults.len());
    for (_, item) in vaults {
        item.wipe.wipe();
        clients.push(item.client);
    }
    if let Some(account) = state.vault_account.write().await.take() {
        clients.push(account.client);
    }
    clients
}

/// Forget the keys. Always succeeds locally: a failed server logout (offline, session already
/// expired) must not leave a vault unlocked.
#[tauri::command]
async fn lock(state: State<'_, AppState>) -> CmdResult<()> {
    for client in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), client.end_session()).await;
    }
    Ok(())
}

/// Panic key: wipe all keys immediately and return. The server logout runs in the
/// background with a short timeout, so the wipe never waits on the network.
#[tauri::command]
async fn panic_lock(state: State<'_, AppState>) -> CmdResult<()> {
    for client in wipe_vault(&state).await {
        tauri::async_runtime::spawn(async move {
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(5), client.end_session()).await;
        });
    }
    Ok(())
}

/// Log out: wipe the keys and end the server sessions, so the app returns to the sign-in screen.
#[tauri::command]
async fn logout(state: State<'_, AppState>) -> CmdResult<()> {
    for client in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), client.end_session()).await;
    }
    Ok(())
}

/// Delete the account for good: the server removes the lookup record, members and every drive,
/// then the local keys are wiped. This signs in again first (so it needs a fresh key touch), and
/// the server call must succeed before anything local is wiped, so a failure (offline, wrong key)
/// leaves everything as it was.
#[tauri::command]
async fn delete_account(
    app: AppHandle,
    state: State<'_, AppState>,
    server: String,
    username: String,
) -> CmdResult<()> {
    let client =
        strongbox_client::vault::connect_account(&server, &username, authenticator(&app, &state))
            .await
            .map_err(cerr)?;
    client.delete_account().await.map_err(cerr)?;
    for client in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), client.end_session()).await;
    }
    Ok(())
}

#[tauri::command]
async fn list(state: State<'_, AppState>, path: String) -> CmdResult<Vec<ListEntry>> {
    let v = current_vault(&state).await?;
    let session = v.lock().await;
    session.drive.list(&path).map_err(cerr)
}

#[tauri::command]
async fn search(state: State<'_, AppState>, query: String) -> CmdResult<Vec<SearchHit>> {
    let v = current_vault(&state).await?;
    let session = v.lock().await;
    Ok(strongbox_client::vault::search_in(
        session.drive.tree(),
        &query,
    ))
}

#[tauri::command]
async fn mkdir(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    session.drive.mkdir(&path).await.map_err(cerr)
}

fn join_remote(dir: &str, name: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

/// Expand dropped/picked local paths into folders to create and files to upload (with their
/// remote directory). Symlinks are skipped so a link loop cannot recurse forever.
fn expand_local(paths: &[String], dir: &str) -> (Vec<String>, Vec<(PathBuf, String)>, Vec<String>) {
    let (mut dirs, mut files, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
    let mut stack: Vec<(PathBuf, String)> = paths
        .iter()
        .map(|p| (PathBuf::from(p), dir.to_string()))
        .collect();
    stack.reverse();
    while let Some((path, remote_dir)) = stack.pop() {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_file() => files.push((path, remote_dir)),
            Ok(m) if m.is_dir() => {
                let remote = join_remote(&remote_dir, &name);
                dirs.push(remote.clone());
                let mut children: Vec<PathBuf> = std::fs::read_dir(&path)
                    .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect())
                    .unwrap_or_default();
                children.sort();
                stack.extend(children.into_iter().rev().map(|c| (c, remote.clone())));
            }
            _ => skipped.push(name),
        }
    }
    (dirs, files, skipped)
}

#[derive(Serialize)]
struct TransferSummary {
    done: usize,
    failed: usize,
    cancelled: usize,
    skipped: Vec<String>,
}

/// Upload files and folders (recursively) into `dir`. Each file is its own transfer with
/// progress events and can be cancelled; one failure does not stop the rest.
#[tauri::command]
async fn upload(
    app: AppHandle,
    state: State<'_, AppState>,
    paths: Vec<String>,
    dir: String,
    conflict: OnConflict,
) -> CmdResult<TransferSummary> {
    let v = current_vault(&state).await?;
    let (dirs, files, skipped) = expand_local(&paths, &dir);
    let mut session = v.lock().await;
    // Folders and files are committed in batches (one metadata write per batch, not per file);
    // a file is reported done once the batch holding it is committed.
    let mut staged = session.drive.stage();
    for remote in dirs {
        session
            .drive
            .mkdir_p_staged(&mut staged, &remote)
            .map_err(cerr)?;
    }
    let mut waiting = Vec::new();
    let mut summary = TransferSummary {
        done: 0,
        failed: 0,
        cancelled: 0,
        skipped,
    };
    for (path, remote_dir) in files {
        let total = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let (id, flag) = state.transfers.start();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut ev = TransferEvent {
            id,
            kind: "upload",
            name,
            target: remote_dir.clone(),
            done: 0,
            total,
            state: "active",
            error: None,
        };
        let _ = app.emit("transfer", ev.clone());
        let progress = {
            let (app, ev) = (app.clone(), ev.clone());
            move |done, total| {
                let _ = app.emit(
                    "transfer",
                    TransferEvent {
                        done,
                        total,
                        ..ev.clone()
                    },
                );
            }
        };
        let opts = TransferOptions {
            progress: Some(&progress),
            cancel: Some(&flag),
            on_conflict: conflict,
        };
        let res = session
            .drive
            .upload_staged(&mut staged, &path, &remote_dir, opts)
            .await
            .map_err(cerr);
        state.transfers.finish(id);
        match res {
            Ok(stored) => {
                ev.name = stored;
                waiting.push(ev);
            }
            Err(e) if flag.load(Ordering::Relaxed) => {
                summary.cancelled += 1;
                ev.state = "cancelled";
                ev.error = Some(e);
                let _ = app.emit("transfer", ev);
            }
            Err(e) => {
                summary.failed += 1;
                ev.state = "error";
                ev.error = Some(e);
                let _ = app.emit("transfer", ev);
            }
        }
        if session.drive.staged_due(&staged) {
            commit_uploads(
                &app,
                &mut session.drive,
                &mut staged,
                &mut waiting,
                &mut summary,
            )
            .await?;
        }
    }
    commit_uploads(
        &app,
        &mut session.drive,
        &mut staged,
        &mut waiting,
        &mut summary,
    )
    .await?;
    Ok(summary)
}

/// Commit a batch of uploads and report its files done (or failed, with the commit's error).
/// The error is returned only if no file was waiting to carry it (a batch of new folders).
async fn commit_uploads(
    app: &AppHandle,
    drive: &mut strongbox_client::vault::VaultDrive,
    staged: &mut strongbox_client::vault::Staged,
    waiting: &mut Vec<TransferEvent>,
    summary: &mut TransferSummary,
) -> CmdResult<()> {
    let res = drive.commit_staged(staged).await.map_err(cerr);
    if waiting.is_empty() {
        return res;
    }
    for mut ev in waiting.drain(..) {
        match &res {
            Ok(()) => {
                summary.done += 1;
                ev.state = "done";
            }
            Err(e) => {
                summary.failed += 1;
                ev.state = "error";
                ev.error = Some(e.clone());
            }
        }
        let _ = app.emit("transfer", ev);
    }
    Ok(())
}

#[derive(Deserialize)]
struct RemoteItem {
    path: String,
    is_dir: bool,
}

/// Download one file to an exact local path (from a save dialog), or several files/folders
/// into a local folder (`dest_dir`), never overwriting what is already there.
#[tauri::command]
async fn download(
    app: AppHandle,
    state: State<'_, AppState>,
    items: Vec<RemoteItem>,
    dest: Option<String>,
    dest_dir: Option<String>,
) -> CmdResult<TransferSummary> {
    let v = current_vault(&state).await?;
    let session = v.lock().await;
    let mut summary = TransferSummary {
        done: 0,
        failed: 0,
        cancelled: 0,
        skipped: vec![],
    };
    for item in items {
        let name = item.path.rsplit('/').next().unwrap_or_default().to_string();
        let target = match (&dest, &dest_dir) {
            (Some(dest), _) => PathBuf::from(dest),
            (None, Some(dir)) if item.is_dir => PathBuf::from(dir),
            (None, Some(dir)) => unique_local_path(Path::new(dir).join(local_safe_name(&name))),
            (None, None) => return Err("no download destination".into()),
        };
        let (id, flag) = state.transfers.start();
        let mut ev = TransferEvent {
            id,
            kind: "download",
            name,
            target: target.display().to_string(),
            done: 0,
            total: 0,
            state: "active",
            error: None,
        };
        let _ = app.emit("transfer", ev.clone());
        let progress = {
            let (app, ev) = (app.clone(), ev.clone());
            move |done, total| {
                let _ = app.emit(
                    "transfer",
                    TransferEvent {
                        done,
                        total,
                        ..ev.clone()
                    },
                );
            }
        };
        let opts = TransferOptions {
            progress: Some(&progress),
            cancel: Some(&flag),
            ..Default::default()
        };
        let res = if item.is_dir {
            session
                .drive
                .download_dir(&item.path, &target, opts)
                .await
                .map(|p| p.display().to_string())
        } else {
            session
                .drive
                .download(&item.path, &target, opts)
                .await
                .map(|()| target.display().to_string())
        }
        .map_err(cerr);
        state.transfers.finish(id);
        match res {
            Ok(saved) => {
                summary.done += 1;
                ev.target = saved;
                ev.state = "done";
            }
            Err(e) if flag.load(Ordering::Relaxed) => {
                summary.cancelled += 1;
                ev.error = Some(e);
                ev.state = "cancelled";
            }
            Err(e) => {
                summary.failed += 1;
                ev.error = Some(e);
                ev.state = "error";
            }
        }
        let _ = app.emit("transfer", ev);
    }
    Ok(summary)
}

/// Cancel one transfer, or all of them when `id` is omitted.
#[tauri::command]
fn cancel_transfer(state: State<'_, AppState>, id: Option<u64>) {
    state.transfers.cancel(id);
}

/// Decrypt a file into memory for the preview pane. Raw bytes, no base64 round trip.
#[tauri::command]
async fn preview(state: State<'_, AppState>, path: String) -> CmdResult<Response> {
    let v = current_vault(&state).await?;
    let session = v.lock().await;
    session
        .drive
        .read_file(&path, MAX_PREVIEW_BYTES)
        .await
        .map(Response::new)
        .map_err(cerr)
}

/// Delete a file or folder permanently (vaults have no trash).
#[tauri::command]
async fn remove(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    session.drive.remove(&path).await.map_err(cerr)
}

/// Whether anything is unlocked (the UI asks after a reload).
#[tauri::command]
async fn is_unlocked(state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(state.vault_account.read().await.is_some() || !state.vaults.read().await.is_empty())
}

#[tauri::command]
async fn rename(state: State<'_, AppState>, from: String, to: String) -> CmdResult<()> {
    let v = current_vault(&state).await?;
    let mut session = v.lock().await;
    session.drive.rename(&from, &to).await.map_err(cerr)
}

#[derive(Serialize)]
struct AccountView {
    username: String,
    server: String,
    used_bytes: u64,
    quota_bytes: Option<u64>,
}

#[tauri::command]
async fn account(state: State<'_, AppState>) -> CmdResult<AccountView> {
    if let Ok(v) = current_vault(&state).await {
        let v = v.lock().await;
        let (used_bytes, quota_bytes) = v.drive.usage();
        return Ok(AccountView {
            username: v.username.clone(),
            server: v.server.clone(),
            used_bytes,
            quota_bytes: Some(quota_bytes),
        });
    }
    let guard = state.vault_account.read().await;
    let account = guard.as_ref().ok_or("locked")?;
    Ok(AccountView {
        username: account.username.clone(),
        server: account.server.clone(),
        used_bytes: 0,
        quota_bytes: None,
    })
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            answer_prompt,
            vault_create_account,
            vault_sign_in,
            vault_account_recover,
            vault_slot_count,
            vault_open,
            vault_recover,
            vault_add_account_key,
            vault_add_key_to_current,
            vault_new_account_recovery,
            vault_drive_access,
            vault_grant_key,
            vault_revoke_key,
            vault_revoke_recovery,
            vault_new_recovery,
            vault_members,
            vault_rename_member,
            vault_suggest_label,
            vault_change_pin,
            vault_remove_member,
            vault_tabs,
            vault_select,
            vault_lock,
            lock,
            panic_lock,
            logout,
            delete_account,
            is_unlocked,
            list,
            search,
            mkdir,
            upload,
            download,
            cancel_transfer,
            preview,
            remove,
            rename,
            account,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Strongbox")
        .run(|app, event| {
            // The process ends with std::process::exit right after this event, which skips
            // destructors, so wipe the keys explicitly (and end the server session) here.
            if let RunEvent::Exit = event {
                let state = app.state::<AppState>();
                tauri::async_runtime::block_on(async {
                    for client in wipe_vault(&state).await {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            client.end_session(),
                        )
                        .await;
                    }
                });
            }
        });
}
