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
    local_safe_name, unique_local_path, Drive, ListEntry, OnConflict, Profile, RegisterOptions,
    SearchHit, TransferOptions, TrashEntry, Ui,
};
use strongbox_core::keyslot::KeyslotKind;
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
    /// Shared so that lock / panic can take the drive out (and wipe its keys) at once, without
    /// waiting for running operations, which hold their own clone until they stop.
    drive: RwLock<Option<Arc<Drive>>>,
    /// Open deniable vaults, with one selected for file operations.
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

impl Ui for TauriUi {
    fn request_password(&self) -> Option<String> {
        self.ask("password", None)
    }
}

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// Client errors for the UI. An expired or revoked session gets a fixed prefix.
fn cerr(e: strongbox_client::Error) -> String {
    match e {
        strongbox_client::Error::Api { status: 401, .. } => {
            format!("{SESSION_EXPIRED}: your session has expired; unlock the drive again")
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

macro_rules! with_drive {
    ($state:expr, $d:ident => $body:expr) => {{
        let $d = current(&$state).await?;
        let $d = &*$d;
        $body.await.map_err(cerr)
    }};
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
fn get_profile() -> CmdResult<Option<Profile>> {
    Profile::load().map_err(err)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
async fn register(
    app: AppHandle,
    state: State<'_, AppState>,
    server: String,
    username: String,
    invite: Option<String>,
    label: String,
    password: Option<String>,
    recovery: bool,
) -> CmdResult<Option<String>> {
    let opts = RegisterOptions {
        server_url: server,
        username,
        invite: nonempty(invite),
        key_label: label,
        password: nonempty(password),
        recovery_code: recovery,
        rp_id: None,
    };
    let (drive, code) = strongbox_client::register(opts, authenticator(&app, &state))
        .await
        .map_err(cerr)?;
    *state.drive.write().await = Some(Arc::new(drive));
    Ok(code)
}

/// Sign in to an existing account from this device (no local profile needed).
#[tauri::command]
async fn sign_in(
    app: AppHandle,
    state: State<'_, AppState>,
    server: String,
    username: String,
) -> CmdResult<()> {
    let drive = strongbox_client::sign_in(
        &server,
        &username,
        None,
        authenticator(&app, &state),
        ui(&app, &state),
    )
    .await
    .map_err(cerr)?;
    *state.drive.write().await = Some(Arc::new(drive));
    Ok(())
}

#[tauri::command]
async fn sign_in_with_recovery(
    state: State<'_, AppState>,
    server: String,
    username: String,
    code: String,
) -> CmdResult<()> {
    let drive = strongbox_client::sign_in_with_recovery(&server, &username, &code)
        .await
        .map_err(cerr)?;
    *state.drive.write().await = Some(Arc::new(drive));
    Ok(())
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
    if let Some(drive) = wipe_now(&state).await {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), drive.end_session()).await;
    }
    for previous in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), previous.end_session()).await;
    }
    *state.vault_account.write().await = Some(VaultAccount {
        client,
        server,
        username,
    });
    let _ = Profile::forget();
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
    if let Some(drive) = wipe_now(&state).await {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), drive.end_session()).await;
    }
    for previous in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), previous.end_session()).await;
    }
    *state.vault_account.write().await = Some(VaultAccount {
        client,
        server,
        username,
    });
    let _ = Profile::forget();
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
    if let Some(drive) = wipe_now(&state).await {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), drive.end_session()).await;
    }
    for previous in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), previous.end_session()).await;
    }
    *state.vault_account.write().await = Some(VaultAccount {
        client,
        server,
        username,
    });
    let _ = Profile::forget();
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
    *state.drive.write().await = None;
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
    *state.drive.write().await = None;
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
        .ok_or_else(|| "locked".to_string())?;
    state
        .vaults
        .read()
        .await
        .get(&active)
        .map(|item| item.session.clone())
        .ok_or_else(|| "locked".to_string())
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

#[tauri::command]
async fn unlock(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    let profile = Profile::load()
        .map_err(err)?
        .ok_or("no account configured")?;
    let drive = strongbox_client::login(profile, authenticator(&app, &state), ui(&app, &state))
        .await
        .map_err(cerr)?;
    *state.drive.write().await = Some(Arc::new(drive));
    Ok(())
}

#[tauri::command]
async fn unlock_with_recovery(state: State<'_, AppState>, code: String) -> CmdResult<()> {
    let profile = Profile::load()
        .map_err(err)?
        .ok_or("no account configured")?;
    let drive = strongbox_client::login_with_recovery(profile, &code)
        .await
        .map_err(cerr)?;
    *state.drive.write().await = Some(Arc::new(drive));
    Ok(())
}

/// The unlocked drive, cloned out so the state lock is never held during an operation.
async fn current(state: &AppState) -> Result<Arc<Drive>, String> {
    state
        .drive
        .read()
        .await
        .clone()
        .ok_or_else(|| "locked".to_string())
}

/// Take the drive out of the app state, stop everything using it and wipe its keys. Returns
/// it so the caller can end the server session.
async fn wipe_now(state: &AppState) -> Option<Arc<Drive>> {
    state.transfers.cancel(None);
    // Unblock an authenticator thread waiting for a PIN/password from the UI.
    if let Some(tx) = state
        .prompt
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
    {
        let _ = tx.send(None);
    }
    let drive = state.drive.write().await.take()?;
    drive.wipe();
    Some(drive)
}

async fn wipe_vault(state: &AppState) -> Vec<strongbox_client::vault::VaultClient> {
    state.transfers.cancel(None);
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
/// expired) must not leave the drive unlocked.
#[tauri::command]
async fn lock(state: State<'_, AppState>) -> CmdResult<()> {
    if let Some(drive) = wipe_now(&state).await {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), drive.end_session()).await;
    }
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
    if let Some(drive) = wipe_now(&state).await {
        tauri::async_runtime::spawn(async move {
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(5), drive.end_session()).await;
        });
    }
    for client in wipe_vault(&state).await {
        tauri::async_runtime::spawn(async move {
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(5), client.end_session()).await;
        });
    }
    // Also forget the cached account so the next screen is the plain sign-in, not the
    // "welcome back, <name>" lock screen.
    Profile::forget().map_err(err)
}

/// Log out: wipe the keys, end the server session and remove the cached account from this
/// device, so the app returns to the sign-in screen.
#[tauri::command]
async fn logout(state: State<'_, AppState>) -> CmdResult<()> {
    if let Some(drive) = wipe_now(&state).await {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), drive.end_session()).await;
    }
    for client in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), client.end_session()).await;
    }
    Profile::forget().map_err(err)
}

/// Delete the account for good: the server removes the keyslots, files and username, then the
/// local keys and cached profile are wiped. The server call must succeed first, so a failure
/// (offline, expired session) leaves everything as it was.
#[tauri::command]
async fn delete_account(
    app: AppHandle,
    state: State<'_, AppState>,
    server: String,
    username: String,
) -> CmdResult<()> {
    let has_vault_account =
        state.vault_account.read().await.is_some() || !state.vaults.read().await.is_empty();
    if has_vault_account {
        let client = strongbox_client::vault::connect_account(
            &server,
            &username,
            authenticator(&app, &state),
        )
        .await
        .map_err(cerr)?;
        client.delete_account().await.map_err(cerr)?;
    } else {
        let drive = strongbox_client::sign_in(
            &server,
            &username,
            None,
            authenticator(&app, &state),
            ui(&app, &state),
        )
        .await
        .map_err(cerr)?;
        drive.delete_account().await.map_err(cerr)?;
    }
    if let Some(drive) = wipe_now(&state).await {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), drive.end_session()).await;
    }
    for client in wipe_vault(&state).await {
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(10), client.end_session()).await;
    }
    Profile::forget().map_err(err)
}

#[tauri::command]
async fn list(state: State<'_, AppState>, path: String) -> CmdResult<Vec<ListEntry>> {
    if let Ok(v) = current_vault(&state).await {
        return v.lock().await.drive.list(&path).map_err(cerr);
    }
    with_drive!(state, d => d.list(&path))
}

#[tauri::command]
async fn search(state: State<'_, AppState>, query: String) -> CmdResult<Vec<SearchHit>> {
    if let Ok(v) = current_vault(&state).await {
        let session = v.lock().await;
        return Ok(strongbox_client::vault::search_in(
            session.drive.tree(),
            &query,
        ));
    }
    with_drive!(state, d => d.search(&query))
}

#[tauri::command]
async fn mkdir(state: State<'_, AppState>, path: String) -> CmdResult<()> {
    if let Ok(v) = current_vault(&state).await {
        return v.lock().await.drive.mkdir(&path).await.map_err(cerr);
    }
    with_drive!(state, d => d.mkdir(&path))
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
    if let Ok(v) = current_vault(&state).await {
        let (dirs, files, skipped) = expand_local(&paths, &dir);
        let mut session = v.lock().await;
        for remote in dirs {
            session.drive.mkdir_p(&remote).await.map_err(cerr)?;
        }
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
                .upload(&path, &remote_dir, opts)
                .await
                .map_err(cerr);
            state.transfers.finish(id);
            match res {
                Ok(stored) => {
                    summary.done += 1;
                    ev.name = stored;
                    ev.state = "done";
                }
                Err(e) if flag.load(Ordering::Relaxed) => {
                    summary.cancelled += 1;
                    ev.state = "cancelled";
                    ev.error = Some(e);
                }
                Err(e) => {
                    summary.failed += 1;
                    ev.state = "error";
                    ev.error = Some(e);
                }
            }
            let _ = app.emit("transfer", ev);
        }
        return Ok(summary);
    }
    let d = current(&state).await?;
    let (dirs, files, skipped) = expand_local(&paths, &dir);

    let jobs: Vec<_> = files
        .into_iter()
        .map(|(path, remote_dir)| {
            let (id, flag) = state.transfers.start();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let total = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let ev = TransferEvent {
                id,
                kind: "upload",
                name,
                target: remote_dir.clone(),
                done: 0,
                total,
                state: "queued",
                error: None,
            };
            let _ = app.emit("transfer", ev.clone());
            (path, remote_dir, flag, ev)
        })
        .collect();

    let mut summary = TransferSummary {
        done: 0,
        failed: 0,
        cancelled: 0,
        skipped,
    };
    let mut dir_error = None;
    for remote in &dirs {
        if let Err(e) = d.mkdir_p(remote).await {
            dir_error = Some(cerr(e));
            break;
        }
    }

    for (path, remote_dir, flag, mut ev) in jobs {
        let result = if let Some(e) = &dir_error {
            Err(e.clone())
        } else if flag.load(Ordering::Relaxed) {
            Err(strongbox_client::Error::Cancelled.to_string())
        } else {
            ev.state = "active";
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
            d.upload_with(&path, &remote_dir, opts).await.map_err(cerr)
        };
        state.transfers.finish(ev.id);
        ev.done = ev.total;
        match result {
            Ok(stored) => {
                summary.done += 1;
                ev.state = "done";
                ev.name = stored;
            }
            Err(e) if flag.load(Ordering::Relaxed) => {
                summary.cancelled += 1;
                ev.state = "cancelled";
                ev.error = Some(e);
            }
            Err(e) => {
                summary.failed += 1;
                ev.state = "error";
                ev.error = Some(e);
            }
        }
        let _ = app.emit("transfer", ev);
    }
    if summary.done == 0 && summary.failed == 0 && summary.cancelled == 0 {
        if let Some(e) = dir_error {
            return Err(e);
        }
    }
    Ok(summary)
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
    if let Ok(v) = current_vault(&state).await {
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
        return Ok(summary);
    }
    let d = current(&state).await?;
    let mut summary = TransferSummary {
        done: 0,
        failed: 0,
        cancelled: 0,
        skipped: vec![],
    };
    for item in items {
        let name = item.path.rsplit('/').next().unwrap_or_default().to_string();
        let (id, flag) = state.transfers.start();
        let target = match (&dest, &dest_dir) {
            (Some(dest), _) => PathBuf::from(dest),
            (None, Some(dir)) if item.is_dir => PathBuf::from(dir),
            (None, Some(dir)) => unique_local_path(Path::new(dir).join(local_safe_name(&name))),
            (None, None) => return Err("no download destination".into()),
        };
        let mut ev = TransferEvent {
            id,
            kind: "download",
            name: name.clone(),
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
        let result = if item.is_dir {
            d.download_dir(&item.path, &target, opts)
                .await
                .map(|p| p.display().to_string())
        } else {
            d.download_with(&item.path, &target, opts)
                .await
                .map(|()| target.display().to_string())
        };
        state.transfers.finish(id);
        match result {
            Ok(saved) => {
                summary.done += 1;
                ev.state = "done";
                ev.target = saved;
            }
            Err(e) if flag.load(Ordering::Relaxed) => {
                summary.cancelled += 1;
                ev.state = "cancelled";
                ev.error = Some(cerr(e));
            }
            Err(e) => {
                summary.failed += 1;
                ev.state = "error";
                ev.error = Some(cerr(e));
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
    if let Ok(v) = current_vault(&state).await {
        return v
            .lock()
            .await
            .drive
            .read_file(&path, MAX_PREVIEW_BYTES)
            .await
            .map(Response::new)
            .map_err(cerr);
    }
    let bytes = with_drive!(state, d => d.read_file(&path, MAX_PREVIEW_BYTES))?;
    Ok(Response::new(bytes))
}

/// Move to the trash (returns the trash id, for undo), or delete permanently.
#[tauri::command]
async fn remove(
    state: State<'_, AppState>,
    path: String,
    permanent: bool,
) -> CmdResult<Option<String>> {
    if let Ok(v) = current_vault(&state).await {
        v.lock().await.drive.remove(&path).await.map_err(cerr)?;
        return Ok(None);
    }
    if permanent {
        with_drive!(state, d => d.remove(&path)).map(|()| None)
    } else {
        with_drive!(state, d => d.trash(&path)).map(Some)
    }
}

/// Whether the drive is unlocked (the UI asks after a reload).
#[tauri::command]
async fn is_unlocked(state: State<'_, AppState>) -> CmdResult<bool> {
    Ok(state.drive.read().await.is_some()
        || state.vault_account.read().await.is_some()
        || !state.vaults.read().await.is_empty())
}

#[tauri::command]
async fn session_kind(state: State<'_, AppState>) -> CmdResult<&'static str> {
    Ok(
        if state.vault_account.read().await.is_some() || !state.vaults.read().await.is_empty() {
            "vault"
        } else {
            "account"
        },
    )
}

#[tauri::command]
async fn rename(state: State<'_, AppState>, from: String, to: String) -> CmdResult<()> {
    if let Ok(v) = current_vault(&state).await {
        return v.lock().await.drive.rename(&from, &to).await.map_err(cerr);
    }
    with_drive!(state, d => d.rename(&from, &to))
}

#[tauri::command]
async fn trash_list(state: State<'_, AppState>) -> CmdResult<Vec<TrashEntry>> {
    with_drive!(state, d => d.list_trash())
}

#[tauri::command]
async fn trash_restore(state: State<'_, AppState>, id: String) -> CmdResult<String> {
    with_drive!(state, d => d.restore(&id))
}

#[tauri::command]
async fn trash_delete(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    with_drive!(state, d => d.delete_from_trash(&id))
}

#[tauri::command]
async fn trash_empty(state: State<'_, AppState>) -> CmdResult<usize> {
    with_drive!(state, d => d.empty_trash())
}

#[derive(Serialize)]
struct KeyslotView {
    id: String,
    label: String,
    kind: &'static str,
}

#[tauri::command]
async fn keyslots(state: State<'_, AppState>) -> CmdResult<Vec<KeyslotView>> {
    let slots = with_drive!(state, d => d.keyslots())?;
    Ok(slots
        .into_iter()
        .map(|s| KeyslotView {
            id: s.id.to_string(),
            label: s.label,
            kind: match s.kind {
                KeyslotKind::Fido {
                    password: Some(_), ..
                } => "key+password",
                KeyslotKind::Fido { .. } => "key",
                KeyslotKind::Recovery => "recovery",
            },
        })
        .collect())
}

#[tauri::command]
async fn add_security_key(
    app: AppHandle,
    state: State<'_, AppState>,
    label: String,
    password: Option<String>,
) -> CmdResult<()> {
    let authn = authenticator(&app, &state);
    with_drive!(state, d => d.add_security_key(authn, label, nonempty(password)))?;
    Ok(())
}

#[tauri::command]
async fn add_recovery_code(state: State<'_, AppState>) -> CmdResult<String> {
    with_drive!(state, d => d.add_recovery_code())
}

#[tauri::command]
async fn remove_keyslot(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let id = id.parse().map_err(err)?;
    with_drive!(state, d => d.remove_keyslot(&id))
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
    if let Some(account) = state.vault_account.read().await.as_ref() {
        return Ok(AccountView {
            username: account.username.clone(),
            server: account.server.clone(),
            used_bytes: 0,
            quota_bytes: None,
        });
    }
    let d = current(&state).await?;
    let u = d.usage().await.map_err(cerr)?;
    Ok(AccountView {
        username: d.profile().username.clone(),
        server: d.profile().server_url.clone(),
        used_bytes: u.used_bytes,
        quota_bytes: u.quota_bytes,
    })
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            answer_prompt,
            get_profile,
            register,
            sign_in,
            sign_in_with_recovery,
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
            vault_remove_member,
            vault_tabs,
            vault_select,
            vault_lock,
            unlock,
            unlock_with_recovery,
            lock,
            panic_lock,
            logout,
            delete_account,
            is_unlocked,
            session_kind,
            list,
            search,
            mkdir,
            upload,
            download,
            cancel_transfer,
            preview,
            remove,
            rename,
            trash_list,
            trash_restore,
            trash_delete,
            trash_empty,
            keyslots,
            add_security_key,
            add_recovery_code,
            remove_keyslot,
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
                    if let Some(drive) = wipe_now(&state).await {
                        let _ = tokio::time::timeout(
                            std::time::Duration::from_secs(3),
                            drive.end_session(),
                        )
                        .await;
                    }
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
