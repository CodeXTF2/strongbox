// Stands in for the desktop app's Rust process (apps/desktop/src/main.rs): the same commands
// and events, exposed as `window.__TAURI__`, so app.js runs unchanged in spirit. Every key and
// every byte of crypto stays in this page (client.js); the server that hosts the page only
// serves these static files and is never sent anything.

import * as vault from "./client.js";
import { webAuthenticator, softAuthenticator, rpIdFor } from "./authn.js";

const MAX_PREVIEW_BYTES = 256 * 1024 * 1024;
const SESSION_EXPIRED = "SESSION_EXPIRED";

// ---------------------------------------------------------------- events

const listeners = new Map();
function emit(name, payload) {
  for (const cb of listeners.get(name) ?? []) cb({ payload });
}
function listen(name, cb) {
  if (!listeners.has(name)) listeners.set(name, new Set());
  listeners.get(name).add(cb);
  return Promise.resolve(() => listeners.get(name).delete(cb));
}

// ---------------------------------------------------------------- state

/** One open drive at a time per vault: operations queue like the desktop's async mutex. */
class Mutex {
  #tail = Promise.resolve();
  run(fn) {
    const result = this.#tail.then(fn);
    this.#tail = result.catch(() => {});
    return result;
  }
}

const state = {
  vaults: new Map(), // id -> { drive, server, username, client, slot, lock }
  active: null,
  account: null, // { client, server, username }
  nextVault: 0,
  transfers: { next: 0, flags: new Map() },
};

/**
 * The insecure software key, for development without hardware: only on a loopback page opened
 * with `?soft`. Its secrets live in this browser's localStorage.
 */
const SOFT = ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname) && new URLSearchParams(location.search).has("soft");

function authenticator() {
  if (SOFT) {
    return softAuthenticator({
      load: () => JSON.parse(localStorage.getItem("strongbox.softkey") || "{}"),
      save: (s) => localStorage.setItem("strongbox.softkey", JSON.stringify(s)),
    });
  }
  return webAuthenticator(rpIdFor(location.hostname));
}

/** Client errors for the UI, as the desktop formats them. An expired session gets a fixed prefix. */
function cerr(e) {
  if (typeof e === "string") return e;
  if (e?.status === 401) return `${SESSION_EXPIRED}: your session has expired; unlock the vault again`;
  return String(e?.message ?? e);
}

const nonempty = (s) => (s ? s : null);
const withTimeout = (p, ms) => Promise.race([Promise.resolve(p).catch(() => {}), new Promise((r) => setTimeout(r, ms))]);

function installVault(client, drive, server, username, slot) {
  const id = `vault-${++state.nextVault}`;
  state.vaults.set(id, { drive, server, username, client, slot, lock: new Mutex() });
  state.active = id;
  return id;
}

/** Stop transfers, wipe every open vault's keys and forget the sessions. Returns the clients. */
function wipeVault() {
  for (const f of state.transfers.flags.values()) f.cancelled = true;
  state.active = null;
  const clients = [];
  for (const item of state.vaults.values()) {
    item.drive.wipe();
    clients.push(item.client);
  }
  state.vaults.clear();
  if (state.account) clients.push(state.account.client);
  state.account = null;
  return clients;
}

async function signInAccount(client, server, username) {
  for (const previous of wipeVault()) await withTimeout(previous.endSession(), 5000);
  state.account = { client, server, username };
}

function currentItem() {
  const item = state.active && state.vaults.get(state.active);
  if (!item) throw "no vault unlocked";
  return item;
}

/** Run `fn(item)` holding the current vault's lock. */
const withVault = (fn) => { const item = currentItem(); return item.lock.run(() => fn(item)); };

function currentClient() {
  const item = state.active && state.vaults.get(state.active);
  if (item) return item.client;
  if (state.account) return state.account.client;
  throw "locked";
}

function syncClients(source) {
  for (const item of state.vaults.values()) item.client.syncAccountRecordFrom(source);
  state.account?.client.syncAccountRecordFrom(source);
}

function startTransfer() {
  const id = ++state.transfers.next;
  const flag = { cancelled: false };
  state.transfers.flags.set(id, flag);
  return [id, flag];
}

// ---------------------------------------------------------------- local files (pickers, drops)
// The desktop passes file system paths around; here picked and dropped files are registered
// under opaque tokens that look like paths ("…/name"), so app.js can show their names.

const picked = new Map();
let nextPick = 0;
function register(node) {
  const token = `local-${++nextPick}/${node.name}`;
  picked.set(token, node);
  return token;
}

/** Folder tree from the files of an <input webkitdirectory> ("Top/sub/file" relative paths). */
function treeFromRelative(files) {
  const top = { children: [], map: new Map() };
  for (const file of files) {
    const parts = (file.webkitRelativePath || file.name).split("/").filter(Boolean);
    let node = top;
    for (const p of parts.slice(0, -1)) {
      let next = node.map.get(p);
      if (!next) { next = { kind: "dir", name: p, children: [], map: new Map() }; node.map.set(p, next); node.children.push(next); }
      node = next;
    }
    node.children.push({ kind: "file", name: parts[parts.length - 1], file });
  }
  return top.children;
}

function pickFiles({ directory }) {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.multiple = true;
    if (directory) input.webkitdirectory = true;
    input.addEventListener("change", () => {
      const files = [...input.files];
      if (!files.length) return resolve(null);
      resolve((directory ? treeFromRelative(files) : files.map((file) => ({ kind: "file", name: file.name, file }))).map(register));
    });
    input.addEventListener("cancel", () => resolve(null));
    input.click();
  });
}

/** Read a dropped FileSystemEntry tree (folders keep empty subfolders, unlike the picker). */
async function readEntry(entry) {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej)).catch(() => null);
    return file ? { kind: "file", name: entry.name, file } : { kind: "skip", name: entry.name };
  }
  if (entry.isDirectory) {
    const reader = entry.createReader();
    const children = [];
    for (;;) {
      const batch = await new Promise((res, rej) => reader.readEntries(res, rej)).catch(() => []);
      if (!batch.length) break;
      for (const e of batch) children.push(await readEntry(e));
    }
    return { kind: "dir", name: entry.name, children };
  }
  return { kind: "skip", name: entry.name };
}

/** Tokens for files and folders dropped onto the page. Call synchronously in the drop handler. */
function dropTokens(dataTransfer) {
  const entries = [...(dataTransfer?.items ?? [])].filter((i) => i.kind === "file").map((i) => i.webkitGetAsEntry?.());
  if (entries.length && entries.every(Boolean)) return Promise.all(entries.map(readEntry)).then((nodes) => nodes.map(register));
  return Promise.resolve([...(dataTransfer?.files ?? [])].map((file) => register({ kind: "file", name: file.name, file })));
}

/** Expand picked tokens into folders to create and files to upload (with their remote folder). */
function expandLocal(tokens, dir) {
  const dirs = [], files = [], skipped = [];
  const stack = tokens.map((t) => [picked.get(t) ?? { kind: "skip", name: t.split("/").pop() }, dir]).reverse();
  const joinRemote = (d, n) => `${d.replace(/\/+$/, "")}/${n}`;
  while (stack.length) {
    const [node, remoteDir] = stack.pop();
    if (node.kind === "file") files.push([node.file, remoteDir]);
    else if (node.kind === "dir") {
      const remote = joinRemote(remoteDir, node.name);
      dirs.push(remote);
      const children = [...node.children].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      for (const ch of children.reverse()) stack.push([ch, remote]);
    } else skipped.push(node.name);
  }
  for (const t of tokens) picked.delete(t);
  return { dirs, files, skipped };
}

// ---------------------------------------------------------------- download destinations

const destinations = new Map();
let nextDest = 0;
const fsAccess = typeof window.showSaveFilePicker === "function" && typeof window.showDirectoryPicker === "function";

function destToken(d) {
  const token = `dest-${++nextDest}/${d.name}`;
  destinations.set(token, d);
  return token;
}

async function askSave(defaultPath) {
  if (!fsAccess) return destToken({ kind: "browser", name: defaultPath });
  try {
    const handle = await window.showSaveFilePicker({ suggestedName: defaultPath, id: "strongbox-save" });
    return destToken({ kind: "file", name: handle.name, handle });
  } catch (e) {
    if (e?.name === "AbortError") return null;
    return destToken({ kind: "browser", name: defaultPath });
  }
}

async function askFolder() {
  if (!fsAccess) return destToken({ kind: "browser", name: "Downloads" });
  try {
    const handle = await window.showDirectoryPicker({ id: "strongbox-save", mode: "readwrite" });
    return destToken({ kind: "dir", name: handle.name, handle });
  } catch (e) {
    if (e?.name === "AbortError") return null;
    return destToken({ kind: "browser", name: "Downloads" });
  }
}

/** Hand a decrypted file to the browser's own download (no file system access API). */
function saveBlob(parts, name, type = "application/octet-stream") {
  const url = URL.createObjectURL(new Blob(parts, { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

async function exists(dirHandle, name) {
  for (const get of ["getFileHandle", "getDirectoryHandle"]) {
    try { await dirHandle[get](name); return true; } catch (e) { if (e?.name === "TypeMismatchError") return true; }
  }
  return false;
}

/** `name`, or "name (n)" if it already exists in the folder. */
async function uniqueLocalName(dirHandle, name, isDir = false) {
  if (!(await exists(dirHandle, name))) return name;
  const i = isDir ? -1 : name.lastIndexOf(".");
  const [stem, ext] = i > 0 ? [name.slice(0, i), name.slice(i)] : [name, ""];
  for (let n = 1; ; n++) if (!(await exists(dirHandle, `${stem} (${n})${ext}`))) return `${stem} (${n})${ext}`;
}

/** A file sink in a local folder: the file only appears once it is complete and verified. */
async function fileSink(fileHandle) {
  const w = await fileHandle.createWritable();
  return { write: (b) => w.write(b), done: () => w.close(), fail: () => w.abort().catch(() => {}) };
}

function memorySink() {
  const parts = [];
  return { parts, write: (b) => { parts.push(b); }, done: () => {}, fail: () => { parts.length = 0; } };
}

async function fetchInto(drive, f, sink, opts) {
  try {
    await drive.fetch(f, sink, opts);
    await sink.done();
  } catch (e) {
    await sink.fail();
    throw e;
  }
}

/** Files and folders under `remote`, checked for local name clashes like the desktop. */
function collectDir(drive, remote) {
  const parts = vault.comps(remote);
  const root = vault.dirAt(drive.tree, parts);
  const dirs = [[]], files = [];
  const stack = [[[], parts, root]];
  while (stack.length) {
    const [rel, rc, d] = stack.pop();
    vault.checkLocalNameClashes(d.entries.keys());
    for (const [n, node] of d.entries) {
      const child = [...rel, vault.localSafeName(n)];
      if (node.kind === "dir") { dirs.push(child); stack.push([child, [...rc, n], node]); }
      else files.push([child, node]);
    }
  }
  return { name: parts.length ? vault.localSafeName(parts[parts.length - 1]) : "Strongbox", dirs, files };
}

/** Download a folder tree into a new folder of `dirHandle`, or a .zip without one. */
async function downloadDir(drive, remote, dest, opts) {
  const { name, dirs, files } = collectDir(drive, remote);
  const total = files.reduce((n, [, f]) => n + f.size, 0);
  let base = 0;
  const progress = (done) => opts.progress?.(base + done, total);
  if (dest.kind === "dir") {
    const top = await dest.handle.getDirectoryHandle(await uniqueLocalName(dest.handle, name, true), { create: true });
    const dirOf = async (rel) => { let h = top; for (const p of rel) h = await h.getDirectoryHandle(p, { create: true }); return h; };
    for (const d of dirs) await dirOf(d);
    for (const [rel, f] of files) {
      const parent = await dirOf(rel.slice(0, -1));
      await fetchInto(drive, f, await fileSink(await parent.getFileHandle(rel[rel.length - 1], { create: true })), { ...opts, progress });
      base += f.size;
    }
    return `${dest.handle.name}/${top.name}`;
  }
  const zip = zipWriter();
  for (const d of dirs) zip.dir([name, ...d].join("/"));
  for (const [rel, f] of files) {
    const sink = memorySink();
    await fetchInto(drive, f, sink, { ...opts, progress });
    zip.file([name, ...rel].join("/"), sink.parts, f.mtime);
    base += f.size;
  }
  saveBlob(zip.finish(), `${name}.zip`, "application/zip");
  return `Downloads/${name}.zip`;
}

/** Minimal store-only ZIP (for folder downloads in browsers without folder access). */
function zipWriter() {
  const table = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
  const crc32 = (parts) => { let c = 0xffffffff; for (const p of parts) for (let i = 0; i < p.length; i++) c = table[(c ^ p[i]) & 255] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
  const enc = new TextEncoder();
  const out = [], central = [];
  let offset = 0;
  const dosTime = (ms) => {
    const d = new Date(ms || Date.now());
    return [((d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1)) & 0xffff,
      (((Math.max(1980, d.getFullYear()) - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate()) & 0xffff];
  };
  const header = (sig, fields) => {
    const b = new DataView(new ArrayBuffer(fields.reduce((n, [, size]) => n + size, 4)));
    b.setUint32(0, sig, true);
    let at = 4;
    for (const [v, size] of fields) { if (size === 2) b.setUint16(at, v, true); else b.setUint32(at, v, true); at += size; }
    return new Uint8Array(b.buffer);
  };
  const add = (path, parts, mtime, isDir) => {
    const name = enc.encode(path + (isDir ? "/" : ""));
    const size = parts.reduce((n, p) => n + p.length, 0);
    if (offset + size > 0xfffff000) throw "this folder is too large to save as a .zip in this browser; use a browser that can save into a folder (Chrome or Edge)";
    const crc = crc32(parts);
    const [time, date] = dosTime(mtime);
    const common = [[0, 2], [0x0800, 2], [0, 2], [time, 2], [date, 2], [crc, 4], [size, 4], [size, 4], [name.length, 2], [0, 2]];
    const local = header(0x04034b50, [[20, 2], ...common]);
    central.push(header(0x02014b50, [[20, 2], [20, 2], ...common, [0, 2], [0, 2], [0, 2], [isDir ? 0x10 : 0, 4], [offset, 4]]), name);
    out.push(local, name, ...parts);
    offset += local.length + name.length + size;
  };
  return {
    dir: (path) => add(path, [], Date.now(), true),
    file: (path, parts, mtime) => add(path, parts, mtime, false),
    finish() {
      const cdSize = central.reduce((n, p) => n + p.length, 0);
      const count = central.length / 2;
      out.push(...central, header(0x06054b50, [[0, 2], [0, 2], [count, 2], [count, 2], [cdSize, 4], [offset, 4], [0, 2]]));
      return out;
    },
  };
}

// ---------------------------------------------------------------- commands

const commands = {
  answer_prompt() { /* the browser asks for the security key's PIN itself */ },

  async vault_create_account({ server, username, invite, label }) {
    const client = await vault.createVaultNamed(server, username, nonempty(invite), authenticator(), label);
    await signInAccount(client, server, username);
  },

  async vault_slot_count({ server }) {
    return (await vault.vaultLayout(server)).slots;
  },

  async vault_sign_in({ server, username }) {
    await signInAccount(await vault.connectAccount(server, username, authenticator()), server, username);
  },

  async vault_account_recover({ server, username, code }) {
    await signInAccount(await vault.connectAccountWithRecovery(server, username, code), server, username);
  },

  async vault_open({ server, username, slot, pin, create }) {
    const { client, key } = await vault.connect(server, username, authenticator(), slot, pin);
    const drive = create ? await client.create(key) : await client.open(key);
    if (!drive) throw "No drive found for that slot and PIN";
    installVault(client, drive, server, username, slot);
  },

  async vault_recover({ server, username, code }) {
    const { client, key, drive } = await vault.connectWithRecovery(server, username, code);
    installVault(client, drive, server, username, key.slot);
    return key.slot;
  },

  async vault_add_account_key({ label }) {
    const client = currentClient();
    await client.addAccountKeyNamed(authenticator(), label);
    syncClients(client);
  },

  async vault_add_key_to_current({ label, pin }) {
    const client = currentClient();
    const existing = client.members.map((m) => m.id);
    const authn = authenticator();
    await client.addAccountKeyNamed(authn, label);
    const member = client.members.find((m) => m.kind === "security_key" && m.slot == null && !existing.includes(m.id));
    if (!member) throw "new security key was added but could not be identified";
    syncClients(client);
    return withVault(({ drive }) => drive.grantAccountKey(authn, pin, member.id));
  },

  async vault_new_account_recovery({ label }) {
    const client = currentClient();
    const code = await client.newAccountRecoveryCodeNamed(label);
    syncClients(client);
    return code;
  },

  vault_drive_access() {
    return withVault(async ({ drive }) => {
      const grants = drive.accessGrants();
      const { current } = await drive.client.membersList();
      const view = (m) => ({ id: m.id, label: m.label, granted: grants.some((g) => g.memberId === m.id), current: m.id === current });
      const members = drive.client.members;
      return {
        keys: members.filter((m) => m.kind === "security_key" && m.slot == null).map(view),
        recovery_codes: members.filter((m) => m.kind === "recovery_code" && m.slot === drive.slot).map(view),
      };
    });
  },

  vault_grant_key({ id, pin }) {
    return withVault(({ drive }) => drive.grantAccountKey(authenticator(), pin, id));
  },

  vault_revoke_key({ id }) {
    return withVault(({ drive }) => drive.revokeAccountKey(id));
  },

  async vault_revoke_recovery({ id }) {
    await withVault(async ({ drive }) => { await drive.revokeRecoveryCode(id); syncClients(drive.client); });
  },

  vault_new_recovery({ label }) {
    return withVault(async ({ drive }) => {
      const code = await drive.newRecoveryCodeNamed(label);
      syncClients(drive.client);
      return code;
    });
  },

  async vault_members() {
    const client = currentClient();
    const { current } = await client.membersList();
    return { members: client.members.map((m) => ({ id: m.id, label: m.label, kind: m.kind, slot: m.slot, current: m.id === current })) };
  },

  async vault_suggest_label({ base, replacesVaultRecovery }) {
    const client = currentClient();
    const ignore = replacesVaultRecovery ? await withVault(({ drive }) => drive.recoveryIds()) : [];
    return client.suggestLabel(base, ignore);
  },

  async vault_rename_member({ id, label }) {
    const client = currentClient();
    await client.renameMember(id, label);
    syncClients(client);
  },

  vault_change_pin({ newPin }) {
    return withVault(({ drive }) => drive.changePin(authenticator(), newPin));
  },

  async vault_remove_member({ id }) {
    const client = currentClient();
    await client.removeMember(id);
    syncClients(client);
  },

  vault_tabs() {
    return [...state.vaults].map(([id, item]) => ({ id, slot: item.slot, active: id === state.active }))
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  },

  vault_select({ id }) {
    if (!state.vaults.has(id)) throw "vault is locked";
    state.active = id;
  },

  async vault_lock({ id }) {
    const item = state.vaults.get(id);
    if (!item) throw "vault is already locked";
    state.vaults.delete(id);
    item.drive.wipe();
    const remaining = state.vaults.keys().next().value ?? null;
    if (state.active === id) state.active = remaining;
    await withTimeout(item.client.endSession(), 5000);
    return remaining != null || state.account != null;
  },

  async lock() {
    for (const client of wipeVault()) await withTimeout(client.endSession(), 10_000);
  },

  panic_lock() {
    for (const client of wipeVault()) withTimeout(client.endSession(), 5000);
  },

  async logout() {
    for (const client of wipeVault()) await withTimeout(client.endSession(), 10_000);
  },

  async delete_account({ server, username }) {
    const client = await vault.connectAccount(server, username, authenticator());
    await client.deleteAccount();
    for (const c of wipeVault()) await withTimeout(c.endSession(), 10_000);
  },

  is_unlocked() {
    return state.account != null || state.vaults.size > 0;
  },

  list({ path }) {
    return withVault(({ drive }) => drive.list(path));
  },

  search({ query }) {
    return withVault(({ drive }) => drive.search(query));
  },

  mkdir({ path }) {
    return withVault(({ drive }) => drive.mkdir(path));
  },

  /** Upload files and folders (recursively) into `dir`, committed in batches. */
  upload({ paths, dir, conflict }) {
    return withVault(async ({ drive }) => {
      const { dirs, files, skipped } = expandLocal(paths, dir);
      const staged = drive.stage();
      for (const remote of dirs) drive.mkdirPStaged(staged, remote);
      const waiting = [];
      const summary = { done: 0, failed: 0, cancelled: 0, skipped };
      const commitUploads = async () => {
        let error = null;
        try { await drive.commitStaged(staged); } catch (e) { error = cerr(e); }
        if (!waiting.length) { if (error) throw error; return; }
        for (const ev of waiting.splice(0)) {
          if (error) { summary.failed++; emit("transfer", { ...ev, state: "error", error }); }
          else { summary.done++; emit("transfer", { ...ev, state: "done" }); }
        }
      };
      for (const [file, remoteDir] of files) {
        const [id, flag] = startTransfer();
        const ev = { id, kind: "upload", name: file.name, target: remoteDir, done: 0, total: file.size, state: "active", error: null };
        emit("transfer", ev);
        try {
          const stored = await drive.uploadStaged(staged, file, remoteDir, {
            progress: (done, total) => emit("transfer", { ...ev, done, total }),
            cancel: flag,
            onConflict: conflict,
          });
          waiting.push({ ...ev, name: stored, done: file.size });
        } catch (e) {
          if (flag.cancelled) { summary.cancelled++; emit("transfer", { ...ev, state: "cancelled", error: cerr(e) }); }
          else { summary.failed++; emit("transfer", { ...ev, state: "error", error: cerr(e) }); }
        } finally {
          state.transfers.flags.delete(id);
        }
        if (drive.stagedDue(staged)) await commitUploads();
      }
      await commitUploads();
      return summary;
    });
  },

  /** Download one file (`dest`, from the save dialog) or several items into a folder (`destDir`). */
  download({ items, dest, destDir }) {
    return withVault(async ({ drive }) => {
      const summary = { done: 0, failed: 0, cancelled: 0, skipped: [] };
      const target = destinations.get(dest ?? destDir);
      if (!target) throw "no download destination";
      for (const item of items) {
        const name = item.path.split("/").pop();
        const [id, flag] = startTransfer();
        const shown = target.kind === "file" ? target.name : target.kind === "dir" ? `${target.handle.name}/${vault.localSafeName(name)}` : "Downloads";
        const ev = { id, kind: "download", name, target: shown, done: 0, total: 0, state: "active", error: null };
        emit("transfer", ev);
        const opts = { progress: (done, total) => emit("transfer", { ...ev, done, total }), cancel: flag };
        try {
          let saved;
          if (item.is_dir) saved = await downloadDir(drive, item.path, target, opts);
          else {
            const f = drive.file(item.path);
            if (target.kind === "file") {
              await fetchInto(drive, f, await fileSink(target.handle), opts);
              saved = target.name;
            } else if (target.kind === "dir") {
              const local = await uniqueLocalName(target.handle, vault.localSafeName(name));
              await fetchInto(drive, f, await fileSink(await target.handle.getFileHandle(local, { create: true })), opts);
              saved = `${target.handle.name}/${local}`;
            } else {
              const sink = memorySink();
              await fetchInto(drive, f, sink, opts);
              const local = dest ? target.name : vault.localSafeName(name);
              saveBlob(sink.parts, local);
              saved = `Downloads/${local}`;
            }
          }
          summary.done++;
          emit("transfer", { ...ev, target: saved, state: "done" });
        } catch (e) {
          if (flag.cancelled) { summary.cancelled++; emit("transfer", { ...ev, state: "cancelled", error: cerr(e) }); }
          else { summary.failed++; emit("transfer", { ...ev, state: "error", error: cerr(e) }); }
        } finally {
          state.transfers.flags.delete(id);
        }
      }
      destinations.delete(dest ?? destDir);
      return summary;
    });
  },

  cancel_transfer({ id }) {
    for (const [k, f] of state.transfers.flags) if (id == null || id === k) f.cancelled = true;
  },

  preview({ path }) {
    return withVault(async ({ drive }) => (await drive.readFile(path, MAX_PREVIEW_BYTES)).buffer);
  },

  remove({ path }) {
    return withVault(({ drive }) => drive.remove(path));
  },

  rename({ from, to }) {
    return withVault(({ drive }) => drive.rename(from, to));
  },

  account() {
    const item = state.active && state.vaults.get(state.active);
    if (item) {
      const [used, quota] = item.drive.usage();
      return { username: item.username, server: item.server, used_bytes: used, quota_bytes: quota };
    }
    if (!state.account) throw "locked";
    return { username: state.account.username, server: state.account.server, used_bytes: 0, quota_bytes: null };
  },
};

async function invoke(cmd, args = {}) {
  const fn = commands[cmd];
  if (!fn) throw `unknown command ${cmd}`;
  try {
    return await fn(args);
  } catch (e) {
    throw cerr(e);
  }
}

// Leaving the page wipes the keys and ends the server sessions (best effort).
addEventListener("pagehide", () => { for (const c of wipeVault()) c.endSession().catch(() => {}); });
// Closing the tab mid-transfer would lose it: ask first, as a native app would.
addEventListener("beforeunload", (e) => { if (state.transfers.flags.size) e.preventDefault(); });

window.__TAURI__ = {
  core: { invoke },
  event: { listen },
  dialog: {
    open: ({ multiple, directory } = {}) => (multiple ? pickFiles({ directory }) : askFolder()),
    save: ({ defaultPath } = {}) => askSave(defaultPath),
  },
  web: { dropTokens, soft: SOFT },
};
