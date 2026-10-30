// Strongbox desktop UI. Rendering only: all crypto and key handling happens in the Rust core.
// User data (file names etc.) is only ever inserted with textContent, never innerHTML.
"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const dialog = window.__TAURI__.dialog;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const SESSION_EXPIRED = "SESSION_EXPIRED";
const MAX_PREVIEW = 256 * 1024 * 1024;
const MAX_TEXT_PREVIEW = 2 * 1024 * 1024;
const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,63}$/;

// ---------------------------------------------------------------- storage (best effort)

const prefs = {
  get(k, d) { try { const v = localStorage.getItem("fd." + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem("fd." + k, JSON.stringify(v)); } catch { /* ignore */ } },
};

// ---------------------------------------------------------------- state

const state = {
  view: "drive",          // drive | search
  cwd: [],                // path components while browsing
  query: "",
  entries: [],            // normalized items currently shown (sorted)
  selected: new Set(),    // item keys
  anchor: null,           // key for shift-range selection
  focus: null,            // key with keyboard focus
  sort: prefs.get("sort", { key: "name", dir: 1 }),
  layout: prefs.get("layout", "list"),
  profile: null,
  vaultTabs: [],
  unlocked: false,
  loadSeq: 0,
};

// ---------------------------------------------------------------- helpers

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else if (k === "text") e.textContent = v;
    else if (k === "icon") e.dataset.icon = v;
    else if (k === "data") Object.assign(e.dataset, v);
    else if (k === "attrs") for (const [a, av] of Object.entries(v)) e.setAttribute(a, av);
    else if (k === "vars") for (const [a, av] of Object.entries(v)) e.style.setProperty(a, av);
    else e[k] = v;
  }
  for (const c of children.flat()) if (c != null && c !== false) e.append(c);
  if (props.icon) e.prepend(icon(props.icon));
  return e;
}

const pathStr = (parts) => "/" + parts.join("/");
const pathParts = (s) => s.split("/").filter(Boolean);
const joinPath = (dir, name) => (dir === "/" ? "" : dir) + "/" + name;
const parentOf = (p) => pathStr(pathParts(p).slice(0, -1));
const baseName = (p) => p.split(/[\\/]/).filter(Boolean).pop() || p;

function human(n) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let u = 0;
  while (n >= 1024 && u < units.length - 1) { n /= 1024; u++; }
  return u === 0 ? `${n} B` : `${n < 10 ? n.toFixed(1) : Math.round(n)} ${units[u]}`;
}

function shortDate(ms) {
  if (!ms) return "—";
  const d = new Date(ms), now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
  const opts = d.getFullYear() === now.getFullYear() ? { month: "short", day: "numeric" } : { month: "short", day: "numeric", year: "numeric" };
  return d.toLocaleDateString(undefined, opts);
}
const longDate = (ms) => (ms ? new Date(ms).toLocaleString(undefined, { dateStyle: "full", timeStyle: "short" }) : "");

function errText(e) {
  let s = String(e?.message ?? e);
  if (s.startsWith(SESSION_EXPIRED + ":")) s = s.slice(SESSION_EXPIRED.length + 1).trim();
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Plain-language wording for server replies, by what the server said. */
const SERVER_MESSAGES = [
  [/storage for this account is missing/i, "This account's files are missing on the server, so its vaults can't be opened. Delete the account (Account security) and create it again, or ask the server's operator to restore the data."],
  [/out of disk space/i, "The server is out of disk space. Tell its operator, then try again."],
  [/username taken/i, "That username is already taken. Sign in if it is yours, or choose another."],
  [/invalid invite token/i, "This server is invite-only, and that invite code isn't valid. Ask the server's operator for a new one."],
  [/registration is closed/i, "This server isn't accepting new accounts."],
  [/slow down|rate.?limit/i, "Too many attempts. Wait a minute and try again."],
  [/not whole blocks|block range|too many blocks|malformed|invalid (lookup|id)|must be 32 bytes/i, "The server rejected the request. Update Strongbox, or try again."],
  [/too many members/i, "This account already has the maximum number of keys. Remove one first."],
  [/last member|cannot be removed|at least one/i, "An account needs at least one sign-in method. Add another before removing this one."],
];

/** Friendlier wording for common errors from the Rust side. */
function friendly(e) {
  const s = errText(e);
  const api = /^Server error \((\d+)\):\s*([\s\S]*)$/i.exec(s);
  if (api) {
    const [, status, msg] = api;
    for (const [re, text] of SERVER_MESSAGES) if (re.test(msg)) return text;
    if (status === "401") return "Your session has expired. Sign in again.";
    if (Number(status) >= 500) return "The server ran into a problem. Try again in a moment, and tell its operator if it keeps happening.";
    if (status === "404") return "The server couldn't find that. It may have been deleted.";
    return errText(msg);
  }
  if (/could not authenticate|not registered for the account|UnknownCredential/i.test(s)) return "That security key isn't registered for this account, or the username is wrong.";
  if (/operation cancelled|^Cancelled$/i.test(s)) return "Cancelled.";
  if (/network:|error sending request|connection refused|dns error|timed out|timeout/i.test(s)) return "Can't reach the server. Check the address and your connection.";
  if (/rate.?limit|slow down|too many requests/i.test(s)) return "Too many attempts. Wait a minute and try again.";
  if (/decryption failed/i.test(s)) return "That code or password doesn't match this account.";
  if (/^locked$/i.test(s)) return "Nothing is unlocked. Sign in first.";
  if (/^no vault unlocked$/i.test(s)) return "No vault is unlocked. Unlock one from the sidebar first.";
  return s || "Something went wrong. Try again.";
}

/** invoke() that returns to the lock screen when the server session has expired. */
async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    const s = String(e);
    if (s.startsWith(SESSION_EXPIRED)) {
      await lockNow("Your session expired. Unlock to continue.");
    } else if (s === "locked" && state.unlocked) {
      await lockNow();
    }
    throw e;
  }
}

async function busy(btn, fn) {
  btn.disabled = true;
  btn.classList.add("busy");
  try { return await fn(); } finally { btn.disabled = false; btn.classList.remove("busy"); }
}

// ---------------------------------------------------------------- file types

const EXT = {
  image: "png jpg jpeg gif webp bmp svg ico avif heic tif tiff",
  video: "mp4 webm mov m4v mkv avi ogv wmv",
  audio: "mp3 wav ogg oga m4a flac aac opus wma",
  pdf: "pdf",
  doc: "doc docx odt rtf pages",
  sheet: "xls xlsx ods csv tsv numbers",
  slides: "ppt pptx odp key",
  archive: "zip rar 7z tar gz tgz bz2 xz zst iso dmg",
  code: "js mjs ts tsx jsx rs py go java c h cpp hpp cs rb php swift kt sh ps1 bat sql html htm css scss json xml yaml yml toml ini lua",
  text: "txt md log cfg conf env",
};
const CAT_ICON = { folder: "folder", image: "image", video: "video", audio: "music", pdf: "pdf", doc: "file-text", sheet: "sheet", slides: "slides", archive: "archive", code: "code", text: "file-text", file: "file" };
const EXT_CAT = {};
for (const [cat, list] of Object.entries(EXT)) for (const x of list.split(" ")) EXT_CAT[x] = cat;
const extOf = (name) => { const i = name.lastIndexOf("."); return i > 0 ? name.slice(i + 1).toLowerCase() : ""; };
const catOf = (name, isDir) => (isDir ? "folder" : EXT_CAT[extOf(name)] || "file");
const typeLabel = (it) => (it.is_dir ? "Folder" : (extOf(it.name) ? extOf(it.name).toUpperCase() + " file" : "File"));

function ftype(name, isDir) {
  const cat = catOf(name, isDir);
  return el("span", { class: "ftype", vars: { "--c": `var(--t-${cat})` } }, icon(CAT_ICON[cat]));
}

const MIME = {
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", bmp: "image/bmp",
  svg: "image/svg+xml", ico: "image/x-icon", avif: "image/avif",
  mp4: "video/mp4", m4v: "video/mp4", webm: "video/webm", ogv: "video/ogg", mov: "video/mp4",
  mp3: "audio/mpeg", wav: "audio/wav", ogg: "audio/ogg", oga: "audio/ogg", m4a: "audio/mp4", flac: "audio/flac", aac: "audio/aac", opus: "audio/ogg",
  pdf: "application/pdf",
};
function previewKind(name) {
  const x = extOf(name);
  if (MIME[x]?.startsWith("image/")) return "image";
  if (MIME[x]?.startsWith("video/")) return "video";
  if (MIME[x]?.startsWith("audio/")) return "audio";
  if (x === "pdf") return "pdf";
  if (EXT_CAT[x] === "code" || EXT_CAT[x] === "text" || x === "csv" || x === "tsv" || x === "") return "text";
  return null;
}

// ---------------------------------------------------------------- motion

/** Restart a CSS entrance animation on `node` by toggling `cls`. */
function replay(node, cls = "enter") {
  node.classList.remove(cls);
  void node.offsetWidth;
  node.classList.add(cls);
}

/** Show or hide `node` with a fade; the content is already wiped by the caller when that matters. */
function setShown(node, on, ms = 150) {
  clearTimeout(node._hideTimer);
  if (on) { node.classList.remove("closing"); node.hidden = false; return; }
  if (node.hidden) return;
  node.classList.add("closing");
  node._hideTimer = setTimeout(() => { node.hidden = true; node.classList.remove("closing"); }, ms);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- toasts

function toast(message, { type = "info", action = null, timeout = 4500 } = {}) {
  const lead = icon(type === "error" ? "alert" : type === "success" ? "check-circle" : "info", "lead");
  const t = el("div", { class: `toast ${type}`, attrs: { role: type === "error" ? "alert" : "status" } }, lead, el("span", { class: "msg", text: message }));
  const close = () => { clearTimeout(timer); t.classList.add("closing"); setTimeout(() => t.remove(), 160); };
  if (action) t.append(el("button", { class: "btn link sm", text: action.label, onclick: () => { close(); action.fn(); } }));
  t.append(el("button", { class: "icon-btn", attrs: { "aria-label": "Dismiss" }, onclick: close }, icon("x")));
  $("#toasts").append(t);
  while ($("#toasts").children.length > 3) $("#toasts").firstElementChild.remove();
  const timer = setTimeout(close, type === "error" ? Math.max(timeout, 7000) : timeout);
}
const toastError = (e) => toast(friendly(e), { type: "error" });

// ---------------------------------------------------------------- modals

/**
 * Show a dialog. Resolves with the clicked action's value (or the input's value for the
 * primary action when there is an input), or null when dismissed. A fresh <dialog> is
 * created each time so prompts can stack (e.g. a PIN request over another dialog).
 */
function modal({ title, body = [], input = null, actions = null, validate = null, wide = false }) {
  actions ??= [{ label: "Cancel", value: null }, { label: "OK", value: true, primary: true }];
  const dlg = el("dialog", { class: "dialog" + (wide ? " wide" : "") });
  const err = el("p", { class: "form-error", hidden: true });
  const bodyEl = el("div", { class: "dialog-body" }, ...(typeof body === "string" ? [el("p", { text: body })] : body));
  let field = null;
  if (input) {
    field = el("input", { type: input.type || "text", value: input.value || "", placeholder: input.placeholder || "", autocomplete: "off", spellcheck: false });
    bodyEl.append(input.label ? el("label", { class: "field", text: input.label }, field) : field);
  }
  const form = el("form", { novalidate: true }, el("h2", { text: title }), bodyEl, err);
  const row = el("div", { class: "dialog-actions" });
  form.append(row);
  dlg.append(form);
  document.body.append(dlg);

  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; dlg.close(); dlg.remove(); resolve(v); };
    const primary = actions.find((a) => a.primary) || actions[actions.length - 1];
    const submit = (a) => {
      let v = a.value;
      if (field && a === primary) {
        v = field.value;
        const msg = validate?.(v);
        if (msg) { err.textContent = msg; err.hidden = false; field.setAttribute("aria-invalid", "true"); field.focus(); return; }
      }
      finish(v);
    };
    for (const a of actions) {
      row.append(el("button", {
        type: "button",
        class: "btn" + (a.primary ? (a.danger ? " danger" : " primary") : a.ghost ? " ghost" : ""),
        text: a.label,
        onclick: () => submit(a),
      }));
    }
    form.addEventListener("submit", (e) => { e.preventDefault(); submit(primary); });
    dlg.addEventListener("cancel", (e) => { e.preventDefault(); finish(null); });
    dlg.showModal();
    if (field) {
      field.focus();
      if (input.selectStem) {
        const dot = field.value.lastIndexOf(".");
        field.setSelectionRange(0, dot > 0 ? dot : field.value.length);
      } else field.select();
      field.addEventListener("input", () => { err.hidden = true; field.removeAttribute("aria-invalid"); });
    } else {
      row.querySelector(".primary, .danger")?.focus();
    }
  });
}

const confirmDialog = (title, message, label = "OK", danger = false) =>
  modal({ title, body: message, actions: [{ label: "Cancel", value: null }, { label, value: true, primary: true, danger }] });

function validateName(v, existing = []) {
  const s = v.trim();
  if (!s) return "Enter a name.";
  if (s === "." || s === "..") return "That name isn't allowed.";
  if (s.includes("/")) return "Names can't contain “/”.";
  if (s.length > 255) return "That name is too long.";
  if (existing.includes(s)) return `“${s}” already exists here.`;
  return null;
}

/** Name of the vault's root folder in breadcrumbs, move targets and transfer lists. */
function rootName() {
  const tab = state.vaultTabs.find((t) => t.active);
  return tab ? `Vault ${tab.slot}` : "Vault";
}

// ---------------------------------------------------------------- security key wait

let keyWaitDepth = 0;
function keyWait(on, text) {
  keyWaitDepth += on ? 1 : -1;
  setShown($("#keywait"), keyWaitDepth > 0, 140);
  if (on) $("#keywait-text").textContent = text || "Insert your security key, enter its PIN and touch it when it blinks.";
}
async function withKey(text, fn) {
  keyWait(true, text);
  try { return await fn(); } finally { keyWait(false); }
}

listen("status", (e) => {
  if (!$("#keywait").hidden) $("#keywait-text").textContent = e.payload;
});

listen("prompt", async (e) => {
  const { kind, attempts_left } = e.payload;
  const body = [];
  if (attempts_left != null) body.push(el("div", { class: "callout warn" }, icon("alert"), el("span", { text: `Wrong PIN. ${attempts_left} attempt${attempts_left === 1 ? "" : "s"} left before the key locks.` })));
  else body.push(el("p", { text: kind === "pin" ? "Enter the PIN of your security key." : "This key also requires your account password." }));
  const value = await modal({
    title: kind === "pin" ? "Security key PIN" : "Password",
    body,
    input: { type: "password", placeholder: kind === "pin" ? "PIN" : "Password" },
    actions: [{ label: "Cancel", value: null }, { label: "Continue", value: true, primary: true }],
    validate: (v) => (v ? null : "Required."),
  });
  await invoke("answer_prompt", { value });
});

// ---------------------------------------------------------------- views

function showView(name) {
  for (const v of ["auth", "drive"]) $(`#view-${v}`).hidden = v !== name;
}

function avatarFor(target, username) {
  target.textContent = (username || "?").charAt(0);
  let h = 0;
  for (const c of username || "") h = (h * 31 + c.charCodeAt(0)) % 360;
  target.style.setProperty("background", `hsl(${h} 55% 50%)`);
}

function applyTheme() {
  const t = prefs.get("theme", "system");
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}

// ---------------------------------------------------------------- auth

function authTab(which) {
  $("#tab-signin").setAttribute("aria-selected", which === "signin");
  $("#tab-create").setAttribute("aria-selected", which === "create");
  $("#signin-form").hidden = which !== "signin";
  $("#setup-form").hidden = which !== "create";
  $$(".form-error", $("#view-auth")).forEach((e) => { e.hidden = true; });
  const f = which === "signin" ? $("#signin-form") : $("#setup-form");
  (f.server.value ? f.username : f.server).focus();
}

function showAuth(tab = "signin") {
  const last = prefs.get("server", "");
  for (const f of [$("#signin-form"), $("#setup-form")]) if (!f.server.value) f.server.value = last;
  showView("auth");
  authTab(tab);
}

function formError(form, msg) {
  const e = $(".form-error", form);
  e.textContent = msg;
  e.hidden = !msg;
}

// The relying party id the security key's credentials are bound to. Remembered between runs and
// sent to the backend at startup and whenever it is changed in Settings.
const RP_DEFAULT = "strongbox.invalid";
async function applyRp(rp) {
  await invoke("set_rp_id", { rpId: rp });
  prefs.set("rp", rp);
}

const appSettings = $("#app-settings"), appSettingsForm = $("#app-settings-form");
$("#btn-auth-settings").addEventListener("click", () => {
  $("#app-pref-theme").value = prefs.get("theme", "system");
  appSettingsForm.rp.value = prefs.get("rp", RP_DEFAULT);
  formError(appSettingsForm, "");
  appSettings.showModal();
});
$("#app-pref-theme").addEventListener("change", (e) => { prefs.set("theme", e.target.value); applyTheme(); });
$("#app-settings-close").addEventListener("click", () => appSettings.close());
$("#app-settings-reset").addEventListener("click", () => { appSettingsForm.rp.value = RP_DEFAULT; });
appSettingsForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const rp = appSettingsForm.rp.value.trim().toLowerCase() || RP_DEFAULT;
  try { await applyRp(rp); }
  catch (e) { formError(appSettingsForm, friendly(e)); return; }
  appSettings.close();
  toast("Relying party ID saved.", { type: "success" });
});

function checkServer(form) {
  const s = form.server.value.trim();
  let url;
  try { url = new URL(s); } catch { return "Enter the server address, e.g. https://drive.example.org"; }
  const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) return "The server address must start with https:// (http:// only for localhost).";
  return null;
}

function checkUsername(form) {
  form.username.value = form.username.value.trim().toLowerCase();
  return USERNAME_RE.test(form.username.value) ? null : "Usernames are 3–64 characters: a–z, 0–9, dot, dash or underscore, starting with a letter or digit.";
}

// Usernames are secrets, so the fields are masked; let people check what they typed.
for (const f of [$("#signin-form"), $("#setup-form")]) {
  const toggle = el("button", { type: "button", class: "btn link sm reveal", text: "Show", onclick: () => {
    const show = f.username.type === "password";
    f.username.type = show ? "text" : "password";
    toggle.textContent = show ? "Hide" : "Show";
  } });
  f.username.closest("label").append(toggle);
}

$("#tab-signin").addEventListener("click", () => authTab("signin"));
$("#tab-create").addEventListener("click", () => authTab("create"));

async function finishVaultEntry() {
  await enterDrive();
  for (const f of [$("#signin-form"), $("#setup-form")]) {
    f.username.value = "";
    f.server.value = "";
  }
}

const PASSPHRASE_ADVICE = "Use a passphrase: several random words, or a long random string. Something you could guess or that follows a pattern is easy to break, however long it is. At least 8 characters.";

async function askVaultSlotAndPin(server, { slotTitle = "Vault number", pinBody = [], pinTitle = "Vault passphrase" } = {}) {
  const count = await invoke("vault_slot_count", { server });
  const max = count - 1;
  const slot = await modal({
    title: slotTitle,
    input: { label: "Vault number", placeholder: "0-" + max },
    validate: v => /^\d+$/.test(v) && Number(v) < count ? null : "Enter a number from 0 to " + max + ".",
  });
  if (slot == null) return null;
  const pin = await modal({
    title: pinTitle,
    body: pinBody,
    input: { type: "password", label: "Vault passphrase" },
    validate: v => v.length >= 8 ? null : "Use at least 8 characters.",
  });
  if (pin == null) return null;
  return { slot: Number(slot), pin };
}

$("#signin-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const problem = checkServer(f) || checkUsername(f);
  formError(f, problem);
  if (problem) return;
  const server = f.server.value.trim(), username = f.username.value;
  await busy($("button[type=submit]", f), async () => {
    try {
      await withKey("Insert your security key, enter its PIN and touch it.", () => invoke("vault_sign_in", { server, username }));
      await finishVaultEntry();
    } catch (e) {
      formError(f, friendly(e));
    }
  });
});

$("#setup-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const problem = checkServer(f) || checkUsername(f);
  formError(f, problem);
  if (problem) return;
  const invite = f.invite.value.trim();
  const server = f.server.value.trim(), username = f.username.value;
  const label = await modal({ title: "Name this security key", input: { label: "Name", value: "Security key 1" }, validate: v => v.trim() && v.length <= 80 ? null : "Enter a name up to 80 characters." });
  if (label == null) return;
  await busy($("button[type=submit]", f), async () => {
    try {
      await withKey("Insert your security key and touch it when prompted.", () =>
        invoke("vault_create_account", { server, username, invite, label: label.trim() }));
      await finishVaultEntry();
    } catch (e) { formError(f, friendly(e)); }
  });
});
// ---------------------------------------------------------------- drive: entering / locking

async function enterDrive() {
  const a = await invoke("account");
  state.profile = { username: a.username, server_url: a.server };
  state.vaultTabs = await invoke("vault_tabs");
  state.unlocked = true;
  lastActivity = Date.now();
  avatarFor($("#me-avatar"), state.profile.username);
  $("#me-name").textContent = state.profile.username;
  $("#me-server").textContent = state.profile.server_url.replace(/^https?:\/\//, "");
  showView("drive");
  $("#vault-empty-note").hidden = state.vaultTabs.length > 0;
  renderVaultTabs();
  const hasDrive = state.vaultTabs.length > 0;
  $("#search").disabled = !hasDrive;
  $("#search").placeholder = hasDrive ? "Search in this vault" : "Unlock a vault to search";
  $("#btn-new").hidden = !hasDrive;
  $("#btn-new-vault-drive").textContent = state.vaultTabs.length ? "Create another vault..." : "Create a vault...";
  setLayout(state.layout);
  if (hasDrive) {
    await navigate([]);
    replay($("#items"));
  } else {
    Object.assign(state, { cwd: [], query: "", view: "drive", entries: [], selected: new Set() });
    state.account = null;
    $("#search").value = "";
    render();
    refreshUsage();
  }
}

async function lockNow(message) {
  if (!state.unlocked) return;
  state.unlocked = false;
  try { await invoke("lock"); } catch { /* the Rust side drops the keys regardless */ }
  closePreview();
  hideMenu();
  for (const d of $$("dialog[open]")) { d.close(); if (!d.id) d.remove(); }
  Object.assign(state, { entries: [], selected: new Set(), cwd: [], view: "drive", query: "" });
  $("#items").replaceChildren();
  $("#search").value = "";
  transfers.clear();
  state.profile = null;
  // Keys and decrypted state are already gone; only the empty shell fades out.
  const drive = $("#view-drive");
  if (!drive.hidden) { drive.classList.add("leaving"); await sleep(220); drive.classList.remove("leaving"); }
  showAuth();
  if (message) toast(message);
}

$("#btn-lock").addEventListener("click", () => lockNow());

$("#btn-new-vault-drive").addEventListener("click", async () => {
  if (!state.profile) return;
  if (!(await confirmDialog("Create or reset a vault?", "This permanently replaces the contents of the selected vault number, if it already contains a vault.", "Continue", true))) return;
  let credentials;
  try { credentials = await askVaultSlotAndPin(state.profile.server_url, { slotTitle: "New vault number", pinTitle: "New vault passphrase", pinBody: PASSPHRASE_ADVICE }); }
  catch (e) { toastError(e); return; }
  if (!credentials) return;
  // Recreating a vault that is open here erases it; say so before touching the key.
  if (state.vaultTabs.some((t) => t.slot === credentials.slot)
    && !(await confirmDialog(`Erase Vault ${credentials.slot}?`, `Vault ${credentials.slot} is open. Creating it again permanently erases everything in it.`, "Erase and recreate", true))) return;
  try {
    await withKey("Insert your security key, enter its PIN and touch it.", () =>
      invoke("vault_open", { server: state.profile.server_url, username: state.profile.username, ...credentials, create: true }));
    await enterDrive();
  } catch (e) { if (state.unlocked) toastError(e); return; }
});

$("#btn-open-vault-drive").addEventListener("click", async () => {
  if (!state.profile) return;
  let credentials;
  try { credentials = await askVaultSlotAndPin(state.profile.server_url); }
  catch (e) { toastError(e); return; }
  if (!credentials) return;
  try {
    await withKey("Insert your security key, enter its PIN and touch it.", () =>
      call("vault_open", { server: state.profile.server_url, username: state.profile.username, ...credentials, create: false }));
    await enterDrive();
  } catch (e) { if (state.unlocked) toastError(e); }
});

const shownVaultTabs = new Set();

function renderVaultTabs() {
  const host = $("#vault-tabs");
  const seen = new Set(shownVaultTabs);
  shownVaultTabs.clear();
  host.replaceChildren(...state.vaultTabs.map((tab) => {
    const select = el("button", {
      class: "nav-item vault-tab" + (tab.active ? " active" : ""),
      title: `Vault ${tab.slot}`,
      attrs: { role: "tab", "aria-selected": String(tab.active) },
      onclick: async () => {
        if (tab.active) return;
        try {
          await call("vault_select", { id: tab.id });
          await enterDrive();
        } catch (e) { toastError(e); }
      },
    }, icon("drive"), el("span", { text: `Vault ${tab.slot}` }));
    const lock = el("button", {
      class: "vault-tab-lock", text: "×", title: `Lock Vault ${tab.slot}`,
      attrs: { "aria-label": `Lock Vault ${tab.slot}`, type: "button" },
      onclick: async (ev) => {
        const row = ev.currentTarget.closest(".vault-tab-row");
        try {
          const remaining = await call("vault_lock", { id: tab.id });
          state.vaultTabs = await call("vault_tabs");
          if (remaining) { row?.classList.add("leaving"); await sleep(180); }
          if (!remaining) await lockNow();
          else if (tab.active) await enterDrive();
          else renderVaultTabs();
        } catch (e) { toastError(e); }
      },
    });
    const access = el("button", {
      class: "vault-tab-access", title: `Manage access for Vault ${tab.slot}`,
      attrs: { "aria-label": `Manage access for Vault ${tab.slot}`, type: "button" },
      icon: "key",
      onclick: async () => {
        if (!tab.active) {
          try {
            await call("vault_select", { id: tab.id });
            await enterDrive();
          } catch (e) { toastError(e); return; }
        }
        openVaultAccess(tab.slot);
      },
    });
    shownVaultTabs.add(tab.id);
    return el("div", { class: "vault-tab-row" + (seen.has(tab.id) ? "" : " entering") }, select, access, lock);
  }));
}

function openVaultAccess(slot) {
  $("#vault-access-title").textContent = `Vault ${slot}`;
  $("#vault-access").showModal();
  renderVaultAccess();
}

async function renderVaultAccess() {
  let data;
  try { data = await call("vault_drive_access"); }
  catch (e) { if (state.unlocked) toastError(e); return; }
  const usable = data.keys.filter((key) => key.granted).length;
  const keyItems = data.keys.map((key) => el("li", {},
    el("span", { class: "key-icon" }, icon("key")),
    el("div", { class: "key-meta" },
      el("div", { class: "key-label", text: key.label }),
      el("div", { class: "key-sub", text: (key.granted ? "Opens this vault" : "Account sign-in only") + (key.current ? " · Current key" : "") })),
    renameButton(key, renderVaultAccess),
    el("button", {
      class: key.granted ? "btn sm danger-ghost" : "btn sm",
      text: key.granted ? "Revoke" : "Grant",
      disabled: key.granted && usable <= 1,
      title: key.granted && usable <= 1 ? "Grant another key first" : "",
      onclick: async () => {
        if (!key.granted) {
          const pin = await modal({
            title: "Grant access to this vault",
            body: `Enter this vault's passphrase, then insert “${key.label}” and enter that security key's PIN when prompted.`,
            input: { type: "password", label: "Vault passphrase" },
            validate: v => v.length >= 8 ? null : "Use at least 8 characters.",
          });
          if (pin == null) return;
          try {
            await withKey(`Insert “${key.label}”, enter its PIN and touch it.`, () => call("vault_grant_key", { id: key.id, pin }));
            toast(`“${key.label}” can now open this vault.`, { type: "success" });
          } catch (e) { if (state.unlocked) toastError(e); }
        } else {
          if (!(await confirmDialog("Revoke this vault's access?", `“${key.label}” will still sign in to the account and may open other vaults. It will no longer open this vault.`, "Revoke", true))) return;
          try { await call("vault_revoke_key", { id: key.id }); toast("Vault access revoked.", { type: "success" }); }
          catch (e) { if (state.unlocked) toastError(e); }
        }
        await renderVaultAccess();
      },
    })));
  if (!keyItems.length) keyItems.push(el("li", { class: "key-empty muted", text: "Add a backup key in Account security first." }));
  $("#vault-access-keys").replaceChildren(...keyItems);
}

/**
 * Prompt for the name of a key. The field is prefilled with `base`, or `base 2`,
 * `base 3`... when that is taken, and a name already used by another key is
 * refused (ignoring case). `ignoreIds` are members about to be replaced; `prefill` overrides
 * the suggestion (renaming). Resolves to the trimmed name, or null if cancelled.
 */
async function askName(title, base, { ignoreIds = [], prefill = null } = {}) {
  let taken, value;
  try {
    const [data, suggested] = await Promise.all([
      call("vault_members"),
      prefill == null ? call("vault_suggest_label", { base }) : null,
    ]);
    taken = new Set(data.members.filter((m) => !ignoreIds.includes(m.id)).map((m) => m.label.trim().toLowerCase()));
    value = prefill ?? suggested;
  } catch (e) { if (state.unlocked) toastError(e); return null; }
  const label = await modal({
    title, input: { label: "Name", value },
    validate: (v) => !v.trim() || v.trim().length > 80 ? "Enter a name up to 80 characters."
      : taken.has(v.trim().toLowerCase()) ? "A key already has this name." : null,
  });
  return label == null ? null : label.trim();
}

/** A "Rename" button for a key row (`item` has id and label). */
function renameButton(item, refresh) {
  return el("button", {
    class: "btn sm ghost", text: "Rename",
    onclick: async () => {
      const label = await askName("Rename", item.label, { ignoreIds: [item.id], prefill: item.label });
      if (label == null || label === item.label) return;
      try { await call("vault_rename_member", { id: item.id, label }); toast("Renamed.", { type: "success" }); }
      catch (e) { if (state.unlocked) toastError(e); }
      await refresh();
    },
  });
}

$("#btn-change-vault-pin").addEventListener("click", async () => {
  const pin = el("input", { type: "password", autocomplete: "new-password" });
  const again = el("input", { type: "password", autocomplete: "new-password" });
  const ok = await modal({
    title: "Change vault passphrase",
    body: [
      el("p", { text: "Choose a new passphrase for this vault. A long, random passphrase of several words is best. Your security key will ask for its PIN and a touch. Other security keys that open this vault will lose access until you grant them again with the new passphrase." }),
      el("label", { class: "field", text: "New vault passphrase" }, pin),
      el("label", { class: "field", text: "Repeat new passphrase" }, again),
    ],
    actions: [{ label: "Cancel", value: null }, { label: "Change passphrase", value: true, primary: true }],
  });
  if (!ok) return;
  if (pin.value.length < 8) return toast("Use at least 8 characters.", { type: "error" });
  if (pin.value !== again.value) return toast("The passphrases do not match.", { type: "error" });
  try {
    const revoked = await withKey("Insert the security key you unlocked this vault with, enter its PIN and touch it.", () =>
      call("vault_change_pin", { newPin: pin.value }));
    toast(revoked ? `Vault passphrase changed. ${revoked} other key${revoked === 1 ? " lost" : "s lost"} access until granted again.` : "Vault passphrase changed.", { type: "success", timeout: 8000 });
  } catch (e) { if (state.unlocked) toastError(e); }
  await renderVaultAccess();
});

$("#vault-access-close").addEventListener("click", () => $("#vault-access").close());
$("#btn-add-vault-key").addEventListener("click", async () => {
  let taken, suggested;
  try {
    const [data, s] = await Promise.all([call("vault_members"), call("vault_suggest_label", { base: "Security key" })]);
    taken = new Set(data.members.map((m) => m.label.trim().toLowerCase()));
    suggested = s;
  } catch (e) { if (state.unlocked) toastError(e); return; }
  const name = el("input", { value: suggested, spellcheck: false });
  const pin = el("input", { type: "password", autocomplete: "current-password" });
  const ok = await modal({
    title: "Add security key to this vault",
    body: [
      el("p", { text: "This key will also be added for account sign-in. Enter this vault's passphrase, then insert the new key and follow the security key prompts." }),
      el("label", { class: "field", text: "Name" }, name),
      el("label", { class: "field", text: "Vault passphrase" }, pin),
    ],
    actions: [{ label: "Cancel", value: null }, { label: "Add key", value: true, primary: true }],
  });
  if (!ok) return;
  if (!name.value.trim() || name.value.trim().length > 80) return toast("Enter a name up to 80 characters.", { type: "error" });
  if (taken.has(name.value.trim().toLowerCase())) return toast("A key already has this name.", { type: "error" });
  if (pin.value.length < 8) return toast("Enter this vault's passphrase.", { type: "error" });
  try {
    await withKey("Insert the new security key, enter its key PIN and touch it when prompted.", () =>
      call("vault_add_key_to_current", { label: name.value.trim(), pin: pin.value }));
    toast("Security key added to this account and vault.", { type: "success" });
  } catch (e) { if (state.unlocked) toastError(e); }
  await renderVaultAccess();
});
/** Reset the UI to a signed-out state and show the sign-in screen. */
function resetToSignIn() {
  try { localStorage.removeItem("fd.server"); } catch { /* ignore */ }
  closePreview();
  hideMenu();
  for (const d of $$("dialog[open]")) { d.close(); if (!d.id) d.remove(); }
  Object.assign(state, { entries: [], selected: new Set(), cwd: [], view: "drive", query: "", profile: null });
  $("#items").replaceChildren();
  $("#search").value = "";
  for (const f of [$("#signin-form"), $("#setup-form")]) f.reset();
  transfers.clear();
  showAuth("signin");
}

async function deleteAccountNow() {
  const username = state.profile.username;
  const typed = await modal({
    title: "Delete account?",
    body: [
      el("p", { text: "This permanently deletes your account, all vaults, encryption keys, and every file from the server. Your security keys will no longer open anything, and nobody, including you, can recover the files." }),
      el("p", { text: "You'll be asked to authenticate with your security key again before deletion." }),
      el("p", { text: `The username “${username}” becomes available for anyone to register again.` }),
    ],
    input: { placeholder: username, label: `Type “${username}” to confirm` },
    actions: [{ label: "Cancel", value: null }, { label: "Delete account", value: true, primary: true, danger: true }],
    validate: (v) => (v.trim() === username ? null : "That doesn't match your username."),
  });
  if (!typed) return;
  const wasUnlocked = state.unlocked;
  state.unlocked = false;
  try {
    await invoke("delete_account", { server: state.profile.server_url, username });
  } catch (e) {
    state.unlocked = wasUnlocked;
    toastError(e);
    return;
  }
  resetToSignIn();
  toast(`Account “${username}” was deleted.`, { type: "success" });
}
$("#btn-delete-account").addEventListener("click", deleteAccountNow);

// Auto-lock after inactivity (no lock while transfers are running).
let lastActivity = Date.now();
for (const t of ["pointerdown", "keydown", "wheel", "pointermove"]) document.addEventListener(t, () => { lastActivity = Date.now(); }, { passive: true });
setInterval(() => {
  const mins = Number(prefs.get("autolock", 15));
  if (state.unlocked && mins > 0 && !transfers.active() && Date.now() - lastActivity > mins * 60_000) {
    lockNow("Locked after inactivity.");
  }
}, 20_000);

// ---------------------------------------------------------------- loading data

function normalize(e, parent) {
  const path = joinPath(parent, e.name);
  return { key: path, name: e.name, is_dir: e.is_dir, size: e.size, mtime: e.mtime, path, parent };
}

async function load(fn) {
  const seq = ++state.loadSeq;
  const spinner = setTimeout(() => { if (seq === state.loadSeq) $("#loading").hidden = false; }, 180);
  try {
    const result = await fn();
    return seq === state.loadSeq ? result : undefined; // a newer navigation won
  } finally {
    clearTimeout(spinner);
    if (seq === state.loadSeq) $("#loading").hidden = true;
  }
}

async function navigate(parts, { keepSelection = false, select = null } = {}) {
  let list;
  try {
    list = await load(() => call("list", { path: pathStr(parts) }));
  } catch (e) {
    if (!state.unlocked) return;
    toastError(e);
    if (parts.length) return navigate(parts.slice(0, -1));
    return;
  }
  if (list === undefined) return;
  const changedFolder = state.view !== "drive" || pathStr(parts) !== pathStr(state.cwd);
  state.view = "drive";
  state.cwd = parts;
  state.query = "";
  $("#search").value = "";
  state.entries = list.map((e) => normalize(e, pathStr(parts)));
  if (changedFolder || !keepSelection) clearSelection(false);
  pruneSelection();
  if (select) selectOnly(joinPath(pathStr(parts), select));
  render();
  if (changedFolder) replay($("#items"));
  if (changedFolder) $("#content").scrollTop = 0;
  refreshUsage();
}

async function runSearch(q) {
  state.query = q;
  if (!q.trim()) {
    if (state.view === "search") navigate(state.cwd);
    return;
  }
  let hits;
  try { hits = await load(() => call("search", { query: q })); } catch (e) { if (state.unlocked) toastError(e); return; }
  if (hits === undefined || state.query !== q) return;
  state.view = "search";
  state.entries = hits.map((h) => {
    const entry = h.entry || h;
    return { key: h.path, name: entry.name, is_dir: entry.is_dir, size: entry.size, mtime: entry.mtime, path: h.path, parent: h.parent };
  });
  clearSelection(false);
  render();
}

function refresh() {
  if (state.view === "search") return runSearch(state.query);
  return navigate(state.cwd, { keepSelection: true });
}

let usageTimer;
function refreshUsage() {
  clearTimeout(usageTimer);
  usageTimer = setTimeout(async () => {
    try {
      if (state.vaultTabs.length === 0) {
        const fill = $("#usage-fill");
        fill.style.setProperty("width", "0");
        fill.classList.remove("warn", "full");
        $("#usage-text").textContent = "Unlock a vault to view storage";
        return;
      }
      const a = await call("account");
      const pct = a.quota_bytes ? Math.min(100, (a.used_bytes / a.quota_bytes) * 100) : 0;
      const fill = $("#usage-fill");
      fill.style.setProperty("width", a.quota_bytes ? pct + "%" : "0%");
      fill.classList.toggle("warn", pct >= 80 && pct < 95);
      fill.classList.toggle("full", pct >= 95);
      $("#usage-text").textContent = a.quota_bytes ? `${human(a.used_bytes)} of ${human(a.quota_bytes)} used` : `${human(a.used_bytes)} used`;
      state.account = a;
    } catch { /* non-critical */ }
  }, 150);
}

// ---------------------------------------------------------------- rendering

function sortEntries() {
  const { key, dir } = state.sort;
  const cmpName = (a, b) => a.name.localeCompare(b.name, undefined, { numeric: true, sensitivity: "base" });
  state.entries.sort((a, b) => {
    if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1;
    let c = 0;
    if (key === "size") c = a.size - b.size;
    else if (key === "mtime") c = a.mtime - b.mtime;
    return (c || cmpName(a, b)) * dir;
  });
}

function renderBreadcrumb() {
  const nav = $("#breadcrumb");
  const crumbs = [];
  if (state.view === "search") {
    crumbs.push(el("button", { class: "crumb current", text: `Results for “${state.query.trim()}”` }));
  } else {
    const all = [{ name: rootName(), parts: [] }, ...state.cwd.map((n, i) => ({ name: n, parts: state.cwd.slice(0, i + 1) }))];
    // Collapse long paths: Vault › … › last two.
    const shown = all.length > 4 ? [all[0], null, ...all.slice(-2)] : all;
    shown.forEach((c, i) => {
      if (i > 0) crumbs.push(el("span", { class: "crumb-sep" }, icon("chevron-right")));
      if (c === null) {
        const hidden = all.slice(1, -2);
        crumbs.push(el("button", { class: "crumb", text: "…", title: hidden.map((h) => h.name).join(" › "), onclick: (e) => showMenu(e, hidden.map((h) => ({ label: h.name, icon: "folder", fn: () => navigate(h.parts) }))) }));
        return;
      }
      const isLast = c === shown[shown.length - 1];
      crumbs.push(el("button", {
        class: "crumb" + (isLast ? " current" : ""), text: c.name, title: c.name,
        data: { dropPath: pathStr(c.parts) },
        onclick: () => (isLast ? null : navigate(c.parts)),
        oncontextmenu: isLast ? (e) => backgroundMenu(e) : null,
      }));
    });
  }
  nav.replaceChildren(...crumbs);
}

function render() {
  sortEntries();
  renderBreadcrumb();
  $("#btn-refresh").hidden = state.view === "search" || state.vaultTabs.length === 0;
  const content = $("#content");
  content.classList.toggle("with-loc", state.view !== "drive");
  content.classList.toggle("grid-mode", state.layout === "grid");
  $("#head-loc").textContent = "Location";
  $("#head-date").firstChild.textContent = "Modified";
  for (const b of $$(".list-head .sort")) {
    const active = b.dataset.sort === state.sort.key;
    b.classList.toggle("active", active);
    b.querySelector("svg")?.remove();
    if (active) b.append(icon(state.sort.dir > 0 ? "chevron-up" : "chevron-down"));
  }

  const items = $("#items");
  items.className = "items " + state.layout;
  const nodes = [];
  if (state.layout === "grid") {
    const folders = state.entries.filter((e) => e.is_dir), files = state.entries.filter((e) => !e.is_dir);
    if (folders.length) nodes.push(el("div", { class: "grid-section", text: "Folders" }), ...folders.map(cardItem));
    if (files.length) nodes.push(el("div", { class: "grid-section", text: "Files" }), ...files.map(cardItem));
  } else {
    nodes.push(...state.entries.map(rowItem));
  }
  items.replaceChildren(...nodes);
  renderEmpty();
  renderSelection();
}

function renderEmpty() {
  const empty = state.entries.length === 0;
  $("#empty").hidden = !empty;
  $("#list-head").hidden = empty;
  if (!empty) return;
  const [ic, title, text] =
    state.vaultTabs.length === 0 ? ["lock", "No vaults unlocked", "Unlock one of your vaults from the sidebar to view its files."]
    : state.view === "search" ? ["search-x", "No matches", "No file or folder names contain that text."]
    : state.cwd.length ? ["folder", "This folder is empty", "Drop files here, or use New to upload files or create a folder."]
    : ["upload", "This vault is empty", "Drop files anywhere in this window, or use New → File upload. Everything is encrypted before it leaves this computer."];
  $("#empty-icon").replaceChildren(icon(ic));
  $("#empty-title").textContent = title;
  $("#empty-text").textContent = text;
}

function checkbox(it) {
  return el("span", {
    class: "cb", attrs: { role: "checkbox", "aria-label": "Select " + it.name },
    onclick: (e) => { e.stopPropagation(); toggleSelect(it.key); },
    onpointerdown: (e) => e.stopPropagation(),
  }, icon("check"));
}

function moreButton(it) {
  return el("button", {
    class: "icon-btn more-btn", attrs: { "aria-label": "More actions" },
    onclick: (e) => { e.stopPropagation(); if (!state.selected.has(it.key)) selectOnly(it.key); itemMenu(e, true); },
    onpointerdown: (e) => e.stopPropagation(),
  }, icon("more"));
}

function locationCell(it) {
  if (state.view === "drive") return el("span", { class: "col-loc" });
  const label = it.parent === "/" ? rootName() : pathParts(it.parent).pop();
  return el("span", { class: "col-loc" }, el("button", {
    class: "loc-link", title: it.parent === "/" ? rootName() : rootName() + it.parent.replaceAll("/", " › "),
    onclick: (e) => { e.stopPropagation(); if (state.view === "search") navigate(pathParts(it.parent), { select: it.name }); },
  }, icon("folder"), el("span", { text: label })));
}

function bindItem(node, it) {
  node.dataset.key = it.key;
  node.setAttribute("role", "option");
  if (it.is_dir) node.dataset.dropPath = it.path;
  node.classList.toggle("selected", state.selected.has(it.key));
  node.classList.toggle("focused", state.focus === it.key);
  node.addEventListener("click", (e) => clickItem(e, it));
  node.addEventListener("dblclick", () => openItem(it));
  node.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    if (!state.selected.has(it.key)) selectOnly(it.key);
    itemMenu(e);
  });
  node.addEventListener("pointerdown", (e) => startItemDrag(e, it));
  return node;
}

function rowItem(it) {
  const dateTitle = longDate(it.mtime);
  return bindItem(el("div", { class: "item row-item" },
    el("span", { class: "col-check" }, checkbox(it)),
    el("span", { class: "col-name", title: it.name }, ftype(it.name, it.is_dir), el("span", { class: "name-text", text: it.name })),
    locationCell(it),
    el("span", { class: "col-date", text: shortDate(it.mtime), title: dateTitle }),
    el("span", { class: "col-size", text: it.is_dir ? "—" : human(it.size) }),
    el("span", { class: "col-more" }, moreButton(it)),
  ), it);
}

function cardItem(it) {
  const cat = catOf(it.name, it.is_dir);
  return bindItem(el("div", { class: "item card" + (it.is_dir ? " folder-card" : ""), vars: { "--c": `var(--t-${cat})` }, title: it.name },
    checkbox(it),
    el("div", { class: "card-thumb" }, icon(CAT_ICON[cat])),
    el("div", { class: "card-top" }, ftype(it.name, it.is_dir), el("span", { class: "name-text", text: it.name }), moreButton(it)),
    el("div", { class: "card-meta" }, el("span", { text: shortDate(it.mtime) }), el("span", { text: it.is_dir ? "" : human(it.size) })),
  ), it);
}

function setLayout(layout) {
  state.layout = layout;
  prefs.set("layout", layout);
  $("#view-list").setAttribute("aria-pressed", layout === "list");
  $("#view-grid").setAttribute("aria-pressed", layout === "grid");
}
$("#view-list").addEventListener("click", () => { setLayout("list"); render(); });
$("#view-grid").addEventListener("click", () => { setLayout("grid"); render(); });

for (const b of $$(".list-head .sort")) {
  b.addEventListener("click", () => {
    const key = b.dataset.sort;
    state.sort = { key, dir: state.sort.key === key ? -state.sort.dir : key === "name" ? 1 : -1 };
    prefs.set("sort", state.sort);
    render();
  });
}

// ---------------------------------------------------------------- selection

const byKey = (k) => state.entries.find((e) => e.key === k);
const selectedItems = () => state.entries.filter((e) => state.selected.has(e.key));

function pruneSelection() {
  const keys = new Set(state.entries.map((e) => e.key));
  for (const k of [...state.selected]) if (!keys.has(k)) state.selected.delete(k);
  if (state.focus && !keys.has(state.focus)) state.focus = null;
}

function updateItemClasses() {
  for (const n of $$("#items .item")) {
    n.classList.toggle("selected", state.selected.has(n.dataset.key));
    n.classList.toggle("focused", state.focus === n.dataset.key);
    n.setAttribute("aria-selected", state.selected.has(n.dataset.key));
  }
  renderSelection();
}

function clearSelection(update = true) {
  state.selected.clear();
  state.anchor = null;
  if (update) updateItemClasses();
}
function selectOnly(key) {
  state.selected = new Set([key]);
  state.anchor = state.focus = key;
  updateItemClasses();
}
function toggleSelect(key) {
  if (state.selected.has(key)) state.selected.delete(key); else state.selected.add(key);
  state.anchor = state.focus = key;
  updateItemClasses();
}
function selectRange(toKey) {
  const keys = state.entries.map((e) => e.key);
  const a = keys.indexOf(state.anchor ?? toKey), b = keys.indexOf(toKey);
  const [lo, hi] = a < b ? [a, b] : [b, a];
  state.selected = new Set(keys.slice(lo, hi + 1));
  state.focus = toKey;
  updateItemClasses();
}

function clickItem(e, it) {
  if (suppressClick) return;
  if (e.shiftKey && state.anchor) selectRange(it.key);
  else if (e.ctrlKey || e.metaKey) toggleSelect(it.key);
  else selectOnly(it.key);
}

function renderSelection() {
  const sel = selectedItems();
  $("#items").classList.toggle("has-selection", sel.length > 0);
  const all = $("#select-all");
  all.classList.toggle("checked", sel.length > 0 && sel.length === state.entries.length);
  all.classList.toggle("partial", sel.length > 0 && sel.length < state.entries.length);
  all.setAttribute("aria-checked", sel.length === 0 ? "false" : sel.length === state.entries.length ? "true" : "mixed");
  $("#selection-bar").hidden = sel.length === 0;
  if (!sel.length) return;
  $("#sel-count").textContent = `${sel.length} selected`;
  const acts = actionsFor(sel).filter((a) => a.bar);
  $("#sel-actions").replaceChildren(...acts.map((a) =>
    el("button", { class: "btn sm" + (a.danger ? " danger-ghost" : ""), title: a.label + (a.shortcut ? ` (${a.shortcut})` : ""), onclick: a.fn }, icon(a.icon), el("span", { text: a.label }))));
}
$("#sel-clear").addEventListener("click", () => clearSelection());
$("#select-all").addEventListener("click", () => {
  if (state.selected.size === state.entries.length) clearSelection();
  else { state.selected = new Set(state.entries.map((x) => x.key)); updateItemClasses(); }
});

// Clicking empty space clears the selection.
$("#content").addEventListener("click", (e) => {
  if (!e.target.closest(".item, .list-head, button") && !suppressClick) clearSelection();
});

// ---------------------------------------------------------------- actions

function actionsFor(items) {
  const one = items.length === 1 ? items[0] : null;
  const acts = [];
  if (one) acts.push({ label: one.is_dir ? "Open" : "Preview", icon: "open", fn: () => openItem(one), shortcut: "Enter" });
  acts.push({ label: "Download", icon: "download", bar: true, fn: () => downloadItems(items) });
  if (one) acts.push({ label: "Rename", icon: "edit", bar: true, shortcut: "F2", fn: () => renameItem(one) });
  acts.push({ label: "Move to…", icon: "move", bar: true, fn: () => moveItems(items) });
  if (state.view === "search" && one) acts.push({ label: "Show in folder", icon: "folder", fn: () => navigate(pathParts(one.parent), { select: one.name }) });
  acts.push({ sep: true });
  acts.push({ label: "Delete permanently", icon: "trash", danger: true, bar: true, shortcut: "Del", fn: () => deleteForever(items) });
  return acts;
}

async function openItem(it) {
  if (it.is_dir) return navigate(pathParts(it.path));
  return openPreview(it);
}

async function downloadItems(items) {
  if (!items.length) return;
  try {
    if (items.length === 1 && !items[0].is_dir) {
      const dest = await dialog.save({ defaultPath: items[0].name, title: "Save decrypted copy" });
      if (!dest) return;
      transfers.show();
      const r = await call("download", { items: [{ path: items[0].path, is_dir: false }], dest });
      if (r.failed) toast(`Couldn't download “${items[0].name}”.`, { type: "error" });
    } else {
      const dir = await dialog.open({ directory: true, title: "Choose where to save" });
      if (!dir) return;
      transfers.show();
      const r = await call("download", { items: items.map((i) => ({ path: i.path, is_dir: i.is_dir })), destDir: dir });
      if (r.failed) toast(`${r.failed} item${r.failed === 1 ? "" : "s"} couldn't be downloaded.`, { type: "error" });
    }
  } catch (e) { if (state.unlocked) toastError(e); }
}

async function renameItem(it) {
  const siblings = state.view === "drive" ? state.entries.filter((e) => e !== it).map((e) => e.name) : [];
  const to = await modal({
    title: "Rename",
    input: { value: it.name, selectStem: !it.is_dir },
    actions: [{ label: "Cancel", value: null }, { label: "Rename", value: true, primary: true }],
    validate: (v) => validateName(v, siblings),
  });
  if (!to || to.trim() === it.name) return;
  const name = to.trim();
  try {
    await call("rename", { from: it.path, to: joinPath(it.parent, name) });
    if (state.view === "search") await runSearch(state.query);
    else await navigate(state.cwd, { select: name });
  } catch (e) { if (state.unlocked) toastError(e); }
}

async function createFolder() {
  if (state.view !== "drive") await navigate(state.cwd);
  const names = state.entries.map((e) => e.name);
  let def = "Untitled folder", n = 1;
  while (names.includes(def)) def = `Untitled folder (${n++})`;
  const name = await modal({
    title: "New folder",
    input: { value: def },
    actions: [{ label: "Cancel", value: null }, { label: "Create", value: true, primary: true }],
    validate: (v) => validateName(v, names),
  });
  if (!name) return;
  try {
    await call("mkdir", { path: joinPath(pathStr(state.cwd), name.trim()) });
    await navigate(state.cwd, { select: name.trim() });
  } catch (e) { if (state.unlocked) toastError(e); }
}

async function deleteForever(items) {
  if (!items.length) return;
  const what = items.length === 1 ? `“${items[0].name}”` : `${items.length} items`;
  const folderNote = items.some((i) => i.is_dir) ? " Folders are deleted with everything inside them." : "";
  if (!(await confirmDialog("Delete permanently?", `${what} will be deleted permanently. This can't be undone.${folderNote}`, "Delete permanently", true))) return;
  for (const it of items) {
    try {
      await call("remove", { path: it.path });
    } catch (e) { if (!state.unlocked) return; toastError(e); }
  }
  clearSelection(false);
  await refresh();
  refreshUsage();
}

// ---------------------------------------------------------------- move

async function moveItemsTo(items, targetParts) {
  const target = pathStr(targetParts);
  const movable = items.filter((it) => it.parent !== target && !(it.is_dir && (target === it.path || target.startsWith(it.path + "/"))));
  if (!movable.length) return;
  let ok = 0;
  for (const it of movable) {
    try { await call("rename", { from: it.path, to: joinPath(target, it.name) }); ok++; } catch (e) {
      if (!state.unlocked) return;
      toast(/already exists/i.test(String(e)) ? `“${it.name}” already exists in that folder.` : `${it.name}: ${friendly(e)}`, { type: "error" });
    }
  }
  await refresh();
  if (ok) {
    const where = targetParts.length ? targetParts[targetParts.length - 1] : rootName();
    toast(ok === 1 ? `Moved “${movable[0].name}” to ${where}` : `Moved ${ok} items to ${where}`, { action: { label: "Open", fn: () => navigate(targetParts) } });
  }
}

let moveState = null;
async function moveItems(items) {
  const dlg = $("#move-dialog");
  const blocked = new Set(items.filter((i) => i.is_dir).map((i) => i.path));
  moveState = { items, parts: pathParts(items[0].parent) };
  $("#move-title").textContent = items.length === 1 ? `Move “${items[0].name}”` : `Move ${items.length} items`;
  const show = async () => {
    const where = pathStr(moveState.parts);
    $("#move-where").textContent = moveState.parts.length ? moveState.parts[moveState.parts.length - 1] : rootName();
    $("#move-up").disabled = moveState.parts.length === 0;
    let list = [];
    try { list = await call("list", { path: where }); } catch (e) { if (!state.unlocked) return; toastError(e); }
    const dirs = list.filter((e) => e.is_dir).sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
    const rows = dirs.map((d) => {
      const p = joinPath(where, d.name);
      const off = blocked.has(p);
      return el("li", {}, el("button", { disabled: off, title: off ? "Can't move a folder into itself" : "", ondblclick: () => { moveState.parts = pathParts(p); show(); }, onclick: () => { moveState.parts = pathParts(p); show(); } },
        icon("folder"), el("span", { class: "name-text", text: d.name }), icon("chevron-right")));
    });
    $("#move-list").replaceChildren(...(rows.length ? rows : [el("li", { class: "empty-row", text: "No folders here" })]));
    const same = items.every((i) => i.parent === where);
    $("#move-ok").disabled = same;
    $("#move-ok").textContent = same ? "Already here" : "Move here";
  };
  dlg.showModal();
  await show();
  moveState.show = show;
}
$("#move-up").addEventListener("click", () => { moveState.parts.pop(); moveState.show(); });
$("#move-cancel").addEventListener("click", () => $("#move-dialog").close());
$("#move-ok").addEventListener("click", async () => {
  $("#move-dialog").close();
  await moveItemsTo(moveState.items, [...moveState.parts]);
});
$("#move-newfolder").addEventListener("click", async () => {
  const name = await modal({ title: "New folder", input: { value: "Untitled folder" }, actions: [{ label: "Cancel", value: null }, { label: "Create", value: true, primary: true }], validate: (v) => validateName(v) });
  if (!name) return;
  try {
    await call("mkdir", { path: joinPath(pathStr(moveState.parts), name.trim()) });
    moveState.parts.push(name.trim());
    await moveState.show();
  } catch (e) { if (state.unlocked) toastError(e); }
});

// ---------------------------------------------------------------- upload

async function pickAndUpload(directory) {
  const picked = await dialog.open({ multiple: true, directory, title: directory ? "Upload folder" : "Upload files" });
  if (!picked) return;
  const paths = Array.isArray(picked) ? picked : [picked];
  await uploadPaths(paths, state.view === "drive" ? state.cwd : []);
}

async function uploadPaths(paths, targetParts) {
  if (!paths.length || !state.unlocked) return;
  if (!state.vaultTabs.length) { toast("No vault is unlocked. Unlock one from the sidebar first.", { type: "error" }); return; }
  const dir = pathStr(targetParts);
  // Ask once about name clashes with existing files in the target folder.
  let conflict = "keep_both";
  try {
    const existing = await call("list", { path: dir });
    const files = new Set(existing.filter((e) => !e.is_dir).map((e) => e.name));
    const clashes = paths.map(baseName).filter((n) => files.has(n));
    if (clashes.length) {
      const msg = clashes.length === 1
        ? `“${clashes[0]}” already exists in this location. Replace it, or keep both?`
        : `${clashes.length} items already exist in this location. Replace them, or keep both?`;
      const choice = await modal({
        title: "Upload options",
        body: msg,
        actions: [{ label: "Cancel", value: null }, { label: "Replace", value: "replace" }, { label: "Keep both", value: "keep_both", primary: true }],
      });
      if (!choice) return;
      conflict = choice;
    }
  } catch (e) {
    if (!state.unlocked) return;
    toastError(e);
    return;
  }
  transfers.show();
  try {
    const r = await call("upload", { paths, dir, conflict });
    if (r.skipped.length) toast(`Skipped ${r.skipped.length} item(s) that aren't regular files or folders.`);
    if (r.failed) toast(`${r.failed} upload${r.failed === 1 ? "" : "s"} failed. See the transfers panel for details.`, { type: "error" });
  } catch (e) { if (state.unlocked) toastError(e); }
  if (state.unlocked) {
    if (state.view === "drive" && (pathStr(state.cwd) === dir || dir.startsWith(pathStr(state.cwd)))) await navigate(state.cwd, { keepSelection: true });
    refreshUsage();
  }
}

// ---------------------------------------------------------------- transfers panel

const transfers = (() => {
  const rows = new Map(); // id -> { li, ev }
  let collapsed = false;
  const panel = $("#transfers");

  function row(ev) {
    const bar = el("div");
    const li = el("li", { class: "transfer" },
      ftype(ev.name, false),
      el("div", { class: "t-name", text: ev.name, title: ev.name }),
      el("div", { class: "t-state" }),
      el("div", { class: "t-bar" }, bar),
      el("div", { class: "t-sub" }));
    return { li, bar };
  }

  function update(ev) {
    let r = rows.get(ev.id);
    if (!r) {
      r = row(ev);
      rows.set(ev.id, r);
      $("#transfers-list").prepend(r.li);
    }
    r.ev = ev;
    $(".t-name", r.li).textContent = ev.name;
    const pct = ev.total ? Math.min(100, (ev.done / ev.total) * 100) : 0;
    r.bar.style.setProperty("width", (ev.state === "done" ? 100 : pct) + "%");
    $(".t-bar", r.li).hidden = ev.state !== "active" && ev.state !== "queued";
    const sub = $(".t-sub", r.li);
    sub.classList.toggle("err", ev.state === "error");
    const where = ev.kind === "upload" ? (ev.target === "/" ? rootName() : pathParts(ev.target).pop()) : ev.target;
    sub.textContent =
      ev.state === "queued" ? "Waiting…"
      : ev.state === "active" ? (ev.total ? `${human(ev.done)} of ${human(ev.total)}` : "Starting…")
      : ev.state === "done" ? (ev.kind === "upload" ? `Uploaded to ${where}` : `Saved to ${where}`)
      : ev.state === "cancelled" ? "Cancelled"
      : friendly(ev.error || "Failed");
    sub.title = ev.state === "done" ? ev.target : sub.textContent;
    const st = $(".t-state", r.li);
    if (ev.state === "queued" || ev.state === "active") {
      st.replaceChildren(el("button", { class: "icon-btn", title: "Cancel", attrs: { "aria-label": "Cancel" }, onclick: () => invoke("cancel_transfer", { id: ev.id }) }, icon("x")));
    } else {
      st.replaceChildren(icon(ev.state === "done" ? "check-circle" : ev.state === "cancelled" ? "x" : "alert", ev.state === "done" ? "t-ok" : ev.state === "cancelled" ? "t-cancel" : "t-err"));
    }
    show();
    summarize();
  }

  function active() {
    return [...rows.values()].some((r) => r.ev.state === "active" || r.ev.state === "queued");
  }

  function summarize() {
    const all = [...rows.values()].map((r) => r.ev);
    const running = all.filter((e) => e.state === "active" || e.state === "queued");
    const ups = running.filter((e) => e.kind === "upload").length, downs = running.length - ups;
    const failed = all.filter((e) => e.state === "error").length;
    const done = all.filter((e) => e.state === "done").length;
    $("#transfers-title").textContent = running.length
      ? [ups && `Uploading ${ups} item${ups === 1 ? "" : "s"}`, downs && `Downloading ${downs} item${downs === 1 ? "" : "s"}`].filter(Boolean).join(" · ")
      : failed ? `${done} done, ${failed} failed` : `${done} transfer${done === 1 ? "" : "s"} complete`;
    if (running.length) {
      const total = running.reduce((s, e) => s + e.total, 0), d = running.reduce((s, e) => s + Math.min(e.done, e.total), 0);
      $("#transfers-summary").textContent = total ? `${Math.round((d / total) * 100)}% · ${human(total - d)} left` : "Preparing…";
    } else {
      $("#transfers-summary").textContent = "All transfers finished";
    }
    $("#transfers-cancel").hidden = !running.length;
    $("#transfers-close").hidden = running.length > 0;
  }

  function show() {
    panel.hidden = rows.size === 0;
    panel.classList.toggle("collapsed", collapsed);
    $("#transfers-toggle").replaceChildren(icon(collapsed ? "chevron-up" : "chevron-down"));
  }

  function clear() {
    rows.clear();
    $("#transfers-list").replaceChildren();
    panel.hidden = true;
  }

  $("#transfers-toggle").addEventListener("click", () => { collapsed = !collapsed; show(); });
  $("#transfers-close").addEventListener("click", clear);
  $("#transfers-cancel").addEventListener("click", () => invoke("cancel_transfer", { id: null }));

  return { update, active, clear, show: () => { if (rows.size) show(); } };
})();

listen("transfer", (e) => transfers.update(e.payload));

// ---------------------------------------------------------------- preview

let previewUrl = null;
let previewItem = null;
let previewSeq = 0;

let previewBytes = null;

function closePreview() {
  const pv = $("#preview");
  if (pv) setShown(pv, false, 140);
  $("#preview-stage")?.replaceChildren();
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  // The decrypted file: overwrite our copy rather than leave it for the garbage collector.
  previewBytes?.fill(0);
  previewBytes = null;
  previewUrl = null;
  previewItem = null;
}

function previewSiblings() {
  return state.entries.filter((e) => !e.is_dir);
}

async function openPreview(it) {
  const seq = ++previewSeq;
  previewItem = it;
  if (previewUrl) { URL.revokeObjectURL(previewUrl); previewUrl = null; }
  setShown($("#preview"), true);
  $("#preview-name").textContent = it.name;
  $("#preview-icon").replaceChildren(ftype(it.name, false));
  const sibs = previewSiblings(), idx = sibs.indexOf(it);
  $("#preview-prev").hidden = idx <= 0;
  $("#preview-next").hidden = idx < 0 || idx >= sibs.length - 1;
  const stage = $("#preview-stage");
  const message = (text, withDownload = true) => stage.replaceChildren(el("div", { class: "preview-msg" },
    ftype(it.name, false),
    el("div", { text }),
    withDownload ? el("button", { class: "btn on-dark", onclick: () => downloadItems([it]) }, icon("download"), el("span", { text: "Download" })) : null));

  const kind = previewKind(it.name);
  if (!kind) return message("No preview available for this type of file.");
  if (it.size > MAX_PREVIEW) return message("This file is too large to preview.");
  if (kind === "text" && extOf(it.name) === "" && it.size > MAX_TEXT_PREVIEW) return message("No preview available for this file.");
  stage.replaceChildren(el("div", { class: "preview-msg" }, el("span", { class: "spinner" }), el("div", { text: "Decrypting…" })));

  let buf;
  try { buf = await call("preview", { path: it.path }); } catch (e) {
    if (seq === previewSeq && state.unlocked) message(friendly(e));
    return;
  }
  if (seq !== previewSeq) { new Uint8Array(buf).fill(0); return; }
  previewBytes?.fill(0);
  const bytes = previewBytes = new Uint8Array(buf);
  if (kind === "text") {
    const slice = bytes.subarray(0, MAX_TEXT_PREVIEW);
    let text = new TextDecoder("utf-8", { fatal: false }).decode(slice);
    if (/\u0000/.test(text.slice(0, 4096))) return message("This looks like a binary file, so there's no preview.");
    if (bytes.length > MAX_TEXT_PREVIEW) text += "\n\n… (preview truncated)";
    stage.replaceChildren(el("pre", { text }));
    return;
  }
  previewUrl = URL.createObjectURL(new Blob([bytes], { type: MIME[extOf(it.name)] || "application/octet-stream" }));
  if (kind === "image") {
    const img = el("img", { alt: it.name, src: previewUrl, onerror: () => message("This image can't be displayed.") });
    stage.replaceChildren(img);
  } else if (kind === "video") {
    stage.replaceChildren(el("video", { src: previewUrl, controls: true, autoplay: true, onerror: () => message("This video format can't be played here.") }));
  } else if (kind === "audio") {
    stage.replaceChildren(el("div", { class: "preview-msg" }, ftype(it.name, false), el("audio", { src: previewUrl, controls: true, autoplay: true })));
  } else if (kind === "pdf") {
    stage.replaceChildren(el("iframe", { src: previewUrl, title: it.name }));
  }
}

function previewStep(d) {
  const sibs = previewSiblings(), idx = sibs.indexOf(previewItem);
  const next = sibs[idx + d];
  if (next) { selectOnly(next.key); openPreview(next); }
}
$("#preview-close").addEventListener("click", closePreview);
$("#preview-prev").addEventListener("click", () => previewStep(-1));
$("#preview-next").addEventListener("click", () => previewStep(1));
$("#preview-download").addEventListener("click", () => previewItem && downloadItems([previewItem]));

// ---------------------------------------------------------------- context menus

function showMenu(e, entries) {
  e.preventDefault();
  e.stopPropagation();
  const m = $("#menu");
  m.replaceChildren(...entries.map((a) => a.sep
    ? el("div", { class: "menu-sep" })
    : el("button", { class: "menu-item" + (a.danger ? " danger" : ""), attrs: { role: "menuitem" }, onclick: () => { hideMenu(); a.fn(); } },
      icon(a.icon), el("span", { text: a.label }), a.shortcut ? el("span", { class: "shortcut", text: a.shortcut }) : null)));
  m.hidden = false;
  const r = m.getBoundingClientRect();
  let x = e.clientX, y = e.clientY;
  if (e.type === "click" && e.currentTarget?.getBoundingClientRect) {
    const b = e.currentTarget.getBoundingClientRect();
    x = b.left; y = b.bottom + 4;
  }
  x = Math.min(x, innerWidth - r.width - 8);
  y = y + r.height > innerHeight - 8 ? Math.max(8, y - r.height) : y;
  m.style.setProperty("left", x + "px");
  m.style.setProperty("top", y + "px");
  m.querySelector(".menu-item")?.focus();
}
function hideMenu() { $("#menu").hidden = true; }
document.addEventListener("pointerdown", (e) => { if (!e.target.closest("#menu")) hideMenu(); });
window.addEventListener("blur", hideMenu);
window.addEventListener("resize", hideMenu);

function itemMenu(e) {
  const acts = actionsFor(selectedItems());
  // Drop a leading/trailing separator.
  showMenu(e, acts.filter((a, i) => !(a.sep && (i === 0 || i === acts.length - 1))));
}

function newMenuEntries() {
  return [
    { label: "New folder", icon: "folder-plus", shortcut: "Ctrl+Shift+N", fn: createFolder },
    { sep: true },
    { label: "File upload", icon: "file-up", shortcut: "Ctrl+U", fn: () => pickAndUpload(false) },
    { label: "Folder upload", icon: "folder-up", fn: () => pickAndUpload(true) },
  ];
}

function backgroundMenu(e) {
  showMenu(e, [...newMenuEntries(), { sep: true }, { label: "Refresh", icon: "refresh", shortcut: "F5", fn: refresh }]);
}

$("#btn-new").addEventListener("click", (e) => showMenu(e, newMenuEntries()));
$("#content").addEventListener("contextmenu", (e) => { if (!e.target.closest(".item")) { clearSelection(); backgroundMenu(e); } });
// No browser context menu anywhere except in text fields.
document.addEventListener("contextmenu", (e) => { if (!e.target.closest("input, textarea, pre")) e.preventDefault(); });

// ---------------------------------------------------------------- nav, search, buttons

$("#btn-refresh").addEventListener("click", refresh);

let searchTimer;
$("#search").addEventListener("input", (e) => {
  clearTimeout(searchTimer);
  const q = e.target.value;
  searchTimer = setTimeout(() => runSearch(q), q.trim() ? 300 : 0);
});
$("#search").addEventListener("keydown", (e) => {
  if (e.key === "Escape") { e.target.value = ""; runSearch(""); e.target.blur(); }
  if (e.key === "Enter") { clearTimeout(searchTimer); runSearch(e.target.value); }
  if (e.key === "ArrowDown" && state.entries.length) { e.preventDefault(); $("#content").focus(); moveFocus(1, false); }
});

// ---------------------------------------------------------------- keyboard

function moveFocus(delta, extend) {
  if (!state.entries.length) return;
  const keys = state.entries.map((e) => e.key);
  let i = keys.indexOf(state.focus);
  let step = delta;
  if (state.layout === "grid" && Math.abs(delta) === 10) {
    const items = $$("#items .item");
    const perRow = Math.max(1, Math.round($("#items").clientWidth / (items[0]?.offsetWidth + 14 || 190)));
    step = Math.sign(delta) * perRow;
  }
  i = i < 0 ? 0 : Math.max(0, Math.min(keys.length - 1, i + step));
  const k = keys[i];
  if (extend) { state.anchor ??= state.focus ?? k; selectRange(k); } else selectOnly(k);
  $(`#items .item[data-key="${CSS.escape(k)}"]`)?.scrollIntoView({ block: "nearest" });
}

document.addEventListener("keydown", (e) => {
  if (!state.unlocked || $("#view-drive").hidden) return;
  const typing = e.target.closest("input, textarea, select");
  const ctrl = e.ctrlKey || e.metaKey;
  if (e.key === "F5" || (ctrl && e.key.toLowerCase() === "r")) { e.preventDefault(); refresh(); return; }
  if (ctrl && e.key.toLowerCase() === "l") { e.preventDefault(); lockNow(); return; }

  if (!$("#preview").hidden) {
    if (e.key === "Escape") { e.preventDefault(); closePreview(); }
    else if (e.key === "ArrowLeft") previewStep(-1);
    else if (e.key === "ArrowRight") previewStep(1);
    return;
  }
  if (document.querySelector("dialog[open]") || typing) return;
  if (!$("#menu").hidden) { if (e.key === "Escape") hideMenu(); return; }

  const sel = selectedItems();
  if (ctrl && e.key.toLowerCase() === "k" || e.key === "/") { e.preventDefault(); $("#search").focus(); $("#search").select(); }
  else if (ctrl && e.shiftKey && e.key.toLowerCase() === "n") { e.preventDefault(); createFolder(); }
  else if (ctrl && e.key.toLowerCase() === "u") { e.preventDefault(); pickAndUpload(false); }
  else if (ctrl && e.key.toLowerCase() === "a") { e.preventDefault(); state.selected = new Set(state.entries.map((x) => x.key)); updateItemClasses(); }
  else if (e.key === "Escape") { if (sel.length) clearSelection(); else if (state.view === "search") { $("#search").value = ""; runSearch(""); } }
  else if (e.key === "Delete") { e.preventDefault(); deleteForever(sel); }
  else if (e.key === "F2" && sel.length === 1) { e.preventDefault(); renameItem(sel[0]); }
  else if (e.key === "Enter" && sel.length === 1) { e.preventDefault(); openItem(sel[0]); }
  else if ((e.key === "Backspace" || (e.altKey && e.key === "ArrowUp")) && state.view === "drive" && state.cwd.length) { e.preventDefault(); navigate(state.cwd.slice(0, -1)); }
  else if (e.key === "ArrowDown") { e.preventDefault(); moveFocus(state.layout === "grid" ? 10 : 1, e.shiftKey); }
  else if (e.key === "ArrowUp") { e.preventDefault(); moveFocus(state.layout === "grid" ? -10 : -1, e.shiftKey); }
  else if (e.key === "ArrowRight" && state.layout === "grid") { e.preventDefault(); moveFocus(1, e.shiftKey); }
  else if (e.key === "ArrowLeft" && state.layout === "grid") { e.preventDefault(); moveFocus(-1, e.shiftKey); }
  else if (e.key === "Home") { e.preventDefault(); moveFocus(-1e9, e.shiftKey); }
  else if (e.key === "End") { e.preventDefault(); moveFocus(1e9, e.shiftKey); }
});

// ---------------------------------------------------------------- drag to move (in-app)
// Pointer-based rather than HTML5 drag-and-drop: on Windows the webview's HTML5 DnD is
// disabled while native file drops are enabled, and we need native drops for uploads.

let drag = null;
let suppressClick = false;

function dropTargetAt(x, y, exclude) {
  const t = document.elementFromPoint(x, y)?.closest("[data-drop-path]");
  if (!t) return null;
  const p = t.dataset.dropPath;
  if (exclude && exclude(p)) return null;
  return t;
}

function setDropHover(t) {
  for (const n of $$(".drop-hover")) if (n !== t) n.classList.remove("drop-hover");
  t?.classList.add("drop-hover");
}

function startItemDrag(e, it) {
  if (e.button !== 0 || e.target.closest(".cb, .more-btn, .loc-link")) return;
  drag = { x: e.clientX, y: e.clientY, it, started: false };
}

document.addEventListener("pointermove", (e) => {
  if (!drag) return;
  if (!drag.started) {
    if (Math.hypot(e.clientX - drag.x, e.clientY - drag.y) < 6) return;
    if (!state.selected.has(drag.it.key)) selectOnly(drag.it.key);
    drag.items = selectedItems();
    drag.started = true;
    document.body.classList.add("dragging-items");
    const g = $("#drag-ghost");
    g.replaceChildren(ftype(drag.items[0].name, drag.items[0].is_dir), el("span", { text: drag.items.length === 1 ? drag.items[0].name : `${drag.items.length} items` }));
    g.hidden = false;
    for (const it of drag.items) $(`#items .item[data-key="${CSS.escape(it.key)}"]`)?.classList.add("cut");
  }
  const g = $("#drag-ghost");
  g.style.setProperty("left", e.clientX + "px");
  g.style.setProperty("top", e.clientY + "px");
  const items = drag.items;
  setDropHover(dropTargetAt(e.clientX, e.clientY, (p) =>
    items.some((it) => it.path === p || (it.is_dir && p.startsWith(it.path + "/")) || it.parent === p)));
});

function endDrag(commit, e) {
  if (!drag) return;
  const d = drag;
  drag = null;
  if (!d.started) return;
  document.body.classList.remove("dragging-items");
  $("#drag-ghost").hidden = true;
  $$(".item.cut").forEach((n) => n.classList.remove("cut"));
  const target = $(".drop-hover");
  setDropHover(null);
  suppressClick = true;
  setTimeout(() => { suppressClick = false; }, 0);
  if (commit && target && e) moveItemsTo(d.items, pathParts(target.dataset.dropPath));
}
document.addEventListener("pointerup", (e) => endDrag(true, e));
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && drag) endDrag(false); }, true);
window.addEventListener("blur", () => endDrag(false));

// ---------------------------------------------------------------- native file drop (upload)

let nativeDrop = null;

function nativeTarget(pos) {
  const dpr = window.devicePixelRatio || 1;
  const t = pos ? dropTargetAt(pos.x / dpr, pos.y / dpr) : null;
  if (t) return { el: t, parts: pathParts(t.dataset.dropPath) };
  return { el: null, parts: state.view === "drive" ? state.cwd : [] };
}

function showDropOverlay(target) {
  const name = target.parts.length ? target.parts[target.parts.length - 1] : rootName();
  $("#drop-target").textContent = `Files will be encrypted and uploaded to ${name}`;
  $("#drop-overlay").hidden = false;
  setDropHover(target.el);
}

listen("tauri://drag-enter", (e) => {
  if (!state.unlocked || $("#view-drive").hidden || document.querySelector("dialog[open]") || !$("#preview").hidden) return;
  nativeDrop = { paths: e.payload.paths || [] };
  showDropOverlay(nativeTarget(e.payload.position));
});
listen("tauri://drag-over", (e) => {
  if (!nativeDrop) return;
  showDropOverlay(nativeTarget(e.payload.position));
});
listen("tauri://drag-leave", () => {
  nativeDrop = null;
  $("#drop-overlay").hidden = true;
  setDropHover(null);
});
listen("tauri://drag-drop", async (e) => {
  const active = nativeDrop;
  nativeDrop = null;
  $("#drop-overlay").hidden = true;
  const target = nativeTarget(e.payload.position);
  setDropHover(null);
  if (!active || !state.unlocked) return;
  const paths = e.payload.paths || [];
  if (paths.length) await uploadPaths(paths, target.parts);
});
// Never let the webview navigate to a file dropped onto it.
for (const t of ["dragover", "drop"]) window.addEventListener(t, (e) => e.preventDefault());

// ---------------------------------------------------------------- settings

async function renderKeys() {
  let data;
  try { data = await call("vault_members"); }
  catch (e) { if (state.unlocked) toastError(e); return; }
  const members = data.members;
  const items = members.map((m) => el("li", {},
    el("span", { class: "key-icon" }, icon("key")),
    el("div", { class: "key-meta" },
      el("div", { class: "key-label", text: m.label }),
      el("div", { class: "key-sub", text: "Security key · Account sign-in" + (m.current ? " · Current" : "") })),
    renameButton(m, renderKeys),
    el("button", {
      class: "btn sm danger-ghost", text: "Remove", disabled: members.length <= 1,
      title: members.length <= 1 ? "Keep at least one account sign-in method" : "",
      onclick: async () => {
        const scope = "This key will no longer sign in to the account or open any of its vaults.";
        if (!(await confirmDialog("Remove account sign-in method?", scope, "Remove", true))) return;
        try { await call("vault_remove_member", { id: m.id }); toast("Account sign-in method removed.", { type: "success" }); }
        catch (e) { if (state.unlocked) toastError(e); }
        await renderKeys();
      },
    })));
  if (!items.length) items.push(el("li", { class: "key-empty muted", text: "No account sign-in methods." }));
  $("#keys-list").replaceChildren(...items);
}

$("#btn-settings").addEventListener("click", async () => {
  $("#set-user").textContent = state.profile.username;
  $("#set-server").textContent = state.profile.server_url;
  const a = state.account;
  $("#set-usage").textContent = a ? (a.quota_bytes ? `${human(a.used_bytes)} of ${human(a.quota_bytes)}` : human(a.used_bytes)) : "—";
  $("#pref-autolock").value = String(prefs.get("autolock", 15));
  $("#pref-theme").value = prefs.get("theme", "system");
  recording = null;
  renderPanicCombo();
  $("#keys-list").replaceChildren(el("li", {}, el("span", { class: "spinner" })));
  $("#settings").showModal();
  await renderKeys();
});

$("#settings-close").addEventListener("click", () => $("#settings").close());
$("#settings").addEventListener("close", () => { recording = null; });
$("#pref-autolock").addEventListener("change", (e) => prefs.set("autolock", Number(e.target.value)));
$("#pref-theme").addEventListener("change", (e) => { prefs.set("theme", e.target.value); applyTheme(); });

$("#btn-add-key").addEventListener("click", async () => {
  const label = await askName("Name this security key", "Backup key");
  if (label == null) return;
  try {
    await withKey("Insert the backup security key, enter its PIN and touch it.", () => call("vault_add_account_key", { label }));
    toast("Backup key added for account sign-in. Grant it access from each vault you want it to open.", { type: "success", timeout: 8000 });
  } catch (e) { if (state.unlocked) toast(friendly(e), { type: "error" }); }
  await renderKeys();
});

// ---------------------------------------------------------------- panic key
// A user-chosen combination of 1-3 keys held together. Off by default. Pressing it wipes the
// keys in the Rust core (zeroize), clears everything the UI shows and reloads the page so the
// JS heap holding file names is discarded.

const MODIFIERS = ["Control", "Shift", "Alt", "Meta"];
const pressed = new Set();
let recording = null; // Set of keys while recording a new combination
let panicking = false;

/** event.code with left/right variants of modifiers folded together. */
function normKey(code) {
  const m = /^(Control|Shift|Alt|Meta)(Left|Right)$/.exec(code);
  return m ? m[1] : code;
}

function keyLabel(k) {
  if (k === "Control") return "Ctrl";
  if (k === "Meta") return "Win";
  return k.replace(/^Key/, "").replace(/^Digit/, "").replace(/^Numpad/, "Num ").replace(/^Arrow/, "") || k;
}

function sortCombo(keys) {
  return [...keys].sort((a, b) => {
    const ia = MODIFIERS.indexOf(a), ib = MODIFIERS.indexOf(b);
    return (ia < 0 ? 9 : ia) - (ib < 0 ? 9 : ib) || a.localeCompare(b);
  });
}

function panicCombo() {
  const c = prefs.get("panicCombo", null);
  return Array.isArray(c) && c.length >= 1 && c.length <= 3 ? c : null;
}

function renderPanicCombo() {
  const el_ = $("#panic-combo");
  el_.classList.toggle("recording", !!recording);
  if (recording) {
    el_.replaceChildren(document.createTextNode(recording.size ? "" : "Press up to 3 keys together…"),
      ...sortCombo(recording).map((k) => el("kbd", { text: keyLabel(k) })));
  } else {
    const c = panicCombo();
    el_.replaceChildren(...(c ? sortCombo(c).map((k) => el("kbd", { text: keyLabel(k) })) : [document.createTextNode("Not set")]));
  }
  $("#panic-record").textContent = recording ? "Cancel" : panicCombo() ? "Change…" : "Set…";
  $("#panic-clear").hidden = !!recording || !panicCombo();
}

/** Single plain keys would fire while typing (file names, search), so require a modifier or
 *  a function key. */
function comboProblem(keys) {
  if (keys.length > 3) return "Use at most 3 keys.";
  if (keys.includes("Escape")) return "Escape is used to close dialogs; choose other keys.";
  const safe = keys.some((k) => MODIFIERS.includes(k) || /^F\d{1,2}$/.test(k) || k === "Pause" || k === "ScrollLock");
  if (!safe) return "Include Ctrl, Alt, Shift or a function key (F1–F12), so normal typing can't trigger it.";
  if (keys.every((k) => MODIFIERS.includes(k)) && keys.length === 1) return "A single modifier key would trigger too easily; add another key.";
  return null;
}

$("#panic-record").addEventListener("click", () => {
  recording = recording ? null : new Set();
  renderPanicCombo();
});
$("#panic-clear").addEventListener("click", () => {
  prefs.set("panicCombo", null);
  renderPanicCombo();
  toast("Panic key removed.");
});

async function panicNow() {
  if (panicking) return;
  panicking = true;
  const wiped = invoke("panic_lock").catch(() => {});
  // While Rust wipes the keys: zero the decrypted preview buffer, drop every on-screen trace.
  closePreview();
  try { sessionStorage.clear(); localStorage.removeItem("fd.server"); } catch { /* ignore */ }
  document.body.replaceChildren();
  document.title = "Strongbox";
  await Promise.race([wiped, new Promise((r) => setTimeout(r, 1500))]);
  location.reload();
}

window.addEventListener("keydown", (e) => {
  const k = normKey(e.code);
  if (recording) {
    e.preventDefault();
    e.stopImmediatePropagation();
    if (k === "Escape" && recording.size === 0) { recording = null; renderPanicCombo(); return; }
    pressed.add(k);
    recording.add(k);
    renderPanicCombo();
    return;
  }
  pressed.add(k);
  const combo = panicCombo();
  if (combo && pressed.size === combo.length && combo.every((c) => pressed.has(c))) {
    e.preventDefault();
    e.stopImmediatePropagation();
    panicNow();
  }
}, true);

window.addEventListener("keyup", (e) => {
  pressed.delete(normKey(e.code));
  if (recording && pressed.size === 0 && recording.size > 0) {
    e.preventDefault();
    e.stopImmediatePropagation();
    const keys = sortCombo(recording);
    recording = null;
    const problem = comboProblem(keys);
    if (problem) toast(problem, { type: "error" });
    else {
      prefs.set("panicCombo", keys);
      toast(`Panic key set: ${keys.map(keyLabel).join(" + ")}`, { type: "success" });
    }
    renderPanicCombo();
  }
}, true);

// Keys released while the window was not focused never send keyup.
window.addEventListener("blur", () => pressed.clear());
document.addEventListener("visibilitychange", () => pressed.clear());

// ---------------------------------------------------------------- start

// Anything that slips past a handler becomes a message, not a silent failure.
window.addEventListener("unhandledrejection", (ev) => {
  ev.preventDefault();
  const msg = String(ev.reason?.message ?? ev.reason ?? "");
  if (msg.startsWith(SESSION_EXPIRED)) { lockNow("Your session expired. Sign in again."); return; }
  if (state.unlocked || document.querySelector("#view-auth:not([hidden])")) toastError(ev.reason);
});
window.addEventListener("error", (ev) => {
  if (ev.message && !/ResizeObserver/.test(ev.message)) toast("Something went wrong. Try again.", { type: "error" });
});

(async () => {
  applyTheme();
  applyIcons();
  if (window.matchMedia) matchMedia("(prefers-color-scheme: dark)").addEventListener("change", applyTheme);
  try {
    await invoke("set_rp_id", { rpId: prefs.get("rp", RP_DEFAULT) });
    if (await invoke("is_unlocked")) return enterDrive();
  } catch (e) {
    toastError(e);
  }
  showAuth("signin");
})();
