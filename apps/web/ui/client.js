// Strongbox client: a JavaScript port of `crates/client` (api.rs and vault.rs). Log in with
// the security key, open a drive by (slot, drive PIN), and work with its files. Everything is
// encrypted and decrypted here, in the page; the server only ever sees the sealed channel,
// username-sealed account records and fixed-size random-looking blocks.
//
// Nothing is stored in the browser: no profile, no credential id, no caches.

import * as c from "./core.js";
import { StrongboxError } from "./core.js";

/** WebAuthn relying party id of the desktop app and CLI (see `authn.js` for the browser). */
export const DEFAULT_RP_ID = "strongbox.app";
/** User name given to vault credentials. Generic on purpose: it must not name an account. */
export const VAULT_USER_NAME = "Strongbox";
export const MAX_BLOCKS_PER_REQUEST = 32;
/** Requests kept in flight during a file transfer. */
const IN_FLIGHT = 3;
const STAGE_MAX_FILES = 64;
const STAGE_MAX_AGE_MS = 10_000;

const invalid = (msg) => new StrongboxError(msg);
export const cancelled = () => new StrongboxError("cancelled", { cancelled: true });
const nowMs = () => Date.now();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- HTTP API

/** Plain HTTP is only allowed to loopback (development); everything else must use HTTPS. */
export function checkServerUrl(server) {
  let url;
  try { url = new URL(server); } catch (e) { throw invalid(`bad server URL: ${e.message}`); }
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (!(url.protocol === "https:" || (url.protocol === "http:" && loopback))) {
    throw invalid("server URL must use https:// (http:// only for localhost)");
  }
  url.search = "";
  url.hash = "";
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}

function apiError(status, body) {
  let code = null, message;
  try {
    const e = JSON.parse(new TextDecoder().decode(body));
    if (typeof e.message !== "string") throw 0;
    ({ code, message } = e);
  } catch {
    message = new TextDecoder().decode(body);
  }
  return new StrongboxError(`server error (${status}): ${message}`, { status, code });
}

export class Api {
  constructor(server) {
    this.base = checkServerUrl(server);
    this.token = null;
    this.channel = null;
  }

  url(path) { return new URL(path.replace(/^\/+/, ""), this.base); }

  async http(path, init = {}) {
    let resp;
    try {
      resp = await fetch(this.url(path), {
        ...init,
        // Never follow redirects: one could point the clear calls somewhere else.
        redirect: "error",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
      });
    } catch (e) {
      throw new StrongboxError(`network: error sending request: ${e?.message ?? e}`);
    }
    const body = new Uint8Array(await resp.arrayBuffer().catch((e) => { throw new StrongboxError(`network: ${e?.message ?? e}`); }));
    if (!resp.ok) throw apiError(resp.status, body);
    return body;
  }

  async plainJson(path, init) {
    const body = await this.http(path, init);
    try { return JSON.parse(new TextDecoder().decode(body)); } catch { throw invalid("the server sent a malformed reply"); }
  }

  info() { return this.plainJson("/v1/info"); }

  /** Sign-up. Not sealed (no channel yet): it carries the transport key, so it must happen on a trusted network. */
  createVault(req) {
    return this.plainJson("/v2/vaults", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(req) });
  }

  async vaultRecord(lookup) {
    const r = await this.plainJson(`/v2/lookup/${c.toHex(lookup)}`);
    return c.fromB64(r.record);
  }

  /** Open a sealed channel. Fails unless the server proves it holds the member's transport key. */
  async openChannel(memberIdBytes, transport) {
    const clientNonce = c.randomBytes(c.HELLO_NONCE_LEN);
    const reply = await this.http("/v2/channel", { method: "POST", body: c.concat(memberIdBytes, clientNonce) });
    if (reply.length !== c.HELLO_NONCE_LEN + c.SID_LEN + 32) throw invalid("malformed channel reply");
    const serverNonce = reply.subarray(0, c.HELLO_NONCE_LEN);
    const sid = reply.slice(c.HELLO_NONCE_LEN, c.HELLO_NONCE_LEN + c.SID_LEN);
    const confirm = reply.subarray(c.HELLO_NONCE_LEN + c.SID_LEN);
    if (!c.bytesEqual(c.confirmTag(transport, clientNonce, serverNonce, sid), confirm)) {
      throw invalid("the server could not prove it is the server this account was created on");
    }
    const [c2s, s2c] = c.sessionKeys(transport, clientNonce, serverNonce, sid);
    this.channel = { sid, c2s, s2c, counter: 0 };
  }

  /** One sealed round trip: returns [status, body]. */
  async call(method, path, json, body = new Uint8Array(0)) {
    const ch = this.channel;
    if (!ch) throw invalid("secure channel is not open");
    const counter = ++ch.counter;
    const inner = c.concat(c.encodeRequestHead(method, json, path, this.token ?? ""), body);
    const msg = c.concat(ch.sid, c.u64be(counter), c.sealMessage(ch.c2s, ch.sid, counter, inner));
    const reply = await this.http("/v2/rpc", { method: "POST", body: msg });
    let out;
    try { out = c.openMessage(ch.s2c, ch.sid, counter, reply); } catch { throw invalid("the server's reply failed authentication"); }
    if (out.length < 2) throw invalid("malformed channel response");
    return [(out[0] << 8) | out[1], out.subarray(2)];
  }

  async sealed(method, path, jsonBody = null, raw = null) {
    const body = jsonBody != null ? new TextEncoder().encode(JSON.stringify(jsonBody)) : raw ?? new Uint8Array(0);
    const [status, out] = await this.call(method, path, jsonBody != null, body);
    if (status < 200 || status >= 300) throw apiError(status, out);
    return out;
  }

  async sealedJson(method, path, jsonBody = null) {
    const out = await this.sealed(method, path, jsonBody);
    try { return JSON.parse(new TextDecoder().decode(out)); } catch { throw invalid("the server sent a malformed reply"); }
  }

  sealedInfo() { return this.sealedJson("GET", "/v2/info"); }
  deleteAccount() { return this.sealed("DELETE", "/v2/vaults"); }
  updateVaultRecord(lookup, record) { return this.sealed("PUT", "/v2/record", { lookup: c.toB64(lookup), record: c.toB64(record) }); }
  async vaultChallenge(locator) { return c.fromB64((await this.sealedJson("POST", "/v2/auth/challenge", { locator: c.toB64(locator) })).challenge); }
  vaultSession(req) { return this.sealedJson("POST", "/v2/auth/session", req); }
  vaultLogout() { return this.sealed("DELETE", "/v2/auth/session"); }
  vaultMembers() { return this.sealedJson("GET", "/v2/members"); }
  addVaultMember(req) { return this.sealed("POST", "/v2/members", req); }
  removeVaultMember(id) { return this.sealed("DELETE", `/v2/members/${id}`); }

  async readBlocks(slot, start, count) {
    const out = await this.sealed("GET", `/v2/slots/${slot}/blocks?start=${start}&count=${count}`);
    if (out.length !== count * c.BLOCK_SIZE) throw invalid("server returned a short block read");
    return out;
  }

  async readAllEntries(slots) {
    const out = await this.sealed("GET", "/v2/entries");
    if (out.length !== slots * c.HEADER_BLOCKS * c.ENTRIES_LEN) throw invalid("server returned a short entry read");
    return out;
  }

  async readHeaders(slot) {
    const out = await this.sealed("GET", `/v2/slots/${slot}/headers`);
    if (out.length !== c.HEADER_BLOCKS * c.HEADER_LEN) throw invalid("server returned a short header read");
    return out;
  }

  writeHeader(slot, copy, header) { return this.sealed("PUT", `/v2/slots/${slot}/headers/${copy}`, null, header); }
  writeBlocks(slot, start, data) { return this.sealed("PUT", `/v2/slots/${slot}/blocks?start=${start}`, null, data); }
}

// ---------------------------------------------------------------- sign-in

async function server(serverUrl) {
  const api = new Api(serverUrl);
  const info = await api.info();
  const layout = info.vault;
  if (layout?.block_size !== c.BLOCK_SIZE || !(layout.blocks_per_slot > c.HEADER_BLOCKS) || !(layout.slots > 0)) {
    throw invalid("unsupported vault layout");
  }
  return { api, serverId: info.server_id, layout };
}

/** The server's vault layout, without logging in. */
export async function vaultLayout(serverUrl) {
  return (await server(serverUrl)).layout;
}

async function usernameKeys(username, serverId) {
  if (!username.trim()) throw invalid("enter a username");
  return c.UsernameKeys.derive(username, serverId);
}

/** Fetch and decrypt a username's record. A wrong username gets a decoy that does not decrypt. */
async function credentials(api, keys) {
  const opened = keys.openRecord(await api.vaultRecord(keys.lookup));
  if (!opened) throw invalid("unknown username on this server");
  return opened;
}

const sameLayout = (a, b) => a && b && a.slots === b.slots && a.blocks_per_slot === b.blocks_per_slot && a.block_size === b.block_size;

async function login(api, serverId, layout, username, { credentialIds, members }, creds) {
  // From here on everything is sealed under the member's transport key.
  await api.openChannel(c.locatorHash(creds.locator), creds.transport);
  // The server id and layout came in the clear; confirm them now that they can be authenticated.
  const sealed = await api.sealedInfo();
  if (sealed.server_id !== serverId || !sameLayout(sealed.vault, layout)) {
    throw invalid("the server's details differ from what the network showed; refusing to continue");
  }
  let session = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    const challenge = await api.vaultChallenge(creds.locator);
    try {
      session = await api.vaultSession({
        locator: c.toB64(creds.locator),
        challenge: c.toB64(challenge),
        signature: c.toB64(creds.signChallenge(serverId, challenge)),
      });
      break;
    } catch (e) {
      if (e.status !== 401) throw e;
      if (attempt === 2) throw invalid("this security key could not authenticate to the vault on this server");
      await sleep(100);
    }
  }
  api.token = session.token;
  return new VaultClient(api, layout, username, credentialIds, members);
}

function checkSlot(layout, slot) {
  if (!Number.isInteger(slot) || slot < 0 || slot >= layout.slots) throw invalid(`slot must be 0–${layout.slots - 1}`);
}

/** Authenticate to an account without opening any drive. */
export async function connectAccount(serverUrl, username, authn) {
  const { api, serverId, layout } = await server(serverUrl);
  const keys = await usernameKeys(username, serverId);
  const record = await credentials(api, keys);
  const pair = await authn.prf2(record.credentialIds, keys.vaultSalt(), null);
  return login(api, serverId, layout, keys, record, c.MemberCreds.fromPrf(pair.first));
}

/** Authenticate with an account recovery code, without opening a drive. */
export async function connectAccountWithRecovery(serverUrl, username, code) {
  const rc = c.RecoveryCode.decode(code);
  const { api, serverId, layout } = await server(serverUrl);
  const keys = await usernameKeys(username, serverId);
  const record = await credentials(api, keys);
  const creds = rc.memberCreds();
  const id = c.memberId(creds.locator);
  if (!record.members.some((m) => m.id === id && m.kind === "recovery_code" && m.slot == null)) {
    throw invalid("this is not an account recovery code");
  }
  return login(api, serverId, layout, keys, record, creds);
}

/** Enroll a credential and get its vault-login PRF output (one touch if the key can, else two). */
async function enrollWithVaultSecret(authn, exclude, salt) {
  const enrolled = await authn.enroll(exclude, salt);
  if (enrolled.first) return enrolled;
  const pair = await authn.prf2([enrolled.credentialId], salt, null);
  return { credentialId: enrolled.credentialId, first: pair.first };
}

/** Create an account under `username` with a new non-discoverable credential on the key. */
export async function createVaultNamed(serverUrl, username, invite, authn, label) {
  const { api, serverId, layout } = await server(serverUrl);
  const keys = await usernameKeys(username, serverId);
  keys.newSeed();
  const { credentialId, first } = await enrollWithVaultSecret(authn, [], keys.vaultSalt());
  const creds = c.MemberCreds.fromPrf(first);
  const credentialIds = [credentialId];
  const members = [{ id: c.memberId(creds.locator), label, kind: "security_key", slot: null }];
  await api.createVault({
    lookup: c.toB64(keys.lookup),
    record: c.toB64(keys.sealRecord(credentialIds, members)),
    locator: c.toB64(creds.locator),
    auth_public_key: c.toB64(creds.publicKey()),
    transport_key: c.toB64(creds.transport),
    invite: invite || null,
  });
  try {
    return await login(api, serverId, layout, keys, { credentialIds, members }, creds);
  } catch (e) {
    if (!/could not authenticate/.test(e.message)) throw e;
    try { return await connectAccount(serverUrl, username, authn); } catch {
      throw invalid("the account was created, but the security key could not complete sign-in; try signing in again instead of creating the account again");
    }
  }
}

/** Log in as `username` and derive the key for one slot with a single touch. */
export async function connect(serverUrl, username, authn, slot, pin) {
  c.checkDrivePin(pin);
  const { api, serverId, layout } = await server(serverUrl);
  checkSlot(layout, slot);
  const keys = await usernameKeys(username, serverId);
  const record = await credentials(api, keys);
  const pair = await authn.prf2(record.credentialIds, keys.vaultSalt(), c.driveSalt(slot, pin));
  if (!pair.second) throw new StrongboxError("security key: the security key does not support the PRF / hmac-secret extension");
  const member = c.MemberCreds.fromPrf(pair.first);
  const client = await login(api, serverId, layout, keys, record, member);
  return { client, key: { slot, key: c.entryKey(pair.second), kind: c.KIND_KEY, memberId: c.memberId(member.locator) } };
}

/** Log in with a drive recovery code and find the drive it opens. */
export async function connectWithRecovery(serverUrl, username, code) {
  const rc = c.RecoveryCode.decode(code);
  const { api, serverId, layout } = await server(serverUrl);
  const keys = await usernameKeys(username, serverId);
  const record = await credentials(api, keys);
  const creds = rc.memberCreds();
  const client = await login(api, serverId, layout, keys, record, creds);
  // One request for every slot's entry table, then open only the slots this code unlocks.
  const perSlot = c.HEADER_BLOCKS * c.ENTRIES_LEN;
  const all = await client.api.readAllEntries(layout.slots);
  for (let slot = 0; slot < layout.slots; slot++) {
    const keyList = [{ key: rc.entryKey(slot), kind: c.KIND_RECOVERY }];
    const prefixes = [0, 1].map((i) => all.subarray(slot * perSlot + i * c.ENTRIES_LEN, slot * perSlot + (i + 1) * c.ENTRIES_LEN));
    if (!prefixes.some((p) => c.entriesOpen(slot, p, keyList))) continue;
    const k = { slot, key: rc.entryKey(slot), kind: c.KIND_RECOVERY, memberId: c.memberId(creds.locator) };
    const drive = await client.open(k);
    if (drive) return { client, key: k, drive };
  }
  throw invalid("this recovery code does not open any drive");
}

// ---------------------------------------------------------------- account

/** A logged-in vault session. It knows nothing about which drives exist. */
export class VaultClient {
  constructor(api, layout, username, credentialIds, members) {
    this.api = api;
    this.layout = layout;
    this.username = username;
    this.credentialIds = credentialIds;
    this.members = members;
  }

  /** Derive the key for another slot (one touch). */
  async slotKey(authn, slot, pin) {
    c.checkDrivePin(pin);
    checkSlot(this.layout, slot);
    const pair = await authn.prf2(this.credentialIds, this.username.vaultSalt(), c.driveSalt(slot, pin));
    if (!pair.second) throw new StrongboxError("security key: the security key does not support the PRF / hmac-secret extension");
    return { slot, key: c.entryKey(pair.second), kind: c.KIND_KEY, memberId: c.memberId(c.MemberCreds.fromPrf(pair.first).locator) };
  }

  /** Open the drive in a slot. `null`: no drive for this slot and PIN (wrong PIN or unused slot alike). */
  async open(k) {
    const headers = await this.api.readHeaders(k.slot);
    const keys = [{ key: k.key, kind: k.kind }];
    let best = null;
    for (const copy of [0, 1]) {
      const h = headers.subarray(copy * c.HEADER_LEN, (copy + 1) * c.HEADER_LEN);
      const o = c.openHeader(k.slot, copy, h, keys);
      if (o && (!best || o.body.generation >= best.opened.body.generation)) best = { copy, opened: o, header: h };
    }
    if (!best) return null;
    const drive = new VaultDrive(this, k.slot, best.opened.driveKey, c.headerEntries(best.header), best.opened.body, best.copy, c.newDir());
    drive.tree = await drive.readMeta();
    return drive;
  }

  /** Create a new, empty drive in the slot, destroying whatever was there. */
  async create(k) {
    if (k.kind !== c.KIND_KEY) throw invalid("a recovery code cannot create drives");
    const driveKey = c.randomBytes(32);
    const entries = Array.from({ length: c.KEY_ENTRIES + 1 }, () => c.randomEntry());
    entries[0] = c.wrapEntry(k.slot, 0, k.key, driveKey);
    const drive = new VaultDrive(this, k.slot, driveKey, entries, {
      generation: 0, usedEntries: 1, metaBlocks: [], metaLen: 0, grants: [{ entry: 0, memberId: k.memberId }],
    }, 1, c.newDir(nowMs()));
    // Copy 1 becomes filler: an old header there could still open with the same PIN.
    await this.api.writeHeader(k.slot, 1, c.randomHeader());
    await drive.writeCommit(c.cloneDir(drive.tree));
    return drive;
  }

  async membersList() {
    const r = await this.api.vaultMembers();
    return { members: r.members, current: r.current };
  }

  async saveRecord(credentialIds, members) {
    await this.api.updateVaultRecord(this.username.lookup, this.username.sealRecord(credentialIds, members));
  }

  async removeMember(id) {
    const removed = this.members.find((m) => m.id === id);
    if (!removed) throw invalid("account key or recovery code not found");
    const members = this.members.filter((m) => m.id !== id);
    const credentialIds = [...this.credentialIds];
    if (removed.kind === "security_key") {
      const index = this.members.filter((m) => m.kind === "security_key").findIndex((m) => m.id === id);
      if (index < 0) throw invalid("account key record is incomplete");
      if (index < credentialIds.length) credentialIds.splice(index, 1);
    }
    await this.api.removeVaultMember(id);
    await this.saveRecord(credentialIds, members);
    this.credentialIds = credentialIds;
    this.members = members;
  }

  /** Rename a security key or recovery code. Labels live only in the encrypted record. */
  async renameMember(id, label) {
    label = this.cleanLabel(label, [id]);
    const members = this.members.map((m) => ({ ...m }));
    const m = members.find((x) => x.id === id);
    if (!m) throw invalid("account key or recovery code not found");
    m.label = label;
    await this.saveRecord(this.credentialIds, members);
    this.members = members;
  }

  cleanLabel(label, ignore) {
    label = label.trim();
    if (!label || [...label].length > 80) throw invalid("enter a name up to 80 characters");
    if (this.labelTaken(label, ignore)) throw invalid(`a key or recovery code is already named “${label}”; choose another name`);
    return label;
  }

  labelTaken(label, ignore) {
    const key = label.trim().toLowerCase();
    return this.members.some((m) => !ignore.includes(m.id) && m.label.trim().toLowerCase() === key);
  }

  /** `base`, or `base` with the lowest free number after it ("Recovery code 2"). */
  suggestLabel(base, ignore) {
    if (!this.labelTaken(base, ignore)) return base;
    const stem = base.replace(/[0-9]+$/, "").trimEnd() || base;
    for (let n = 2; ; n++) if (!this.labelTaken(`${stem} ${n}`, ignore)) return `${stem} ${n}`;
  }

  /** Copy the decrypted account record from another open session of this account. */
  syncAccountRecordFrom(source) {
    if (source === this) return;
    this.credentialIds = [...source.credentialIds];
    this.members = source.members.map((m) => ({ ...m }));
  }

  /** Add an account sign-in key without granting it access to any drive. */
  async addAccountKeyNamed(authn, label) {
    label = this.cleanLabel(label, []);
    if (this.credentialIds.length >= c.MAX_RECORD_CREDENTIALS) throw invalid(`this username already has ${c.MAX_RECORD_CREDENTIALS} keys`);
    const { credentialId, first } = await enrollWithVaultSecret(authn, this.credentialIds, this.username.vaultSalt());
    const member = c.MemberCreds.fromPrf(first);
    await this.addMember(member);
    const credentialIds = [...this.credentialIds, credentialId];
    const members = [...this.members, { id: c.memberId(member.locator), label, kind: "security_key", slot: null }];
    await this.saveRecord(credentialIds, members);
    this.credentialIds = credentialIds;
    this.members = members;
  }

  /** Add an account recovery code. It authenticates the account but cannot open drives. */
  async newAccountRecoveryCodeNamed(label) {
    label = this.cleanLabel(label, []);
    const code = c.RecoveryCode.generate();
    const member = code.memberCreds();
    await this.addMember(member);
    const members = [...this.members, { id: c.memberId(member.locator), label, kind: "recovery_code", slot: null }];
    await this.saveRecord(this.credentialIds, members);
    this.members = members;
    return code.encode();
  }

  async addMember(creds) {
    try {
      await this.api.addVaultMember({
        locator: c.toB64(creds.locator),
        auth_public_key: c.toB64(creds.publicKey()),
        transport_key: c.toB64(creds.transport),
      });
    } catch (e) {
      if (e.status !== 409) throw e;
    }
  }

  endSession() { return this.api.vaultLogout(); }
  deleteAccount() { return this.api.deleteAccount(); }
}

// ---------------------------------------------------------------- drives

function comps(path) {
  const parts = path.split("/").filter(Boolean);
  for (const p of parts) c.validateName(p);
  return parts;
}

function split(path) {
  const parts = comps(path);
  const name = parts.pop();
  if (name === undefined) throw invalid("path refers to the root directory");
  return [parts, name];
}

function dir(root, parts) {
  let cur = root;
  parts.forEach((p, i) => {
    const n = cur.entries.get(p);
    if (!n) throw new StrongboxError(`not found: /${parts.slice(0, i + 1).join("/")}`, { notFound: true });
    if (n.kind !== "dir") throw invalid(`/${parts.slice(0, i + 1).join("/")} is a file`);
    cur = n;
  });
  return cur;
}

function uniqueName(d, name) {
  if (!d.entries.has(name)) return name;
  const i = name.lastIndexOf(".");
  const [stem, ext] = i > 0 ? [name.slice(0, i), name.slice(i)] : [name, ""];
  for (let n = 1; ; n++) if (!d.entries.has(`${stem} (${n})${ext}`)) return `${stem} (${n})${ext}`;
}

/** Create the folder `parts` and any missing parents. True if anything was created. */
function mkdirIn(tree, parts) {
  let cur = tree, changed = false;
  parts.forEach((name, i) => {
    let next = cur.entries.get(name);
    if (!next) { next = c.newDir(nowMs()); cur.entries.set(name, next); changed = true; }
    if (next.kind !== "dir") throw invalid(`/${parts.slice(0, i + 1).join("/")} is a file`);
    cur = next;
  });
  return changed;
}

/** Group (block, data) pairs into runs of consecutive blocks, each at most MAX_BLOCKS_PER_REQUEST. */
function runs(blocks) {
  const sorted = [...blocks].sort((a, b) => a[0] - b[0]);
  const out = [];
  for (const [b, data] of sorted) {
    const last = out[out.length - 1];
    if (last && last.start + last.parts.length === b && last.parts.length < MAX_BLOCKS_PER_REQUEST) last.parts.push(data);
    else out.push({ start: b, parts: [data] });
  }
  return out.map((r) => [r.start, r.parts.length === 1 ? r.parts[0] : c.concat(...r.parts)]);
}

async function writeRuns(api, slot, blocks) {
  for (const [start, data] of runs(blocks)) await api.writeBlocks(slot, start, data);
}

/** Read blocks (any order); returns them in the order asked. */
async function readRuns(api, slot, which) {
  const out = [];
  for (let i = 0; i < which.length;) {
    let n = 1;
    while (i + n < which.length && which[i + n] === which[i] + n && n < MAX_BLOCKS_PER_REQUEST) n++;
    const data = await api.readBlocks(slot, which[i], n);
    for (let k = 0; k < n; k++) out.push(data.subarray(k * c.BLOCK_SIZE, (k + 1) * c.BLOCK_SIZE));
    i += n;
  }
  return out;
}

/** Let in-flight work finish quietly after a transfer has already failed. */
const settle = (promises) => { for (const p of promises) p.catch(() => {}); };

const toEntry = (name, n) => n.kind === "dir"
  ? { name, is_dir: true, size: 0, mtime: n.mtime }
  : { name, is_dir: false, size: n.size, mtime: n.mtime };

/** An open drive. Every change is one copy-on-write commit (docs/deniable-drives.md §6). */
export class VaultDrive {
  constructor(client, slot, driveKey, entries, body, copy, tree) {
    this.client = client;
    this.slot = slot;
    this.driveKey = driveKey;
    this.entries = entries;
    this.body = body;
    this.copy = copy;
    this.tree = tree;
  }

  get api() { return this.client.api; }

  /** The drive key; fails once wiped, which stops all encryption and decryption. */
  dk() {
    if (!this.driveKey) throw invalid("the drive is locked");
    return this.driveKey;
  }

  /** Erase the drive key and the file keys in the tree now. */
  wipe() {
    c.wipe(this.driveKey);
    this.driveKey = null;
    const stack = [this.tree];
    while (stack.length) {
      for (const n of stack.pop().entries.values()) if (n.kind === "dir") stack.push(n); else c.wipe(n.key);
    }
  }

  accessGrants() { return this.body.grants.map((g) => ({ ...g })); }

  async readMeta() {
    if (!this.body.metaBlocks.length) return c.newDir();
    const sealed = await readRuns(this.api, this.slot, this.body.metaBlocks);
    return c.openMeta(this.dk(), this.slot, this.body, sealed);
  }

  /** Blocks in use by the committed state plus `tree`'s files. */
  used(tree) {
    const set = new Set([0, 1, ...this.body.metaBlocks]);
    for (const b of c.fileBlocks(tree)) set.add(b);
    for (const b of c.fileBlocks(this.tree)) set.add(b);
    return set;
  }

  allocate(n, used) {
    const free = [];
    for (let b = c.HEADER_BLOCKS; b < this.client.layout.blocks_per_slot && free.length < n; b++) if (!used.has(b)) free.push(b);
    if (free.length < n) throw invalid("this drive is full");
    return free;
  }

  /** Capacity in bytes: [used, total]. */
  usage() {
    const total = (this.client.layout.blocks_per_slot - c.HEADER_BLOCKS) * c.BLOCK_PAYLOAD;
    const used = (c.fileBlocks(this.tree).length + this.body.metaBlocks.length) * c.BLOCK_PAYLOAD;
    return [Math.min(used, total), total];
  }

  /** Commit a new tree, refusing if another device committed since this drive was opened. */
  async commit(tree) {
    const headers = await this.api.readHeaders(this.slot);
    const dk = this.dk();
    let latest = 0;
    for (const copy of [0, 1]) {
      const b = c.openHeaderBody(this.slot, copy, headers.subarray(copy * c.HEADER_LEN, (copy + 1) * c.HEADER_LEN), dk);
      if (b && b.generation > latest) latest = b.generation;
    }
    if (latest !== this.body.generation) throw invalid("this drive was changed on another device; close and reopen it");
    await this.writeCommit(tree);
  }

  /** Metadata to free blocks, then the older header copy, then wipe the previous metadata. */
  async writeCommit(tree) {
    const cbor = c.encodeMeta(tree);
    const used = this.used(tree);
    const metaBlocks = this.allocate(c.metaBlockCount(cbor.length), used);
    const sealed = c.sealMeta(this.dk(), this.slot, metaBlocks, cbor);
    await writeRuns(this.api, this.slot, metaBlocks.map((b, i) => [b, sealed[i]]));

    const body = {
      generation: this.body.generation + 1,
      usedEntries: this.body.usedEntries,
      metaBlocks,
      metaLen: cbor.length,
      grants: this.body.grants.map((g) => ({ ...g })),
    };
    const copy = 1 - this.copy;
    await this.api.writeHeader(this.slot, copy, c.sealHeader(this.slot, copy, this.dk(), this.entries, body));

    const oldMeta = this.body.metaBlocks;
    this.body = body;
    this.copy = copy;
    this.tree = tree;
    await writeRuns(this.api, this.slot, oldMeta.filter((b) => !metaBlocks.includes(b)).map((b) => [b, c.randomBlock()]));
  }

  list(path) {
    const d = dir(this.tree, comps(path));
    return [...d.entries].map(([name, n]) => toEntry(name, n));
  }

  /** Case-insensitive name search over the decrypted tree. */
  search(query) {
    const q = query.trim().toLowerCase();
    const hits = [];
    if (!q) return hits;
    const stack = [[[], this.tree]];
    while (stack.length) {
      const [parts, d] = stack.pop();
      for (const [name, n] of d.entries) {
        const cc = [...parts, name];
        if (name.toLowerCase().includes(q)) hits.push({ path: "/" + cc.join("/"), parent: "/" + parts.join("/"), entry: toEntry(name, n) });
        if (n.kind === "dir") stack.push([cc, n]);
      }
    }
    hits.sort((a, b) => { const x = a.entry.name.toLowerCase(), y = b.entry.name.toLowerCase(); return x < y ? -1 : x > y ? 1 : 0; });
    return hits.slice(0, 500);
  }

  async mkdir(path) {
    const [parent, name] = split(path);
    const tree = c.cloneDir(this.tree);
    const p = dir(tree, parent);
    if (p.entries.has(name)) throw new StrongboxError(`${path} already exists`);
    p.entries.set(name, c.newDir(nowMs()));
    await this.commit(tree);
  }

  async remove(path) {
    const [parent, name] = split(path);
    const tree = c.cloneDir(this.tree);
    if (!dir(tree, parent).entries.delete(name)) throw new StrongboxError(`not found: ${path}`, { notFound: true });
    await this.commit(tree);
  }

  async rename(from, to) {
    const [sp, sn] = split(from);
    const [dp, dn] = split(to);
    if (sp.join("/") === dp.join("/") && sn === dn) return;
    const src = [...sp, sn];
    if (dp.length >= src.length && src.every((x, i) => dp[i] === x)) throw invalid("cannot move a folder into itself");
    const tree = c.cloneDir(this.tree);
    const sd = dir(tree, sp);
    const node = sd.entries.get(sn);
    if (!node) throw new StrongboxError(`not found: ${from}`, { notFound: true });
    sd.entries.delete(sn);
    const d = dir(tree, dp);
    if (d.entries.has(dn)) throw new StrongboxError(`${to} already exists`);
    d.entries.set(dn, node);
    await this.commit(tree);
  }

  // ---------------- batched uploads

  /** Start a batch of changes to commit together. */
  stage() {
    return { tree: c.cloneDir(this.tree), generation: this.body.generation, changed: false, files: 0, since: null, replaced: false };
  }

  stagedDue(s) {
    return s.replaced || s.files >= STAGE_MAX_FILES || (s.since != null && nowMs() - s.since >= STAGE_MAX_AGE_MS);
  }

  /** Commit the batch (if anything changed) and start a new one on the drive as it then is. */
  async commitStaged(s) {
    let error = null;
    try {
      if (s.generation !== this.body.generation) throw invalid("the drive changed while uploads were waiting to be saved");
      if (s.changed) await this.commit(c.cloneDir(s.tree));
    } catch (e) { error = e; }
    Object.assign(s, this.stage());
    if (error) throw error;
  }

  mkdirPStaged(s, path) {
    if (mkdirIn(s.tree, comps(path))) s.changed = true;
  }

  /**
   * Encrypt and upload a browser `File` into `remoteDir` of a batch. Its blocks are written
   * now; it appears in the drive when the batch is committed. Returns the stored name.
   * `opts`: { progress(done, total), cancel: { cancelled }, onConflict }.
   */
  async uploadStaged(s, file, remoteDir, opts = {}) {
    const checkCancel = () => { if (opts.cancel?.cancelled) throw cancelled(); };
    const name = file.name;
    c.validateName(name);
    const parent = comps(remoteDir);
    const size = file.size;
    const mtime = file.lastModified || nowMs();
    const d = dir(s.tree, parent);
    const existing = d.entries.get(name);
    let stored = name;
    if (existing) {
      const mode = opts.onConflict ?? "replace";
      if (mode === "keep_both") stored = uniqueName(d, name);
      else if (mode === "replace" && existing.kind === "dir") throw new StrongboxError(`a folder named ${name} already exists`);
      else if (mode === "fail") throw new StrongboxError(`${name} already exists`);
    }

    const n = c.fileBlockCount(size);
    // Replaced files keep their blocks until the commit, and other staged files keep theirs.
    const blocks = this.allocate(n, this.used(s.tree));
    // A fresh key for every upload: blocks cannot be swapped, reordered or rolled back.
    const key = c.randomBytes(32);
    let batch = [], queued = 0;
    const writes = [];
    try {
      for (let k = 0; k < n; k++) {
        checkCancel();
        this.dk();
        const end = Math.min(size, queued + c.BLOCK_PAYLOAD);
        const plain = new Uint8Array(await file.slice(queued, end).arrayBuffer());
        if (plain.length !== end - queued) throw invalid("file changed while uploading");
        batch.push([blocks[k], c.sealFileBlock(key, this.slot, blocks[k], k, plain)]);
        queued = end;
        if (batch.length === MAX_BLOCKS_PER_REQUEST || k + 1 === n) {
          if (writes.length >= IN_FLIGHT) opts.progress?.(await writes.shift(), size);
          const data = batch, upto = queued;
          batch = [];
          writes.push(writeRuns(this.api, this.slot, data).then(() => upto));
        }
      }
      while (writes.length) opts.progress?.(await writes.shift(), size);
    } catch (e) {
      settle(writes);
      throw e;
    }
    if (queued !== size) throw invalid("file changed while uploading");
    const committed = (() => { try { return dir(this.tree, parent).entries.get(stored); } catch { return undefined; } })();
    if (committed?.kind === "file") s.replaced = true;
    dir(s.tree, parent).entries.set(stored, { kind: "file", size, mtime, key, blocks });
    s.changed = true;
    s.files += 1;
    s.since ??= nowMs();
    return stored;
  }

  // ---------------- downloads

  file(remote) {
    const [parent, name] = split(remote);
    const n = dir(this.tree, parent).entries.get(name);
    if (!n) throw new StrongboxError(`not found: ${remote}`, { notFound: true });
    if (n.kind === "dir") throw invalid(`${remote} is a folder`);
    return n;
  }

  /**
   * Decrypt a file into `sink` (async `write(bytes)`), verifying every block. Reads run ahead
   * of decryption; only ciphertext is fetched early.
   */
  async fetch(f, sink, opts = {}) {
    let left = f.size;
    this.dk(); // a wiped drive must not keep decrypting with the file keys it still holds
    const chunks = [];
    for (let i = 0; i < f.blocks.length; i += MAX_BLOCKS_PER_REQUEST) chunks.push(f.blocks.slice(i, i + MAX_BLOCKS_PER_REQUEST));
    const reads = [];
    let next = 0;
    try {
      for (let ci = 0; ci < chunks.length; ci++) {
        while (next < chunks.length && reads.length < IN_FLIGHT) reads.push(readRuns(this.api, this.slot, chunks[next++]));
        if (opts.cancel?.cancelled) throw cancelled();
        this.dk();
        const data = await reads.shift();
        for (let j = 0; j < chunks[ci].length; j++) {
          const k = ci * MAX_BLOCKS_PER_REQUEST + j;
          const plain = c.openFileBlock(f.key, this.slot, chunks[ci][j], k, data[j]);
          const take = Math.min(left, plain.length);
          await sink.write(plain.subarray(0, take));
          left -= take;
        }
        opts.progress?.(f.size - left, f.size);
      }
    } catch (e) {
      settle(reads);
      throw e;
    }
    if (left !== 0) throw new StrongboxError("cryptography: content integrity check failed");
  }

  /** Decrypt a whole file into memory (previews). Refuses files over `maxSize`. */
  async readFile(remote, maxSize) {
    const f = this.file(remote);
    if (f.size > maxSize) throw invalid("file is too large to preview");
    const out = new Uint8Array(f.size);
    let at = 0;
    await this.fetch(f, { write: (b) => { out.set(b, at); at += b.length; } });
    return out;
  }

  // ---------------- access

  /** Grant an existing account key access to this drive only. */
  async grantAccountKey(authn, pin, targetId) {
    c.checkDrivePin(pin);
    const index = [...Array(c.KEY_ENTRIES).keys()].find((i) => (this.body.usedEntries & (1 << i)) === 0);
    if (index === undefined) throw invalid(`this drive already has ${c.KEY_ENTRIES} key slots`);
    if (this.body.grants.some((g) => g.memberId === targetId)) throw invalid("this key already opens this vault");
    const keys = this.client.members.filter((m) => m.kind === "security_key");
    const keyIndex = keys.findIndex((m) => m.id === targetId);
    if (keyIndex < 0) throw invalid("account security key not found");
    const credential = this.client.credentialIds[keyIndex];
    if (!credential) throw invalid("account security key record is incomplete");
    const knownId = keys[keyIndex].id;
    const pair = await authn.prf2([credential], this.client.username.vaultSalt(), c.driveSalt(this.slot, pin));
    if (!pair.second) throw new StrongboxError("security key: the security key does not support the PRF / hmac-secret extension");
    if (c.memberId(c.MemberCreds.fromPrf(pair.first).locator) !== knownId) throw invalid("insert the selected account security key");
    this.entries[index] = c.wrapEntry(this.slot, index, c.entryKey(pair.second), this.dk());
    this.body.usedEntries |= 1 << index;
    this.body.grants.push({ entry: index, memberId: knownId });
    await this.commit(c.cloneDir(this.tree));
  }

  /** Change this drive's PIN for the key that opened it. Returns how many other keys were revoked. */
  async changePin(authn, newPin) {
    c.checkDrivePin(newPin);
    const { current } = await this.client.membersList();
    const mine = this.body.grants.find((g) => g.memberId === current && g.entry < c.KEY_ENTRIES);
    if (!mine) throw invalid("only a security key that opens this vault can change its PIN");
    const index = this.client.members.filter((m) => m.kind === "security_key").findIndex((m) => m.id === current);
    if (index < 0) throw invalid("account security key not found");
    const credential = this.client.credentialIds[index];
    if (!credential) throw invalid("account security key record is incomplete");
    const pair = await authn.prf2([credential], this.client.username.vaultSalt(), c.driveSalt(this.slot, newPin));
    if (!pair.second) throw new StrongboxError("security key: the security key does not support the PRF / hmac-secret extension");
    if (c.memberId(c.MemberCreds.fromPrf(pair.first).locator) !== current) throw invalid("touch the security key you unlocked this vault with");
    const dk = this.dk();
    let revoked = 0;
    for (const g of this.body.grants.filter((g) => g.memberId !== current && g.entry < c.KEY_ENTRIES)) {
      this.entries[g.entry] = c.randomEntry();
      this.body.usedEntries &= ~(1 << g.entry);
      this.body.grants = this.body.grants.filter((x) => x.memberId !== g.memberId);
      revoked++;
    }
    this.entries[mine.entry] = c.wrapEntry(this.slot, mine.entry, c.entryKey(pair.second), dk);
    await this.commit(c.cloneDir(this.tree));
    // Rewrite both header copies so an older copy cannot keep an entry for the old PIN.
    await this.commit(c.cloneDir(this.tree));
    return revoked;
  }

  /** Ids of this drive's recovery codes (a new one replaces them). */
  recoveryIds() {
    return this.client.members.filter((m) => m.kind === "recovery_code" && m.slot === this.slot).map((m) => m.id);
  }

  /** Revoke one account key from this drive. */
  async revokeAccountKey(memberId) {
    const grant = this.body.grants.find((g) => g.memberId === memberId);
    if (!grant) throw invalid("key does not open this vault");
    if (grant.entry >= c.KEY_ENTRIES) throw invalid("invalid key access entry");
    this.entries[grant.entry] = c.randomEntry();
    this.body.usedEntries &= ~(1 << grant.entry);
    this.body.grants = this.body.grants.filter((g) => g.memberId !== memberId);
    await this.commit(c.cloneDir(this.tree));
    await this.commit(c.cloneDir(this.tree));
  }

  /** Revoke a recovery code from this drive and remove its account sign-in member. */
  async revokeRecoveryCode(memberId) {
    const member = this.client.members.find((m) => m.id === memberId && m.kind === "recovery_code" && m.slot === this.slot);
    if (!member) throw invalid("recovery code not found for this vault");
    await this.client.removeMember(member.id);
    this.entries[c.RECOVERY_ENTRY] = c.randomEntry();
    this.body.usedEntries &= ~(1 << c.RECOVERY_ENTRY);
    this.body.grants = this.body.grants.filter((g) => g.memberId !== memberId);
    await this.commit(c.cloneDir(this.tree));
    await this.commit(c.cloneDir(this.tree));
  }

  /** Create (or replace) this drive's recovery code. Show it once; it opens only this drive. */
  async newRecoveryCodeNamed(label) {
    const oldIds = this.recoveryIds();
    label = this.client.cleanLabel(label, oldIds);
    const code = c.RecoveryCode.generate();
    const creds = code.memberCreds();
    for (const id of oldIds) await this.client.removeMember(id);
    await this.client.addMember(creds);
    const recoveryId = c.memberId(creds.locator);
    const members = [...this.client.members, { id: recoveryId, label, kind: "recovery_code", slot: this.slot }];
    await this.client.saveRecord(this.client.credentialIds, members);
    this.client.members = members;
    this.entries[c.RECOVERY_ENTRY] = c.wrapEntry(this.slot, c.RECOVERY_ENTRY, code.entryKey(this.slot), this.dk());
    this.body.usedEntries |= 1 << c.RECOVERY_ENTRY;
    this.body.grants = this.body.grants.filter((g) => g.entry !== c.RECOVERY_ENTRY);
    this.body.grants.push({ entry: c.RECOVERY_ENTRY, memberId: recoveryId });
    await this.commit(c.cloneDir(this.tree));
    return code.encode();
  }
}

// ---------------------------------------------------------------- local names

/** Make a remote name safe as a local file name on every platform. */
export function localSafeName(name) {
  let s = [...name].map((ch) => (/\p{Cc}/u.test(ch) || '<>:"/\\|?*'.includes(ch) ? "_" : ch)).join("");
  s = s.replace(/[. ]+$/, "");
  const stem = s.split(".")[0].toUpperCase();
  const reserved = ["CON", "PRN", "AUX", "NUL"].includes(stem) || /^(COM|LPT)[0-9]$/.test(stem);
  if (!s || reserved) s = "_" + s;
  return s;
}

/** Fail if two entries of one remote folder would get the same local name. */
export function checkLocalNameClashes(names) {
  const seen = new Set();
  for (const n of names) {
    const local = localSafeName(n);
    if (seen.has(local.toLowerCase())) {
      throw invalid(`“${n}” would be saved under the same name as another item in its folder (“${local}”), so nothing was downloaded. Rename one of them first`);
    }
    seen.add(local.toLowerCase());
  }
}

export { dir as dirAt, comps };
