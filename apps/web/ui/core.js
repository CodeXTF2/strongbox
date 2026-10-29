// Strongbox client-side cryptography and formats: a JavaScript port of `crates/core` (see
// docs/deniable-drives.md §5-§8). Byte-for-byte compatible with the Rust client. Pure: no I/O.
// Every primitive comes from the audited @noble libraries in vendor.js.

import { xchacha20poly1305, sha256, hkdf, argon2idAsync, ed25519 } from "./vendor.js";

// ---------------------------------------------------------------- errors

/** Error whose message matches the Rust client's `Display` output, which the UI keys on. */
export class StrongboxError extends Error {
  constructor(message, extra = {}) {
    super(message);
    Object.assign(this, extra);
  }
}
export const malformed = (what) => new StrongboxError(`cryptography: malformed data: ${what}`);
export const decryptFailed = () => new StrongboxError("cryptography: decryption failed (wrong key or tampered data)");

// ---------------------------------------------------------------- bytes

export const utf8 = (s) => new TextEncoder().encode(s);
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

/** CSPRNG bytes (getRandomValues fills at most 64 KiB per call). */
export function randomBytes(n) {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(b.subarray(i, Math.min(n, i + 65536)));
  return b;
}

export const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

export function toB64(b) {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}
export const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const u16be = (n) => new Uint8Array([(n >>> 8) & 255, n & 255]);
export const u32be = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };
export const u64be = (n) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n)); return b; };

export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** Overwrite secret bytes (best effort: the engine may hold other copies). */
export const wipe = (b) => { if (b instanceof Uint8Array) b.fill(0); };

// ---------------------------------------------------------------- KDF and AEAD

/** HKDF `info`: label ‖ 0 ‖ (u32be len ‖ part)*. */
export function info(label, parts = []) {
  return concat(utf8(label), new Uint8Array([0]), ...parts.flatMap((p) => [u32be(p.length), p]));
}

/** HKDF-SHA256 (extract with no salt, then expand) to 32 bytes. */
export const derive = (ikm, label, parts = []) => hkdf(sha256, ikm, undefined, info(label, parts), 32);

export const aad = info;
export const NONCE_LEN = 24;
export const TAG_LEN = 16;

export function sealWithNonce(key, nonce, ad, plaintext) {
  return xchacha20poly1305(key, nonce, ad).encrypt(plaintext);
}

export function openWithNonce(key, nonce, ad, ct) {
  try { return xchacha20poly1305(key, nonce, ad).decrypt(ct); } catch { throw decryptFailed(); }
}

/** `nonce ‖ ciphertext ‖ tag` with a fresh random nonce. */
export function seal(key, ad, plaintext) {
  const nonce = randomBytes(NONCE_LEN);
  return concat(nonce, sealWithNonce(key, nonce, ad, plaintext));
}

export function open(key, ad, data) {
  if (data.length < NONCE_LEN + TAG_LEN) throw malformed("ciphertext too short");
  return openWithNonce(key, data.subarray(0, NONCE_LEN), ad, data.subarray(NONCE_LEN));
}

function tryOpen(key, ad, data) {
  try { return open(key, ad, data); } catch { return null; }
}

// ---------------------------------------------------------------- CBOR (the subset serde/ciborium uses)

function cborHead(major, n, out) {
  const m = major << 5;
  if (n < 24) out.push(m | n);
  else if (n < 0x100) out.push(m | 24, n);
  else if (n < 0x10000) out.push(m | 25, n >>> 8, n & 255);
  else if (n < 0x100000000) out.push(m | 26, n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
  else {
    const b = u64be(n);
    out.push(m | 27, ...b);
  }
}

/**
 * Encode numbers (integers), strings, Uint8Array (byte strings), arrays, Maps and plain
 * objects (both as maps) and null. Integers are minimal, lengths definite, as ciborium writes.
 */
export function cborEncode(value) {
  const out = [];
  const chunks = [];
  const flush = () => { if (out.length) { chunks.push(Uint8Array.from(out)); out.length = 0; } };
  const enc = (v) => {
    if (v === null || v === undefined) out.push(0xf6);
    else if (v === true) out.push(0xf5);
    else if (v === false) out.push(0xf4);
    else if (typeof v === "number") {
      if (!Number.isSafeInteger(v)) throw new StrongboxError("encoding error: not an integer");
      if (v >= 0) cborHead(0, v, out); else cborHead(1, -1 - v, out);
    } else if (typeof v === "string") {
      const b = utf8(v);
      cborHead(3, b.length, out);
      flush();
      chunks.push(b);
    } else if (v instanceof Uint8Array) {
      cborHead(2, v.length, out);
      flush();
      chunks.push(v);
    } else if (Array.isArray(v)) {
      cborHead(4, v.length, out);
      for (const x of v) enc(x);
    } else if (v instanceof Map) {
      cborHead(5, v.size, out);
      for (const [k, x] of v) { enc(k); enc(x); }
    } else if (typeof v === "object") {
      const keys = Object.keys(v);
      cborHead(5, keys.length, out);
      for (const k of keys) { enc(k); enc(v[k]); }
    } else throw new StrongboxError("encoding error: unsupported value");
  };
  enc(value);
  flush();
  return concat(...chunks);
}

/** Decode one CBOR item. Maps become `Map`s (names are user data: never object keys). */
export function cborDecode(data) {
  let at = 0;
  const bad = () => new StrongboxError("encoding error: malformed CBOR");
  const byte = () => { if (at >= data.length) throw bad(); return data[at++]; };
  const take = (n) => { if (at + n > data.length) throw bad(); const b = data.subarray(at, at + n); at += n; return b; };
  const arg = (info) => {
    if (info < 24) return info;
    if (info === 24) return byte();
    if (info === 25) return (byte() << 8) | byte();
    if (info === 26) return new DataView(take(4).slice().buffer).getUint32(0);
    if (info === 27) {
      const n = new DataView(take(8).slice().buffer).getBigUint64(0);
      if (n > BigInt(Number.MAX_SAFE_INTEGER)) throw bad();
      return Number(n);
    }
    throw bad(); // indefinite lengths: never written by ciborium for these types
  };
  const item = (depth) => {
    if (depth > 64) throw bad();
    const b = byte();
    const major = b >> 5, inf = b & 31;
    switch (major) {
      case 0: return arg(inf);
      case 1: return -1 - arg(inf);
      case 2: return take(arg(inf)).slice();
      case 3: try { return utf8Decoder.decode(take(arg(inf))); } catch { throw bad(); }
      case 4: { const n = arg(inf), a = []; for (let i = 0; i < n; i++) a.push(item(depth + 1)); return a; }
      case 5: { const n = arg(inf), m = new Map(); for (let i = 0; i < n; i++) { const k = item(depth + 1); m.set(k, item(depth + 1)); } return m; }
      case 6: arg(inf); return item(depth + 1); // tag: ignore
      case 7:
        if (inf === 20) return false;
        if (inf === 21) return true;
        if (inf === 22 || inf === 23) return null;
        throw bad();
    }
    throw bad();
  };
  const v = item(0);
  return v;
}

/** Field of a decoded struct (a Map with string keys), or an error if missing. */
function field(m, name, check) {
  if (!(m instanceof Map) || !m.has(name)) throw new StrongboxError(`encoding error: missing field \`${name}\``);
  const v = m.get(name);
  if (check && !check(v)) throw new StrongboxError(`encoding error: invalid field \`${name}\``);
  return v;
}
const isInt = (v) => Number.isSafeInteger(v);
const isUint = (v) => Number.isSafeInteger(v) && v >= 0;
const isBytes = (v) => v instanceof Uint8Array;
const isStr = (v) => typeof v === "string";

// ---------------------------------------------------------------- vault constants

export const BLOCK_SIZE = 256 * 1024;
export const BLOCK_PAYLOAD = BLOCK_SIZE - NONCE_LEN - TAG_LEN;
export const KEY_ENTRIES = 8;
export const RECOVERY_ENTRY = KEY_ENTRIES;
const ENTRIES = KEY_ENTRIES + 1;
export const ENTRY_LEN = NONCE_LEN + 32 + TAG_LEN;
export const ENTRIES_LEN = ENTRIES * ENTRY_LEN;
export const HEADER_LEN = 16 * 1024;
const HEADER_BODY_PLAIN = HEADER_LEN - ENTRIES_LEN - NONCE_LEN - TAG_LEN;
export const HEADER_BLOCKS = 2;
export const MIN_DRIVE_PIN_LEN = 8;
const RECORD_PLAIN = 8192;
export const RECORD_LEN = NONCE_LEN + RECORD_PLAIN + TAG_LEN;
export const MAX_RECORD_CREDENTIALS = KEY_ENTRIES;

const L_DRIVE_SALT = "strongbox/drive-salt/v1";
const L_LOCATOR = "strongbox/vault/locator/v1";
const L_AUTH = "strongbox/vault/auth/v1";
const L_TRANSPORT = "strongbox/vault/transport/v1";
const L_REC_TRANSPORT = "strongbox/vault/recovery-transport/v1";
const L_VAULT_SEED = "strongbox/vault-salt/seeded/v1";
const L_REC_LOCATOR = "strongbox/vault/recovery-locator/v1";
const L_REC_AUTH = "strongbox/vault/recovery-auth/v1";
const L_ENTRY = "strongbox/drive/entry/v1";
const L_REC_ENTRY = "strongbox/drive/recovery-entry/v1";
const L_HEADER = "strongbox/drive/header/v2";
const L_META = "strongbox/drive/meta/v1";
const L_FILE = "strongbox/drive/file/v1";
const L_CHALLENGE = "strongbox/vault-auth-challenge/v1";
const L_USERNAME_SALT = "strongbox/vault/username/v1";
const L_LOOKUP = "strongbox/vault/lookup/v1";
const L_RECORD = "strongbox/vault/record/v1";

/** PRF input for drive `slot` with `pin` (every guess needs the physical key). */
export const driveSalt = (slot, pin) => sha256(info(L_DRIVE_SALT, [u32be(slot), utf8(pin)]));

/** PRF input for the vault login of an account with this random per-account seed. */
export const vaultSalt = (seed) => sha256(info(L_VAULT_SEED, [seed]));

export function checkDrivePin(pin) {
  if ([...pin].length < MIN_DRIVE_PIN_LEN) throw malformed("drive PIN too short (at least 8 characters)");
}

// ---------------------------------------------------------------- login credentials

export const locatorHash = (locator) => sha256(locator);
export const memberId = (locator) => toHex(locatorHash(locator));

/** What a vault member (security key or recovery code) uses to log in. */
export class MemberCreds {
  constructor(ikm, lLocator, lAuth, lTransport) {
    this.locator = derive(ikm, lLocator);
    this.authSeed = derive(ikm, lAuth);
    this.transport = derive(ikm, lTransport);
  }
  static fromPrf(prfVault) { return new MemberCreds(prfVault, L_LOCATOR, L_AUTH, L_TRANSPORT); }
  publicKey() { return ed25519.getPublicKey(this.authSeed); }
  signChallenge(serverId, challenge) {
    return ed25519.sign(info(L_CHALLENGE, [utf8(serverId), locatorHash(this.locator), challenge]), this.authSeed);
  }
  wipe() { wipe(this.authSeed); wipe(this.transport); }
}

// ---------------------------------------------------------------- usernames

/** Keys derived from a username with Argon2id (salt: the server id), and the account seed. */
export class UsernameKeys {
  static async derive(username, serverId) {
    const salt = sha256(info(L_USERNAME_SALT, [utf8(serverId)]));
    let out;
    try {
      out = await argon2idAsync(utf8(username), salt, { t: 3, m: 64 * 1024, p: 4, dkLen: 32, version: 0x13, asyncTick: 10 });
    } catch (e) {
      throw new StrongboxError(`cryptography: key derivation failed: ${e?.message ?? e}`);
    }
    const k = new UsernameKeys();
    k.lookup = derive(out, L_LOOKUP);
    k.recordKey = derive(out, L_RECORD);
    k.seed = null;
    wipe(out);
    return k;
  }

  newSeed() { this.seed = randomBytes(32); }

  vaultSalt() {
    if (!this.seed) throw malformed("account seed not loaded");
    return vaultSalt(this.seed);
  }

  /** Encrypt the credential ids and member labels into a fixed-size record. */
  sealRecord(credentialIds, members) {
    if (!this.seed) throw malformed("account seed not loaded");
    if (credentialIds.length === 0 || credentialIds.length > MAX_RECORD_CREDENTIALS) {
      throw malformed("credential record must hold 1-8 credentials");
    }
    const cbor = cborEncode({
      credential_ids: credentialIds,
      members: members.map((m) => ({ id: m.id, label: m.label, kind: m.kind, slot: m.slot ?? null })),
      seed: this.seed,
    });
    if (cbor.length + 4 > RECORD_PLAIN) throw malformed("credential ids too long");
    const plain = new Uint8Array(RECORD_PLAIN);
    plain.set(u32be(cbor.length));
    plain.set(cbor, 4);
    return seal(this.recordKey, aad(L_RECORD, [this.lookup]), plain);
  }

  /** `null` for a record this username does not open (including the server's decoys). */
  openRecord(record) {
    const plain = tryOpen(this.recordKey, aad(L_RECORD, [this.lookup]), record);
    if (!plain || plain.length < 4) return null;
    const len = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
    if (4 + len > plain.length) return null;
    try {
      const r = cborDecode(plain.subarray(4, 4 + len));
      const seed = field(r, "seed", isBytes);
      if (seed.length !== 32) return null;
      const credentialIds = field(r, "credential_ids", Array.isArray);
      if (!credentialIds.every(isBytes)) return null;
      const members = field(r, "members", Array.isArray).map((m) => ({
        id: field(m, "id", isStr),
        label: field(m, "label", isStr),
        kind: field(m, "kind", isStr),
        slot: field(m, "slot", (v) => v === null || isUint(v)),
      }));
      this.seed = seed;
      return { credentialIds, members };
    } catch {
      return null;
    }
  }
}

// ---------------------------------------------------------------- recovery codes

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** A recovery code: one 256-bit secret, printed as 52 base32 characters in groups of 4. */
export class RecoveryCode {
  constructor(secret) { this.secret = secret; }
  static generate() { return new RecoveryCode(randomBytes(32)); }

  encode() {
    let bits = 0, nbits = 0, chars = "";
    for (const b of this.secret) {
      bits = ((bits << 8) | b) & 0xffff;
      nbits += 8;
      while (nbits >= 5) { nbits -= 5; chars += ALPHABET[(bits >> nbits) & 31]; }
    }
    if (nbits > 0) chars += ALPHABET[(bits << (5 - nbits)) & 31];
    return chars.match(/.{1,4}/g).join("-");
  }

  static decode(code) {
    const out = new Uint8Array(32);
    let bits = 0, nbits = 0, i = 0;
    for (const c of code) {
      if (/\s/.test(c) || c === "-") continue;
      const v = ALPHABET.indexOf(c.length === 1 && c < "\u0080" ? c.toUpperCase() : "?");
      if (v < 0) throw malformed("recovery code character");
      bits = ((bits << 5) | v) & 0xffff;
      nbits += 5;
      if (nbits >= 8) {
        nbits -= 8;
        if (i === 32) throw malformed("recovery code length");
        out[i++] = (bits >> nbits) & 255;
      }
    }
    if (i !== 32) throw malformed("recovery code length");
    return new RecoveryCode(out);
  }

  memberCreds() { return new MemberCreds(this.secret, L_REC_LOCATOR, L_REC_AUTH, L_REC_TRANSPORT); }
  entryKey(slot) { return derive(this.secret, L_REC_ENTRY, [u32be(slot)]); }
}

/** Entry key from the PRF output for `driveSalt`. */
export const entryKey = (prfDrive) => derive(prfDrive, L_ENTRY);

// ---------------------------------------------------------------- blocks and headers

export const randomHeader = () => randomBytes(HEADER_LEN);
export const randomBlock = () => randomBytes(BLOCK_SIZE);
export const randomEntry = () => randomBytes(ENTRY_LEN);

function sealBlock(key, ad, plaintext) {
  if (plaintext.length > BLOCK_PAYLOAD) throw new Error("block payload too large");
  const padded = new Uint8Array(BLOCK_PAYLOAD);
  padded.set(plaintext);
  return seal(key, ad, padded);
}

function openBlock(key, ad, block) {
  if (block.length !== BLOCK_SIZE) throw malformed("block size");
  return open(key, ad, block);
}

const entryAad = (slot, index) => aad(L_ENTRY, [u32be(slot), new Uint8Array([index])]);
const headerKey = (driveKey) => derive(driveKey, L_HEADER);
const headerAad = (slot, copy) => aad(L_HEADER, [u32be(slot), new Uint8Array([copy])]);

export const wrapEntry = (slot, index, entryKey, driveKey) => seal(entryKey, entryAad(slot, index), driveKey);

/** The entries of a header (valid or random), to carry over when rewriting it. */
export function headerEntries(header) {
  return Array.from({ length: ENTRIES }, (_, i) => header.slice(i * ENTRY_LEN, (i + 1) * ENTRY_LEN));
}

function encodeHeaderBody(b) {
  return cborEncode({
    generation: b.generation,
    used_entries: b.usedEntries,
    meta_blocks: b.metaBlocks,
    meta_len: b.metaLen,
    grants: b.grants.map((g) => ({ entry: g.entry, member_id: g.memberId })),
  });
}

function decodeHeaderBody(cbor) {
  const m = cborDecode(cbor);
  const metaBlocks = field(m, "meta_blocks", Array.isArray);
  if (!metaBlocks.every(isUint)) throw malformed("meta blocks");
  return {
    generation: field(m, "generation", isUint),
    usedEntries: field(m, "used_entries", isUint),
    metaBlocks,
    metaLen: field(m, "meta_len", isUint),
    grants: field(m, "grants", Array.isArray).map((g) => ({ entry: field(g, "entry", isUint), memberId: field(g, "member_id", isStr) })),
  };
}

export function sealHeader(slot, copy, driveKey, entries, body) {
  const cbor = encodeHeaderBody(body);
  if (cbor.length + 4 > HEADER_BODY_PLAIN) throw malformed("header body too large");
  const plain = new Uint8Array(HEADER_BODY_PLAIN);
  plain.set(u32be(cbor.length));
  plain.set(cbor, 4);
  const out = concat(...entries, seal(headerKey(driveKey), headerAad(slot, copy), plain));
  if (out.length !== HEADER_LEN) throw new Error("header length");
  return out;
}

/** Decrypt a header copy's body with a known drive key; `null` if it does not authenticate. */
export function openHeaderBody(slot, copy, header, driveKey) {
  if (header.length !== HEADER_LEN) return null;
  const plain = tryOpen(headerKey(driveKey), headerAad(slot, copy), header.subarray(ENTRIES_LEN));
  if (!plain) return null;
  const len = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
  if (4 + len > plain.length) return null;
  try { return decodeHeaderBody(plain.subarray(4, 4 + len)); } catch { return null; }
}

export const KIND_KEY = "key";
export const KIND_RECOVERY = "recovery";

/** The drive keys that `key` unwraps from a header's entries, with their entry index. */
function* openEntries(slot, entries, key, kind) {
  const [lo, hi] = kind === KIND_KEY ? [0, KEY_ENTRIES] : [RECOVERY_ENTRY, RECOVERY_ENTRY + 1];
  for (let i = lo; i < hi; i++) {
    const dk = tryOpen(key, entryAad(slot, i), entries[i]);
    if (dk && dk.length === 32) yield [i, dk];
  }
}

/**
 * Try to open one header copy with any of `keys` ([{key, kind}]). `null` means nothing opened
 * it, deliberately the same for a wrong PIN and an unused slot.
 */
export function openHeader(slot, copy, header, keys) {
  if (header.length !== HEADER_LEN) return null;
  const entries = headerEntries(header);
  for (const { key, kind } of keys) {
    for (const [i, driveKey] of openEntries(slot, entries, key, kind)) {
      const body = openHeaderBody(slot, copy, header, driveKey);
      if (body) return { driveKey, entry: i, body };
    }
  }
  return null;
}

/** Whether any of `keys` opens an entry in `prefix` (the first ENTRIES_LEN bytes of a copy). */
export function entriesOpen(slot, prefix, keys) {
  if (prefix.length !== ENTRIES_LEN) return false;
  const entries = headerEntries(prefix);
  return keys.some(({ key, kind }) => !openEntries(slot, entries, key, kind).next().done);
}

// ---------------------------------------------------------------- metadata
// Dir  = { kind: "dir", entries: Map<name, Node>, mtime }
// File = { kind: "file", size, mtime, key: Uint8Array(32), blocks: number[] }
// On the wire: serde's externally tagged enum, `{"Dir": {...}}` / `{"File": {...}}`.

export const newDir = (mtime = 0) => ({ kind: "dir", entries: new Map(), mtime });

function dirToCbor(d) {
  const entries = new Map();
  for (const [name, n] of d.entries) {
    entries.set(name, n.kind === "dir"
      ? { Dir: dirToCbor(n) }
      : { File: { size: n.size, mtime: n.mtime, key: n.key, blocks: n.blocks } });
  }
  return { entries, mtime: d.mtime };
}

function dirFromCbor(m) {
  const d = newDir(field(m, "mtime", isInt));
  const entries = field(m, "entries", (v) => v instanceof Map);
  for (const [name, node] of entries) {
    if (!isStr(name) || !(node instanceof Map) || node.size !== 1) throw malformed("metadata node");
    const [tag, v] = [...node][0];
    if (tag === "Dir") d.entries.set(name, dirFromCbor(v));
    else if (tag === "File") {
      const key = field(v, "key", isBytes);
      if (key.length !== 32) throw malformed("file key");
      const blocks = field(v, "blocks", Array.isArray);
      if (!blocks.every(isUint)) throw malformed("file blocks");
      d.entries.set(name, { kind: "file", size: field(v, "size", isUint), mtime: field(v, "mtime", isInt), key, blocks });
    } else throw malformed("metadata node");
  }
  return d;
}

/** Deep copy of the folder structure (file nodes are never mutated, so they are shared). */
export function cloneDir(d) {
  const c = newDir(d.mtime);
  for (const [name, n] of d.entries) c.entries.set(name, n.kind === "dir" ? cloneDir(n) : n);
  return c;
}

/** Every block referenced by files under this directory. */
export function fileBlocks(d, out = []) {
  for (const n of d.entries.values()) {
    if (n.kind === "dir") fileBlocks(n, out); else for (const b of n.blocks) out.push(b);
  }
  return out;
}

const metaKey = (driveKey) => derive(driveKey, L_META);
const metaAad = (slot, block) => aad(L_META, [u32be(slot), u32be(block)]);

export const encodeMeta = (root) => cborEncode(dirToCbor(root));
export const metaBlockCount = (len) => Math.max(1, Math.ceil(len / BLOCK_PAYLOAD));

export function sealMeta(driveKey, slot, blocks, cbor) {
  const key = metaKey(driveKey);
  const chunks = [];
  for (let i = 0; i < cbor.length; i += BLOCK_PAYLOAD) chunks.push(cbor.subarray(i, i + BLOCK_PAYLOAD));
  if (!chunks.length) chunks.push(new Uint8Array(0));
  if (chunks.length !== blocks.length) throw new Error("metadata block count");
  return blocks.map((b, i) => sealBlock(key, metaAad(slot, b), chunks[i]));
}

export function openMeta(driveKey, slot, body, sealed) {
  if (sealed.length !== body.metaBlocks.length) throw malformed("metadata block count");
  const key = metaKey(driveKey);
  const parts = body.metaBlocks.map((b, i) => openBlock(key, metaAad(slot, b), sealed[i]));
  const cbor = concat(...parts).subarray(0, body.metaLen);
  return dirFromCbor(cborDecode(cbor));
}

// ---------------------------------------------------------------- file content

const fileAad = (slot, block, index) => aad(L_FILE, [u32be(slot), u32be(block), u32be(index)]);

export const fileBlockCount = (size) => Math.ceil(size / BLOCK_PAYLOAD);

export const sealFileBlock = (fileKey, slot, block, index, data) => sealBlock(fileKey, fileAad(slot, block, index), data);
export const openFileBlock = (fileKey, slot, block, index, sealed) => openBlock(fileKey, fileAad(slot, block, index), sealed);

// ---------------------------------------------------------------- names

export function validateName(name) {
  if (!name || name === "." || name === ".." || name.includes("/") || name.includes("\0")) throw malformed("invalid file name");
  if (utf8(name).length > 1024) throw malformed("file name too long");
}

// ---------------------------------------------------------------- sealed channel

export const SID_LEN = 16;
export const HELLO_NONCE_LEN = 32;
export const REQUEST_HEADER_LEN = SID_LEN + 8;
const L_CONFIRM = "strongbox/channel/confirm/v1";
const L_C2S = "strongbox/channel/c2s/v1";
const L_S2C = "strongbox/channel/s2c/v1";
const L_MSG = "strongbox/channel/msg/v1";

export const confirmTag = (transport, cn, sn, sid) => derive(transport, L_CONFIRM, [cn, sn, sid]);
export const sessionKeys = (transport, cn, sn, sid) => [derive(transport, L_C2S, [cn, sn, sid]), derive(transport, L_S2C, [cn, sn, sid])];

function channelNonce(counter) {
  const n = new Uint8Array(NONCE_LEN);
  n.set(u64be(counter), NONCE_LEN - 8);
  return n;
}
const messageAad = (sid, counter) => info(L_MSG, [sid, u64be(counter)]);

export const sealMessage = (key, sid, counter, pt) => sealWithNonce(key, channelNonce(counter), messageAad(sid, counter), pt);
export const openMessage = (key, sid, counter, ct) => openWithNonce(key, channelNonce(counter), messageAad(sid, counter), ct);

export const METHOD = { GET: 0, POST: 1, PUT: 2, DELETE: 3 };

/** Framing of a request inside a sealed message: method, path, token; the body follows. */
export function encodeRequestHead(method, json, path, token) {
  const p = utf8(path), t = utf8(token);
  return concat(new Uint8Array([METHOD[method] | (json ? 0x80 : 0)]), u16be(p.length), p, u16be(t.length), t);
}
