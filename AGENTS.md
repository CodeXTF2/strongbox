# AGENTS.md

Strongbox is an end-to-end encrypted cloud drive with **deniable hidden drives**. It is
unlocked by a FIDO2 security key (WebAuthn PRF / hmac-secret) and a drive PIN. The server is a
blind store of fixed-size random-looking blocks. Rust workspace, not audited. Pre-release:
there is **no backward compatibility** to preserve (formats, routes and schema may change
freely; servers are wiped on format changes).

Full spec: `docs/deniable-drives.md` (§1 threat model, §5 derivations, §6 formats, §8 server and
sealed channel). Read the relevant section before touching crypto, formats or server storage.

## Layout

| Path | What |
|---|---|
| `crates/core` | Pure crypto and formats, no I/O: `aead` (XChaCha20-Poly1305), `kdf` (HKDF-SHA256, `label ‖ 0 ‖ (u32be len ‖ part)*`), `vault` (usernames, entries, headers, metadata, file blocks), `channel` (sealed transport) |
| `crates/proto` | Wire types and limits (`MAX_BLOCKS_PER_REQUEST`) |
| `crates/fido` | Authenticators: Windows WebAuthn, CTAP, `soft` (insecure test key, feature-gated) |
| `crates/client` | `api.rs` (HTTP + sealed channel), `vault.rs` (`VaultClient` = signed-in account, `VaultDrive` = an open drive), `transfer.rs`, `sbox` CLI |
| `crates/server` | axum + SQLite (`migrations/0001_init.sql`), `vaultstore.rs` (one preallocated file per vault), `vault_api.rs`, `channel_api.rs`, admin page |
| `apps/desktop` | Tauri 2 app; Rust commands in `src/main.rs`, plain JS UI in `ui/` |
| `deploy/` | Caddy, Dockerfile, systemd unit |

## Threat model (what every change must preserve)

Protected: **one snapshot of an honest server, plus the user's security key and its PIN**
(coerced). Given that, the adversary must not be able to:

- tell how many drives (slots) are in use, or prove hidden drives exist;
- find other usernames on the key except by offline Argon2id guessing per username;
- read names, sizes, counts or contents; recover deleted files with a coerced drive PIN;
- guess drive PINs without one physical key touch per guess.

Also: a hostile proxy / forged TLS must see only ciphertext and cannot forge, replay or reorder
calls (sealed channel); the same key on two servers yields unrelated secrets (per-account seed).

**Out of scope** (don't add complexity for these, but don't make them worse): multiple
snapshots or a recording server, a malicious server, network traffic analysis (sizes, timing,
IPs), plaintext the user exports, data destruction.

## How it works

1. **Sign-in.** Username → Argon2id (64 MiB, salt = server id) → lookup id + record key. The
   server returns an encrypted fixed-size credential record, or a stable decoy for unknown ids.
   One key touch evaluates two PRF inputs: `vault_salt(seed)` (login, transport key) and
   `drive_salt(slot, pin)` (drive entry key). Login = Ed25519 challenge, inside the sealed
   channel. Only `/v1/info`, the record lookup, sign-up and the channel hello are in the clear.
2. **Vault.** Every account has `slots` (default 100) drives × fixed size, all filled with CSPRNG
   output at creation (spares are pre-filled in `vault-spares/`). Used and unused slots are
   indistinguishable. Blocks are 256 KiB; blocks 0–1 of a slot hold two header copies.
3. **Header** (first 16 KiB of each header block, rest stays filler): 8 key entries
   (each wraps the drive key), then a sealed fixed-size body (generation, entry
   bitmap, grants, metadata block list). Wrong PIN and unused slot fail identically.
4. **Metadata.** The whole tree is one CBOR doc sealed into metadata blocks under a key derived
   from the drive key. Each file has a fresh random key; block *k* is sealed with AAD
   `(slot, block, k)`. No whole-file hash: that AEAD binding is the integrity guarantee, so
   **never reuse a file key for new content**.
5. **Commit** (copy-on-write): file blocks → new metadata in free blocks → older header copy
   with generation+1 → overwrite old metadata with random bytes (destroys deleted files' keys).
   Uploads are batched into one commit (`stage`/`upload_staged`/`commit_staged`); a batch that
   replaces a committed file commits at once. Commits refuse if another device committed.

## Rules for changes

- **Server stores nothing identifying or ordering:** random ids, `WITHOUT ROWID` tables, no
  timestamps, counters or usage accounting, no vault/slot/block ids in logs (only with
  `--debug`). A vault is one file (a file per slot would show used slots through `ctime`), only overwritten
  in place; atime and mtime are reset to a constant. SQLite runs with `secure_delete`, no WAL.
- **No recovery codes or other per-drive secrets known to the server or the account record:**
  nothing outside a drive's encrypted header may name a slot.
  Sessions and challenges live in memory.
- **Everything stored looks random and fixed-size.** No lazy allocation, no sparse files, no
  length that reveals content. New per-user data goes inside encrypted drive metadata, not
  in server tables linked to a vault.
- New authenticated routes go in `vault_api::sealed_routes` (reachable only via the channel).
- New KDF/AAD uses get their own versioned label (`strongbox/<area>/<name>/vN`).
- Keep `core` pure (no I/O); secrets in `Key`/`Zeroizing`; a wiped drive (`dk()` fails) must
  stop all encryption and decryption.
- When a change affects the threat model, formats, routes or transfers, update
  `docs/deniable-drives.md` (and the README diagram if the flow changes).

## Build and test

```sh
cargo build --workspace
cargo test --workspace          # e2e tests run a real server with the soft authenticator
cargo clippy --workspace --all-targets
cargo fmt --all
```

Windows helpers: `start-server.bat` (local server, open registration), `start-client.bat`
(desktop app; `--soft` uses the insecure software key, no hardware needed), `reset-server.bat` (wipe local server data). Tests construct `Config` literally:
new server options need a value in `crates/client/tests/{vault_e2e,hostile_proxy}.rs`.
