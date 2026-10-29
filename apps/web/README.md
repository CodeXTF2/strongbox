# Strongbox web client (work in progress)

A standalone browser version of the desktop app. Every key and every byte of crypto stays in the
page. The web server that hosts it only serves static files and is never sent anything. It talks to
the same Strongbox server, with the same formats, as the desktop app and CLI.

## Layout

| Path | What |
|---|---|
| `ui/core.js` | Port of `crates/core`: HKDF/AEAD helpers, CBOR (the serde/ciborium subset), usernames and records, recovery codes, headers, metadata, file blocks, sealed channel |
| `ui/client.js` | Port of `crates/client` (`api.rs` + `vault.rs`): `Api` (sealed channel), `VaultClient`, `VaultDrive`, batched uploads, pipelined transfers, access management |
| `ui/authn.js` | WebAuthn PRF authenticator (non-discoverable, credProtect 3 enforced, UV required, two PRF inputs per touch), plus the insecure soft key (same state format as `crates/fido/src/soft.rs`) |
| `ui/bridge.js` | Stands in for the desktop's Rust process: the same `invoke` commands and events as `apps/desktop/src/main.rs`, exposed as `window.__TAURI__`, plus browser file pickers, drops, downloads (File System Access API, or blob/zip fallback) |
| `ui/app.js`, `index.html`, `style.css`, `icons.js` | Copied from `apps/desktop/ui`, with small changes: HTML5 file drop, touch handling, phone drawer and floating New button, CSP meta |
| `ui/mobile.css` | Phone and touch layout (style.css is unchanged): off-canvas sidebar, bottom-sheet menus, docked transfers, icon-only selection bar, edge-to-edge preview with swipe |
| `ui/vendor.js` | Audited `@noble` ciphers/hashes/curves bundled into one local file (`vendor/`, `npm install && npm run build`). Pinned versions; no CDN |
| `serve.mjs` | Zero-dependency static server. `--api URL` proxies `/v1/` and `/v2/` for same-origin local development |
| `test/e2e.mjs` | Node end-to-end test of `client.js` against a real server with the soft key (**currently hangs, see below**) |

Run locally (from the repo root, with a server on :8080 started by `start-server.bat`):

```sh
node apps/web/serve.mjs --api http://127.0.0.1:8080
# open http://127.0.0.1:8090/        (real security key, WebAuthn)
# open http://127.0.0.1:8090/?soft   (insecure software key; loopback pages only)
```

## Verified

- **Format interop with the Rust client, both ways**, against a real server (a scratch harness
  using `strongbox-client` with the soft key). The JS port read a Rust-created account, record,
  drive and file. It uploaded, made folders, renamed and searched. The Rust client then read the
  JS-written metadata, file blocks, header and record byte-for-byte. Rust-made account and vault
  recovery codes work in JS, and a JS-made account code works too. A wrong PIN and an unused slot
  both open nothing; an unknown username is refused.
- **Browser UI, headless Chromium, soft key, desktop (1280×800) and phone (390×844, touch)**:
  - create account (with its recovery code), create vault (with its recovery code)
  - upload two files and create a folder
  - preview a text file
  - download through the blob fallback, byte-identical
  - lock, sign in again and reopen the vault
  - zero console errors
- Argon2id (64 MiB, t=3, p=4) takes about 1 s in Node with noble.

## Remaining bugs and gaps

1. **`test/e2e.mjs` hangs in Node** at the first `uploadStaged` on a freshly created drive.
   - The main thread spins: CPU time keeps climbing, timers never fire, and an inspector
     `Debugger.pause` from a worker never lands.
   - Direct `api.writeBlocks` of 3 blocks on the same drive works. `uploadStaged` hangs both
     with a `File` and with a plain `{ slice().arrayBuffer() }` object.
   - The hang is not deterministic: in one run it happened before account creation finished.
   - The earlier `uploadStaged` run in the interop script, and every browser upload, worked.
   - Root cause unknown. Next step: take a CPU profile (`node --cpu-prof` with a self-exit
     timer), and bisect the noble Argon2 async loop (`asyncTick`) against concurrent fetches.
2. **Access management is ported but untested**, because it sits behind the e2e test:
   - grant and revoke a key
   - change PIN (revokes other keys)
   - add a key to the current vault
   - revoke a vault recovery code
   - rename and remove members
   - delete account
3. **Real security keys are untested.** Only the soft key was exercised. Still to check:
   - WebAuthn PRF with UV and credProtect enforcement on a YubiKey in Chrome, Edge, Firefox
     and Safari
   - the `NotAllowedError` → "Cancelled" mapping
4. **Relying party id.** Browsers only allow an RP id that matches the page's own domain. On
   `strongbox.app` (or a subdomain) the client uses `strongbox.app`, so keys are shared with the
   desktop app. Anywhere else, credentials are bound to that host: accounts created there are
   web-only, and desktop-created accounts can't sign in there.
5. **No CORS on the server.** The page must share an origin with the API: a reverse proxy routes
   `/v1/` and `/v2/` to the server and everything else to `ui/`. `serve.mjs --api` does this for
   development. A production Caddy example is still to write. Cross-origin use would need a
   `CorsLayer` in the server, which we've left unchanged.
6. **Trust in the page host.** A hostile host can serve altered JS. Implemented:
   - no third-party scripts
   - strict CSP meta (`script-src 'self'`)
   - frame/referrer hardening in `serve.mjs`

   Still to do: a single-file build with a published SHA-256 (or SRI) so users can verify what
   they run, and documenting self-hosting as the strong option.
7. **Untested download and upload paths:**
   - the File System Access API download path (save picker, folder picker; headless can't drive
     native pickers)
   - the zip fallback for folder downloads
   - drag-and-drop folder upload
8. **Known limits:**
   - the folder-upload picker omits empty subfolders (drag-and-drop keeps them)
   - the zip fallback is in memory and capped below 4 GiB
   - browsers can't set file mtimes
   - closing the tab ends the server session on a best-effort basis only
9. **Docs.** `docs/deniable-drives.md` and the README don't mention the web client yet (AGENTS.md
   asks for this when clients or flows change).
