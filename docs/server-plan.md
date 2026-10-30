# Strongbox server plan

## 1. What the server is (and is not)

The server is a **blind, untrusted store**. It is trusted for availability only, never for
confidentiality, and only partly for integrity: clients detect a moved header generation within
a session (see [deniable-drives.md](deniable-drives.md#9-client-and-device) for what they cannot
detect across restarts).

| The server stores | The server never sees |
|---|---|
| per-vault random id, whole fixed-size blocks | usernames, file or folder names, paths, tree structure |
| lookup id (Argon2id of the secret username) and a fixed-size encrypted credential record | file timestamps or exact sizes |
| `H(locator)` and an Ed25519 public key per key | contents, PRF outputs, drive PINs, any decryption key |
| the vault layout (slots × blocks) and server settings | which of a vault's slots are in use |

What it **can** still observe: client IPs, when an account is online, which blocks are read
and written and how often (access patterns), the number of vaults, and the number of
members of each. See §4 for mitigations.

## 2. Current implementation

`crates/server`: Rust, axum, SQLite (rollback journal, `secure_delete`) for the small metadata tables, one
fixed-size file per vault, single binary.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/info` | – | server id, registration mode, vault layout |
| `POST /v2/vaults` | invite/open | create an account and allocate its vault (carries the first member's transport key; sent in the clear, so sign up on a trusted network) |
| `POST /v2/channel`, `POST /v2/rpc` | – | sealed channel: every other call below travels inside it (see [deniable-drives.md §8.1](deniable-drives.md#81-sealed-channel)) |
| `DELETE /v2/vaults` | bearer | delete the account and every drive |
| `GET /v2/lookup/{id}` | – (rate-limited) | encrypted credential record, or a stable decoy |
| `PUT /v2/record` | bearer | replace the record (backup keys) |
| `POST /v2/auth/challenge`, `POST /v2/auth/session` | – (rate-limited) | Ed25519 challenge/response, returns a bearer token |
| `DELETE /v2/auth/session` | bearer | logout |
| `GET/POST /v2/members`, `DELETE /v2/members/{id}` | bearer | manage keys (the last member cannot be removed) |
| `GET/PUT /v2/slots/{slot}/blocks` | bearer | read and write whole blocks |
| `GET/PUT /v2/slots/{slot}/headers` | bearer | read both header copies, write one |

Details of each endpoint are in [deniable-drives.md](deniable-drives.md#8-server-v2).

Properties already in place: sessions and challenges live in memory only and are stored as
SHA-256(token); single-use 2-minute challenges; per-IP token bucket on pre-login routes
(`--trust-proxy` takes the IP from the local proxy's `X-Forwarded-For`, otherwise every proxied
request shares one bucket); constant-time invite check; filler written at creation so used and
unused slots look alike; constant slot-file modification times; `Cache-Control: no-store` and
`nosniff` on every response.

**No unauthenticated data access.** Blocks, members and deletion require a bearer session
scoped to one vault. The only per-user data served before login is the encrypted record, which
must be: it is what the client decrypts. Unknown usernames get a stable, same-size decoy record
(derived from a server-local secret) and a throwaway challenge rather than a 404, so these
endpoints do not reveal which usernames exist. Creating an account still does, so keep
registration invite-only.

## 3. Hardening backlog

- TLS only (enforced by the client except on localhost) and HSTS at the proxy.
- **Sealed channel (done).** TLS is treated as optional protection: after sign-up every API
  call is an XChaCha20-Poly1305 message (`POST /v2/rpc`) under keys derived from a per-member
  `transport_key` (from the security-key PRF output, registered at sign-up).
  A hostile proxy, or a forged TLS certificate, sees only ciphertext lengths and cannot read,
  alter or replay messages (each counter is accepted once, within a 1024-wide window), nor answer a hello
  (the server must prove it holds the key). Only `/v1/info`, the record lookup, sign-up and the
  hello are in the clear. **Sign-up must happen on a network the user trusts**: it carries the
  transport key. Each account also has a random seed in its encrypted record that salts the
  PRF input, so the same credential on two servers yields unrelated secrets. Still visible to a proxy:
  IPs, timing, message sizes, the lookup id and the member id at hello. No forward secrecy
  against later disclosure of the server's stored transport keys (file contents are
  end-to-end encrypted regardless).
- **Logging (done, first step).** By default the server logs nothing that identifies a user,
  object or request: no request traces, no IPs, no usernames or ids, errors only as coarse
  categories, and `RUST_LOG` is ignored so an environment variable cannot turn that off. The
  shipped Caddyfile has no access log. `--debug` / `STRONGBOX_DEBUG=true` restores full logging
  for development and prints a warning at startup.
- **Registration and disk use.** Creating an account allocates and fills the whole vault
  (25 GiB with the default layout), so open registration on a public server is a disk-fill
  risk. Use `invite` mode (the default) or add per-day caps. `--spare-vaults` (default 1)
  keeps vaults filled in advance so creation is instant; each spare costs one vault of disk.
- **Account deletion** needs only a valid session. The desktop app signs in again first, but
  the server could require a fresh signature over the request.
- **Session binding**: optional per-device keys, so stolen bearer tokens are useless.
- **Abuse handling**: users are responsible for their own content. Content moderation is
  impossible from the operator side by design, so policy can only act at account level
  (invites, payment, deletion).
- Fuzz the JSON and block-range parsers; get an external crypto and design audit before any
  public release.

## 4. Metadata leakage that remains, and mitigations

| Leak | Mitigation |
|---|---|
| exact file size | files are chunked inside fixed-size drives; only the drive size is visible |
| number of files and directories | stored inside the encrypted drive metadata |
| when you read or write | batching; optional cover traffic (costly) |
| which blocks you touch | not hidden; access patterns can show a drive's active region (see [deniable-drives.md](deniable-drives.md#1-threat-model)) |
| who you are / where from | invite-only or anonymous signup; Tor-friendly (no IP binding) |
