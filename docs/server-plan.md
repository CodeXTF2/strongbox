# Strongbox server plan

## 1. What the server is (and is not)

The server is a **blind, untrusted store**. It is trusted for availability only, never for
confidentiality, and only partly for integrity: clients detect tampering and rollback on
their own.

| The server stores | The server never sees |
|---|---|
| username, Ed25519 auth public key | file/folder names, paths, tree structure |
| keyslots (AMK wrapped under 256-bit KEKs) | file timestamps (mtime/ctime) |
| sealed directory nodes `(id, version, bytes)` | exact file sizes (Padmé-padded, 4 KiB minimum) |
| encrypted chunks `(id, bytes)` | contents, PRF outputs, PINs, passwords, any decryption key |
| per-account change sequence numbers, quota usage | which chunks belong to which file |

What it **can** still observe: account identity, client IPs, when you are online,
access patterns (which opaque ids are read/written together), the number of directories
and chunks, and padded sizes. See §7 for mitigations.

## 2. Current implementation (v0, in this repo)

`crates/server`: Rust, axum, SQLite (WAL), filesystem blob store, single binary.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/info` | – | server id (pinned by clients), limits, registration mode |
| `POST /v1/accounts` | invite/open | create account: username, auth pubkey, keyslots |
| `GET /v1/accounts/{u}/keyslots` | – (rate-limited) | fetch keyslots to unlock |
| `POST /v1/auth/challenge`, `POST /v1/auth/session` | – (rate-limited) | Ed25519 challenge/response, returns bearer token |
| `DELETE /v1/auth/session` | bearer | logout |
| `PUT/DELETE /v1/keyslots/{id}` | bearer | add/remove keys (last one cannot be removed) |
| `GET /v1/nodes/{id}` | bearer | sealed node + version header |
| `GET /v1/changes?since=` | bearer | incremental sync feed (tombstones included) |
| `POST /v1/commit` | bearer | atomic multi-node CAS writes + blob deletions |
| `PUT/GET/DELETE /v1/blobs/{id}`, `GET /v1/blobs` | bearer | encrypted chunks |
| `GET /v1/usage` | bearer | padded bytes used / quota |
| `/v2/…` | see spec | deniable vaults: username lookup, login, members, fixed-size slot blocks ([deniable-drives.md](deniable-drives.md#8-server-v2)) |

Properties already in place: sessions stored as SHA-256(token); single-use 2-minute
challenges bound to the pinned server id (at most 16 outstanding per account); per-IP token
bucket on pre-login routes (`--trust-proxy` takes the IP from the local proxy's
`X-Forwarded-For`, otherwise every proxied request shares one bucket); constant-time invite
check; quotas charged on padded sizes; all-or-nothing commits with optimistic concurrency
(409 + current versions on conflict); write-then-rename blob writes; keyslots are insert-only
(a stolen session cannot overwrite a working keyslot); `Cache-Control: no-store` and
`nosniff` on every response.

**No unauthenticated data access.** Nodes, blobs, the change feed and usage all require a
bearer session and are scoped to its account. The only per-user data served before login is
the keyslot set, which must be: it is what the client unlocks. Unknown usernames get stable
decoy keyslots (derived from a server-local secret) and a throwaway challenge rather than a
404, so these endpoints no longer reveal which usernames exist (registration still does).

## 3. Target architecture: control plane / data plane split

```
            ┌──────────── control plane (small, consistent) ────────────┐
client ───► │ stateless API nodes (N)  ──►  Postgres (accounts, keyslots, │
  TLS       │   auth, quotas, CAS          sessions, nodes, blob index)  │
            └───────────────┬────────────────────────────────────────────┘
                            │ presigned URLs (short-lived, per blob id)
            ┌───────────────▼──────────── data plane (big, dumb) ─────────┐
client ───► │ BlobStore: FS │ S3/MinIO/R2/B2 │ erasure-coded k-of-n backends │
            └──────────────────────────────────────────────────────────────┘
```

**Control plane.** It is tiny per user: a directory tree is usually a few hundred KB of
sealed nodes. It needs strong consistency for compare-and-swap commits.

- Swap SQLite for **Postgres** behind the existing `Db` interface. It's the same schema;
  `SELECT … FOR UPDATE` per account row replaces the process-wide write lock. Partition
  `nodes`/`blobs` by `account_id` when tables grow.
- API nodes are stateless (sessions and challenges live in the DB), so you scale
  horizontally behind a load balancer. Move rate limiting to the proxy or Redis.

**Data plane.** Nearly all bytes live here. It needs no consistency beyond read-your-writes
on a single object, because blob ids are random and written once.

- `BlobStore` trait (already there). Next implementation: **S3-compatible** via the
  `object_store` crate (AWS, MinIO, Cloudflare R2, Backblaze B2, Garage).
- **Presigned URLs**: `PUT /v1/blobs/{id}` becomes "reserve quota, return a signed URL",
  and the client uploads directly to object storage. API nodes then never carry bulk
  traffic, which is the main scaling lever.
- Server-side orphan sweep for objects with no DB row, using the object store's own
  timestamps. This is internal to the operator and not exposed per file.

## 4. Decentralization roadmap (self-hostable + pluggable storage)

Confidentiality never depends on the operator, so decentralizing targets **availability,
durability and exit rights**. Building a P2P network is not the goal.

**Phase A: self-host (done).** One binary plus a TLS proxy (see `deploy/`). Anyone can run
a server; the client takes any server URL and pins its id.

**Phase B: multi-instance.** Postgres plus S3. Run your own MinIO/Garage cluster, or rent
storage. Still one operator.

**Phase C: erasure-coded storage across independent backends.** This is where most of the
"decentralized" value comes from.

- An `ErasureBlobStore` splits each encrypted chunk with Reed-Solomon into *n* shards,
  any *k* of which recover it, e.g. k=3, n=5 (1.67× overhead).
- Shards are placed on *n* independent backends: different S3 providers or regions,
  friends' servers, or volunteer "storage peers" running a minimal blob-only daemon (the
  same `PUT/GET/DELETE /blobs/{id}` API with peer authentication).
- The shard map `blob → [(backend, shard index, hash)]` lives in the control plane. A
  repair worker re-creates lost shards. Random audits (`HMAC(nonce, shard range)`) check
  that peers still hold their data.
- Storage peers learn nothing: they hold fragments of ciphertext.

**Phase D: account portability.** Everything is client-encrypted and self-authenticating,
so moving servers is just copying data. `sbox migrate --to <server>` copies keyslots,
nodes (same ids and versions) and blobs, then re-pins the profile. This gives users a
credible exit from any operator, which is the core promise of federation, without
cross-server protocols.

**Phase E (optional): federation for sharing.** Cross-server shares need user identity
keys (X25519/Ed25519 derived from the AMK) published by each home server, plus **key
transparency** (an append-only, verifiable log of username→key) so a server cannot swap
in its own key. Share capabilities are `(node id, dir key)` sealed to the recipient.

**Not planned: a full P2P DHT network.** It brings Sybil resistance, incentive design, churn
repair and NAT traversal problems, and it leaks access patterns to arbitrary peers. Phases
C and D deliver the resilience benefits with far less risk.

## 5. Scaling notes

- **Hot path**: commits touch one account row and a few node rows, so they parallelize
  across accounts. Chunk transfer goes directly to object storage once presigned URLs land.
- **Large directories**: a directory is one sealed node, which is fine to ~10⁴ entries.
  Beyond that, split directory nodes into a B-tree of sealed pages (a client-only change).
- **Sync**: `GET /v1/changes?since=` is a per-account monotonic feed, so desktop sync
  clients poll cheaply. Add SSE or long-poll for push.
- **Uploads**: the client already overlaps encryption and upload. Next steps are
  parallel chunk uploads and resumable uploads (chunk ids are deterministic per content
  key, so a client can resume by listing which chunks exist).
- **Small files**: optional pack files (many small files in one chunk sequence) cut object
  counts and hide the number of files.

## 6. Security hardening backlog

- TLS only (enforced by the client except on localhost) and HSTS at the proxy.
- **Logging (done, first step).** By default the server logs nothing that identifies a user,
  object or request: no request traces, no IPs, no usernames or ids, errors only as coarse
  categories, and `RUST_LOG` is ignored so an environment variable cannot turn that off. The
  shipped Caddyfile has no access log. `--debug` / `STRONGBOX_DEBUG=true` restores full logging
  (request paths, raw errors, `RUST_LOG`) for development and prints a warning at startup.
  Still to do: the database itself holds activity metadata (sessions with expiry times,
  per-account counters, blob file timestamps); see §7.
- **Username enumeration**: decoy keyslots for unknown users are done. Still open: the
  registration endpoint reveals taken names, (keyslot labels are now encrypted under a key derived from the AMK).
- **Signed root / fork consistency**: the client already detects per-node rollback with
  a local version cache. Add a signed, hash-chained account log (`seq, Merkle root of
  node versions, prev hash`) signed with an AMK-derived Ed25519 key, so a server cannot
  hide or roll back whole subtrees, or fork two devices without detection.
- **Session binding**: optional per-device keys, so stolen bearer tokens are useless.
- **AMK rotation**: re-wrap keyslots, re-key directories lazily, rotate the auth key.
- **Abuse handling**: users are responsible for their own content. Content moderation is
  impossible from the operator side by design: the operator can see accounts and volumes but
  not content, so policy can only act at account level (quotas, invites, payment).
- Fuzz the commit and keyslot JSON parsers; get an external crypto/design audit before
  any public release.

## 7. Metadata leakage that remains, and mitigations

| Leak | Mitigation |
|---|---|
| exact file size | Padmé + 4 KiB minimum (done) |
| number of files | files are entries inside directory nodes (done); pack files (planned) |
| number of directories | padded node sizes (done); optional dummy nodes |
| when you upload/read | batching; optional cover traffic (costly) |
| who you are / where from | invite-only or anonymous signup; Tor-friendly (no IP binding) |
| which chunks form a file | upload order and timing; mitigate by interleaving uploads |

## 8. Delivery phases

| Phase | Server | Client |
|---|---|---|
| 0 (done) | SQLite + FS, full v1 API, quotas, CAS commits | core crypto, Windows WebAuthn PRF, CTAP-HID, CLI, Tauri app |
| 1 | Postgres + S3 backends, presigned URLs, Docker image | parallel/resumable transfers, real-hardware test matrix |
| 2 | erasure-coded multi-backend store, repair + audits | signed account log, sync client (watch folder) |
| 3 | storage-peer daemon, `migrate` support | account migration, shares (same server) |
| 4 | key directory + transparency log | cross-server sharing |
