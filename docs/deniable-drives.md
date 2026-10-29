# Deniable drives (vault format v1)

Status: implemented in the library, server, CLI and desktop UI; tested with the software
authenticator only. **Not audited.**

This is Strongbox's only account and storage format: an account is a secret username, its
security keys and recovery codes, and any number of fixed-size drives.

## 1. Threat model

**Adversary capabilities (all at once):**

- A complete snapshot of the server: database, blob files, file metadata, configuration
  (including any server secrets).
- The user's security key, *and* its PIN (obtained by coercion).
- Knowledge of this design and the source code.

**Goal of the user:** open one or more drives under duress ("decoy" drives) and claim that
they are all the drives that exist, without the adversary being able to prove otherwise.

**What must hold:** given the above, the adversary cannot distinguish a vault where the user
has created *k* drives from one where they have created *k + j* drives, for any *j* ≥ 0, and
cannot open a drive without its drive PIN except by guessing it through the physical key.
Likewise for usernames: the adversary cannot tell how many usernames (vaults) the key serves,
nor find one without guessing its username.

**Explicitly out of scope** (stated so nobody relies on them):

| Not protected | Why |
|---|---|
| Multiple snapshots, or a server recording writes | Slots that change between snapshots without the opened drives accounting for it reveal hidden activity. Defeating this needs ORAM-style access hiding. |
| A malicious server from the start | It can log which slots and blocks each session reads and writes, and keep the filler seed. |
| Network observation | IP address and timing link sessions; use Tor if that matters. |
| Plaintext the user exports | Downloaded files, OS caches, thumbnails, swap. |
| Coercion game theory | Deniability means the adversary cannot *prove* more drives exist. An adversary who knows the software supports hidden drives may keep coercing anyway. Users must understand this. |
| Data destruction | An adversary with the key and PIN can "reset" every slot, wiping hidden drives, without learning anything. |

**Honest summary claim:** *deniable against a single seizure of an honest server plus the
security key and its PIN, without the drive PINs.*

## 2. Measured hardware assumptions

Verified on a YubiKey 5 series, firmware 5.8.0 (`FIDO_2_3`), with a raw CTAP2 probe:

1. **Touch is enforced by firmware.** `getAssertion` with `up=false` returns `UP_REQUIRED`
   even with a valid PIN token. Every hmac-secret evaluation needs a physical touch.
2. **credProtect level 3 hides the credential without the PIN.** Without UV, the real
   credential and a never-existing credential id both produce `NO_CREDENTIALS` after a touch.

These are properties of that key model and firmware. Other authenticators may differ, and
the Windows WebAuthn API cannot test them at runtime (it always forces a touch). The client
therefore recommends PIN lengths for the worst case (§7).

## 3. Overview

```
username ──Argon2id──► lookup id + record key
server: lookup id → encrypted record (credential ids of this username's keys)
                    (unknown usernames: a stable decoy of the same size)

security key (non-discoverable credential per username, credProtect=3; nothing stored on it)
   │  one touch, two hmac-secret salts per touch
   ├─ salt "vault"            → vault secret → locator + vault auth key   (logs in)
   └─ salt (slot i, drive PIN) → drive secret → unwraps drive i's key        (opens drive i)

server: vault = 100 slots × fixed number of fixed-size blocks, all random from creation
```

- A username names a vault. One security key can serve any number of usernames, each with
  its own credential; the key itself stores nothing (the credentials are non-discoverable),
  so even with its PIN the key cannot list Strongbox accounts.
- Every vault has exactly `SLOTS` (default 100) drives' worth of space, all filled with random
  bytes when the vault is created. A used slot and an unused slot look the same.
- A drive is opened by (slot number, drive PIN). The drive PIN goes into the hmac-secret
  salt, so each guess costs one physical touch on that specific key. A wrong PIN and an
  unused slot produce the same result: nothing decrypts.
- The server never learns which slots are in use, how many drives exist, or anything about
  their contents. Its only per-vault records are the vault id and the members (security keys
  and recovery codes) allowed to log in.

## 4. Usernames and the security key

- **Usernames are secrets.** `Argon2id(username, salt = H(label ‖ server_id))`, 64 MiB,
  t = 3, p = 4, gives the **lookup id** (the server's index) and the **record key**. The
  record is the AEAD-encrypted list of credential ids of the username's keys, padded to a
  fixed size (`RECORD_LEN`) so it does not reveal how many keys there are.
- `GET /v2/lookup/{id}` returns the record, or for an unknown id a decoy derived from a
  server secret: stable across requests and the same size, so probing usernames online
  reveals nothing. (Creating a vault does reveal whether a username is taken; keep
  registration invite-only.)
- **Credentials are non-discoverable**, one per (username, key), RP id `strongbox.app`,
  `credProtect = 3` (enforced: keys without it are refused), user verification required,
  `user.id` random, `user.name = "Strongbox"`. The key stores nothing; its credential id
  (an encrypted blob only that key can use) lives in the username's record.
- **Why the username must be unguessable:** an adversary holding the key and its PIN can
  test a credential id against the key (one touch). They only obtain credential ids by
  decrypting records, i.e. by guessing usernames offline at Argon2 cost per guess against the
  seized database. A dictionary username ("alice") is found quickly; a random three-word
  name is not. The client says so when a username is chosen.
- Each `getAssertion` evaluates two PRF inputs (`first`, `second`) for whichever of the
  username's credentials is present. Opening a drive uses `first = VAULT_SALT` and
  `second = drive_salt(slot, pin)`: one touch logs in and opens the drive. Testing another
  drive PIN costs another touch.
- **Backup keys** (up to 8 per username): enrolled with the existing credential ids as the
  exclude list, added as account sign-in members, and appended to the encrypted username
  record. Account membership alone does not open drives. Granting a key access to a drive
  wraps that drive's key in one entry of its encrypted header. The same account key can be
  granted separately to multiple drives.

PRF semantics are those of WebAuthn: `hmac_salt = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)` and
`prf_output = HMAC-SHA256(credRandomWithUV, hmac_salt)`, computed inside the authenticator after
PIN verification. Nothing derived from `prf_output` is brute-forceable offline. Clients reject
any registration or assertion whose authenticator data lacks the user-verification flag, and
credentials are created with `credProtect` level 3 so that CTAP 2.0 keys cannot release
`prf_output` without the PIN.

## 5. Derivations

| Use | Primitive |
|---|---|
| AEAD | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) |
| KDF | HKDF-SHA256; `info = label ‖ 0x00 ‖ (u32be len ‖ part)*` |
| Username hardening | Argon2id v1.3, m = 64 MiB, t = 3, p = 4 |
| Login signatures | Ed25519 (`verify_strict`) |
| Hash | SHA-256 |

`H` = SHA-256, `KDF(ikm, label, parts)` = HKDF-SHA256 as above.

```
VAULT_SALT          = "strongbox/vault-salt/v1"
drive_salt(i, pin)  = H("strongbox/drive-salt/v1" ‖ 0 ‖ u32be(i) ‖ pin)

prf_v = PRF(VAULT_SALT),  prf_d = PRF(drive_salt(i, pin))     -- same touch

locator      = KDF(prf_v, "strongbox/vault/locator/v1")         -- 32 bytes, sent at login
auth seed    = KDF(prf_v, "strongbox/vault/auth/v1")            -- Ed25519
entry key    = KDF(prf_d, "strongbox/drive/entry/v1")           -- wraps the drive key
```

The server stores `H(locator)` only. Different keys have different `prf_v` and are separate
**members** of the same vault.

**Account recovery codes** are account members: they can authenticate to the account but
have no drive entry, so they do not open any drive. **Drive recovery codes** are per drive:
one 256-bit random secret `R`, shown as 52 base32 characters. Both uses are derived from the
whole secret under separate labels: the vault member locator and auth key
(`strongbox/vault/recovery-locator/v1`, `…/recovery-auth/v1`) and the drive's recovery entry
key (`strongbox/drive/recovery-entry/v1`, part `u32be(slot)`). Splitting `R` into halves
would leave each use at 128 bits, which Grover-style quantum search would reduce to 2^64;
deriving both from all of `R` keeps each at 256 bits for the same code length. The client
tries the recovery entry of every slot (100 trial decryptions, no server round trips beyond
reading the headers). A coerced drive recovery code cannot be used to guess drive PINs offline.

## 6. Layout and formats

`BLOCK = 256 KiB`. Every stored unit is one block. A vault is `SLOTS × BLOCKS_PER_SLOT`
blocks (server-wide constants; every vault on a server has the same layout, otherwise the
layout itself would be a signal). Default `SLOTS = 100`, `BLOCKS_PER_SLOT = 1024`
(256 MiB per drive, 25 GiB per vault).

### Sealed block

```
block = nonce (24) ‖ XChaCha20-Poly1305(key, nonce, plaintext (BLOCK − 40), aad) ‖ tag (16)
```

Random nonces: blocks are rewritten in place many times under the same key. A sealed block
and filler are both uniformly random to anyone without the key.

### Slot header (blocks 0 and 1)

Two copies so updates are atomic: a commit writes the copy with the older generation.

```
entry[0..8]  key entries      8 × (nonce 24 ‖ AEAD(entry key, drive key 32) ‖ tag 16) = 72 B each
entry[8]     recovery entry   same format, recovery entry key
body         nonce ‖ AEAD(KDF(drive key, "strongbox/drive/header/v1"), cbor body, padded) ‖ tag
```

AAD: entries bind `("strongbox/drive/entry/v1", u32be(slot), u8(index))`; the body binds
`("strongbox/drive/header/v1", u32be(slot), u8(copy))`. Unused entries are random.

Body (CBOR): `{ generation: u64, used_entries: u16 bitmask, grants: [(entry, member_id)], meta: { blocks: [u32], len: u64 } }`.
`used_entries` lets the client add a key or recovery code without overwriting another
key's entry; `grants` records which account members can open this drive. Both are only
readable with the drive key.

Opening slot *i*: read blocks 0–1, try every entry with the entry key, take the copy with
the highest generation whose body authenticates. If no entry opens: **"No drive found for
this slot and PIN"**, the same message, code path and timing for a wrong PIN and an unused
slot.

### Drive metadata and files

The whole tree is one CBOR document, sealed into metadata blocks under
`KDF(drive key, "strongbox/drive/meta/v1")`, AAD `(label, slot, block index)`:

```
Dir  { entries: name → Node, mtime }
Node = Dir | File { size, mtime, sha256, key, blocks: [u32] }
```

File content: block *k* of a file holds plaintext bytes `[k·cap, (k+1)·cap)` (cap = BLOCK − 40),
zero-padded, sealed under the file's own random key with AAD
`("strongbox/drive/file/v1", slot, block index, u32be(k))`. Size is rounded to whole blocks.

**Allocation** is implicit: a block is free unless the header, the current metadata, or a
file references it. No allocation map is stored.

**Commit** (copy-on-write): write file blocks into free blocks; write the new metadata into
free blocks; write the older header copy with `generation + 1`; finally overwrite the
*previous* metadata blocks with fresh random bytes. The last step matters: old metadata holds
the keys of deleted files, and the drive key is long-lived, so a coerced drive PIN would
otherwise recover "deleted" files. Freed file blocks need no wiping once no metadata
references their keys.

**Creating or resetting a drive** writes both header copies with fresh random entries, a new
random drive key and empty metadata. The rest of the slot is left as is (it is
indistinguishable from filler once no key references it). Resetting an in-use slot destroys
that drive; the UI says so every time, since it cannot know.

### What is transferred

Opening a drive downloads only its two header blocks and its metadata blocks (typically
768 KiB in total, whatever the drive's size); the tree is then decrypted and browsed in memory.
File blocks are fetched only when a file is downloaded or previewed. A commit re-reads the
two header blocks, then writes file blocks (for uploads), new metadata, one header copy and
the wipe of the old metadata. Logging in with a recovery code reads both header blocks of
every slot (about 50 MiB with 100 slots), since the code does not say which slot it opens.

On-demand access is why a live or recording server can see which slot is in use (§1):
hiding that would need dummy reads and writes across all slots on every session.

## 7. Drive PIN guidance

Nothing can count failed drive PINs: the key does not know a guess was wrong, and the server
cannot know without learning which slots are used. The only limit is the touch: two guesses
per touch, about 1 touch/s by hand, perhaps 2/s with a robot, on one physical key (no
parallelism; the secret is inside that key).

| Drive PIN | Exhaust one drive at 4 guesses/s | at 2 guesses/s |
|---|---|---|
| 6 digits | ~3 days | ~6 days |
| 8 digits | ~10 months | ~1.6 years |
| 10 digits | ~80 years | ~160 years |

The client requires at least 8 digits and recommends 10, or a passphrase.

## 8. Server (`/v2`)

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /v2/vaults` | invite/open | create a vault (allocates and fills all slots) with its username record and first member |
| `GET /v2/lookup/{id}` | – (rate-limited) | encrypted credential record, or a stable decoy |
| `PUT /v2/record` | bearer | replace this vault's record (backup keys) |
| `DELETE /v2/vaults` | bearer | delete the account: its record, members and every drive |
| `POST /v2/auth/challenge` | – | challenge for a locator; unknown locators get an equally random one |
| `POST /v2/auth/session` | – | Ed25519 signature over the challenge → bearer token |
| `GET /v2/members`, `POST /v2/members`, `DELETE /v2/members/{id}` | bearer | manage keys / recovery codes (last member cannot be removed) |
| `GET /v2/slots/{slot}/blocks?start&count` | bearer | read whole blocks |
| `PUT /v2/slots/{slot}/blocks?start` | bearer | write whole blocks (body = n × BLOCK) |

Deniability requirements on the server:

- **Filler** is written at vault creation from a CSPRNG seeded from the OS and discarded.
  Lazy filling is not allowed: it would reveal which blocks were ever touched. (Production
  deployments should keep a few pre-filled vaults ready so creation is instant.)
- **No ordering or time metadata:** random vault ids, `WITHOUT ROWID` tables, no per-vault
  counters, no usage accounting (a vault is always "full"). Slot files get a constant
  modification time after every write. Sessions and challenges live in memory only.
- **No logs** that identify vaults, slots or blocks (default logging mode).

## 9. Client and device

- Nothing about vaults or drives is written to disk: no profile, no username, no credential
  id, no version cache. The user signs in with the server URL, username and an account key or
  account recovery code, then opens individual drives by slot number and drive PIN. The CLI
  reads the username at a hidden prompt (never from arguments, which end up in shell history).
- Consequence: no rollback detection across restarts. A server can serve an old header
  generation. Within a session the client rejects generations lower than it has seen.
- One writer per drive at a time. Two devices writing the same drive concurrently can corrupt
  it (the server cannot arbitrate without knowing the layout). v1 detects a moved header
  generation before committing and aborts.

## 10. Known limits and future work

- Multi-snapshot / recording-server adversaries (§1): needs oblivious access patterns.
- Fixed per-drive size; spanning several slots would reintroduce cross-drive overwrite risk.
- Drives are single-writer.
- Hardware assumptions (§2) checked on one key model only; build a published test matrix.
- External review before any user relies on this.
