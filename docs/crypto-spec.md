# Strongbox cryptography (format v1)

Status: implemented in `crates/core`, **not yet externally reviewed**.

## Primitives

| Use | Primitive |
|---|---|
| AEAD | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) |
| KDF | HKDF-SHA256; `info = label ‖ 0x00 ‖ (u32be len ‖ part)*` |
| Password hardening (optional) | Argon2id v1.3, m=64 MiB, t=3, p=4, 16-byte salt |
| Auth signatures | Ed25519 (`verify_strict`) |
| Chunk ids | HMAC-SHA256 truncated to 128 bits |
| Hash | SHA-256 |

## Root of trust: FIDO2 PRF

Each security key holds a non-discoverable credential with `hmac-secret`, created and used
with **user verification required** (PIN). Strongbox uses WebAuthn PRF semantics:

```
hmac_salt  = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ prf_salt)       # prf_salt: 32 random bytes per keyslot
prf_output = HMAC-SHA256(credRandomWithUV, hmac_salt)         # computed inside the authenticator
```

`prf_output` is 256 bits of entropy that the authenticator only releases after a correct PIN
(the authenticator enforces the PIN retry limit). Nothing derived from it is ever brute-forceable
offline, with or without a password.

Credentials are created with `credProtect` level 3 (`userVerificationRequired`), and enrollment
fails on keys that do not support it. On CTAP 2.1 keys hmac-secret already uses a separate
secret when UV is performed; on CTAP 2.0 keys it does not, so without credProtect anyone holding
the key could obtain `prf_output` without the PIN. Clients also reject any registration or
assertion whose authenticator data lacks the UV flag.

Keyslots are fetched before login, so their Argon2id parameters are bounded on the client
(m ≤ 1 GiB, t ≤ 16, p ≤ 16, salt 16–64 bytes) to stop a malicious server exhausting memory.

## Keyslots

```
pw     = Argon2id(password, kdf.salt)                    # only if the keyslot has a password
KEK    = HKDF(ikm = prf_output, salt = pw or none,
              "strongbox/kek/fido/v1", [slot_id, credential_id])
KEK    = HKDF(ikm = recovery_secret, none,
              "strongbox/kek/recovery/v1", [slot_id])  # recovery keyslots: 32 random bytes,
                                                         # shown as 52 base32 chars
wrapped_amk = nonce ‖ XChaCha20-Poly1305(KEK, nonce, AMK,
              aad = "strongbox/keyslot/v1" ‖ 0 ‖ [slot_id])
```

The AMK (account master key) is 32 random bytes generated at sign-up. Any keyslot unlocks it.

Keyslot labels are not stored in the clear. `sealed_label = nonce ‖ XChaCha20-Poly1305(
HKDF(AMK, "strongbox/keyslot-label/v1"), label padded to 96 bytes, aad = "strongbox/keyslot-label/v1" ‖ 0 ‖ [slot_id])`
(always 136 bytes), so the pre-login keyslot listing reveals neither the names of the keys nor
how many of each kind exist beyond the keyslots themselves. Labels show once any keyslot has
unlocked the account. Keyslots created before this change keep a legacy plaintext `label`.

## AMK-derived keys

| Derivation (`HKDF(AMK, label)`) | Use |
|---|---|
| `strongbox/auth/v1` | Ed25519 seed: login signatures over `"strongbox/auth-challenge/v1" ‖ 0 ‖ [server_id, username, challenge]` |
| `strongbox/root-id/v1` (first 16 bytes) | root directory node id |
| `strongbox/root-key/v1` | root directory key |

## Directory nodes

A directory is a CBOR map `name → Entry`. `Entry` is either:
- `File { content: ContentRef, mtime, ctime, trashed? }`
- `Dir { id, key, mtime, trashed? }`

`trashed: { name, parent, deleted_at }` is present only on entries inside the trash: a
directory stored in the root under the reserved name `.strongbox-trash`, keyed by random ids.
The field is optional, so nodes written before it existed still decode, and older clients
ignore it. Trashed items are ordinary sealed entries; the server cannot tell them apart.

```
plaintext = u32be(len(cbor)) ‖ cbor ‖ zero padding to max(Padmé(4+len), 512)
stored    = 0x01 ‖ nonce ‖ XChaCha20-Poly1305(dir_key, nonce, plaintext,
                aad = "strongbox/node/v1" ‖ 0 ‖ [node_id, u64be(version)])
```

Binding `node_id` and `version` stops the server from swapping nodes or replaying an old
version under a new number. Clients also keep the highest version they have seen per node
and reject anything lower (rollback detection).

## File content

Every file version gets a fresh random `content_key`:

```
enc_key = HKDF(content_key, "strongbox/content/enc/v1")
id_key  = HKDF(content_key, "strongbox/content/id/v1")
padded  = plaintext ‖ zeros up to max(Padmé(size), 4096)
chunk_i = padded[i*4MiB .. (i+1)*4MiB]
id_i    = HMAC-SHA256(id_key, u64be(i))[..16]
blob_i  = XChaCha20-Poly1305(enc_key, nonce = 0^16 ‖ u64be(i), chunk_i,
                             aad = "strongbox/chunk/v1" ‖ 0 ‖ [id_i, u64be(i)])
```

`ContentRef = { content_key, size, padded_size, chunk_size, sha256(plaintext) }` is stored only
inside the sealed parent directory. Decryption checks each chunk's tag and length, the chunk
count, the true size and the whole-file SHA-256.

The counter nonces are safe because each `content_key` encrypts exactly one stream.

## Padmé

`padme(L)`: let `E = ⌊log2 L⌋`, `S = ⌊log2 E⌋ + 1`, and zero the low `E − S` bits rounding up.
This leaks O(log log L) bits of the length, with at most 12.5% overhead.

## Open items before a stable v1

- Cross-implementation test vectors (`spec/test-vectors/*.json`).
- Confirm on real hardware that the Windows WebAuthn API, CTAP-HID and (later) browsers
  produce identical PRF outputs for the same credential and salt.
- Signed account log (fork consistency); AMK rotation; binding the server id and username into the keyslot AAD.
