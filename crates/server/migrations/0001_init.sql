-- Strongbox server schema. Note what is NOT here: file names, paths, timestamps of anything a
-- user did, directory structure, which drives exist. Deliberately minimal: random ids, no
-- rowids on account tables (whose order would reveal creation order), no usage counters.
-- Sessions and challenges are kept in memory only.

CREATE TABLE server_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE vaults (
    id TEXT PRIMARY KEY
) WITHOUT ROWID;

-- One row per security key or recovery code that can sign in to a vault. `transport_key` is
-- the member's sealed-channel key (derived client-side from its PRF output or recovery code;
-- see strongbox_core::channel). It is independent of every key that protects data, so holding
-- it lets the server authenticate and decrypt the transport, never a vault.
CREATE TABLE vault_members (
    locator_hash    BLOB PRIMARY KEY,
    vault_id        TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    auth_public_key BLOB NOT NULL,
    transport_key   BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX vault_members_by_vault ON vault_members (vault_id);

-- Username lookup id (Argon2id-derived by the client) → encrypted, fixed-size record of
-- the credential ids of that username's security keys.
CREATE TABLE vault_lookups (
    lookup   BLOB PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    record   BLOB NOT NULL
) WITHOUT ROWID;

-- Operator-managed invite codes (see the admin page). `single_use` codes are deleted when they
-- admit an account; the rest stay valid until the operator deletes them. Holds nothing about
-- accounts: a used single-use code leaves no trace of who used it.
CREATE TABLE invite_codes (
    id         INTEGER PRIMARY KEY,
    code       TEXT    NOT NULL UNIQUE,
    single_use INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
