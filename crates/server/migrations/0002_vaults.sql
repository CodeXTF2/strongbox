-- Deniable vaults (docs/deniable-drives.md). Deliberately minimal: random ids, no rowids
-- (whose order would reveal creation order), no timestamps, no usage counters. Sessions and
-- challenges for vaults are kept in memory only.

CREATE TABLE vaults (
    id TEXT PRIMARY KEY
) WITHOUT ROWID;

CREATE TABLE vault_members (
    locator_hash    BLOB PRIMARY KEY,
    vault_id        TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    auth_public_key BLOB NOT NULL
) WITHOUT ROWID;
CREATE INDEX vault_members_by_vault ON vault_members (vault_id);

-- Username lookup id (Argon2id-derived by the client) → encrypted, fixed-size record of
-- the credential ids of that username's security keys.
CREATE TABLE vault_lookups (
    lookup   BLOB PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    record   BLOB NOT NULL
) WITHOUT ROWID;
