-- Strongbox server schema. Note what is NOT here: file names, paths, timestamps of files,
-- directory structure. The server only knows accounts, opaque keyslots, sealed nodes and blobs.

CREATE TABLE server_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE accounts (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    auth_public_key BLOB    NOT NULL,
    quota_bytes     INTEGER,
    used_bytes      INTEGER NOT NULL DEFAULT 0,
    seq             INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE keyslots (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slot_id    TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    PRIMARY KEY (account_id, slot_id)
);

CREATE TABLE challenges (
    challenge  BLOB    PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE sessions (
    token_hash BLOB    PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

-- data IS NULL marks a tombstone (kept so sync clients learn about deletions).
CREATE TABLE nodes (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id         TEXT    NOT NULL,
    version    INTEGER NOT NULL,
    seq        INTEGER NOT NULL,
    size       INTEGER NOT NULL,
    data       BLOB,
    PRIMARY KEY (account_id, id)
);
CREATE INDEX nodes_by_seq ON nodes (account_id, seq);

CREATE TABLE blobs (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    id         TEXT    NOT NULL,
    size       INTEGER NOT NULL,
    PRIMARY KEY (account_id, id)
);
