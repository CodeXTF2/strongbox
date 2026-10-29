-- Operator-managed invite codes (see the admin page). `single_use` codes are deleted when they
-- admit an account; the rest stay valid until the operator deletes them. Holds nothing about
-- accounts: a used single-use code leaves no trace of who used it.
CREATE TABLE invite_codes (
    id         INTEGER PRIMARY KEY,
    code       TEXT    NOT NULL UNIQUE,
    single_use INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
