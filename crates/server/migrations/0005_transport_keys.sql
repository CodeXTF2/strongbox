-- Sealed-channel key of each vault member (derived client-side from the member's security-key
-- PRF output or recovery code, registered at sign-up; see strongbox_core::channel). It is
-- independent of every key that protects data, so holding it lets the server authenticate
-- and decrypt the transport, never a vault. Members created before this migration have none
-- and cannot open a channel: their accounts must be recreated.
ALTER TABLE vault_members ADD COLUMN transport_key BLOB;
