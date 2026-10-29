-- Password-less, key-only vault accounts are the only account type. Drop the tables of the
-- original keyslot/node/blob account format.
DROP TABLE IF EXISTS blobs;
DROP INDEX IF EXISTS nodes_by_seq;
DROP TABLE IF EXISTS nodes;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS challenges;
DROP TABLE IF EXISTS keyslots;
DROP TABLE IF EXISTS accounts;
