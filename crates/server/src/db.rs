//! Metadata store (SQLite). Writes that read-then-write are serialized through `write_lock`,
//! which is what lets SQLite give us all-or-nothing commits without busy/deadlock retries.
//! A Postgres implementation for multi-instance deployments is planned (docs/server-plan.md).

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
use strongbox_core::Id;
use strongbox_proto::{BlobMeta, CommitAction, CommitOp, NodeMeta, NodeVersion};
use tokio::sync::Mutex;

pub struct Db {
    pool: SqlitePool,
    write_lock: Mutex<()>,
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub struct Account {
    pub id: i64,
    pub auth_public_key: Vec<u8>,
}

pub enum CommitOutcome {
    Ok {
        versions: Vec<NodeVersion>,
        deleted_blobs: Vec<Id>,
    },
    Conflict(Vec<NodeVersion>),
    QuotaExceeded,
}

pub enum KeyslotDelete {
    Deleted,
    NotFound,
    LastKeyslot,
}

pub enum KeyslotAdd {
    Added,
    Exists,
    TooMany,
}

/// Outstanding login challenges kept per account; older ones are dropped.
const MAX_CHALLENGES_PER_ACCOUNT: i64 = 16;

impl Db {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(10));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Db {
            pool,
            write_lock: Mutex::new(()),
        })
    }

    pub async fn meta(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(sqlx::query("SELECT value FROM server_meta WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
            .map(|r| r.get("value")))
    }

    /// Read a `server_meta` value, creating it with `init` on first use.
    pub async fn meta_or_init(
        &self,
        key: &str,
        init: impl FnOnce() -> String,
    ) -> anyhow::Result<String> {
        let _w = self.write_lock.lock().await;
        if let Some(row) = sqlx::query("SELECT value FROM server_meta WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
        {
            return Ok(row.get("value"));
        }
        let value = init();
        sqlx::query("INSERT INTO server_meta (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(&value)
            .execute(&self.pool)
            .await?;
        Ok(value)
    }

    /// Returns `None` if the username is taken.
    pub async fn create_account(
        &self,
        username: &str,
        auth_public_key: &[u8],
        keyslots: &[(String, String)],
        quota: Option<u64>,
    ) -> sqlx::Result<Option<i64>> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        let res = sqlx::query(
            "INSERT INTO accounts (username, auth_public_key, quota_bytes) VALUES (?, ?, ?)",
        )
        .bind(username)
        .bind(auth_public_key)
        .bind(quota.map(|q| q as i64))
        .execute(&mut *tx)
        .await;
        let account = match res {
            Ok(r) => r.last_insert_rowid(),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => return Ok(None),
            Err(e) => return Err(e),
        };
        for (slot_id, body) in keyslots {
            sqlx::query("INSERT INTO keyslots (account_id, slot_id, body) VALUES (?, ?, ?)")
                .bind(account)
                .bind(slot_id)
                .bind(body)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(Some(account))
    }

    /// Delete an account and everything it owns (keyslots, sessions, nodes, blob records; all
    /// `ON DELETE CASCADE`). The username becomes free to register again.
    pub async fn delete_account(&self, account: i64) -> sqlx::Result<bool> {
        let _w = self.write_lock.lock().await;
        let res = sqlx::query("DELETE FROM accounts WHERE id = ?")
            .bind(account)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn account_by_username(&self, username: &str) -> sqlx::Result<Option<Account>> {
        Ok(
            sqlx::query("SELECT id, auth_public_key FROM accounts WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?
                .map(|r| Account {
                    id: r.get("id"),
                    auth_public_key: r.get("auth_public_key"),
                }),
        )
    }

    pub async fn keyslots(&self, account: i64) -> sqlx::Result<Vec<String>> {
        let rows = sqlx::query("SELECT body FROM keyslots WHERE account_id = ? ORDER BY slot_id")
            .bind(account)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get("body")).collect())
    }

    /// Add a keyslot. Existing keyslots are never overwritten: replacing a working keyslot
    /// with garbage would lock the user out, so a stolen session token must not be able to.
    pub async fn add_keyslot(
        &self,
        account: i64,
        slot_id: &str,
        body: &str,
        max: usize,
    ) -> sqlx::Result<KeyslotAdd> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM keyslots WHERE account_id = ?")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?
            .get("n");
        if count as usize >= max {
            return Ok(KeyslotAdd::TooMany);
        }
        let res = sqlx::query("INSERT INTO keyslots (account_id, slot_id, body) VALUES (?, ?, ?)")
            .bind(account)
            .bind(slot_id)
            .bind(body)
            .execute(&mut *tx)
            .await;
        match res {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                return Ok(KeyslotAdd::Exists)
            }
            Err(e) => return Err(e),
        }
        tx.commit().await?;
        Ok(KeyslotAdd::Added)
    }

    pub async fn delete_keyslot(&self, account: i64, slot_id: &str) -> sqlx::Result<KeyslotDelete> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM keyslots WHERE account_id = ?")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?
            .get("n");
        let exists = sqlx::query("SELECT 1 FROM keyslots WHERE account_id = ? AND slot_id = ?")
            .bind(account)
            .bind(slot_id)
            .fetch_optional(&mut *tx)
            .await?
            .is_some();
        if !exists {
            return Ok(KeyslotDelete::NotFound);
        }
        if count <= 1 {
            return Ok(KeyslotDelete::LastKeyslot);
        }
        sqlx::query("DELETE FROM keyslots WHERE account_id = ? AND slot_id = ?")
            .bind(account)
            .bind(slot_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(KeyslotDelete::Deleted)
    }

    pub async fn create_challenge(
        &self,
        account: i64,
        challenge: &[u8],
        expires_at: i64,
    ) -> sqlx::Result<()> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        // Bound the table: anyone can request challenges for any username.
        sqlx::query(
            "DELETE FROM challenges WHERE account_id = ? AND (expires_at <= ? OR challenge NOT IN
               (SELECT challenge FROM challenges WHERE account_id = ? ORDER BY expires_at DESC LIMIT ?))",
        )
        .bind(account)
        .bind(now())
        .bind(account)
        .bind(MAX_CHALLENGES_PER_ACCOUNT - 1)
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO challenges (challenge, account_id, expires_at) VALUES (?, ?, ?)")
            .bind(challenge)
            .bind(account)
            .bind(expires_at)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Consume a challenge; true if it existed, belonged to `account` and had not expired.
    pub async fn take_challenge(&self, account: i64, challenge: &[u8]) -> sqlx::Result<bool> {
        let row = sqlx::query(
            "DELETE FROM challenges WHERE challenge = ? RETURNING account_id, expires_at",
        )
        .bind(challenge)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some_and(|r| {
            r.get::<i64, _>("account_id") == account && r.get::<i64, _>("expires_at") > now()
        }))
    }

    pub async fn create_session(
        &self,
        token_hash: &[u8],
        account: i64,
        expires_at: i64,
    ) -> sqlx::Result<()> {
        sqlx::query("INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?, ?, ?)")
            .bind(token_hash)
            .bind(account)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn session_account(&self, token_hash: &[u8]) -> sqlx::Result<Option<i64>> {
        Ok(
            sqlx::query("SELECT account_id FROM sessions WHERE token_hash = ? AND expires_at > ?")
                .bind(token_hash)
                .bind(now())
                .fetch_optional(&self.pool)
                .await?
                .map(|r| r.get("account_id")),
        )
    }

    pub async fn delete_session(&self, token_hash: &[u8]) -> sqlx::Result<()> {
        sqlx::query("DELETE FROM sessions WHERE token_hash = ?")
            .bind(token_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn purge_expired(&self) -> sqlx::Result<()> {
        let t = now();
        sqlx::query("DELETE FROM sessions WHERE expires_at <= ?")
            .bind(t)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM challenges WHERE expires_at <= ?")
            .bind(t)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Live node: `(version, data)`. Tombstones and missing nodes are `None`.
    pub async fn get_node(&self, account: i64, id: &Id) -> sqlx::Result<Option<(u64, Vec<u8>)>> {
        Ok(sqlx::query(
            "SELECT version, data FROM nodes WHERE account_id = ? AND id = ? AND data IS NOT NULL",
        )
        .bind(account)
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .map(|r| (r.get::<i64, _>("version") as u64, r.get("data"))))
    }

    pub async fn changes(
        &self,
        account: i64,
        since: u64,
        limit: u32,
    ) -> sqlx::Result<Vec<NodeMeta>> {
        let rows = sqlx::query(
            "SELECT id, version, seq, size, data IS NULL AS deleted FROM nodes
             WHERE account_id = ? AND seq > ? ORDER BY seq LIMIT ?",
        )
        .bind(account)
        .bind(since as i64)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(NodeMeta {
                    id: r
                        .get::<String, _>("id")
                        .parse()
                        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
                    version: r.get::<i64, _>("version") as u64,
                    seq: r.get::<i64, _>("seq") as u64,
                    size: r.get::<i64, _>("size") as u64,
                    deleted: r.get::<bool, _>("deleted"),
                })
            })
            .collect()
    }

    pub async fn commit(
        &self,
        account: i64,
        ops: &[CommitOp],
        delete_blobs: &[Id],
    ) -> sqlx::Result<CommitOutcome> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;

        let acct = sqlx::query("SELECT seq, used_bytes, quota_bytes FROM accounts WHERE id = ?")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?;
        let mut seq: i64 = acct.get("seq");
        let used: i64 = acct.get("used_bytes");
        let quota: Option<i64> = acct.get("quota_bytes");

        let mut conflicts = Vec::new();
        let mut current = Vec::with_capacity(ops.len());
        for op in ops {
            let row =
                sqlx::query("SELECT version, size FROM nodes WHERE account_id = ? AND id = ?")
                    .bind(account)
                    .bind(op.id.to_string())
                    .fetch_optional(&mut *tx)
                    .await?;
            let (version, size) = row.map_or((0u64, 0i64), |r| {
                (r.get::<i64, _>("version") as u64, r.get("size"))
            });
            if version != op.expect_version {
                conflicts.push(NodeVersion { id: op.id, version });
            }
            current.push(size);
        }
        if !conflicts.is_empty() {
            return Ok(CommitOutcome::Conflict(conflicts));
        }

        let mut delta: i64 = 0;
        let mut versions = Vec::with_capacity(ops.len());
        for (op, old_size) in ops.iter().zip(current) {
            seq += 1;
            let version = op.expect_version + 1;
            let data = match &op.action {
                CommitAction::Put { data } => Some(data.as_slice()),
                CommitAction::Delete => None,
            };
            let size = data.map_or(0, |d| d.len() as i64);
            delta += size - old_size;
            sqlx::query(
                "INSERT INTO nodes (account_id, id, version, seq, size, data) VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT (account_id, id) DO UPDATE SET
                   version = excluded.version, seq = excluded.seq, size = excluded.size, data = excluded.data",
            )
            .bind(account)
            .bind(op.id.to_string())
            .bind(version as i64)
            .bind(seq)
            .bind(size)
            .bind(data)
            .execute(&mut *tx)
            .await?;
            versions.push(NodeVersion { id: op.id, version });
        }

        let mut deleted_blobs = Vec::new();
        for id in delete_blobs {
            if let Some(r) =
                sqlx::query("DELETE FROM blobs WHERE account_id = ? AND id = ? RETURNING size")
                    .bind(account)
                    .bind(id.to_string())
                    .fetch_optional(&mut *tx)
                    .await?
            {
                delta -= r.get::<i64, _>("size");
                deleted_blobs.push(*id);
            }
        }

        if delta > 0 && quota.is_some_and(|q| used + delta > q) {
            return Ok(CommitOutcome::QuotaExceeded);
        }
        sqlx::query("UPDATE accounts SET seq = ?, used_bytes = used_bytes + ? WHERE id = ?")
            .bind(seq)
            .bind(delta)
            .bind(account)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(CommitOutcome::Ok {
            versions,
            deleted_blobs,
        })
    }

    /// Record a blob (insert or replace) and charge it to the quota. `false` if over quota.
    pub async fn reserve_blob(&self, account: i64, id: &Id, size: u64) -> sqlx::Result<bool> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        let acct = sqlx::query("SELECT used_bytes, quota_bytes FROM accounts WHERE id = ?")
            .bind(account)
            .fetch_one(&mut *tx)
            .await?;
        let used: i64 = acct.get("used_bytes");
        let quota: Option<i64> = acct.get("quota_bytes");
        let old: i64 = sqlx::query("SELECT size FROM blobs WHERE account_id = ? AND id = ?")
            .bind(account)
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await?
            .map_or(0, |r| r.get("size"));
        let delta = size as i64 - old;
        if delta > 0 && quota.is_some_and(|q| used + delta > q) {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO blobs (account_id, id, size) VALUES (?, ?, ?)
             ON CONFLICT (account_id, id) DO UPDATE SET size = excluded.size",
        )
        .bind(account)
        .bind(id.to_string())
        .bind(size as i64)
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE accounts SET used_bytes = used_bytes + ? WHERE id = ?")
            .bind(delta)
            .bind(account)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn blob_exists(&self, account: i64, id: &Id) -> sqlx::Result<bool> {
        Ok(
            sqlx::query("SELECT 1 FROM blobs WHERE account_id = ? AND id = ?")
                .bind(account)
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await?
                .is_some(),
        )
    }

    /// Remove a blob record and refund its size. `false` if it did not exist.
    pub async fn delete_blob(&self, account: i64, id: &Id) -> sqlx::Result<bool> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        let Some(r) =
            sqlx::query("DELETE FROM blobs WHERE account_id = ? AND id = ? RETURNING size")
                .bind(account)
                .bind(id.to_string())
                .fetch_optional(&mut *tx)
                .await?
        else {
            return Ok(false);
        };
        sqlx::query("UPDATE accounts SET used_bytes = used_bytes - ? WHERE id = ?")
            .bind(r.get::<i64, _>("size"))
            .bind(account)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn list_blobs(
        &self,
        account: i64,
        after: Option<&Id>,
        limit: u32,
    ) -> sqlx::Result<Vec<BlobMeta>> {
        let rows = sqlx::query(
            "SELECT id, size FROM blobs WHERE account_id = ? AND id > ? ORDER BY id LIMIT ?",
        )
        .bind(account)
        .bind(after.map(|a| a.to_string()).unwrap_or_default())
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(BlobMeta {
                    id: r
                        .get::<String, _>("id")
                        .parse()
                        .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
                    size: r.get::<i64, _>("size") as u64,
                })
            })
            .collect()
    }

    // ---------------- deniable vaults

    /// Create a vault with its username record and first member. `false` if the username
    /// (lookup id) or the member is taken.
    pub async fn create_vault(
        &self,
        vault_id: &str,
        lookup: &[u8],
        record: &[u8],
        locator_hash: &[u8],
        public_key: &[u8],
    ) -> sqlx::Result<bool> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO vaults (id) VALUES (?)")
            .bind(vault_id)
            .execute(&mut *tx)
            .await?;
        for res in [
            sqlx::query("INSERT INTO vault_lookups (lookup, vault_id, record) VALUES (?, ?, ?)")
                .bind(lookup)
                .bind(vault_id)
                .bind(record)
                .execute(&mut *tx)
                .await,
            sqlx::query("INSERT INTO vault_members (locator_hash, vault_id, auth_public_key) VALUES (?, ?, ?)")
                .bind(locator_hash)
                .bind(vault_id)
                .bind(public_key)
                .execute(&mut *tx)
                .await,
        ] {
            match res {
                Ok(_) => {}
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        tx.commit().await?;
        Ok(true)
    }

    /// Delete a deniable account and cascade its lookup and member records.
    pub async fn delete_vault(&self, vault_id: &str) -> sqlx::Result<bool> {
        let _w = self.write_lock.lock().await;
        let res = sqlx::query("DELETE FROM vaults WHERE id = ?")
            .bind(vault_id)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn vault_record(&self, lookup: &[u8]) -> sqlx::Result<Option<Vec<u8>>> {
        Ok(
            sqlx::query("SELECT record FROM vault_lookups WHERE lookup = ?")
                .bind(lookup)
                .fetch_optional(&self.pool)
                .await?
                .map(|r| r.get("record")),
        )
    }

    /// Replace a record, only if it belongs to `vault_id`. `false` if it does not.
    pub async fn update_vault_record(
        &self,
        vault_id: &str,
        lookup: &[u8],
        record: &[u8],
    ) -> sqlx::Result<bool> {
        Ok(
            sqlx::query("UPDATE vault_lookups SET record = ? WHERE lookup = ? AND vault_id = ?")
                .bind(record)
                .bind(lookup)
                .bind(vault_id)
                .execute(&self.pool)
                .await?
                .rows_affected()
                == 1,
        )
    }

    /// `(vault id, public key)` for a member.
    pub async fn vault_member(
        &self,
        locator_hash: &[u8],
    ) -> sqlx::Result<Option<(String, Vec<u8>)>> {
        Ok(sqlx::query(
            "SELECT vault_id, auth_public_key FROM vault_members WHERE locator_hash = ?",
        )
        .bind(locator_hash)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| (r.get("vault_id"), r.get("auth_public_key"))))
    }

    pub async fn vault_members(&self, vault_id: &str) -> sqlx::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let rows = sqlx::query("SELECT locator_hash, auth_public_key FROM vault_members WHERE vault_id = ? ORDER BY locator_hash")
            .bind(vault_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("locator_hash"), r.get("auth_public_key")))
            .collect())
    }

    /// `false` if that locator already belongs to a vault.
    pub async fn add_vault_member(
        &self,
        vault_id: &str,
        locator_hash: &[u8],
        public_key: &[u8],
        max: usize,
    ) -> sqlx::Result<KeyslotAdd> {
        let _w = self.write_lock.lock().await;
        let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM vault_members WHERE vault_id = ?")
            .bind(vault_id)
            .fetch_one(&self.pool)
            .await?
            .get("n");
        if count as usize >= max {
            return Ok(KeyslotAdd::TooMany);
        }
        match sqlx::query(
            "INSERT INTO vault_members (locator_hash, vault_id, auth_public_key) VALUES (?, ?, ?)",
        )
        .bind(locator_hash)
        .bind(vault_id)
        .bind(public_key)
        .execute(&self.pool)
        .await
        {
            Ok(_) => Ok(KeyslotAdd::Added),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(KeyslotAdd::Exists),
            Err(e) => Err(e),
        }
    }

    pub async fn remove_vault_member(
        &self,
        vault_id: &str,
        locator_hash: &[u8],
    ) -> sqlx::Result<KeyslotDelete> {
        let _w = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await?;
        let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM vault_members WHERE vault_id = ?")
            .bind(vault_id)
            .fetch_one(&mut *tx)
            .await?
            .get("n");
        let exists =
            sqlx::query("SELECT 1 FROM vault_members WHERE vault_id = ? AND locator_hash = ?")
                .bind(vault_id)
                .bind(locator_hash)
                .fetch_optional(&mut *tx)
                .await?
                .is_some();
        if !exists {
            return Ok(KeyslotDelete::NotFound);
        }
        if count <= 1 {
            return Ok(KeyslotDelete::LastKeyslot);
        }
        sqlx::query("DELETE FROM vault_members WHERE vault_id = ? AND locator_hash = ?")
            .bind(vault_id)
            .bind(locator_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(KeyslotDelete::Deleted)
    }

    pub async fn usage(&self, account: i64) -> sqlx::Result<(u64, Option<u64>)> {
        let r = sqlx::query("SELECT used_bytes, quota_bytes FROM accounts WHERE id = ?")
            .bind(account)
            .fetch_one(&self.pool)
            .await?;
        Ok((
            r.get::<i64, _>("used_bytes") as u64,
            r.get::<Option<i64>, _>("quota_bytes").map(|q| q as u64),
        ))
    }
}
