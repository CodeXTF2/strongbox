//! Metadata store (SQLite): server settings, vault lookup records and vault members. Writes that
//! read-then-write are serialized through `write_lock`.

use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};
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

pub enum MemberDelete {
    Deleted,
    NotFound,
    LastMember,
}

pub enum MemberAdd {
    Added,
    Exists,
    TooMany,
}

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

    /// Ids of every vault.
    pub async fn vault_ids(&self) -> sqlx::Result<Vec<String>> {
        Ok(sqlx::query("SELECT id FROM vaults")
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|r| r.get("id"))
            .collect())
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
    ) -> sqlx::Result<MemberAdd> {
        let _w = self.write_lock.lock().await;
        let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM vault_members WHERE vault_id = ?")
            .bind(vault_id)
            .fetch_one(&self.pool)
            .await?
            .get("n");
        if count as usize >= max {
            return Ok(MemberAdd::TooMany);
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
            Ok(_) => Ok(MemberAdd::Added),
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(MemberAdd::Exists),
            Err(e) => Err(e),
        }
    }

    pub async fn remove_vault_member(
        &self,
        vault_id: &str,
        locator_hash: &[u8],
    ) -> sqlx::Result<MemberDelete> {
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
            return Ok(MemberDelete::NotFound);
        }
        if count <= 1 {
            return Ok(MemberDelete::LastMember);
        }
        sqlx::query("DELETE FROM vault_members WHERE vault_id = ? AND locator_hash = ?")
            .bind(vault_id)
            .bind(locator_hash)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(MemberDelete::Deleted)
    }
}
