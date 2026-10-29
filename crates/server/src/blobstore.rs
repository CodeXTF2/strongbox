//! Pluggable storage for encrypted chunks. Blobs are opaque, immutable-by-convention and
//! namespaced per account. Implementations: local filesystem (here); S3-compatible object
//! storage and erasure-coded multi-backend stores are planned (see docs/server-plan.md).

use std::io::ErrorKind;
use std::path::PathBuf;

use async_trait::async_trait;
use strongbox_core::Id;

#[async_trait]
pub trait BlobStore: Send + Sync {
    async fn put(&self, account: i64, id: &Id, data: &[u8]) -> std::io::Result<()>;
    /// `Ok(None)` if the blob does not exist.
    async fn get(&self, account: i64, id: &Id) -> std::io::Result<Option<Vec<u8>>>;
    /// Deleting a missing blob is not an error.
    async fn delete(&self, account: i64, id: &Id) -> std::io::Result<()>;
    /// Remove every blob of an account (account deletion).
    async fn delete_account(&self, account: i64) -> std::io::Result<()>;
}

pub struct FsBlobStore {
    root: PathBuf,
}

impl FsBlobStore {
    pub fn new(root: PathBuf) -> std::io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(FsBlobStore { root })
    }

    fn path(&self, account: i64, id: &Id) -> PathBuf {
        let hex = id.to_string();
        self.root
            .join(format!("{account:x}"))
            .join(&hex[..2])
            .join(hex)
    }
}

#[async_trait]
impl BlobStore for FsBlobStore {
    async fn put(&self, account: i64, id: &Id, data: &[u8]) -> std::io::Result<()> {
        let path = self.path(account, id);
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;
        // Write then rename so readers never see a partial blob.
        let tmp = path.with_extension(format!("tmp-{}", Id::random()));
        tokio::fs::write(&tmp, data).await?;
        if let Err(e) = tokio::fs::rename(&tmp, &path).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        Ok(())
    }

    async fn get(&self, account: i64, id: &Id) -> std::io::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.path(account, id)).await {
            Ok(d) => Ok(Some(d)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn delete(&self, account: i64, id: &Id) -> std::io::Result<()> {
        match tokio::fs::remove_file(self.path(account, id)).await {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }

    async fn delete_account(&self, account: i64) -> std::io::Result<()> {
        match tokio::fs::remove_dir_all(self.root.join(format!("{account:x}"))).await {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}
