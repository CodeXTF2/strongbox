use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("decryption failed (wrong key or tampered data)")]
    Decrypt,
    #[error("malformed data: {0}")]
    Malformed(&'static str),
    #[error("unsupported format version {0}")]
    Version(u8),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("content integrity check failed")]
    Integrity,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
