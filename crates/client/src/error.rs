use strongbox_proto::{ErrorCode, NodeVersion};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("server error ({status}): {message}")]
    Api {
        status: u16,
        code: Option<ErrorCode>,
        message: String,
    },
    #[error("version conflict")]
    Conflict(Vec<NodeVersion>),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0} already exists")]
    Exists(String),
    #[error("{0}")]
    Invalid(String),
    #[error("possible rollback attack: the server returned version {got} of a node already seen at version {seen}")]
    Rollback { seen: u64, got: u64 },
    #[error("server identity changed (expected {expected}, got {got}); refusing to continue")]
    ServerChanged { expected: String, got: String },
    #[error("cryptography: {0}")]
    Crypto(#[from] strongbox_core::Error),
    #[error("security key: {0}")]
    Fido(#[from] strongbox_fido::Error),
    #[error("network: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cancelled")]
    Cancelled,
}

impl Error {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::NotFound(_)) || matches!(self, Error::Api { status: 404, .. })
    }
}

pub type Result<T> = std::result::Result<T, Error>;
