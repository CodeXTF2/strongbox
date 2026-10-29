//! Strongbox client: account setup, unlock, and encrypted drive operations.
//!
//! All encryption and decryption happens here. The only things sent to the server are the
//! types in `strongbox-proto`: keyslots, sealed directory nodes and encrypted chunks.

pub mod api;
pub mod drive;
pub mod error;
pub mod profile;
pub mod session;
pub mod vault;

pub use drive::{
    local_safe_name, unique_local_path, Drive, ListEntry, OnConflict, Progress, SearchHit,
    TransferOptions, TrashEntry, TRASH_NAME,
};
pub use error::{Error, Result};
pub use profile::Profile;
pub use session::{
    login, login_with_recovery, register, sign_in, sign_in_with_recovery, RegisterOptions, Ui,
};
