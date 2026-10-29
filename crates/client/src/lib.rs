//! Strongbox client: vault accounts, drives and encrypted file operations.
//!
//! All encryption and decryption happens here. The server only ever sees the types in
//! `strongbox-proto`: username-sealed account records and fixed-size random-looking blocks.

pub mod api;
pub mod error;
pub mod transfer;
pub mod vault;

pub use error::{Error, Result};
pub use transfer::{
    local_safe_name, unique_local_path, ListEntry, OnConflict, Progress, SearchHit, TransferOptions,
};
