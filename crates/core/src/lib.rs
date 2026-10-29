//! Strongbox client-side cryptography.
//!
//! Everything in this crate runs on the client. The server only ever sees fixed-size random-looking
//! blocks and opaque account records. See `docs/deniable-drives.md` for the key hierarchy.

pub mod aead;
pub mod error;
pub mod ids;
pub mod kdf;
pub mod names;
pub mod recovery;
pub mod serde_b64;
pub mod vault;

pub use error::{Error, Result};
pub use ids::{Id, Key};
