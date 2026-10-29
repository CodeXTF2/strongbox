//! Strongbox client-side cryptography.
//!
//! Everything in this crate runs on the client. The server only ever sees the
//! outputs: opaque keyslots, sealed nodes and encrypted chunks.
//!
//! Key hierarchy (see `docs/crypto-spec.md`):
//!
//! ```text
//! FIDO2 PRF output (+ optional password) -> KEK -> wraps Account Master Key (AMK)
//! AMK -> auth signing key, root directory id + key
//! directory key -> child directory keys and per-file content keys (stored in the sealed parent)
//! content key -> chunk encryption key + chunk id key
//! ```

pub mod account;
pub mod aead;
pub mod content;
pub mod error;
pub mod ids;
pub mod kdf;
pub mod keyslot;
pub mod node;
pub mod padding;
pub mod recovery;
pub mod serde_b64;
pub mod vault;

pub use error::{Error, Result};
pub use ids::{Id, Key};
