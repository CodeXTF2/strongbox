//! Validation of file and folder names.

use crate::{Error, Result};

/// Validate a single path component.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(Error::Malformed("invalid file name"));
    }
    if name.len() > 1024 {
        return Err(Error::Malformed("file name too long"));
    }
    Ok(())
}
