use hkdf::Hkdf;
use sha2::Sha256;

use crate::Key;

/// Build an unambiguous HKDF `info` string: a label followed by length-prefixed parts.
pub fn info(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(label.len() + 1 + parts.iter().map(|p| p.len() + 4).sum::<usize>());
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    for p in parts {
        out.extend_from_slice(&(p.len() as u32).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// HKDF-SHA256 (extract + expand) to a 256-bit key.
pub fn derive(ikm: &[u8], salt: Option<&[u8]>, label: &str, parts: &[&[u8]]) -> Key {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = [0u8; 32];
    hk.expand(&info(label, parts), &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Key(out)
}

/// Derive a subkey from an existing key.
pub fn subkey(key: &Key, label: &str, parts: &[&[u8]]) -> Key {
    derive(key.as_bytes(), None, label, parts)
}
