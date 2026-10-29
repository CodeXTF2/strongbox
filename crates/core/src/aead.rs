//! XChaCha20-Poly1305 helpers. Random 192-bit nonces are safe for keys that encrypt many
//! messages (node keys); chunk encryption uses counter nonces under single-use content keys.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

use crate::{Error, Key, Result};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(key.as_bytes().into())
}

/// Encrypt with a fresh random nonce; output is `nonce || ciphertext || tag`.
pub fn seal(key: &Key, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = seal_with_nonce(key, &nonce, aad, plaintext);
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt the output of [`seal`].
pub fn open(key: &Key, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Malformed("ciphertext too short"));
    }
    let (nonce, ct) = data.split_at(NONCE_LEN);
    open_with_nonce(key, nonce.try_into().unwrap(), aad, ct)
}

pub fn seal_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    cipher(key)
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers")
}

pub fn open_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Decrypt)
}

/// Build associated data from a label and fixed fields.
pub fn aad(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    crate::kdf::info(label, parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_aad_binding() {
        let k = Key::random();
        let ct = seal(&k, b"a", b"hello");
        assert_eq!(open(&k, b"a", &ct).unwrap(), b"hello");
        assert!(open(&k, b"b", &ct).is_err());
        assert!(open(&Key::random(), b"a", &ct).is_err());
    }
}
