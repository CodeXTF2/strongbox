//! XChaCha20-Poly1305 helpers. Random 192-bit nonces are safe for keys that encrypt many
//! messages (node keys); chunk encryption uses counter nonces under single-use content keys.

use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
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

/// [`seal_with_nonce`] without copying: encrypts `buf[start..]` in place and appends the tag,
/// so `buf[start..]` ends up exactly as `seal_with_nonce` would return it. For large messages.
pub fn seal_in_place_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut Vec<u8>,
    start: usize,
) {
    let tag = cipher(key)
        .encrypt_in_place_detached(XNonce::from_slice(nonce), aad, &mut buf[start..])
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    buf.extend_from_slice(&tag);
}

/// [`open_with_nonce`] without copying: authenticates and decrypts `buf[start..]` in place
/// and drops the tag. On failure `buf` is left as it was (nothing is decrypted unless the tag
/// verifies).
pub fn open_in_place_with_nonce(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut Vec<u8>,
    start: usize,
) -> Result<()> {
    if buf.len() < start + TAG_LEN {
        return Err(Error::Decrypt);
    }
    let tag_at = buf.len() - TAG_LEN;
    let tag = Tag::clone_from_slice(&buf[tag_at..]);
    cipher(key)
        .decrypt_in_place_detached(
            XNonce::from_slice(nonce),
            aad,
            &mut buf[start..tag_at],
            &tag,
        )
        .map_err(|_| Error::Decrypt)?;
    buf.truncate(tag_at);
    Ok(())
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

    #[test]
    fn in_place_matches_copying() {
        let k = Key::random();
        let n = [7u8; NONCE_LEN];
        let mut buf = b"head".to_vec();
        buf.extend_from_slice(b"hello world");
        seal_in_place_with_nonce(&k, &n, b"a", &mut buf, 4);
        assert_eq!(&buf[4..], seal_with_nonce(&k, &n, b"a", b"hello world"));
        let sealed = buf.clone();
        assert!(open_in_place_with_nonce(&k, &n, b"b", &mut buf, 4).is_err());
        assert_eq!(buf, sealed, "failed open leaves the buffer untouched");
        open_in_place_with_nonce(&k, &n, b"a", &mut buf, 4).unwrap();
        assert_eq!(buf, b"headhello world");
        assert!(open_in_place_with_nonce(&k, &n, b"a", &mut vec![0u8; 10], 0).is_err());
    }
}
