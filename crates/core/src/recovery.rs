//! Printable recovery codes: 256 random bits as RFC 4648 base32 in dash-separated groups.
//! Being full-entropy, a recovery keyslot is no weaker against offline attack than a FIDO one.

use rand::RngCore;
use zeroize::Zeroizing;

use crate::{Error, Result};

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn generate() -> Zeroizing<[u8; 32]> {
    let mut s = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(s.as_mut());
    s
}

pub fn encode(secret: &[u8; 32]) -> String {
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut chars = Vec::with_capacity(52);
    for &b in secret {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            chars.push(ALPHABET[((bits >> nbits) & 31) as usize]);
        }
    }
    if nbits > 0 {
        chars.push(ALPHABET[((bits << (5 - nbits)) & 31) as usize]);
    }
    chars
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

pub fn decode(code: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut out = Zeroizing::new([0u8; 32]);
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut i = 0;
    for c in code.chars().filter(|c| !c.is_whitespace() && *c != '-') {
        let c = c.to_ascii_uppercase() as u8;
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(Error::Malformed("recovery code character"))?;
        bits = (bits << 5) | v as u32;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            if i == 32 {
                return Err(Error::Malformed("recovery code length"));
            }
            out[i] = (bits >> nbits) as u8;
            i += 1;
        }
    }
    if i != 32 {
        return Err(Error::Malformed("recovery code length"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn roundtrip() {
        let s = super::generate();
        let code = super::encode(&s);
        assert_eq!(code.replace('-', "").len(), 52);
        assert_eq!(*super::decode(&code.to_lowercase()).unwrap(), *s);
        assert!(super::decode("AAAA").is_err());
    }
}
