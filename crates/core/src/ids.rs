use std::fmt;
use std::str::FromStr;

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

/// A random 128-bit identifier. Serialized as lowercase hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(pub [u8; 16]);

impl Id {
    pub fn random() -> Self {
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        Id(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({self})")
    }
}

impl FromStr for Id {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut b = [0u8; 16];
        hex::decode_to_slice(s, &mut b).map_err(|_| Error::Malformed("id"))?;
        Ok(Id(b))
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A 256-bit symmetric key, zeroized on drop. Serialized as a byte string (only ever inside
/// encrypted structures).
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Key(pub(crate) [u8; 32]);

impl Key {
    pub fn random() -> Self {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        Key(b)
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        Key(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

impl Serialize for Key {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let mut buf = serde_bytes::ByteBuf::deserialize(d)?;
        let key = <[u8; 32]>::try_from(buf.as_slice())
            .map(Key)
            .map_err(|_| serde::de::Error::invalid_length(buf.len(), &"32 bytes"));
        buf.zeroize();
        key
    }
}
