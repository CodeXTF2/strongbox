//! Keyslots: the account master key (AMK) wrapped under key-encryption keys.
//!
//! A FIDO2 keyslot's KEK comes from the authenticator's PRF output (hmac-secret, with user
//! verification). That output is 256 bits of entropy that never leaves the authenticator
//! without the PIN, so a stolen keyslot cannot be attacked offline even with no password. An
//! optional password adds an Argon2id-hardened second input for defence in depth.
//!
//! Keyslots are not secret: the server hands them out before authentication.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{aead, kdf, Error, Id, Key, Result};

const KEYSLOT_AAD: &str = "strongbox/keyslot/v1";
const LABEL_KEY: &str = "strongbox/keyslot-label/v1";
/// Labels are padded to this many plaintext bytes (1 length byte + text), so every sealed
/// label has the same size.
const LABEL_PLAIN: usize = 96;
/// Size of `Keyslot::sealed_label` (nonce + padded label + tag); the server's decoys match it.
pub const SEALED_LABEL_LEN: usize = aead::NONCE_LEN + LABEL_PLAIN + aead::TAG_LEN;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: Id,
    /// Legacy plaintext label. New keyslots leave this empty and use `sealed_label`, because
    /// the server hands keyslots out before login and labels would tell anyone who asks how
    /// many keys an account has and what they are called.
    #[serde(default)]
    pub label: String,
    /// The label, encrypted under a key derived from the account master key. Readable only
    /// once any keyslot has unlocked the account; see [`Keyslot::label`].
    #[serde(default, skip_serializing_if = "Option::is_none", with = "crate::serde_b64::option")]
    pub sealed_label: Option<Vec<u8>>,
    pub kind: KeyslotKind,
    #[serde(with = "crate::serde_b64")]
    pub wrapped_amk: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyslotKind {
    Fido {
        rp_id: String,
        #[serde(with = "crate::serde_b64")]
        credential_id: Vec<u8>,
        /// WebAuthn PRF `eval.first` input (hashed to the hmac-secret salt by the client).
        #[serde(with = "crate::serde_b64")]
        prf_salt: Vec<u8>,
        password: Option<PasswordKdf>,
    },
    Recovery,
}

/// Argon2id parameters for the optional password factor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordKdf {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    #[serde(with = "crate::serde_b64")]
    pub salt: Vec<u8>,
}

impl PasswordKdf {
    /// RFC 9106 "second recommended" (64 MiB, t=3, p=4) – the password is a secondary factor,
    /// so this favours running on modest machines over maximal hardness.
    pub fn new_default() -> Self {
        let mut salt = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        PasswordKdf {
            m_kib: 64 * 1024,
            t: 3,
            p: 4,
            salt,
        }
    }

    /// Keyslots come from the (untrusted) server before login, so refuse parameters that
    /// would let it exhaust the client's memory or CPU, or that are too weak to be ours.
    fn check_bounds(&self) -> Result<()> {
        let ok = (8 * 1024..=1024 * 1024).contains(&self.m_kib)
            && (1..=16).contains(&self.t)
            && (1..=16).contains(&self.p)
            && (16..=64).contains(&self.salt.len());
        if ok {
            Ok(())
        } else {
            Err(Error::Kdf(
                "password KDF parameters out of the accepted range".into(),
            ))
        }
    }

    pub fn hash(&self, password: &str) -> Result<Zeroizing<[u8; 32]>> {
        #[cfg(not(test))]
        self.check_bounds()?;
        let params = Params::new(self.m_kib, self.t, self.p, Some(32))
            .map_err(|e| Error::Kdf(e.to_string()))?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), &self.salt, out.as_mut())
            .map_err(|e| Error::Kdf(e.to_string()))?;
        Ok(out)
    }
}

pub fn new_prf_salt() -> Vec<u8> {
    let mut salt = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// The secret material that unlocks a keyslot.
pub enum Unlock<'a> {
    Fido {
        prf_output: &'a [u8; 32],
        password: Option<&'a str>,
    },
    Recovery {
        secret: &'a [u8; 32],
    },
}

fn kek(slot_id: &Id, kind: &KeyslotKind, unlock: &Unlock) -> Result<Key> {
    match (kind, unlock) {
        (
            KeyslotKind::Fido {
                credential_id,
                password: kdf_params,
                ..
            },
            Unlock::Fido {
                prf_output,
                password,
            },
        ) => {
            let pw_hash = match (kdf_params, password) {
                (Some(params), Some(pw)) => Some(params.hash(pw)?),
                (None, None) => None,
                (Some(_), None) => {
                    return Err(Error::Kdf("this keyslot requires a password".into()))
                }
                (None, Some(_)) => return Err(Error::Kdf("this keyslot has no password".into())),
            };
            Ok(kdf::derive(
                prf_output.as_slice(),
                pw_hash.as_ref().map(|h| h.as_slice()),
                "strongbox/kek/fido/v1",
                &[slot_id.as_bytes(), credential_id],
            ))
        }
        (KeyslotKind::Recovery, Unlock::Recovery { secret }) => Ok(kdf::derive(
            secret.as_slice(),
            None,
            "strongbox/kek/recovery/v1",
            &[slot_id.as_bytes()],
        )),
        _ => Err(Error::Kdf(
            "unlock method does not match keyslot type".into(),
        )),
    }
}

fn label_key(amk: &Key) -> Key {
    kdf::subkey(amk, LABEL_KEY, &[])
}

fn seal_label(amk: &Key, id: &Id, label: &str) -> Vec<u8> {
    // Truncate at a character boundary so the text fits the fixed-size frame.
    let mut end = label.len().min(LABEL_PLAIN - 1);
    while !label.is_char_boundary(end) {
        end -= 1;
    }
    let mut plain = vec![0u8; LABEL_PLAIN];
    plain[0] = end as u8;
    plain[1..1 + end].copy_from_slice(&label.as_bytes()[..end]);
    aead::seal(
        &label_key(amk),
        &aead::aad(LABEL_KEY, &[id.as_bytes()]),
        &plain,
    )
}

impl Keyslot {
    /// The display label: decrypted with the account master key, or the legacy plaintext one.
    /// A sealed label that does not decrypt (corrupted or swapped by the server) shows as "?".
    pub fn label(&self, amk: &Key) -> String {
        let Some(sealed) = &self.sealed_label else {
            return self.label.clone();
        };
        aead::open(
            &label_key(amk),
            &aead::aad(LABEL_KEY, &[self.id.as_bytes()]),
            sealed,
        )
        .ok()
        .and_then(|p| {
            let n = *p.first()? as usize;
            String::from_utf8(p.get(1..1 + n)?.to_vec()).ok()
        })
        .unwrap_or_else(|| "?".into())
    }

    pub fn create(label: String, kind: KeyslotKind, unlock: &Unlock, amk: &Key) -> Result<Self> {
        let id = Id::random();
        let kek = kek(&id, &kind, unlock)?;
        let wrapped_amk = aead::seal(
            &kek,
            &aead::aad(KEYSLOT_AAD, &[id.as_bytes()]),
            amk.as_bytes(),
        );
        Ok(Keyslot {
            sealed_label: Some(seal_label(amk, &id, &label)),
            label: String::new(),
            id,
            kind,
            wrapped_amk,
        })
    }

    pub fn unlock(&self, unlock: &Unlock) -> Result<Key> {
        let kek = kek(&self.id, &self.kind, unlock)?;
        let amk = Zeroizing::new(aead::open(
            &kek,
            &aead::aad(KEYSLOT_AAD, &[self.id.as_bytes()]),
            &self.wrapped_amk,
        )?);
        let bytes: [u8; 32] = amk
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed("amk length"))?;
        Ok(Key::from_bytes(bytes))
    }

    pub fn credential_id(&self) -> Option<&[u8]> {
        match &self.kind {
            KeyslotKind::Fido { credential_id, .. } => Some(credential_id),
            KeyslotKind::Recovery => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fido_kind(password: Option<PasswordKdf>) -> KeyslotKind {
        KeyslotKind::Fido {
            rp_id: "strongbox.app".into(),
            credential_id: vec![1, 2, 3],
            prf_salt: new_prf_salt(),
            password,
        }
    }

    #[test]
    fn fido_slot() {
        let amk = Key::random();
        let prf = [9u8; 32];
        let slot = Keyslot::create(
            "k".into(),
            fido_kind(None),
            &Unlock::Fido {
                prf_output: &prf,
                password: None,
            },
            &amk,
        )
        .unwrap();
        assert_eq!(
            slot.unlock(&Unlock::Fido {
                prf_output: &prf,
                password: None
            })
            .unwrap(),
            amk
        );
        assert!(slot
            .unlock(&Unlock::Fido {
                prf_output: &[8u8; 32],
                password: None
            })
            .is_err());

        assert!(slot.label.is_empty(), "the label must not be stored in the clear");
        assert_eq!(slot.sealed_label.as_ref().unwrap().len(), SEALED_LABEL_LEN);
        assert_eq!(slot.label(&amk), "k");
        assert_eq!(slot.label(&Key::random()), "?");

        // JSON round trip (this is what the server stores).
        let json = serde_json::to_string(&slot).unwrap();
        let back: Keyslot = serde_json::from_str(&json).unwrap();
        assert_eq!(back, slot);
    }

    #[test]
    fn fido_slot_with_password() {
        let amk = Key::random();
        let prf = [9u8; 32];
        let kdf = PasswordKdf {
            m_kib: 64,
            t: 1,
            p: 1,
            salt: vec![0; 16],
        };
        let u = Unlock::Fido {
            prf_output: &prf,
            password: Some("hunter2"),
        };
        let slot = Keyslot::create("k".into(), fido_kind(Some(kdf)), &u, &amk).unwrap();
        assert_eq!(slot.unlock(&u).unwrap(), amk);
        assert!(slot
            .unlock(&Unlock::Fido {
                prf_output: &prf,
                password: Some("hunter3")
            })
            .is_err());
        assert!(slot
            .unlock(&Unlock::Fido {
                prf_output: &prf,
                password: None
            })
            .is_err());
    }

    #[test]
    fn kdf_bounds() {
        assert!(PasswordKdf::new_default().check_bounds().is_ok());
        let huge = PasswordKdf {
            m_kib: u32::MAX,
            ..PasswordKdf::new_default()
        };
        assert!(huge.check_bounds().is_err());
        let slow = PasswordKdf {
            t: 1_000_000,
            ..PasswordKdf::new_default()
        };
        assert!(slow.check_bounds().is_err());
        let weak = PasswordKdf {
            salt: vec![],
            ..PasswordKdf::new_default()
        };
        assert!(weak.check_bounds().is_err());
    }
}
