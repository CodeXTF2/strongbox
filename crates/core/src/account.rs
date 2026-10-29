//! Keys derived from the account master key.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::{kdf, Id, Key};

pub struct AccountKeys {
    amk: Key,
}

impl AccountKeys {
    pub fn new(amk: Key) -> Self {
        AccountKeys { amk }
    }

    pub fn amk(&self) -> &Key {
        &self.amk
    }

    /// Ed25519 key the server uses to authenticate the account. Derived, so any keyslot that
    /// unlocks the AMK can log in, and the server never learns anything that decrypts data.
    pub fn auth_key(&self) -> SigningKey {
        SigningKey::from_bytes(kdf::subkey(&self.amk, "strongbox/auth/v1", &[]).as_bytes())
    }

    pub fn root_id(&self) -> Id {
        let k = kdf::subkey(&self.amk, "strongbox/root-id/v1", &[]);
        Id(k.as_bytes()[..16].try_into().unwrap())
    }

    pub fn root_key(&self) -> Key {
        kdf::subkey(&self.amk, "strongbox/root-key/v1", &[])
    }

    pub fn sign_auth_challenge(
        &self,
        server_id: &str,
        username: &str,
        challenge: &[u8],
    ) -> [u8; 64] {
        self.auth_key()
            .sign(&auth_message(server_id, username, challenge))
            .to_bytes()
    }
}

/// The message signed to log in. Binding the server id (pinned by the client at sign-up) stops
/// one server relaying another server's challenge.
pub fn auth_message(server_id: &str, username: &str, challenge: &[u8]) -> Vec<u8> {
    kdf::info(
        "strongbox/auth-challenge/v1",
        &[server_id.as_bytes(), username.as_bytes(), challenge],
    )
}

pub fn verify_auth(
    public_key: &[u8; 32],
    server_id: &str,
    username: &str,
    challenge: &[u8],
    sig: &[u8; 64],
) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    vk.verify_strict(
        &auth_message(server_id, username, challenge),
        &ed25519_dalek::Signature::from_bytes(sig),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_roundtrip() {
        let keys = AccountKeys::new(Key::random());
        let pk = keys.auth_key().verifying_key().to_bytes();
        let sig = keys.sign_auth_challenge("srv", "alice", b"nonce");
        assert!(verify_auth(&pk, "srv", "alice", b"nonce", &sig));
        assert!(!verify_auth(&pk, "other", "alice", b"nonce", &sig));
        assert!(!verify_auth(&pk, "srv", "bob", b"nonce", &sig));
    }
}
