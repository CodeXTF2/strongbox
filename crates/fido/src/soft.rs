//! Software authenticator for tests and development. It mimics a CTAP2 authenticator's
//! hmac-secret (`HMAC-SHA256(credRandom, salt)`) with PRF salt hashing, so outputs have the
//! same shape as real keys. Its secrets live in a plain JSON file: it offers NO security.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{
    prf_salt_to_hmac_salt, Authenticator, CredentialSalt, Error, PrfOutput, PrfPair, Result,
};

pub struct SoftAuthenticator {
    path: PathBuf,
    lock: Mutex<()>,
}

type State = BTreeMap<String, String>; // b64(credential id) -> b64(credRandom)

impl SoftAuthenticator {
    pub fn new(path: PathBuf) -> Self {
        SoftAuthenticator {
            path,
            lock: Mutex::new(()),
        }
    }

    fn load(&self) -> State {
        std::fs::read(&self.path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn store(&self, state: &State) -> Result<()> {
        let json = serde_json::to_vec_pretty(state).map_err(|e| Error::Platform(e.to_string()))?;
        std::fs::write(&self.path, json).map_err(|e| Error::Platform(e.to_string()))
    }
}

impl Authenticator for SoftAuthenticator {
    fn name(&self) -> &'static str {
        "software (INSECURE)"
    }

    fn enroll(&self, _rp_id: &str, _user_name: &str, exclude: &[Vec<u8>]) -> Result<Vec<u8>> {
        let _g = self.lock.lock().unwrap();
        let mut state = self.load();
        // Like a real key: refuse if one of the excluded credentials is ours.
        if exclude
            .iter()
            .any(|id| state.contains_key(&STANDARD.encode(id)))
        {
            return Err(Error::AlreadyRegistered);
        }
        let mut id = vec![0u8; 32];
        let mut cred_random = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id);
        rand::thread_rng().fill_bytes(&mut cred_random);
        state.insert(STANDARD.encode(&id), STANDARD.encode(cred_random));
        self.store(&state)?;
        Ok(id)
    }

    fn enroll_prf(
        &self,
        rp_id: &str,
        user_name: &str,
        exclude: &[Vec<u8>],
        first: &[u8],
    ) -> Result<crate::Enrolled> {
        // Models a key with hmac-secret-mc, so the one-touch client path is tested.
        let credential_id = self.enroll(rp_id, user_name, exclude)?;
        let out = self.prf2(rp_id, std::slice::from_ref(&credential_id), first, None)?;
        Ok(crate::Enrolled {
            credential_id,
            first: Some(out.first),
        })
    }

    fn prf(&self, _rp_id: &str, creds: &[CredentialSalt]) -> Result<PrfOutput> {
        let _g = self.lock.lock().unwrap();
        let state = self.load();
        for c in creds {
            if let Some(r) = state.get(&STANDARD.encode(&c.credential_id)) {
                return Ok(PrfOutput {
                    credential_id: c.credential_id.clone(),
                    output: eval(r, &c.prf_salt)?,
                });
            }
        }
        Err(Error::UnknownCredential)
    }

    fn prf2(
        &self,
        _rp_id: &str,
        allow: &[Vec<u8>],
        first: &[u8],
        second: Option<&[u8]>,
    ) -> Result<PrfPair> {
        let _g = self.lock.lock().unwrap();
        let state = self.load();
        for id in allow {
            if let Some(r) = state.get(&STANDARD.encode(id)) {
                return Ok(PrfPair {
                    credential_id: id.clone(),
                    first: eval(r, first)?,
                    second: second.map(|s| eval(r, s)).transpose()?,
                });
            }
        }
        Err(Error::UnknownCredential)
    }
}

/// `HMAC(credRandom, PRF salt)`, as a real authenticator computes hmac-secret.
fn eval(cred_random_b64: &str, prf_input: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let cred_random = STANDARD
        .decode(cred_random_b64)
        .map_err(|e| Error::Platform(e.to_string()))?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&cred_random).unwrap();
    mac.update(&prf_salt_to_hmac_salt(prf_input));
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}
