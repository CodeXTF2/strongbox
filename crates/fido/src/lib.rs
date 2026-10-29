//! FIDO2 PRF access.
//!
//! Strongbox needs exactly two operations from a security key:
//!
//! * **enroll**: create a non-discoverable credential with `hmac-secret` enabled, requiring
//!   user verification (PIN);
//! * **prf2**: evaluate the WebAuthn PRF extension (one or two inputs, one touch) for one of a
//!   set of credentials, again with user verification required.
//!
//! PRF semantics are used everywhere (the hmac-secret salt is
//! `SHA-256("WebAuthn PRF" || 0x00 || input)`), so a credential gives the same output from
//! every backend, and from a browser if a web client is ever added.
//!
//! Backends: Windows WebAuthn API (`webauthn.dll`, no admin rights needed, the OS collects the
//! PIN), CTAP2 over USB HID via Mozilla's `authenticator` crate on Linux/macOS, and a software
//! authenticator for tests (feature `soft`).

use std::sync::Arc;

use zeroize::Zeroizing;

#[cfg(not(windows))]
mod ctap;
#[cfg(feature = "soft")]
pub mod soft;
#[cfg(windows)]
mod win;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no security key responded")]
    NoDevice,
    #[error("operation cancelled")]
    Cancelled,
    #[error("the security key does not support the PRF / hmac-secret extension")]
    PrfUnsupported,
    #[error("this security key is not registered for the account")]
    UnknownCredential,
    #[error("this security key is already registered for this account")]
    AlreadyRegistered,
    #[error("PIN blocked: {0}")]
    PinBlocked(String),
    #[error("the security key did not verify the user (PIN); refusing to continue")]
    NotVerified,
    #[error("the security key does not support credential protection (credProtect), which Strongbox requires so the key cannot be used without its PIN")]
    CredProtectUnsupported,
    #[error("platform error: {0}")]
    Platform(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Callbacks for user interaction. The Windows backend uses the OS dialog and only calls
/// `status`; the CTAP-HID backend also asks for the PIN here.
pub trait Interaction: Send + Sync {
    fn status(&self, message: &str);
    /// Return `None` to cancel.
    fn request_pin(&self, attempts_left: Option<u8>) -> Option<String>;
}

/// Both PRF outputs of one assertion (one touch).
pub struct PrfPair {
    pub credential_id: Vec<u8>,
    pub first: Zeroizing<[u8; 32]>,
    pub second: Option<Zeroizing<[u8; 32]>>,
}

/// User name given to vault credentials. Generic on purpose: it must not name an account.
pub const VAULT_USER_NAME: &str = "Strongbox";

/// A new credential, plus its PRF output when the key evaluated it during enrollment.
pub struct Enrolled {
    pub credential_id: Vec<u8>,
    pub first: Option<Zeroizing<[u8; 32]>>,
}

pub trait Authenticator: Send + Sync {
    fn name(&self) -> &'static str;

    /// [`Authenticator::enroll`], also asking for the PRF output of `first` in the same touch
    /// (CTAP 2.2 `hmac-secret-mc`), so enrollment needs one touch instead of two. `first` is
    /// `None` in the result when the backend or key cannot do that; callers then fall back to
    /// [`Authenticator::prf2`]. A backend may only return a value that is byte-for-byte what a
    /// later assertion with the same input returns, because nothing re-checks it. No hardware
    /// backend implements this yet (the CTAP crate and the Windows bindings we use lack it).
    fn enroll_prf(
        &self,
        rp_id: &str,
        user_name: &str,
        exclude: &[Vec<u8>],
        _first: &[u8],
    ) -> Result<Enrolled> {
        Ok(Enrolled {
            credential_id: self.enroll(rp_id, user_name, exclude)?,
            first: None,
        })
    }

    /// Create a credential with hmac-secret enabled and return its id. `exclude` lists
    /// credential ids already registered, so the same key is not enrolled twice.
    fn enroll(&self, rp_id: &str, user_name: &str, exclude: &[Vec<u8>]) -> Result<Vec<u8>>;

    /// Evaluate PRF with the same one or two inputs on whichever of `allow` is present, with
    /// user verification: two derivations for a single touch.
    fn prf2(
        &self,
        rp_id: &str,
        allow: &[Vec<u8>],
        first: &[u8],
        second: Option<&[u8]>,
    ) -> Result<PrfPair>;
}

/// The platform's hardware authenticator backend. With feature `soft`, setting
/// `STRONGBOX_SOFT_AUTHENTICATOR=<state file>` selects the software authenticator instead.
pub fn platform(ui: Arc<dyn Interaction>) -> Box<dyn Authenticator> {
    #[cfg(feature = "soft")]
    if let Some(path) = std::env::var_os("STRONGBOX_SOFT_AUTHENTICATOR") {
        ui.status("WARNING: using the insecure software authenticator (development only)");
        return Box::new(soft::SoftAuthenticator::new(path.into()));
    }
    #[cfg(windows)]
    {
        let _ = &ui;
        Box::new(win::WindowsAuthenticator)
    }
    #[cfg(not(windows))]
    {
        Box::new(ctap::CtapAuthenticator::new(ui))
    }
}

/// Minimal clientDataJSON. Nothing verifies it (the server never sees FIDO data), but the
/// platform APIs require one, and its hash is what the authenticator signs.
pub(crate) fn client_data_json(kind: &str, rp_id: &str) -> Vec<u8> {
    use rand::RngCore;
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let challenge: String = challenge.iter().map(|b| format!("{b:02x}")).collect();
    format!(r#"{{"type":"{kind}","challenge":"{challenge}","origin":"https://{rp_id}","crossOrigin":false}}"#)
        .into_bytes()
}

/// Authenticator data is `rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ …`.
const AUTH_DATA_FLAGS_OFFSET: usize = 32;
const FLAG_UV: u8 = 0x04;

/// True if raw authenticator data has the "user verified" flag set. The hmac-secret output
/// already differs with and without UV on CTAP 2.1 keys; checking the flag as well means a
/// platform or key that silently skipped the PIN is rejected instead of trusted.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn auth_data_has_uv(auth_data: &[u8]) -> bool {
    auth_data
        .get(AUTH_DATA_FLAGS_OFFSET)
        .is_some_and(|f| f & FLAG_UV != 0)
}

/// Map a PRF input to the hmac-secret salt, as the WebAuthn PRF extension specifies.
pub fn prf_salt_to_hmac_salt(input: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"WebAuthn PRF");
    h.update([0u8]);
    h.update(input);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn uv_flag() {
        let mut ad = vec![0u8; 37];
        assert!(!super::auth_data_has_uv(&ad));
        ad[32] = 0x05;
        assert!(super::auth_data_has_uv(&ad));
        assert!(!super::auth_data_has_uv(&ad[..32]));
    }
}
