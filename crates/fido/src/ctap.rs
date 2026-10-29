//! CTAP2 over USB HID (Linux, macOS, BSDs) via Mozilla's `authenticator` crate, the FIDO stack
//! used by Firefox. PIN entry goes through [`Interaction::request_pin`].

use std::collections::HashMap;
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;

use authenticator::authenticatorservice::{AuthenticatorService, RegisterArgs, SignArgs};
use authenticator::crypto::COSEAlgorithm;
use authenticator::ctap2::attestation::AuthenticatorDataFlags;
use authenticator::ctap2::server::{
    AuthenticationExtensionsClientInputs, AuthenticationExtensionsPRFInputs,
    AuthenticationExtensionsPRFValues, CredentialProtectionPolicy, PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters, PublicKeyCredentialUserEntity, RelyingParty,
    ResidentKeyRequirement, Transport, UserVerificationRequirement,
};
use authenticator::errors::AuthenticatorError;
use authenticator::statecallback::StateCallback;
use authenticator::{Pin, StatusPinUv, StatusUpdate};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    client_data_json, Authenticator, CredentialSalt, Error, Interaction, PrfOutput, PrfPair, Result,
};

const TIMEOUT_MS: u64 = 120_000;

pub struct CtapAuthenticator {
    ui: Arc<dyn Interaction>,
}

impl CtapAuthenticator {
    pub fn new(ui: Arc<dyn Interaction>) -> Self {
        CtapAuthenticator { ui }
    }

    fn service() -> Result<AuthenticatorService> {
        let mut s = AuthenticatorService::new().map_err(|e| Error::Platform(format!("{e:?}")))?;
        s.add_u2f_usb_hid_platform_transports();
        Ok(s)
    }

    /// Relay status updates (touch prompts, PIN requests) to the UI until the operation ends.
    fn status_channel(&self) -> std::sync::mpsc::Sender<StatusUpdate> {
        let (tx, rx) = channel::<StatusUpdate>();
        let ui = self.ui.clone();
        thread::spawn(move || {
            while let Ok(update) = rx.recv() {
                match update {
                    StatusUpdate::PresenceRequired => ui.status("Touch your security key"),
                    StatusUpdate::SelectDeviceNotice => {
                        ui.status("Touch the security key you want to use")
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinRequired(sender)) => {
                        match ui.request_pin(None) {
                            Some(pin) => {
                                let _ = sender.send(Pin::new(&pin));
                            }
                            None => drop(sender),
                        }
                    }
                    StatusUpdate::PinUvError(StatusPinUv::InvalidPin(sender, attempts)) => {
                        match ui.request_pin(attempts) {
                            Some(pin) => {
                                let _ = sender.send(Pin::new(&pin));
                            }
                            None => drop(sender),
                        }
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinAuthBlocked) => {
                        ui.status("Too many wrong PINs: unplug and reinsert the security key")
                    }
                    StatusUpdate::PinUvError(StatusPinUv::PinBlocked) => {
                        ui.status("PIN blocked: the security key must be reset")
                    }
                    _ => {}
                }
            }
        });
        tx
    }
}

fn map_err(e: AuthenticatorError) -> Error {
    match e {
        AuthenticatorError::CancelledByUser => Error::Cancelled,
        AuthenticatorError::PinError(p) => Error::PinBlocked(format!("{p:?}")),
        other => Error::Platform(format!("{other:?}")),
    }
}

fn hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

impl Authenticator for CtapAuthenticator {
    fn name(&self) -> &'static str {
        "CTAP2 USB"
    }

    fn enroll(&self, rp_id: &str, user_name: &str, exclude: &[Vec<u8>]) -> Result<Vec<u8>> {
        self.register_credential(rp_id, user_name, exclude)
    }

    fn prf(&self, rp_id: &str, creds: &[CredentialSalt]) -> Result<PrfOutput> {
        let eval_by_credential: HashMap<Vec<u8>, AuthenticationExtensionsPRFValues> = creds
            .iter()
            .map(|c| {
                (
                    c.credential_id.clone(),
                    AuthenticationExtensionsPRFValues {
                        first: c.prf_salt.clone(),
                        second: None,
                    },
                )
            })
            .collect();
        let allow = creds.iter().map(|c| c.credential_id.clone()).collect();
        let prf = AuthenticationExtensionsPRFInputs {
            eval: None,
            eval_by_credential: Some(eval_by_credential),
        };
        let mut p = self.sign(rp_id, allow, prf)?;
        if p.credential_id.is_empty() && creds.len() == 1 {
            p.credential_id = creds[0].credential_id.clone();
        }
        if p.credential_id.is_empty() {
            return Err(Error::UnknownCredential);
        }
        Ok(PrfOutput {
            credential_id: p.credential_id,
            output: p.first,
        })
    }

    fn prf2(
        &self,
        rp_id: &str,
        allow: &[Vec<u8>],
        first: &[u8],
        second: Option<&[u8]>,
    ) -> Result<PrfPair> {
        // The same inputs for every allowed credential (`eval`, not `evalByCredential`).
        let values = AuthenticationExtensionsPRFValues {
            first: first.to_vec(),
            second: second.map(<[u8]>::to_vec),
        };
        let prf = AuthenticationExtensionsPRFInputs {
            eval: Some(values),
            eval_by_credential: None,
        };
        let mut p = self.sign(rp_id, allow.to_vec(), prf)?;
        if p.credential_id.is_empty() && allow.len() == 1 {
            p.credential_id = allow[0].clone();
        }
        if second.is_some() && p.second.is_none() {
            return Err(Error::PrfUnsupported);
        }
        Ok(p)
    }
}

impl CtapAuthenticator {
    fn register_credential(
        &self,
        rp_id: &str,
        user_name: &str,
        exclude: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        let mut manager = Self::service()?;
        let mut user_id = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut user_id);
        let args = RegisterArgs {
            client_data_hash: hash(&client_data_json("webauthn.create", rp_id)),
            relying_party: RelyingParty {
                id: rp_id.to_string(),
                name: Some("Strongbox".into()),
            },
            origin: format!("https://{rp_id}"),
            user: PublicKeyCredentialUserEntity {
                id: user_id,
                name: Some(user_name.to_string()),
                display_name: Some(user_name.to_string()),
            },
            pub_cred_params: vec![PublicKeyCredentialParameters {
                alg: COSEAlgorithm::ES256,
            }],
            exclude_list: exclude
                .iter()
                .map(|id| PublicKeyCredentialDescriptor {
                    id: id.clone(),
                    transports: vec![Transport::USB],
                })
                .collect(),
            user_verification_req: UserVerificationRequirement::Required,
            resident_key_req: ResidentKeyRequirement::Discouraged,
            extensions: AuthenticationExtensionsClientInputs {
                prf: Some(AuthenticationExtensionsPRFInputs::default()),
                // See win.rs: without credProtect level 3, CTAP 2.0 keys would release the
                // hmac-secret output without the PIN.
                credential_protection_policy: Some(
                    CredentialProtectionPolicy::UserVerificationRequired,
                ),
                enforce_credential_protection_policy: Some(true),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
        };
        let (tx, rx) = channel();
        let cb = StateCallback::new(Box::new(move |rv| {
            let _ = tx.send(rv);
        }));
        manager
            .register(TIMEOUT_MS, args, self.status_channel(), cb)
            .map_err(map_err)?;
        let result = rx
            .recv()
            .map_err(|_| Error::Cancelled)?
            .map_err(|e| match e {
                AuthenticatorError::UnsupportedOption(_) => Error::CredProtectUnsupported,
                AuthenticatorError::CredentialExcluded => Error::AlreadyRegistered,
                e => map_err(e),
            })?;
        if result.extensions.prf.as_ref().and_then(|p| p.enabled) != Some(true) {
            return Err(Error::PrfUnsupported);
        }
        if !result
            .att_obj
            .auth_data
            .flags
            .contains(AuthenticatorDataFlags::USER_VERIFIED)
        {
            return Err(Error::NotVerified);
        }
        result
            .att_obj
            .auth_data
            .credential_data
            .map(|c| c.credential_id)
            .ok_or_else(|| Error::Platform("no credential data returned".into()))
    }

    /// One getAssertion with PRF inputs. `credential_id` is empty if the key did not say
    /// which credential it used (CTAP 2.0 with a single-entry allow list).
    fn sign(
        &self,
        rp_id: &str,
        allow: Vec<Vec<u8>>,
        prf: AuthenticationExtensionsPRFInputs,
    ) -> Result<PrfPair> {
        let mut manager = Self::service()?;
        let args = SignArgs {
            client_data_hash: hash(&client_data_json("webauthn.get", rp_id)),
            origin: format!("https://{rp_id}"),
            relying_party_id: rp_id.to_string(),
            allow_list: allow
                .into_iter()
                .map(|id| PublicKeyCredentialDescriptor {
                    id,
                    transports: vec![Transport::USB],
                })
                .collect(),
            user_verification_req: UserVerificationRequirement::Required,
            user_presence_req: true,
            extensions: AuthenticationExtensionsClientInputs {
                prf: Some(prf),
                ..Default::default()
            },
            pin: None,
            use_ctap1_fallback: false,
        };
        let (tx, rx) = channel();
        let cb = StateCallback::new(Box::new(move |rv| {
            let _ = tx.send(rv);
        }));
        manager
            .sign(TIMEOUT_MS, args, self.status_channel(), cb)
            .map_err(map_err)?;
        let result = rx.recv().map_err(|_| Error::Cancelled)?.map_err(map_err)?;
        if !result
            .assertion
            .auth_data
            .flags
            .contains(AuthenticatorDataFlags::USER_VERIFIED)
        {
            return Err(Error::NotVerified);
        }
        let credential_id = result
            .assertion
            .credentials
            .map(|c| c.id)
            .unwrap_or_default();
        let values = result
            .extensions
            .prf
            .and_then(|p| p.results)
            .ok_or(Error::PrfUnsupported)?;
        let to32 = |v: Vec<u8>| -> Result<Zeroizing<[u8; 32]>> {
            Ok(Zeroizing::new(
                v.as_slice().try_into().map_err(|_| Error::PrfUnsupported)?,
            ))
        };
        Ok(PrfPair {
            credential_id,
            first: to32(values.first)?,
            second: values.second.map(to32).transpose()?,
        })
    }
}
