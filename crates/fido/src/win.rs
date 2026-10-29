//! Windows WebAuthn API backend (`webauthn.dll`). Works without administrator rights (raw
//! FIDO HID access is admin-only since Windows 10 1903), and the PIN is entered in the OS
//! dialog, never seen by Strongbox. PRF on get-assertion needs WebAuthn API version 4+
//! (Windows 11 22H2 and later).

use std::ffi::c_void;

use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{BOOL, FALSE, HWND, TRUE};
use windows::Win32::Networking::WindowsWebServices::*;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;
use zeroize::Zeroizing;

use crate::{
    auth_data_has_uv, client_data_json, Authenticator, CredentialSalt, Error, PrfOutput, PrfPair,
    Result,
};

const TIMEOUT_MS: u32 = 120_000;
const MIN_API_VERSION: u32 = 4;
// Struct versions that contain the fields we set (see webauthn.h).
const MAKE_CREDENTIAL_OPTIONS_VERSION: u32 = 3;
const GET_ASSERTION_OPTIONS_VERSION: u32 = 6;
const NTE_USER_CANCELLED: i32 = 0x8009_0036u32 as i32;
const NTE_NOT_FOUND: i32 = 0x8009_0011u32 as i32;
const NTE_NOT_SUPPORTED: i32 = 0x8009_0029u32 as i32;
const NTE_EXISTS: i32 = 0x8009_000Fu32 as i32;

pub struct WindowsAuthenticator;

fn check_api() -> Result<()> {
    let v = unsafe { WebAuthNGetApiVersionNumber() };
    if v < MIN_API_VERSION {
        return Err(Error::Platform(format!(
            "Windows WebAuthn API version {v} is too old for PRF; Windows 11 22H2 or later is required"
        )));
    }
    Ok(())
}

fn map_err(e: windows::core::Error) -> Error {
    match e.code().0 {
        NTE_USER_CANCELLED => Error::Cancelled,
        NTE_NOT_FOUND => Error::UnknownCredential,
        _ => Error::Platform(e.message().to_string()),
    }
}

fn hwnd() -> HWND {
    unsafe { GetForegroundWindow() }
}

unsafe fn slice<'a>(ptr: *const u8, len: u32) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(ptr, len as usize)
    }
}

fn credential(id: &[u8]) -> WEBAUTHN_CREDENTIAL {
    WEBAUTHN_CREDENTIAL {
        dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
        cbId: id.len() as u32,
        pbId: id.as_ptr() as *mut u8,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    }
}

impl Authenticator for WindowsAuthenticator {
    fn name(&self) -> &'static str {
        "Windows WebAuthn"
    }

    fn enroll(&self, rp_id: &str, user_name: &str, exclude: &[Vec<u8>]) -> Result<Vec<u8>> {
        self.make_credential(rp_id, user_name, exclude)
    }

    fn prf(&self, rp_id: &str, creds: &[CredentialSalt]) -> Result<PrfOutput> {
        // PRF inputs per credential (evalByCredential); Windows hashes them into hmac-secret
        // salts per the WebAuthn spec because WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG is
        // not set.
        let mut salts: Vec<WEBAUTHN_HMAC_SECRET_SALT> = creds
            .iter()
            .map(|c| WEBAUTHN_HMAC_SECRET_SALT {
                cbFirst: c.prf_salt.len() as u32,
                pbFirst: c.prf_salt.as_ptr() as *mut u8,
                cbSecond: 0,
                pbSecond: std::ptr::null_mut(),
            })
            .collect();
        let mut by_cred: Vec<WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT> = creds
            .iter()
            .zip(salts.iter_mut())
            .map(|(c, s)| WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT {
                cbCredID: c.credential_id.len() as u32,
                pbCredID: c.credential_id.as_ptr() as *mut u8,
                pHmacSecretSalt: s,
            })
            .collect();
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: std::ptr::null_mut(),
            cCredWithHmacSecretSaltList: by_cred.len() as u32,
            pCredWithHmacSecretSaltList: by_cred.as_mut_ptr(),
        };
        let allow: Vec<&[u8]> = creds.iter().map(|c| c.credential_id.as_slice()).collect();
        let p = self.assertion(rp_id, &allow, &mut salt_values)?;
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
        // The same inputs for every allowed credential (global salt), PRF-hashed by Windows.
        let mut salt = WEBAUTHN_HMAC_SECRET_SALT {
            cbFirst: first.len() as u32,
            pbFirst: first.as_ptr() as *mut u8,
            cbSecond: second.map_or(0, |s| s.len() as u32),
            pbSecond: second.map_or(std::ptr::null_mut(), |s| s.as_ptr() as *mut u8),
        };
        let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
            pGlobalHmacSalt: &mut salt,
            cCredWithHmacSecretSaltList: 0,
            pCredWithHmacSecretSaltList: std::ptr::null_mut(),
        };
        let allow: Vec<&[u8]> = allow.iter().map(Vec::as_slice).collect();
        let p = self.assertion(rp_id, &allow, &mut salt_values)?;
        if second.is_some() && p.second.is_none() {
            return Err(Error::PrfUnsupported);
        }
        Ok(p)
    }
}

impl WindowsAuthenticator {
    fn make_credential(
        &self,
        rp_id: &str,
        user_name: &str,
        exclude: &[Vec<u8>],
    ) -> Result<Vec<u8>> {
        check_api()?;
        let rp_id_w = HSTRING::from(rp_id);
        let rp_name_w = HSTRING::from("Strongbox");
        let user_w = HSTRING::from(user_name);
        let mut user_id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut user_id);
        let mut client_data = client_data_json("webauthn.create", rp_id);

        let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
            pwszId: PCWSTR(rp_id_w.as_ptr()),
            pwszName: PCWSTR(rp_name_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
        };
        let user = WEBAUTHN_USER_ENTITY_INFORMATION {
            dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
            cbId: user_id.len() as u32,
            pbId: user_id.as_mut_ptr(),
            pwszName: PCWSTR(user_w.as_ptr()),
            pwszIcon: PCWSTR::null(),
            pwszDisplayName: PCWSTR(user_w.as_ptr()),
        };
        let mut param = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
            dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
            pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
            lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
        };
        let params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
            cCredentialParameters: 1,
            pCredentialParameters: &mut param,
        };
        let cd = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data.len() as u32,
            pbClientDataJSON: client_data.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut hmac_secret: BOOL = TRUE;
        // credProtect level 3: the key will not even acknowledge the credential, let alone
        // evaluate hmac-secret, without user verification. Required (not just requested):
        // on CTAP 2.0 keys hmac-secret has no separate with-UV secret, so without this a
        // stolen key would release the PRF output without its PIN.
        let mut cred_protect = WEBAUTHN_CRED_PROTECT_EXTENSION_IN {
            dwCredProtect: WEBAUTHN_USER_VERIFICATION_REQUIRED,
            bRequireCredProtect: TRUE,
        };
        let mut exts = [
            WEBAUTHN_EXTENSION {
                pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET,
                cbExtension: std::mem::size_of::<BOOL>() as u32,
                pvExtension: &mut hmac_secret as *mut BOOL as *mut c_void,
            },
            WEBAUTHN_EXTENSION {
                pwszExtensionIdentifier: WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT,
                cbExtension: std::mem::size_of::<WEBAUTHN_CRED_PROTECT_EXTENSION_IN>() as u32,
                pvExtension: &mut cred_protect as *mut WEBAUTHN_CRED_PROTECT_EXTENSION_IN
                    as *mut c_void,
            },
        ];
        let mut excluded: Vec<WEBAUTHN_CREDENTIAL> =
            exclude.iter().map(|id| credential(id)).collect();

        let opts = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
            dwVersion: MAKE_CREDENTIAL_OPTIONS_VERSION,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: excluded.len() as u32,
                pCredentials: excluded.as_mut_ptr(),
            },
            Extensions: WEBAUTHN_EXTENSIONS {
                cExtensions: exts.len() as u32,
                pExtensions: exts.as_mut_ptr(),
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            bRequireResidentKey: FALSE,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            ..Default::default()
        };

        unsafe {
            let att =
                WebAuthNAuthenticatorMakeCredential(hwnd(), &rp, &user, &params, &cd, Some(&opts))
                    .map_err(|e| match e.code().0 {
                        NTE_NOT_SUPPORTED => Error::CredProtectUnsupported,
                        NTE_EXISTS => Error::AlreadyRegistered,
                        _ => map_err(e),
                    })?;
            let a = &*att;
            let cred_id = slice(a.pbCredentialId, a.cbCredentialId).to_vec();
            let verified = auth_data_has_uv(slice(a.pbAuthenticatorData, a.cbAuthenticatorData));
            // Windows may omit extension outputs entirely (null list). Only an explicit
            // "hmac-secret: false" is a refusal; otherwise the PRF evaluation that follows
            // enrollment is the real capability check.
            let exts = if a.dwVersion >= 2 && !a.Extensions.pExtensions.is_null() {
                std::slice::from_raw_parts(
                    a.Extensions.pExtensions,
                    a.Extensions.cExtensions as usize,
                )
            } else {
                &[]
            };
            let hmac_refused = exts.iter().any(|e| {
                e.pwszExtensionIdentifier
                    .to_string()
                    .is_ok_and(|n| n == "hmac-secret")
                    && !e.pvExtension.is_null()
                    && !(*(e.pvExtension as *const BOOL)).as_bool()
            });
            WebAuthNFreeCredentialAttestation(Some(att));
            if cred_id.is_empty() {
                return Err(Error::Platform("no credential id returned".into()));
            }
            if hmac_refused {
                return Err(Error::PrfUnsupported);
            }
            if !verified {
                return Err(Error::NotVerified);
            }
            Ok(cred_id)
        }
    }

    /// One getAssertion with hmac-secret salts; returns the used credential and both outputs.
    fn assertion(
        &self,
        rp_id: &str,
        allow: &[&[u8]],
        salt_values: &mut WEBAUTHN_HMAC_SECRET_SALT_VALUES,
    ) -> Result<PrfPair> {
        check_api()?;
        let rp_id_w = HSTRING::from(rp_id);
        let mut client_data = client_data_json("webauthn.get", rp_id);
        let cd = WEBAUTHN_CLIENT_DATA {
            dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
            cbClientDataJSON: client_data.len() as u32,
            pbClientDataJSON: client_data.as_mut_ptr(),
            pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
        };
        let mut allow: Vec<WEBAUTHN_CREDENTIAL> = allow.iter().map(|id| credential(id)).collect();
        let opts = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
            dwVersion: GET_ASSERTION_OPTIONS_VERSION,
            dwTimeoutMilliseconds: TIMEOUT_MS,
            CredentialList: WEBAUTHN_CREDENTIALS {
                cCredentials: allow.len() as u32,
                pCredentials: allow.as_mut_ptr(),
            },
            dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
            pHmacSecretSaltValues: salt_values,
            ..Default::default()
        };

        unsafe {
            let assertion = WebAuthNAuthenticatorGetAssertion(
                hwnd(),
                PCWSTR(rp_id_w.as_ptr()),
                &cd,
                Some(&opts),
            )
            .map_err(map_err)?;
            let a = &*assertion;
            let result = (|| {
                if !auth_data_has_uv(slice(a.pbAuthenticatorData, a.cbAuthenticatorData)) {
                    return Err(Error::NotVerified);
                }
                if a.dwVersion < 3 || a.pHmacSecret.is_null() {
                    return Err(Error::PrfUnsupported);
                }
                let hs = &*a.pHmacSecret;
                let first: [u8; 32] = slice(hs.pbFirst, hs.cbFirst)
                    .try_into()
                    .map_err(|_| Error::PrfUnsupported)?;
                let second = match slice(hs.pbSecond, hs.cbSecond) {
                    [] => None,
                    s => Some(Zeroizing::new(
                        <[u8; 32]>::try_from(s).map_err(|_| Error::PrfUnsupported)?,
                    )),
                };
                Ok(PrfPair {
                    credential_id: slice(a.Credential.pbId, a.Credential.cbId).to_vec(),
                    first: Zeroizing::new(first),
                    second,
                })
            })();
            WebAuthNFreeAssertion(assertion);
            result
        }
    }
}
