//! Sign-up and unlock.

use std::sync::Arc;

use strongbox_core::account::AccountKeys;
use strongbox_core::keyslot::{new_prf_salt, Keyslot, KeyslotKind, PasswordKdf, Unlock};
use strongbox_core::{recovery, Key};
use strongbox_fido::{Authenticator, CredentialSalt, Interaction};
use strongbox_proto::{RegisterRequest, SessionRequest};

use crate::api::Api;
use crate::drive::Drive;
use crate::profile::{Profile, DEFAULT_RP_ID};
use crate::{Error, Result};

/// User interaction needed by the client (security key prompts plus the optional password).
pub trait Ui: Interaction {
    /// Return `None` to cancel.
    fn request_password(&self) -> Option<String>;
}

pub struct RegisterOptions {
    pub server_url: String,
    pub username: String,
    pub invite: Option<String>,
    pub key_label: String,
    /// Also require this password (Argon2id) with the security key.
    pub password: Option<String>,
    /// Create a printable recovery code keyslot.
    pub recovery_code: bool,
    pub rp_id: Option<String>,
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    tokio::task::spawn_blocking(f)
        .await
        .expect("blocking task panicked")
}

/// Enroll a security key and build a FIDO keyslot wrapping `amk`. Two touches: one to create
/// the credential, one to evaluate the PRF.
pub(crate) async fn enroll_keyslot(
    authn: Arc<dyn Authenticator>,
    rp_id: &str,
    username: &str,
    label: String,
    password: Option<String>,
    exclude: Vec<Vec<u8>>,
    amk: &Key,
) -> Result<Keyslot> {
    let (rp, user) = (rp_id.to_string(), username.to_string());
    let prf_salt = new_prf_salt();
    let (a, salt) = (authn.clone(), prf_salt.clone());
    // One touch if the key evaluates the PRF while enrolling, otherwise a second one below.
    let enrolled = blocking(move || a.enroll_prf(&rp, &user, &exclude, &salt)).await?;
    let credential_id = enrolled.credential_id;
    let output = match enrolled.first {
        Some(first) => first,
        None => {
            let (rp, cs) = (
                rp_id.to_string(),
                vec![CredentialSalt {
                    credential_id: credential_id.clone(),
                    prf_salt: prf_salt.clone(),
                }],
            );
            blocking(move || authn.prf(&rp, &cs)).await?.output
        }
    };
    let kind = KeyslotKind::Fido {
        rp_id: rp_id.to_string(),
        credential_id,
        prf_salt,
        password: password.as_ref().map(|_| PasswordKdf::new_default()),
    };
    let amk = amk.clone();
    blocking(move || {
        Keyslot::create(
            label,
            kind,
            &Unlock::Fido {
                prf_output: &output,
                password: password.as_deref(),
            },
            &amk,
        )
    })
    .await
    .map_err(Error::from)
}

/// Create an account. Returns the unlocked drive and, if requested, the recovery code, which
/// must be shown to the user exactly once.
pub async fn register(
    opts: RegisterOptions,
    authn: Arc<dyn Authenticator>,
) -> Result<(Drive, Option<String>)> {
    let api = Api::new(&opts.server_url)?;
    let info = api.info().await?;
    let rp_id = opts
        .rp_id
        .clone()
        .unwrap_or_else(|| DEFAULT_RP_ID.to_string());
    let amk = Key::random();

    let mut keyslots = vec![
        enroll_keyslot(
            authn,
            &rp_id,
            &opts.username,
            opts.key_label,
            opts.password,
            vec![],
            &amk,
        )
        .await?,
    ];
    let mut code = None;
    if opts.recovery_code {
        let secret = recovery::generate();
        keyslots.push(Keyslot::create(
            "Recovery code".into(),
            KeyslotKind::Recovery,
            &Unlock::Recovery { secret: &secret },
            &amk,
        )?);
        code = Some(recovery::encode(&secret));
    }

    let keys = AccountKeys::new(amk);
    api.register(&RegisterRequest {
        username: opts.username.clone(),
        auth_public_key: keys.auth_key().verifying_key().to_bytes().to_vec(),
        keyslots,
        invite: opts.invite,
    })
    .await?;

    let profile = Profile {
        server_url: opts.server_url,
        server_id: info.server_id,
        username: opts.username,
        rp_id,
    };
    profile.save()?;
    let drive = open_session(api, profile, keys).await?;
    drive.ensure_root().await?;
    Ok((drive, code))
}

/// Unlock with any enrolled security key (one touch + PIN, plus the password if that keyslot
/// has one).
pub async fn login(
    profile: Profile,
    authn: Arc<dyn Authenticator>,
    ui: Arc<dyn Ui>,
) -> Result<Drive> {
    let api = Api::new(&profile.server_url)?;
    check_server(&api, &profile).await?;
    let slots: Vec<Keyslot> = api
        .keyslots(&profile.username)
        .await?
        .into_iter()
        .filter(|s| matches!(&s.kind, KeyslotKind::Fido { rp_id, .. } if *rp_id == profile.rp_id))
        .collect();
    let creds: Vec<CredentialSalt> = slots
        .iter()
        .filter_map(|s| match &s.kind {
            KeyslotKind::Fido {
                credential_id,
                prf_salt,
                ..
            } => Some(CredentialSalt {
                credential_id: credential_id.clone(),
                prf_salt: prf_salt.clone(),
            }),
            KeyslotKind::Recovery => None,
        })
        .collect();
    if creds.is_empty() {
        return Err(Error::Invalid(
            "this account has no security keys registered".into(),
        ));
    }
    ui.status("Insert your security key, enter its PIN and touch it");
    let rp = profile.rp_id.clone();
    let out = blocking(move || authn.prf(&rp, &creds)).await?;
    let slot = slots
        .into_iter()
        .find(|s| s.credential_id() == Some(out.credential_id.as_slice()))
        .ok_or(strongbox_fido::Error::UnknownCredential)?;
    let needs_password = matches!(
        &slot.kind,
        KeyslotKind::Fido {
            password: Some(_),
            ..
        }
    );
    let password = if needs_password {
        let ui = ui.clone();
        Some(zeroize::Zeroizing::new(
            blocking(move || ui.request_password())
                .await
                .ok_or(Error::Cancelled)?,
        ))
    } else {
        None
    };
    let amk = blocking(move || {
        slot.unlock(&Unlock::Fido {
            prf_output: &out.output,
            password: password.as_ref().map(|p| p.as_str()),
        })
    })
    .await?;
    open_session(api, profile, AccountKeys::new(amk)).await
}

/// First sign-in on a new device: pins the server id, and saves the profile only once the
/// security key has actually unlocked the account. The relying party id is never taken from
/// the server (it decides which credentials the key is asked about).
pub async fn sign_in(
    server_url: &str,
    username: &str,
    rp_id: Option<String>,
    authn: Arc<dyn Authenticator>,
    ui: Arc<dyn Ui>,
) -> Result<Drive> {
    let profile = new_device_profile(server_url, username, rp_id).await?;
    let drive = login(profile.clone(), authn, ui).await?;
    profile.save()?;
    Ok(drive)
}

/// [`sign_in`] with a recovery code instead of a security key.
pub async fn sign_in_with_recovery(server_url: &str, username: &str, code: &str) -> Result<Drive> {
    let profile = new_device_profile(server_url, username, None).await?;
    let drive = login_with_recovery(profile.clone(), code).await?;
    profile.save()?;
    Ok(drive)
}

async fn new_device_profile(
    server_url: &str,
    username: &str,
    rp_id: Option<String>,
) -> Result<Profile> {
    let api = Api::new(server_url)?;
    let info = api.info().await?;
    Ok(Profile {
        server_url: server_url.trim_end_matches('/').to_string(),
        server_id: info.server_id,
        username: username.to_string(),
        rp_id: rp_id.unwrap_or_else(|| DEFAULT_RP_ID.to_string()),
    })
}

/// Unlock with the printable recovery code (e.g. after losing every security key).
pub async fn login_with_recovery(profile: Profile, code: &str) -> Result<Drive> {
    let api = Api::new(&profile.server_url)?;
    check_server(&api, &profile).await?;
    let secret = recovery::decode(code)?;
    let amk = api
        .keyslots(&profile.username)
        .await?
        .iter()
        .filter(|s| s.kind == KeyslotKind::Recovery)
        .find_map(|s| s.unlock(&Unlock::Recovery { secret: &secret }).ok())
        .ok_or_else(|| Error::Invalid("recovery code does not match this account".into()))?;
    open_session(api, profile, AccountKeys::new(amk)).await
}

async fn check_server(api: &Api, profile: &Profile) -> Result<()> {
    let info = api.info().await?;
    if info.server_id != profile.server_id {
        return Err(Error::ServerChanged {
            expected: profile.server_id.clone(),
            got: info.server_id,
        });
    }
    Ok(())
}

async fn open_session(mut api: Api, profile: Profile, keys: AccountKeys) -> Result<Drive> {
    let challenge = api.challenge(&profile.username).await?;
    let signature = keys.sign_auth_challenge(&profile.server_id, &profile.username, &challenge);
    let session = api
        .session(&SessionRequest {
            username: profile.username.clone(),
            challenge,
            signature: signature.to_vec(),
        })
        .await?;
    api.set_token(session.token);
    Drive::new(api, profile, keys)
}
