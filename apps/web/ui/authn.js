// Security keys in the browser: the WebAuthn PRF extension (hmac-secret), the browser's
// counterpart of `crates/fido`. The browser collects the key's PIN in its own dialog; this page
// never sees it. Same semantics as the desktop backends: non-discoverable credentials with
// credProtect level 3 (enforced), user verification required, two PRF inputs per touch.
//
// An authenticator here is { enroll(exclude, first) -> { credentialId, first? },
//                            prf2(allow, first, second) -> { credentialId, first, second } }.

import { sha256, hmac } from "./vendor.js";
import { StrongboxError, cborDecode, randomBytes, concat, utf8, toB64, fromB64 } from "./core.js";
import { DEFAULT_RP_ID, VAULT_USER_NAME } from "./client.js";

const TIMEOUT_MS = 120_000;
const fidoError = (msg) => new StrongboxError(`security key: ${msg}`);
const PRF_UNSUPPORTED = "the security key does not support the PRF / hmac-secret extension";

/**
 * WebAuthn credentials are bound to a relying party id, which a browser only allows for the
 * page's own domain. Pages served from strongbox.app (or a subdomain) use the desktop app's
 * id, so keys work in both; anywhere else the credentials belong to that host.
 */
export function rpIdFor(hostname) {
  return hostname === DEFAULT_RP_ID || hostname.endsWith("." + DEFAULT_RP_ID) ? DEFAULT_RP_ID : hostname;
}

/** Authenticator data is rpIdHash(32) ‖ flags(1) ‖ …; bit 2 is "user verified". */
const hasUv = (authData) => authData.length > 32 && (authData[32] & 0x04) !== 0;

function mapError(e, creating) {
  if (e instanceof StrongboxError) return e;
  switch (e?.name) {
    case "NotAllowedError":
    case "AbortError":
      return fidoError("operation cancelled");
    case "InvalidStateError":
      return fidoError(creating ? "this security key is already registered for this account" : "this security key is not registered for the account");
    case "NotSupportedError":
      return fidoError(creating
        ? "the security key does not support credential protection (credProtect), which Strongbox requires so the key cannot be used without its PIN"
        : PRF_UNSUPPORTED);
    default:
      return fidoError(`platform error: ${e?.message ?? e}`);
  }
}

const bytes = (b) => (b ? new Uint8Array(b instanceof ArrayBuffer ? b : b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)) : null);

export function webAuthenticator(rpId) {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw fidoError("platform error: this browser does not support security keys (WebAuthn); use a current browser over https://");
  }
  return {
    name: "WebAuthn",

    async enroll(exclude) {
      let cred;
      try {
        cred = await navigator.credentials.create({
          publicKey: {
            rp: { id: rpId, name: "Strongbox" },
            user: { id: randomBytes(16), name: VAULT_USER_NAME, displayName: VAULT_USER_NAME },
            challenge: randomBytes(32),
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            timeout: TIMEOUT_MS,
            excludeCredentials: exclude.map((id) => ({ type: "public-key", id })),
            authenticatorSelection: {
              authenticatorAttachment: "cross-platform",
              residentKey: "discouraged",
              requireResidentKey: false,
              userVerification: "required",
            },
            attestation: "none",
            extensions: {
              prf: {},
              // credProtect level 3, required: without it a CTAP 2.0 key would release the PRF
              // output without its PIN.
              credentialProtectionPolicy: "userVerificationRequired",
              enforceCredentialProtectionPolicy: true,
            },
          },
        });
      } catch (e) {
        throw mapError(e, true);
      }
      if (!cred) throw fidoError("operation cancelled");
      const ext = cred.getClientExtensionResults?.() ?? {};
      if (ext.prf && ext.prf.enabled === false) throw fidoError(PRF_UNSUPPORTED);
      let authData = bytes(cred.response.getAuthenticatorData?.());
      if (!authData) authData = cborDecode(new Uint8Array(cred.response.attestationObject)).get("authData");
      if (!(authData instanceof Uint8Array) || !hasUv(authData)) {
        throw fidoError("the security key did not verify the user (PIN); refusing to continue");
      }
      // The PRF output comes from a separate assertion (a second touch), as on the desktop: a
      // value read at creation is trusted by nothing else, so it must never differ.
      return { credentialId: new Uint8Array(cred.rawId), first: null };
    },

    async prf2(allow, first, second) {
      let cred;
      try {
        cred = await navigator.credentials.get({
          publicKey: {
            rpId,
            challenge: randomBytes(32),
            timeout: TIMEOUT_MS,
            allowCredentials: allow.map((id) => ({ type: "public-key", id })),
            userVerification: "required",
            extensions: { prf: { eval: second ? { first, second } : { first } } },
          },
        });
      } catch (e) {
        throw mapError(e, false);
      }
      if (!cred) throw fidoError("operation cancelled");
      if (!hasUv(new Uint8Array(cred.response.authenticatorData))) {
        throw fidoError("the security key did not verify the user (PIN); refusing to continue");
      }
      const results = cred.getClientExtensionResults?.()?.prf?.results;
      const out1 = bytes(results?.first), out2 = bytes(results?.second);
      if (!out1 || out1.length !== 32 || (second && (!out2 || out2.length !== 32))) throw fidoError(PRF_UNSUPPORTED);
      return { credentialId: new Uint8Array(cred.rawId), first: out1, second: second ? out2 : null };
    },
  };
}

// ---------------------------------------------------------------- software key (development only)

/** WebAuthn PRF input → hmac-secret salt. */
const prfSalt = (input) => sha256(concat(utf8("WebAuthn PRF"), new Uint8Array([0]), input));

/**
 * The insecure software authenticator of `crates/fido/src/soft.rs`, with the same state format
 * (b64 credential id → b64 credRandom). `store` is { load() -> object, save(object) }. It
 * offers NO security: development and tests only.
 */
export function softAuthenticator(store) {
  const evalPrf = (credRandom, input) => hmac(sha256, fromB64(credRandom), prfSalt(input));
  const self = {
    name: "software (INSECURE)",
    async enroll(exclude, first) {
      const state = await store.load();
      if (exclude.some((id) => toB64(id) in state)) throw fidoError("this security key is already registered for this account");
      const id = randomBytes(32);
      state[toB64(id)] = toB64(randomBytes(32));
      await store.save(state);
      // Models a key with hmac-secret-mc, like the Rust soft key.
      return { credentialId: id, first: (await self.prf2([id], first, null)).first };
    },
    async prf2(allow, first, second) {
      const state = await store.load();
      for (const id of allow) {
        const r = state[toB64(id)];
        if (r) return { credentialId: id, first: evalPrf(r, first), second: second ? evalPrf(r, second) : null };
      }
      throw fidoError("this security key is not registered for the account");
    },
  };
  return self;
}
