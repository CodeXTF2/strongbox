// The only third-party code in the web client: audited @noble libraries (MIT), bundled into
// ui/vendor.js by `npm run build` so the page loads nothing from other hosts.
export { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
export { sha256 } from "@noble/hashes/sha2.js";
export { hmac } from "@noble/hashes/hmac.js";
export { hkdf } from "@noble/hashes/hkdf.js";
export { argon2idAsync } from "@noble/hashes/argon2.js";
export { ed25519 } from "@noble/curves/ed25519.js";
