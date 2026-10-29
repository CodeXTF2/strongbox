//! Sealed channel: end-to-end encryption and authentication of the HTTP API that does not
//! depend on TLS, so a hostile proxy that terminates or forges TLS sees only ciphertext and
//! cannot forge, replay or reorder requests or responses.
//!
//! Both sides share one symmetric `transport_key` per vault member, derived from the member's
//! security-key PRF output (or recovery code) and registered at sign-up. A session is set up
//! with a hello exchange (`confirm` proves the server holds the key); after that every request
//! and response is an XChaCha20-Poly1305 message under a per-direction session key with a
//! strictly increasing counter as nonce. Pure formats and crypto: no I/O.

use crate::{aead, kdf, Error, Key, Result};

pub const SID_LEN: usize = 16;
pub const HELLO_NONCE_LEN: usize = 32;
/// Request body prefix: session id and counter.
pub const REQUEST_HEADER_LEN: usize = SID_LEN + 8;
/// Width of the replay window (parallel transfers reorder messages slightly).
pub const REPLAY_WINDOW: u64 = 1024;

const L_CONFIRM: &str = "strongbox/channel/confirm/v1";
const L_C2S: &str = "strongbox/channel/c2s/v1";
const L_S2C: &str = "strongbox/channel/s2c/v1";
const L_MSG: &str = "strongbox/channel/msg/v1";

/// Proof, in the server's hello reply, that it holds the member's transport key. Only the
/// holder of the key can compute it for this client's fresh nonce.
pub fn confirm_tag(
    transport: &Key,
    client_nonce: &[u8],
    server_nonce: &[u8],
    sid: &[u8],
) -> [u8; 32] {
    *kdf::derive(
        transport.as_bytes(),
        None,
        L_CONFIRM,
        &[client_nonce, server_nonce, sid],
    )
    .as_bytes()
}

/// Constant-time equality for tags.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `(client→server, server→client)` session keys.
pub fn session_keys(
    transport: &Key,
    client_nonce: &[u8],
    server_nonce: &[u8],
    sid: &[u8],
) -> (Key, Key) {
    let parts: [&[u8]; 3] = [client_nonce, server_nonce, sid];
    (
        kdf::derive(transport.as_bytes(), None, L_C2S, &parts),
        kdf::derive(transport.as_bytes(), None, L_S2C, &parts),
    )
}

fn nonce(counter: u64) -> [u8; aead::NONCE_LEN] {
    let mut n = [0u8; aead::NONCE_LEN];
    n[aead::NONCE_LEN - 8..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn message_aad(sid: &[u8], counter: u64) -> Vec<u8> {
    kdf::info(L_MSG, &[sid, &counter.to_be_bytes()])
}

/// Seal one message. The counter must never repeat under one key.
pub fn seal_message(key: &Key, sid: &[u8], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    aead::seal_with_nonce(key, &nonce(counter), &message_aad(sid, counter), plaintext)
}

pub fn open_message(key: &Key, sid: &[u8], counter: u64, ct: &[u8]) -> Result<Vec<u8>> {
    aead::open_with_nonce(key, &nonce(counter), &message_aad(sid, counter), ct)
}

/// [`seal_message`] in place: `buf[start..]` becomes the sealed message (block transfers are
/// megabytes, so the copying versions would hold several copies of each in memory).
pub fn seal_message_in_place(key: &Key, sid: &[u8], counter: u64, buf: &mut Vec<u8>, start: usize) {
    aead::seal_in_place_with_nonce(key, &nonce(counter), &message_aad(sid, counter), buf, start)
}

/// [`open_message`] in place: on success `buf[start..]` is the plaintext.
pub fn open_message_in_place(
    key: &Key,
    sid: &[u8],
    counter: u64,
    buf: &mut Vec<u8>,
    start: usize,
) -> Result<()> {
    aead::open_in_place_with_nonce(key, &nonce(counter), &message_aad(sid, counter), buf, start)
}

/// Sliding window over accepted counters (as in IPsec/DTLS): each counter is accepted once,
/// and counters more than [`REPLAY_WINDOW`] behind the newest are refused. Counters start at 1.
pub struct ReplayWindow {
    top: u64,
    seen: [u64; (REPLAY_WINDOW / 64) as usize],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow {
            top: 0,
            seen: [0; (REPLAY_WINDOW / 64) as usize],
        }
    }
}

impl ReplayWindow {
    fn bit(n: u64) -> (usize, u64) {
        let i = n % REPLAY_WINDOW;
        ((i / 64) as usize, 1u64 << (i % 64))
    }

    /// Whether `n` would be accepted. Does not change the window: callers check, then
    /// authenticate the message, and only then [`accept`](Self::accept), so a forger cannot
    /// burn counters.
    pub fn would_accept(&self, n: u64) -> bool {
        if n == 0 {
            return false;
        }
        if n > self.top {
            return true;
        }
        if self.top - n >= REPLAY_WINDOW {
            return false;
        }
        let (w, m) = Self::bit(n);
        self.seen[w] & m == 0
    }

    /// Record `n`; `false` (and no change) if it is a replay or too old.
    pub fn accept(&mut self, n: u64) -> bool {
        if !self.would_accept(n) {
            return false;
        }
        if n > self.top {
            // Clear the slots the window slides over so stale bits are not mistaken for seen.
            let advance = (n - self.top).min(REPLAY_WINDOW);
            for k in 1..=advance {
                let (w, m) = Self::bit(self.top + k);
                self.seen[w] &= !m;
            }
            self.top = n;
        }
        let (w, m) = Self::bit(n);
        self.seen[w] |= m;
        true
    }
}

// ---------------------------------------------------------------- inner framing

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

const JSON_FLAG: u8 = 0x80;

/// A request as carried inside a sealed message.
#[derive(Debug, PartialEq, Eq)]
pub struct InnerRequest {
    pub method: Method,
    /// The body is JSON (the server sets the content type).
    pub json: bool,
    /// Path and query, e.g. `/v2/slots/3/blocks?start=2&count=4`.
    pub path: String,
    /// Bearer token, empty if none.
    pub token: String,
    pub body: Vec<u8>,
}

/// A request without its body, which follows the head directly (see [`encode_request_head`]).
#[derive(Debug, PartialEq, Eq)]
pub struct RequestHead {
    pub method: Method,
    pub json: bool,
    pub path: String,
    pub token: String,
}

/// Append the framing that precedes a request body to `out`; the body goes right after it.
pub fn encode_request_head(h: &RequestHead, out: &mut Vec<u8>) {
    let code = match h.method {
        Method::Get => 0u8,
        Method::Post => 1,
        Method::Put => 2,
        Method::Delete => 3,
    } | if h.json { JSON_FLAG } else { 0 };
    out.push(code);
    out.extend_from_slice(&(h.path.len() as u16).to_be_bytes());
    out.extend_from_slice(h.path.as_bytes());
    out.extend_from_slice(&(h.token.len() as u16).to_be_bytes());
    out.extend_from_slice(h.token.as_bytes());
}

/// The head of a framed request and the offset of its body in `data`.
pub fn decode_request_head(data: &[u8]) -> Result<(RequestHead, usize)> {
    let bad = || Error::Malformed("channel request");
    let code = *data.first().ok_or_else(bad)?;
    let method = match code & !JSON_FLAG {
        0 => Method::Get,
        1 => Method::Post,
        2 => Method::Put,
        3 => Method::Delete,
        _ => return Err(bad()),
    };
    let mut at = 1;
    let mut field = || -> Result<String> {
        let len =
            u16::from_be_bytes(data.get(at..at + 2).ok_or_else(bad)?.try_into().unwrap()) as usize;
        let s = data.get(at + 2..at + 2 + len).ok_or_else(bad)?;
        let s = String::from_utf8(s.to_vec()).map_err(|_| bad())?;
        at += 2 + len;
        Ok(s)
    };
    let path = field()?;
    let token = field()?;
    let head = RequestHead {
        method,
        json: code & JSON_FLAG != 0,
        path,
        token,
    };
    Ok((head, at))
}

pub fn encode_request(r: &InnerRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + r.path.len() + r.token.len() + r.body.len());
    encode_request_head(
        &RequestHead {
            method: r.method,
            json: r.json,
            path: r.path.clone(),
            token: r.token.clone(),
        },
        &mut out,
    );
    out.extend_from_slice(&r.body);
    out
}

pub fn decode_request(data: &[u8]) -> Result<InnerRequest> {
    let (h, at) = decode_request_head(data)?;
    Ok(InnerRequest {
        method: h.method,
        json: h.json,
        path: h.path,
        token: h.token,
        body: data[at..].to_vec(),
    })
}

pub fn encode_response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + body.len());
    out.extend_from_slice(&status.to_be_bytes());
    out.extend_from_slice(body);
    out
}

pub fn decode_response(data: &[u8]) -> Result<(u16, &[u8])> {
    let status = u16::from_be_bytes(
        data.get(..2)
            .ok_or(Error::Malformed("channel response"))?
            .try_into()
            .unwrap(),
    );
    Ok((status, &data[2..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_bind_key_direction_counter_and_session() {
        let tk = Key::random();
        let (cn, sn, sid) = ([1u8; 32], [2u8; 32], [3u8; SID_LEN]);
        let (c2s, s2c) = session_keys(&tk, &cn, &sn, &sid);
        let ct = seal_message(&c2s, &sid, 7, b"hello");
        assert_eq!(open_message(&c2s, &sid, 7, &ct).unwrap(), b"hello");
        assert!(open_message(&c2s, &sid, 8, &ct).is_err());
        assert!(open_message(&c2s, &[9u8; SID_LEN], 7, &ct).is_err());
        assert!(open_message(&s2c, &sid, 7, &ct).is_err());
        let (other, _) = session_keys(&Key::random(), &cn, &sn, &sid);
        assert!(open_message(&other, &sid, 7, &ct).is_err());
        assert_ne!(
            confirm_tag(&tk, &cn, &sn, &sid),
            confirm_tag(&Key::random(), &cn, &sn, &sid)
        );
        assert_ne!(
            confirm_tag(&tk, &cn, &sn, &sid),
            confirm_tag(&tk, &[5u8; 32], &sn, &sid)
        );
        // In place is the same wire format.
        let mut buf = b"hdr".to_vec();
        buf.extend_from_slice(b"hello");
        seal_message_in_place(&c2s, &sid, 7, &mut buf, 3);
        assert_eq!(&buf[3..], ct);
        assert!(open_message_in_place(&c2s, &sid, 8, &mut buf, 3).is_err());
        open_message_in_place(&c2s, &sid, 7, &mut buf, 3).unwrap();
        assert_eq!(buf, b"hdrhello");
    }

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        assert!(!w.would_accept(0));
        assert!(w.accept(1));
        assert!(!w.accept(1), "replay");
        assert!(w.accept(3));
        assert!(w.accept(2), "late but unseen");
        assert!(!w.accept(2));
        assert!(w.accept(5000));
        assert!(!w.accept(3), "fell out of the window");
        assert!(w.accept(5000 - REPLAY_WINDOW + 1));
        assert!(!w.accept(5000 - REPLAY_WINDOW));
        // Slots reused after the window slides are not mistaken for seen.
        assert!(w.accept(5000 + REPLAY_WINDOW));
        assert!(w.accept(5000 + 1));
        assert!(!w.accept(5000 + 1));
    }

    #[test]
    fn framing_roundtrip() {
        let r = InnerRequest {
            method: Method::Put,
            json: false,
            path: "/v2/slots/1/blocks?start=2".into(),
            token: "tok".into(),
            body: vec![1, 2, 3],
        };
        assert_eq!(decode_request(&encode_request(&r)).unwrap(), r);
        assert!(decode_request(&[]).is_err());
        assert!(decode_request(&[9]).is_err());
        assert!(
            decode_request(&[2, 0, 5, b'a']).is_err(),
            "field longer than the data"
        );
        let (head, at) = decode_request_head(&encode_request(&r)).unwrap();
        assert_eq!(head.path, r.path);
        assert_eq!(&encode_request(&r)[at..], &r.body[..]);
        let enc = encode_response(204, b"x");
        assert_eq!(decode_response(&enc).unwrap(), (204, &b"x"[..]));
    }
}
