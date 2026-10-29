//! Length hiding.
//!
//! File contents are padded with Padmé (Nikitin et al., "Reducing Metadata Leakage from
//! Encrypted Files and Communication with PURBs", PETS 2019): a length L is rounded up so that
//! only O(log log L) bits of it remain, with at most ~12% overhead. Combined with a minimum
//! size this means the server learns only a rough size bucket, never an exact size.

use crate::{Error, Result};

/// Smallest padded content size; everything below looks the same.
pub const MIN_CONTENT_LEN: u64 = 4096;
/// Smallest padded node plaintext.
pub const MIN_NODE_LEN: usize = 512;

pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - len.leading_zeros() as u64; // floor(log2(len))
    let s = 64 - e.leading_zeros() as u64; // floor(log2(e)) + 1
    let last_bits = e - s;
    let mask = (1u64 << last_bits) - 1;
    (len + mask) & !mask
}

/// Padded size for file content of `len` bytes.
pub fn content_len(len: u64) -> u64 {
    padme(len).max(MIN_CONTENT_LEN)
}

/// Frame a message as `u32 length || message || zeros`, padded with Padmé.
pub fn pad_message(msg: &[u8]) -> Vec<u8> {
    let framed = 4 + msg.len();
    let target = (padme(framed as u64) as usize).max(MIN_NODE_LEN);
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out.resize(target, 0);
    out
}

pub fn unpad_message(padded: &[u8]) -> Result<&[u8]> {
    if padded.len() < 4 {
        return Err(Error::Malformed("padded message too short"));
    }
    let len = u32::from_be_bytes(padded[..4].try_into().unwrap()) as usize;
    padded
        .get(4..4 + len)
        .ok_or(Error::Malformed("padded message length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_bounds() {
        for len in [
            2u64,
            3,
            9,
            100,
            1000,
            4097,
            1 << 20,
            (1 << 20) + 1,
            123_456_789,
            10_000_000_000,
        ] {
            let p = padme(len);
            assert!(p >= len);
            // Overhead never exceeds 12.5% for these sizes (bound is 1/2^(s-1) of the size).
            assert!((p - len) as f64 / len as f64 <= 0.125, "{len} -> {p}");
        }
        assert_eq!(padme(1 << 20), 1 << 20);
    }

    #[test]
    fn padme_hides_low_bits() {
        // Many distinct sizes collapse into the same bucket.
        let buckets: std::collections::BTreeSet<u64> = (1_000_000..1_010_000).map(padme).collect();
        assert!(buckets.len() <= 2, "{buckets:?}");
    }

    #[test]
    fn message_roundtrip() {
        for n in [0usize, 1, 100, 508, 509, 5000] {
            let msg = vec![7u8; n];
            let padded = pad_message(&msg);
            assert!(padded.len() >= MIN_NODE_LEN);
            assert_eq!(unpad_message(&padded).unwrap(), &msg[..]);
        }
    }
}
