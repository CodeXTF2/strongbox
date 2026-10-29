//! File content encryption.
//!
//! A file version gets a fresh random content key. The plaintext is padded to
//! [`padding::content_len`] with zeros and split into fixed-size chunks. Each chunk is encrypted
//! with XChaCha20-Poly1305 under a subkey of the content key, with the chunk index as nonce and
//! in the associated data, so chunks cannot be reordered or swapped between files. The chunk
//! count, true size and a SHA-256 of the plaintext live in the sealed parent directory, which
//! detects truncation and substitution.
//!
//! Chunk blob ids are derived from the content key (HMAC), so they look random to the server
//! but need no storage in the directory entry.

use std::io::{Read, Write};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{aead, kdf, padding, Error, Id, Key, Result};

pub const DEFAULT_CHUNK_SIZE: u32 = 4 * 1024 * 1024;
const CHUNK_AAD: &str = "strongbox/chunk/v1";

/// Everything needed to locate, decrypt and verify one file version. Only stored sealed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRef {
    pub key: Key,
    pub size: u64,
    pub padded_size: u64,
    pub chunk_size: u32,
    #[serde(with = "serde_bytes")]
    pub sha256: Vec<u8>,
}

impl ContentRef {
    pub fn chunk_count(&self) -> u64 {
        chunk_count(self.padded_size, self.chunk_size)
    }

    pub fn chunk_ids(&self) -> Vec<Id> {
        let keys = ContentKeys::new(&self.key);
        (0..self.chunk_count()).map(|i| keys.chunk_id(i)).collect()
    }
}

fn chunk_count(padded_size: u64, chunk_size: u32) -> u64 {
    padded_size.div_ceil(chunk_size as u64)
}

struct ContentKeys {
    enc: Key,
    id: Key,
}

impl ContentKeys {
    fn new(content_key: &Key) -> Self {
        ContentKeys {
            enc: kdf::subkey(content_key, "strongbox/content/enc/v1", &[]),
            id: kdf::subkey(content_key, "strongbox/content/id/v1", &[]),
        }
    }

    fn chunk_id(&self, index: u64) -> Id {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.id.as_bytes()).unwrap();
        mac.update(&index.to_be_bytes());
        let out = mac.finalize().into_bytes();
        Id(out[..16].try_into().unwrap())
    }

    fn nonce(index: u64) -> [u8; aead::NONCE_LEN] {
        let mut n = [0u8; aead::NONCE_LEN];
        n[aead::NONCE_LEN - 8..].copy_from_slice(&index.to_be_bytes());
        n
    }

    fn aad(id: &Id, index: u64) -> Vec<u8> {
        aead::aad(CHUNK_AAD, &[id.as_bytes(), &index.to_be_bytes()])
    }

    fn seal(&self, index: u64, plaintext: &[u8]) -> EncryptedChunk {
        let id = self.chunk_id(index);
        let data = aead::seal_with_nonce(
            &self.enc,
            &Self::nonce(index),
            &Self::aad(&id, index),
            plaintext,
        );
        EncryptedChunk { index, id, data }
    }

    fn open(&self, index: u64, id: &Id, data: &[u8]) -> Result<Vec<u8>> {
        aead::open_with_nonce(&self.enc, &Self::nonce(index), &Self::aad(id, index), data)
    }
}

#[derive(Debug)]
pub struct EncryptedChunk {
    pub index: u64,
    pub id: Id,
    pub data: Vec<u8>,
}

/// Streaming encryptor: yields encrypted chunks from a reader, then the [`ContentRef`] via
/// [`Encryptor::finish`]. Memory use is one chunk.
pub struct Encryptor<R> {
    reader: R,
    content_key: Key,
    keys: ContentKeys,
    chunk_size: u32,
    index: u64,
    size: u64,
    hasher: Sha256,
    eof: bool,
    padded_size: Option<u64>,
    emitted: u64,
}

impl<R: Read> Encryptor<R> {
    pub fn new(reader: R) -> Self {
        Self::with_chunk_size(reader, DEFAULT_CHUNK_SIZE)
    }

    pub fn with_chunk_size(reader: R, chunk_size: u32) -> Self {
        assert!(chunk_size > 0);
        let content_key = Key::random();
        Encryptor {
            reader,
            keys: ContentKeys::new(&content_key),
            content_key,
            chunk_size,
            index: 0,
            size: 0,
            hasher: Sha256::new(),
            eof: false,
            padded_size: None,
            emitted: 0,
        }
    }

    /// Produce the next encrypted chunk, or `None` when the padded stream is exhausted.
    pub fn next_chunk(&mut self) -> Result<Option<EncryptedChunk>> {
        let cs = self.chunk_size as usize;
        let mut buf = Vec::with_capacity(cs);
        while !self.eof && buf.len() < cs {
            let start = buf.len();
            buf.resize(cs, 0);
            let n = self.reader.read(&mut buf[start..])?;
            buf.truncate(start + n);
            if n == 0 {
                self.eof = true;
                self.padded_size = Some(padding::content_len(self.size));
            } else {
                self.size += n as u64;
                self.hasher.update(&buf[start..]);
            }
        }
        if let Some(padded) = self.padded_size {
            let remaining = padded - self.emitted;
            if remaining == 0 {
                return Ok(None);
            }
            let want = remaining.min(cs as u64) as usize;
            buf.resize(want.max(buf.len()), 0);
        }
        self.emitted += buf.len() as u64;
        let chunk = self.keys.seal(self.index, &buf);
        self.index += 1;
        Ok(Some(chunk))
    }

    pub fn finish(self) -> Result<ContentRef> {
        let padded_size = self
            .padded_size
            .ok_or(Error::Malformed("encryptor not drained"))?;
        if self.emitted != padded_size {
            return Err(Error::Malformed("encryptor not drained"));
        }
        Ok(ContentRef {
            key: self.content_key,
            size: self.size,
            padded_size,
            chunk_size: self.chunk_size,
            sha256: self.hasher.finalize().to_vec(),
        })
    }
}

/// Incremental decryptor: feed chunks in index order, writes the true plaintext (padding
/// stripped) and verifies the hash at the end.
pub struct Decryptor<'a, W> {
    content: &'a ContentRef,
    keys: ContentKeys,
    out: W,
    index: u64,
    written: u64,
    hasher: Sha256,
}

impl<'a, W: Write> Decryptor<'a, W> {
    pub fn new(content: &'a ContentRef, out: W) -> Self {
        Decryptor {
            keys: ContentKeys::new(&content.key),
            content,
            out,
            index: 0,
            written: 0,
            hasher: Sha256::new(),
        }
    }

    /// The blob id the next call to [`Decryptor::push`] expects.
    pub fn next_id(&self) -> Option<Id> {
        (self.index < self.content.chunk_count()).then(|| self.keys.chunk_id(self.index))
    }

    pub fn push(&mut self, data: &[u8]) -> Result<()> {
        let id = self.next_id().ok_or(Error::Malformed("too many chunks"))?;
        let pt = self.keys.open(self.index, &id, data)?;
        let expected_len = (self.content.padded_size - self.index * self.content.chunk_size as u64)
            .min(self.content.chunk_size as u64);
        if pt.len() as u64 != expected_len {
            return Err(Error::Integrity);
        }
        let real = (self.content.size - self.written).min(pt.len() as u64) as usize;
        self.hasher.update(&pt[..real]);
        self.out.write_all(&pt[..real])?;
        self.written += real as u64;
        self.index += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        if self.index != self.content.chunk_count() || self.written != self.content.size {
            return Err(Error::Integrity);
        }
        if self.hasher.finalize().as_slice() != self.content.sha256.as_slice() {
            return Err(Error::Integrity);
        }
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(data: &[u8], chunk_size: u32) -> (ContentRef, Vec<EncryptedChunk>) {
        let mut enc = Encryptor::with_chunk_size(data, chunk_size);
        let mut chunks = Vec::new();
        while let Some(c) = enc.next_chunk().unwrap() {
            chunks.push(c);
        }
        let content = enc.finish().unwrap();
        assert_eq!(content.size, data.len() as u64);
        assert_eq!(content.padded_size, padding::content_len(data.len() as u64));
        assert_eq!(chunks.len() as u64, content.chunk_count());
        assert_eq!(
            chunks.iter().map(|c| c.id).collect::<Vec<_>>(),
            content.chunk_ids()
        );

        let mut dec = Decryptor::new(&content, Vec::new());
        for c in &chunks {
            assert_eq!(dec.next_id(), Some(c.id));
            dec.push(&c.data).unwrap();
        }
        assert_eq!(dec.finish().unwrap(), data);
        (content, chunks)
    }

    #[test]
    fn various_sizes() {
        for len in [0usize, 1, 1000, 4096, 4097, 10_000, 65_536, 100_001] {
            let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            roundtrip(&data, 4096);
            roundtrip(&data, 1000);
        }
    }

    #[test]
    fn reorder_and_truncation_detected() {
        let data = vec![1u8; 20_000];
        let (content, chunks) = roundtrip(&data, 4096);
        assert!(chunks.len() > 2);

        let mut dec = Decryptor::new(&content, Vec::new());
        assert!(dec.push(&chunks[1].data).is_err());

        let mut dec = Decryptor::new(&content, Vec::new());
        dec.push(&chunks[0].data).unwrap();
        assert!(dec.finish().is_err());
    }
}
