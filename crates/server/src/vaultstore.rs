//! Storage for deniable vaults: one preallocated file per slot, `blocks × BLOCK_SIZE` bytes.
//!
//! Deniability rules enforced here (docs/deniable-drives.md §8):
//! - every block is filled with CSPRNG output when the vault is created, from a generator
//!   seeded by the OS and dropped afterwards, so nobody can later tell filler from data;
//! - blocks are only ever overwritten in place (no allocation, no growth);
//! - after every write the file's timestamps are reset to a constant, so file metadata does
//!   not reveal which slots were written or when.

use std::fs::{File, FileTimes, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use strongbox_proto::VaultLayout;

/// Constant timestamp for all slot files (2000-01-01T00:00:00Z).
const FIXED_TIME: Duration = Duration::from_secs(946_684_800);

pub struct VaultStore {
    root: PathBuf,
    pub layout: VaultLayout,
}

impl VaultStore {
    pub fn new(root: PathBuf, layout: VaultLayout) -> std::io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(VaultStore { root, layout })
    }

    /// Whether the vault's files are on disk.
    pub fn exists(&self, vault: &str) -> bool {
        self.dir(vault).is_dir()
    }

    fn dir(&self, vault: &str) -> PathBuf {
        self.root.join(vault)
    }

    fn slot_path(&self, vault: &str, slot: u32) -> PathBuf {
        self.dir(vault).join(format!("{slot:03}.bin"))
    }

    fn fix_times(file: &File) -> std::io::Result<()> {
        let t = UNIX_EPOCH + FIXED_TIME;
        file.set_times(FileTimes::new().set_accessed(t).set_modified(t))
    }

    /// Allocate every slot and fill it with random bytes. Slow for big layouts by design
    /// (lazy filling would reveal which blocks were ever touched).
    pub fn create(&self, vault: &str) -> std::io::Result<()> {
        let result = (|| {
            std::fs::create_dir(self.dir(vault))?;
            let mut rng = StdRng::from_entropy();
            let slot_bytes = self.layout.blocks_per_slot as usize * self.layout.block_size as usize;
            let mut buf = vec![0u8; (1 << 20).min(slot_bytes)];
            for slot in 0..self.layout.slots {
                let mut f = File::create(self.slot_path(vault, slot))?;
                let mut left = slot_bytes;
                while left > 0 {
                    let n = left.min(buf.len());
                    rng.fill_bytes(&mut buf[..n]);
                    f.write_all(&buf[..n])?;
                    left -= n;
                }
                f.sync_all()?;
                Self::fix_times(&f)?;
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(self.dir(vault));
        }
        result
    }

    pub fn delete(&self, vault: &str) -> std::io::Result<()> {
        std::fs::remove_dir_all(self.dir(vault))
    }

    fn check(&self, slot: u32, start: u32, count: u32) -> std::io::Result<()> {
        let ok = slot < self.layout.slots
            && count > 0
            && start
                .checked_add(count)
                .is_some_and(|end| end <= self.layout.blocks_per_slot);
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "block range out of bounds",
            ))
        }
    }

    pub fn read(&self, vault: &str, slot: u32, start: u32, count: u32) -> std::io::Result<Vec<u8>> {
        self.check(slot, start, count)?;
        let bs = self.layout.block_size as u64;
        // Write access is needed to reset the timestamps (Windows requires it for that).
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.slot_path(vault, slot))?;
        f.seek(SeekFrom::Start(start as u64 * bs))?;
        let mut out = vec![0u8; (count as u64 * bs) as usize];
        f.read_exact(&mut out)?;
        // Reading updates the access time on some filesystems; undo it.
        Self::fix_times(&f)?;
        Ok(out)
    }

    pub fn write(&self, vault: &str, slot: u32, start: u32, data: &[u8]) -> std::io::Result<()> {
        let bs = self.layout.block_size as usize;
        if data.is_empty() || (data.len() / bs) * bs != data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not whole blocks",
            ));
        }
        self.check(slot, start, (data.len() / bs) as u32)?;
        let mut f = OpenOptions::new()
            .write(true)
            .open(self.slot_path(vault, slot))?;
        f.seek(SeekFrom::Start(start as u64 * bs as u64))?;
        f.write_all(data)?;
        f.sync_data()?;
        Self::fix_times(&f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_read_write_and_times() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = VaultLayout {
            slots: 3,
            blocks_per_slot: 4,
            block_size: 1024,
        };
        let s = VaultStore::new(tmp.path().to_path_buf(), layout).unwrap();
        s.create("v1").unwrap();
        let a = s.read("v1", 0, 0, 4).unwrap();
        assert_eq!(a.len(), 4096);
        assert!(
            a.iter().filter(|&&b| b == 0).count() < 100,
            "filled with random bytes"
        );
        assert_ne!(a, s.read("v1", 1, 0, 4).unwrap());
        s.write("v1", 2, 1, &[7u8; 2048]).unwrap();
        assert_eq!(s.read("v1", 2, 1, 2).unwrap(), vec![7u8; 2048]);
        assert!(s.read("v1", 3, 0, 1).is_err());
        assert!(s.read("v1", 0, 3, 2).is_err());
        assert!(s.write("v1", 0, 0, &[0u8; 100]).is_err());
        for slot in 0..3 {
            let m = std::fs::metadata(s.slot_path("v1", slot))
                .unwrap()
                .modified()
                .unwrap();
            assert_eq!(
                m,
                UNIX_EPOCH + FIXED_TIME,
                "slot {slot} timestamp must not reveal writes"
            );
        }
    }
}
