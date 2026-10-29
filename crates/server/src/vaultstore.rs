//! Storage for deniable vaults: one preallocated file per slot, `blocks × BLOCK_SIZE` bytes.
//!
//! Deniability rules enforced here (docs/deniable-drives.md §8):
//! - every block is filled with CSPRNG output when the vault is created, from a generator
//!   seeded by the OS and dropped afterwards, so nobody can later tell filler from data;
//! - blocks are only ever overwritten in place (no allocation, no growth);
//! - after every write the file's timestamps are reset to a constant, so file metadata does
//!   not reveal which slots were written or when.
//!
//! Filling a vault means writing its whole size in random bytes, which is slow. A few spare
//! vaults are filled ahead of time in a separate directory and renamed into place at sign-up;
//! a spare is indistinguishable from a vault filled at sign-up (same CSPRNG fill, same fixed
//! timestamps) and holds nothing about anyone until it is taken.

use std::fs::{File, FileTimes, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use strongbox_proto::VaultLayout;

/// Constant timestamp for all slot files (2000-01-01T00:00:00Z).
const FIXED_TIME: Duration = Duration::from_secs(946_684_800);

pub struct VaultStore {
    root: PathBuf,
    /// Pre-filled vaults: `ready-*` are complete, `fill-*` are being filled.
    spares: PathBuf,
    pub layout: VaultLayout,
    /// Serialises taking spares, so two sign-ups never race for the same one.
    take: Mutex<()>,
    /// Signalled when a spare is taken, to wake the task that fills replacements.
    pub spare_taken: tokio::sync::Notify,
}

const SPARE_READY: &str = "ready-";
const SPARE_FILLING: &str = "fill-";

impl VaultStore {
    /// `spares` must be on the same filesystem as `root` (spares are moved in by renaming).
    pub fn new(root: PathBuf, spares: PathBuf, layout: VaultLayout) -> std::io::Result<Self> {
        std::fs::create_dir_all(&root)?;
        std::fs::create_dir_all(&spares)?;
        // A fill interrupted by a restart is incomplete: discard it.
        for e in std::fs::read_dir(&spares)? {
            let e = e?;
            if e.file_name().to_string_lossy().starts_with(SPARE_FILLING) {
                std::fs::remove_dir_all(e.path())?;
            }
        }
        Ok(VaultStore {
            root,
            spares,
            layout,
            take: Mutex::new(()),
            spare_taken: tokio::sync::Notify::new(),
        })
    }

    /// Whether the vault's files are on disk.
    pub fn exists(&self, vault: &str) -> bool {
        self.dir(vault).is_dir()
    }

    fn dir(&self, vault: &str) -> PathBuf {
        self.root.join(vault)
    }

    fn slot_path(&self, vault: &str, slot: u32) -> PathBuf {
        self.dir(vault).join(slot_file(slot))
    }

    fn fix_times(file: &File) -> std::io::Result<()> {
        let t = UNIX_EPOCH + FIXED_TIME;
        file.set_times(FileTimes::new().set_accessed(t).set_modified(t))
    }

    /// Allocate every slot and fill it with random bytes: a spare filled earlier if there is
    /// one, else now. Slow for big layouts by design (lazy filling would reveal which blocks
    /// were ever touched).
    pub fn create(&self, vault: &str) -> std::io::Result<()> {
        if self.take_spare(vault) {
            self.spare_taken.notify_one();
            return Ok(());
        }
        let dir = self.dir(vault);
        std::fs::create_dir(&dir)?;
        self.fill(&dir)
    }

    /// Fill the slot files of an empty, existing directory; on failure remove the directory.
    fn fill(&self, dir: &Path) -> std::io::Result<()> {
        let result = (|| {
            let mut rng = StdRng::from_entropy();
            let slot_bytes = self.layout.blocks_per_slot as usize * self.layout.block_size as usize;
            let mut buf = vec![0u8; (1 << 20).min(slot_bytes)];
            for slot in 0..self.layout.slots {
                let mut f = File::create(dir.join(slot_file(slot)))?;
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
            let _ = std::fs::remove_dir_all(dir);
        }
        result
    }

    /// Move a ready spare into place as `vault`. False if there is none (or it could not be
    /// moved, in which case the caller fills a vault itself).
    fn take_spare(&self, vault: &str) -> bool {
        let _guard = self.take.lock().unwrap();
        let Ok(entries) = std::fs::read_dir(&self.spares) else {
            return false;
        };
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with(SPARE_READY)
                && std::fs::rename(e.path(), self.dir(vault)).is_ok()
            {
                sync_dir(&self.root);
                return true;
            }
        }
        false
    }

    fn ready_spares(&self) -> std::io::Result<usize> {
        Ok(std::fs::read_dir(&self.spares)?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with(SPARE_READY))
            .count())
    }

    /// Fill spares until `want` are ready. Blocking; run from a background task.
    pub fn fill_spares(&self, want: usize) -> std::io::Result<()> {
        while self.ready_spares()? < want {
            let name = strongbox_core::Id::random().to_string();
            let filling = self.spares.join(format!("{SPARE_FILLING}{name}"));
            std::fs::create_dir(&filling)?;
            self.fill(&filling)?;
            std::fs::rename(&filling, self.spares.join(format!("{SPARE_READY}{name}")))?;
            sync_dir(&self.spares);
        }
        Ok(())
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

    /// The first `len` bytes of each of the slot's header blocks, concatenated.
    pub fn read_header_prefixes(
        &self,
        vault: &str,
        slot: u32,
        len: usize,
    ) -> std::io::Result<Vec<u8>> {
        let headers = strongbox_core::vault::HEADER_BLOCKS;
        self.check(slot, 0, headers)?;
        let bs = self.layout.block_size as u64;
        if len as u64 > bs {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "prefix longer than a block",
            ));
        }
        // Write access is needed to reset the timestamps (see `read`).
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.slot_path(vault, slot))?;
        let mut out = vec![0u8; headers as usize * len];
        for (b, chunk) in out.chunks_mut(len).enumerate() {
            f.seek(SeekFrom::Start(b as u64 * bs))?;
            f.read_exact(chunk)?;
        }
        Self::fix_times(&f)?;
        Ok(out)
    }

    /// Overwrite the start of header block `copy` with `data` (a header); the rest of the
    /// block keeps its filler.
    pub fn write_header(
        &self,
        vault: &str,
        slot: u32,
        copy: u32,
        data: &[u8],
    ) -> std::io::Result<()> {
        let bs = self.layout.block_size as usize;
        if copy >= strongbox_core::vault::HEADER_BLOCKS || data.is_empty() || data.len() > bs {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a header",
            ));
        }
        self.check(slot, copy, 1)?;
        let mut f = OpenOptions::new()
            .write(true)
            .open(self.slot_path(vault, slot))?;
        f.seek(SeekFrom::Start(copy as u64 * bs as u64))?;
        f.write_all(data)?;
        f.sync_data()?;
        Self::fix_times(&f)
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

fn slot_file(slot: u32) -> String {
    format!("{slot:03}.bin")
}

/// Make a rename durable (directory entries need their own fsync on Unix).
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
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
        let s = VaultStore::new(tmp.path().join("v"), tmp.path().join("s"), layout).unwrap();
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
        let p = s.read_header_prefixes("v1", 2, 10).unwrap();
        assert_eq!(p[..10], s.read("v1", 2, 0, 1).unwrap()[..10]);
        assert_eq!(p[10..], s.read("v1", 2, 1, 1).unwrap()[..10]);
        assert!(s.read_header_prefixes("v1", 3, 10).is_err());
        assert!(s.read_header_prefixes("v1", 0, 1025).is_err());
        let before = s.read("v1", 1, 1, 1).unwrap();
        s.write_header("v1", 1, 1, &[9u8; 10]).unwrap();
        let after = s.read("v1", 1, 1, 1).unwrap();
        assert_eq!(after[..10], [9u8; 10]);
        assert_eq!(
            after[10..],
            before[10..],
            "the rest of the block is untouched"
        );
        assert!(s.write_header("v1", 1, 2, &[9u8; 10]).is_err());
        assert!(s.write_header("v1", 1, 0, &[9u8; 1025]).is_err());
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

    #[test]
    fn spares_are_moved_into_place() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = VaultLayout {
            slots: 2,
            blocks_per_slot: 2,
            block_size: 1024,
        };
        let spares = tmp.path().join("s");
        // An interrupted fill is discarded on start.
        std::fs::create_dir_all(spares.join("fill-x")).unwrap();
        let s = VaultStore::new(tmp.path().join("v"), spares.clone(), layout).unwrap();
        assert!(!spares.join("fill-x").exists());
        s.fill_spares(2).unwrap();
        assert_eq!(s.ready_spares().unwrap(), 2);
        s.create("a").unwrap();
        assert_eq!(s.ready_spares().unwrap(), 1, "sign-up took a spare");
        assert_eq!(s.read("a", 1, 0, 2).unwrap().len(), 2048);
        s.create("b").unwrap();
        s.create("c").unwrap(); // none left: filled on the spot
        assert_ne!(s.read("b", 0, 0, 2).unwrap(), s.read("c", 0, 0, 2).unwrap());
        assert_ne!(s.read("a", 0, 0, 2).unwrap(), s.read("b", 0, 0, 2).unwrap());
        for v in ["a", "b", "c"] {
            for slot in 0..2 {
                let m = std::fs::metadata(s.slot_path(v, slot))
                    .unwrap()
                    .modified()
                    .unwrap();
                assert_eq!(m, UNIX_EPOCH + FIXED_TIME);
            }
        }
    }
}
