//! Local, non-secret client state: which server and account to use, the pinned server id,
//! and the highest node versions seen (for rollback detection). No key material is stored.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use strongbox_core::Id;

use crate::{Error, Result};

pub const DEFAULT_RP_ID: &str = "strongbox.app";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub server_url: String,
    /// Pinned at sign-up; login signatures are bound to it.
    pub server_id: String,
    pub username: String,
    /// WebAuthn relying party id used for this account's credentials.
    pub rp_id: String,
}

fn default_dir() -> PathBuf {
    let base = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    let dir = base.join("strongbox");
    dir
}

/// Where profiles and version caches live. `STRONGBOX_CONFIG_DIR` overrides the OS default.
pub fn config_dir() -> PathBuf {
    std::env::var_os("STRONGBOX_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(default_dir)
}

impl Profile {
    fn path() -> PathBuf {
        config_dir().join("profile.json")
    }

    pub fn load() -> Result<Option<Profile>> {
        match std::fs::read(Self::path()) {
            Ok(b) => {
                Ok(Some(serde_json::from_slice(&b).map_err(|e| {
                    Error::Invalid(format!("profile.json: {e}"))
                })?))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(config_dir())?;
        let tmp = Self::path().with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).unwrap())?;
        std::fs::rename(&tmp, Self::path())?;
        Ok(())
    }

    fn state_dir(&self) -> PathBuf {
        config_dir()
            .join("accounts")
            .join(format!("{}-{}", self.server_id, self.username))
    }

    /// Remove the cached account from this device: the saved profile and this account's
    /// version cache. Files are overwritten with zeros before deletion (best effort; SSDs
    /// and journaling filesystems may keep remnants). Missing files are not an error.
    pub fn forget() -> Result<()> {
        let profile = Self::load().ok().flatten();
        let mut first_err = None;
        if let Some(p) = &profile {
            if let Err(e) = shred_dir(&p.state_dir()) {
                first_err.get_or_insert(e);
            }
        }
        if let Err(e) = shred_file(&Self::path()) {
            first_err.get_or_insert(e);
        }
        // Drop the (now empty) accounts folder too, if nothing else lives there.
        let _ = std::fs::remove_dir(config_dir().join("accounts"));
        match first_err {
            Some(e) => Err(e.into()),
            None => Ok(()),
        }
    }
}

fn shred_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write;
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                let zeros = [0u8; 4096];
                let mut left = m.len();
                while left > 0 {
                    let n = left.min(zeros.len() as u64) as usize;
                    if f.write_all(&zeros[..n]).is_err() {
                        break;
                    }
                    left -= n as u64;
                }
                let _ = f.sync_all();
            }
            std::fs::remove_file(path)
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn shred_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            shred_dir(&p)?;
        } else {
            shred_file(&p)?;
        }
    }
    std::fs::remove_dir(dir)
}

/// Highest version seen per node. A server that serves an older version than one we have
/// already seen is rolling us back, which AEAD alone cannot detect.
pub struct VersionCache {
    path: PathBuf,
    seen: HashMap<Id, u64>,
}

impl VersionCache {
    pub fn open(profile: &Profile) -> Result<Self> {
        let dir = profile.state_dir();
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("versions.json");
        let seen = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => HashMap::new(),
        };
        Ok(VersionCache { path, seen })
    }

    pub fn check(&self, id: &Id, version: u64) -> Result<()> {
        match self.seen.get(id) {
            Some(&seen) if version < seen => Err(Error::Rollback { seen, got: version }),
            _ => Ok(()),
        }
    }

    pub fn seen(&self, id: &Id) -> Option<u64> {
        self.seen.get(id).copied()
    }

    /// Returns true if this raised the recorded version (i.e. the cache needs saving).
    pub fn record(&mut self, id: Id, version: u64) -> bool {
        let v = self.seen.entry(id).or_insert(0);
        let changed = version > *v;
        *v = (*v).max(version);
        changed
    }

    pub fn save(&self) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(&self.seen).unwrap())?;
        std::fs::rename(tmp, &self.path)?;
        Ok(())
    }
}
