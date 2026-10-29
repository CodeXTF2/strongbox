//! Types and helpers shared by vault transfers and the apps that drive them.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{Error, Result};

/// Progress callback: `(bytes done, bytes total)`.
pub type Progress<'a> = &'a (dyn Fn(u64, u64) + Send + Sync);

/// What an upload does when the target name is already taken.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnConflict {
    /// Replace an existing file (its old content is deleted).
    #[default]
    Replace,
    /// Keep both, storing the new one as "name (1).ext".
    KeepBoth,
    /// Fail with [`Error::Exists`].
    Fail,
}

#[derive(Clone, Copy, Default)]
pub struct TransferOptions<'a> {
    pub progress: Option<Progress<'a>>,
    /// Checked between chunks; setting it aborts the transfer with [`Error::Cancelled`].
    pub cancel: Option<&'a AtomicBool>,
    pub on_conflict: OnConflict,
}

impl TransferOptions<'_> {
    pub(crate) fn check_cancel(&self) -> Result<()> {
        match self.cancel {
            Some(c) if c.load(Ordering::Relaxed) => Err(Error::Cancelled),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ListEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SearchHit {
    /// Full path of the match.
    pub path: String,
    /// Path of the directory containing it.
    pub parent: String,
    #[serde(flatten)]
    pub entry: ListEntry,
}

/// Make a remote name safe as a local file name on every platform (no path separators,
/// no characters or device names Windows rejects). Remote names come from other devices of
/// the same account, but must never be able to escape the chosen download folder.
pub fn local_safe_name(name: &str) -> String {
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    while s.ends_with('.') || s.ends_with(' ') {
        s.pop();
    }
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if s.is_empty() || reserved {
        s.insert(0, '_');
    }
    s
}

/// Fail if two entries of one remote folder would get the same local name (e.g. `a:b` and
/// `a_b`, or names differing only in case), since the second download would overwrite the first.
pub fn check_local_name_clashes<'a>(names: impl Iterator<Item = &'a String>) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for n in names {
        let local = local_safe_name(n);
        if !seen.insert(local.to_lowercase()) {
            return Err(Error::Invalid(format!(
                "“{n}” would be saved under the same name as another item in its folder (“{local}”), so nothing was downloaded. Rename one of them first"
            )));
        }
    }
    Ok(())
}

/// `path`, or "path (n)" if it already exists locally.
pub fn unique_local_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => name.split_at(i),
        _ => (name.as_str(), ""),
    };
    (1..)
        .map(|n| path.with_file_name(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_local_names() {
        assert_eq!(local_safe_name(r"..\..\evil.txt"), ".._.._evil.txt");
        assert_eq!(local_safe_name("a:b*c?.txt"), "a_b_c_.txt");
        assert_eq!(local_safe_name("con.txt"), "_con.txt");
        assert_eq!(local_safe_name("COM1"), "_COM1");
        assert_eq!(local_safe_name("dots..."), "dots");
        assert_eq!(local_safe_name("..."), "_");
        assert_eq!(local_safe_name("report.pdf"), "report.pdf");
    }

    #[test]
    fn name_clashes() {
        let ok = ["a".to_string(), "b".to_string()];
        assert!(check_local_name_clashes(ok.iter()).is_ok());
        let clash = ["a:b".to_string(), "a_b".to_string()];
        assert!(check_local_name_clashes(clash.iter()).is_err());
    }
}
