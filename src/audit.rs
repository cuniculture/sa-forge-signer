//! Append-only, hash-chained JSONL audit log, and the per-key signing lock.
//!
//! The signer writes no key material here. `summary` and `intent` are caller-supplied text and
//! are recorded as given: callers must not put secrets in them.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::payload::hex;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Entry {
    pub ts: u64,
    pub key: String,
    pub command: String,
    pub payload_hash: String,
    pub programs: Vec<String>,
    /// Builder-supplied text; not verified.
    pub summary: String,
    pub intent: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
    pub signature: Option<String>,
    pub slot: Option<u64>,
    pub balance_change: Option<i64>,
    pub prev: String,
    pub hash: String,
}

impl Entry {
    fn digest(&self) -> Result<String> {
        let mut unsigned = self.clone();
        unsigned.hash = String::new();
        Ok(hex(&Sha256::digest(serde_json::to_vec(&unsigned)?)))
    }
}

/// An exclusive per-key lock under `state_dir/locks/`, held for a whole sign: from the limit
/// check, through the pre-send intent entry and confirmation, to the final audit entry. It is a
/// file lock, so it serializes signs across `serve` threads and separate CLI processes alike.
pub struct KeyLock {
    file: File,
}

impl KeyLock {
    pub fn acquire(state_dir: &Path, key: &str) -> Result<Self> {
        let dir = state_dir.join("locks");
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(format!("{key}.lock"));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        file.lock()
            .with_context(|| format!("locking {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for KeyLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub struct Audit {
    path: PathBuf,
}

impl Audit {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("audit.jsonl"),
        }
    }

    fn entries_from(file: &File) -> Result<Vec<Entry>> {
        BufReader::new(file)
            .lines()
            .enumerate()
            .map(|(i, line)| {
                let line = line?;
                serde_json::from_str(&line)
                    .with_context(|| format!("audit line {}", i.saturating_add(1)))
            })
            .collect()
    }

    pub fn entries(&self) -> Result<Vec<Entry>> {
        match File::open(&self.path) {
            Ok(f) => Self::entries_from(&f),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    /// Appends under an exclusive file lock, chaining to the last entry.
    pub fn append(&self, mut entry: Entry) -> Result<Entry> {
        if let Some(dir) = self.path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .create(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        file.lock()?;
        let last = Self::entries_from(&file)?.pop();
        entry.prev = last.map_or_else(|| GENESIS.to_owned(), |e| e.hash);
        entry.hash = entry.digest()?;
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        file.unlock()?;
        Ok(entry)
    }

    /// Returns the number of entries, or the first line that breaks the chain.
    pub fn verify(&self) -> Result<std::result::Result<usize, String>> {
        let entries = self.entries()?;
        let mut prev = GENESIS.to_owned();
        for (i, e) in entries.iter().enumerate() {
            let line = i.saturating_add(1);
            if e.prev != prev {
                return Ok(Err(format!(
                    "line {line}: prev does not match the previous entry"
                )));
            }
            if e.digest()? != e.hash {
                return Ok(Err(format!("line {line}: hash does not match its content")));
            }
            prev.clone_from(&e.hash);
        }
        Ok(Ok(entries.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_appends_and_detects_tampering() {
        let dir =
            std::env::temp_dir().join(format!("sa-forge-signer-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let audit = Audit::new(&dir);
        for n in 0..3 {
            audit
                .append(Entry {
                    ts: n,
                    key: "k".into(),
                    outcome: "confirmed".into(),
                    ..Entry::default()
                })
                .unwrap();
        }
        assert_eq!(audit.verify().unwrap(), Ok(3));
        let path = dir.join("audit.jsonl");
        let text = std::fs::read_to_string(&path)
            .unwrap()
            .replacen("\"ts\":1", "\"ts\":9", 1);
        std::fs::write(&path, text).unwrap();
        assert!(audit.verify().unwrap().is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
