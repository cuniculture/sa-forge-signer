//! File key store: `<key_dir>/<name>.json`, Solana CLI keypair format, 0700 dir and 0600 files.

use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zeroize::Zeroizing;

use crate::config::valid_key_name;

pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    pub fn new(dir: &Path) -> Self {
        Self {
            dir: dir.to_path_buf(),
        }
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        if !valid_key_name(name) {
            bail!("key name {name:?}: use lowercase letters, digits, '-' or '_'");
        }
        Ok(self.dir.join(format!("{name}.json")))
    }

    /// Generates a key; refuses to overwrite. Returns only the pubkey.
    pub fn create(&self, name: &str) -> Result<Address> {
        let path = self.path(name)?;
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        check_private(&self.dir, 0o077)?;
        let keypair = Keypair::new();
        let bytes = Zeroizing::new(keypair.to_bytes());
        let json = Zeroizing::new(serde_json::to_string(&bytes.as_slice())?);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("creating {} (it may already exist)", path.display()))?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(keypair.pubkey())
    }

    /// Zeroes and deletes a key file.
    pub fn destroy(&self, name: &str) -> Result<()> {
        destroy_file(&self.path(name)?)
    }

    pub fn load(&self, name: &str) -> Result<Keypair> {
        let path = self.path(name)?;
        check_private(&self.dir, 0o077)?;
        check_private(&path, 0o077)?;
        let text = Zeroizing::new(
            std::fs::read_to_string(&path).with_context(|| format!("reading key {name:?}"))?,
        );
        let bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
            serde_json::from_str(&text)
                .with_context(|| format!("key {name:?} is not a JSON byte array"))?,
        );
        Keypair::try_from(bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("key {name:?} is not a 64-byte keypair"))
    }
}

/// Overwrites the key file with zeros, then deletes it. Best effort: SSDs and backups may keep copies.
pub fn destroy_file(path: &Path) -> Result<()> {
    let len = usize::try_from(std::fs::metadata(path)?.len())?;
    let mut file = OpenOptions::new().write(true).open(path)?;
    file.write_all(&vec![0_u8; len])?;
    file.sync_all()?;
    drop(file);
    std::fs::remove_file(path).with_context(|| format!("removing {}", path.display()))
}

/// Writes a new random bearer token to `out` (0600, must not exist); returns its sha256 only.
pub fn create_token(out: &Path) -> Result<String> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::fill(bytes.as_mut_slice()).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let token = Zeroizing::new(format!(
        "sfs_{}",
        bs58::encode(bytes.as_slice()).into_string()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .with_context(|| format!("creating {} (it may already exist)", out.display()))?;
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    Ok(crate::serve::token_hash(&token))
}

/// Refuses paths readable or writable by group or others.
fn check_private(path: &Path, forbidden: u32) -> Result<()> {
    let mode = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .permissions()
        .mode();
    if mode & forbidden != 0 {
        bail!(
            "{} has mode {:o}; it must not be accessible to group or others",
            path.display(),
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sa-forge-signer-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn create_load_and_refuse_overwrite() {
        let dir = temp_dir("ks");
        let ks = KeyStore::new(&dir);
        let pubkey = ks.create("alice-session").unwrap();
        assert_eq!(ks.load("alice-session").unwrap().pubkey(), pubkey);
        assert!(ks.create("alice-session").is_err());
        assert!(ks.load("../etc").is_err());
        std::fs::set_permissions(
            dir.join("alice-session.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(ks.load("alice-session").is_err());
        ks.destroy("alice-session").unwrap();
        assert!(!dir.join("alice-session.json").exists());
        assert!(ks.destroy("alice-session").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
