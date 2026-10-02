use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use solana_address::Address;

use crate::cluster::{self, Cluster};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum KeyClass {
    Session,
    Wallet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Approval {
    Auto,
    Confirm,
    Deny,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_cluster")]
    cluster: String,
    rpc_url: Option<String>,
    key_dir: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    #[serde(default)]
    keys: BTreeMap<String, RawKey>,
    serve: Option<RawServe>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServe {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_hosts")]
    allowed_hosts: Vec<String>,
    #[serde(default)]
    tokens: Vec<RawToken>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawToken {
    name: String,
    sha256: String,
    keys: Vec<String>,
}

fn default_listen() -> String {
    "127.0.0.1:8790".to_owned()
}

fn default_hosts() -> Vec<String> {
    vec!["127.0.0.1".to_owned(), "localhost".to_owned()]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    class: KeyClass,
    pubkey: String,
    profile: Option<String>,
    approval: Option<Approval>,
    #[serde(default)]
    transfer_to: Vec<String>,
    #[serde(default)]
    extra_programs: Vec<String>,
    rate_limit_per_minute: Option<u32>,
    daily_lamport_cap: Option<u64>,
    /// Wallet keys only: permit `approval = "auto"` and serve tokens. Off by default; only for a
    /// throwaway testnet key whose grants you do not mind an agent choosing.
    #[serde(default)]
    allow_unattended: bool,
}

fn default_cluster() -> String {
    cluster::ZINK_TESTNET.name.to_owned()
}

pub struct KeyConfig {
    pub name: String,
    pub class: KeyClass,
    pub allow_unattended: bool,
    pub pubkey: Address,
    pub profile: Option<Address>,
    pub approval: Approval,
    pub transfer_to: Vec<Address>,
    pub extra_programs: Vec<Address>,
    pub rate_limit_per_minute: u32,
    pub daily_lamport_cap: u64,
}

pub struct Config {
    pub cluster: &'static Cluster,
    pub rpc_url: String,
    pub key_dir: PathBuf,
    pub state_dir: PathBuf,
    pub keys: Vec<KeyConfig>,
    pub serve: Option<ServeConfig>,
}

pub struct ServeConfig {
    pub listen: String,
    /// Host names accepted in the Host and Origin headers (DNS-rebinding guard).
    pub allowed_hosts: Vec<String>,
    pub tokens: Vec<TokenConfig>,
}

/// A bearer token, stored only as its sha256, and the keys it may sign with.
pub struct TokenConfig {
    pub name: String,
    pub sha256: String,
    pub keys: Vec<String>,
}

/// Defaults sized for burst play loops; 0.05 ZINK per day.
const DEFAULT_RATE_PER_MINUTE: u32 = 30;
const DEFAULT_DAILY_LAMPORT_CAP: u64 = 50_000_000;

pub fn parse_address(field: &str, value: &str) -> Result<Address> {
    Address::from_str(value).map_err(|e| anyhow::anyhow!("{field}: invalid address {value:?}: {e}"))
}

pub fn valid_key_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Default config path: `$SA_FORGE_SIGNER_CONFIG`, else `~/.config/sa-forge-signer/config.toml`.
pub fn default_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("SA_FORGE_SIGNER_CONFIG") {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME").context("HOME is not set; pass --config")?;
    Ok(PathBuf::from(home).join(".config/sa-forge-signer/config.toml"))
}

impl Config {
    /// Loads the config; a missing file yields defaults (enough for `key new`).
    pub fn load(path: &Path, must_exist: bool) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !must_exist => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let raw: RawConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        Self::from_raw(raw, base)
    }

    fn from_raw(raw: RawConfig, base: &Path) -> Result<Self> {
        let Some(cluster) = cluster::by_name(&raw.cluster) else {
            bail!(
                "unknown cluster {:?} (supported: zink-testnet)",
                raw.cluster
            );
        };
        let mut keys = Vec::new();
        for (name, k) in raw.keys {
            if !valid_key_name(&name) {
                bail!("key name {name:?}: use lowercase letters, digits, '-' or '_'");
            }
            let addrs = |field: &str, list: &[String]| -> Result<Vec<Address>> {
                list.iter()
                    .map(|v| parse_address(&format!("keys.{name}.{field}"), v))
                    .collect()
            };
            let approval = k.approval.unwrap_or(match k.class {
                KeyClass::Session => Approval::Auto,
                KeyClass::Wallet => Approval::Confirm,
            });
            // A wallet key is the profile authority: the signer does not decode a Player Profile
            // grant's recipient or permissions, so an automatically approved wallet key would sign
            // whatever grant a requester built. It signs only with a person at the terminal.
            if k.class == KeyClass::Wallet && approval == Approval::Auto && !k.allow_unattended {
                bail!(
                    "keys.{name}: a wallet key cannot use approval = \"auto\"; use \"confirm\" (a person approves each signature at the terminal) or \"deny\", or set allow_unattended = true for a throwaway testnet key"
                );
            }
            keys.push(KeyConfig {
                pubkey: parse_address(&format!("keys.{name}.pubkey"), &k.pubkey)?,
                profile: k
                    .profile
                    .as_deref()
                    .map(|p| parse_address(&format!("keys.{name}.profile"), p))
                    .transpose()?,
                transfer_to: addrs("transfer_to", &k.transfer_to)?,
                extra_programs: addrs("extra_programs", &k.extra_programs)?,
                class: k.class,
                allow_unattended: k.allow_unattended,
                approval,
                rate_limit_per_minute: k.rate_limit_per_minute.unwrap_or(DEFAULT_RATE_PER_MINUTE),
                daily_lamport_cap: k.daily_lamport_cap.unwrap_or(DEFAULT_DAILY_LAMPORT_CAP),
                name,
            });
        }
        let resolve = |p: Option<PathBuf>, default: &str| {
            let p = p.unwrap_or_else(|| PathBuf::from(default));
            if p.is_absolute() { p } else { base.join(p) }
        };
        let serve = raw.serve.map(|s| serve_from_raw(s, &keys)).transpose()?;
        Ok(Self {
            serve,
            cluster,
            rpc_url: raw
                .rpc_url
                .unwrap_or_else(|| cluster.default_rpc.to_owned()),
            key_dir: resolve(raw.key_dir, "keys"),
            state_dir: resolve(raw.state_dir, "state"),
            keys,
        })
    }

    pub fn key(&self, name: &str) -> Result<&KeyConfig> {
        self.keys
            .iter()
            .find(|k| k.name == name)
            .with_context(|| format!("no key {name:?} in the config"))
    }

    pub fn key_for_pubkey(&self, pubkey: &Address) -> Result<&KeyConfig> {
        self.keys
            .iter()
            .find(|k| &k.pubkey == pubkey)
            .with_context(|| {
                format!("no configured key has pubkey {pubkey} (the payload's fee payer)")
            })
    }

    pub fn allowed_programs(&self, key: &KeyConfig) -> Result<Vec<Address>> {
        let mut out = self
            .cluster
            .programs
            .iter()
            .map(|(label, addr)| parse_address(label, addr))
            .collect::<Result<Vec<_>>>()?;
        out.extend(key.extra_programs.iter().copied());
        Ok(out)
    }

    /// The allowed programs that own game state: everything but the System, token and compute
    /// budget programs. An account they own can only be changed by game logic.
    pub fn game_programs(&self, key: &KeyConfig) -> Result<Vec<Address>> {
        let utility = [
            cluster::SYSTEM_PROGRAM,
            cluster::ASSOCIATED_TOKEN_PROGRAM,
            cluster::TOKEN_PROGRAM,
            cluster::TOKEN_2022_PROGRAM,
            cluster::COMPUTE_BUDGET_PROGRAM,
        ]
        .iter()
        .map(|a| parse_address("program", a))
        .collect::<Result<Vec<_>>>()?;
        Ok(self
            .allowed_programs(key)?
            .into_iter()
            .filter(|p| !utility.contains(p))
            .collect())
    }
}

fn serve_from_raw(raw: RawServe, keys: &[KeyConfig]) -> Result<ServeConfig> {
    let mut tokens: Vec<TokenConfig> = Vec::new();
    for t in raw.tokens {
        if !valid_key_name(&t.name) || tokens.iter().any(|o| o.name == t.name) {
            bail!("serve.tokens: invalid or duplicate name {:?}", t.name);
        }
        if t.sha256.len() != 64 || !t.sha256.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
            bail!(
                "serve.tokens.{}: sha256 must be 64 lowercase hex characters",
                t.name
            );
        }
        if let Some(k) = t.keys.iter().find(|k| !keys.iter().any(|c| &c.name == *k)) {
            bail!("serve.tokens.{}: no key {k:?} in the config", t.name);
        }
        // Serve has no terminal: a wallet key on a token could only ever be refused (confirm) or,
        // worse, would put the profile authority behind an agent-reachable token. Use the CLI.
        if let Some(k) = t.keys.iter().find(|k| {
            keys.iter()
                .any(|c| &c.name == *k && c.class == KeyClass::Wallet && !c.allow_unattended)
        }) {
            bail!(
                "serve.tokens.{}: key {k:?} is a wallet key; wallet keys sign only through the CLI with a person at the terminal, unless the key sets allow_unattended = true (throwaway testnet keys only)",
                t.name
            );
        }
        tokens.push(TokenConfig {
            name: t.name,
            sha256: t.sha256,
            keys: t.keys,
        });
    }
    Ok(ServeConfig {
        listen: raw.listen,
        allowed_hosts: raw.allowed_hosts,
        tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "7JJhMrnvgqxS6MW59QQcr2Ki1NjZ7SrAjST4YtAFE8zR";

    fn parse(text: &str) -> Result<Config> {
        Config::from_raw(toml::from_str(text)?, Path::new("/cfg"))
    }

    #[test]
    fn defaults_by_class() {
        let c = parse(&format!(
            "[keys.a]\nclass = \"session\"\npubkey = \"{KEY}\"\n[keys.b]\nclass = \"wallet\"\npubkey = \"{KEY}\"\n"
        ))
        .unwrap();
        assert_eq!(c.key("a").unwrap().approval, Approval::Auto);
        assert_eq!(c.key("b").unwrap().approval, Approval::Confirm);
        assert_eq!(c.key_dir, PathBuf::from("/cfg/keys"));
        assert_eq!(c.rpc_url, "https://rpc1.z.ink");
    }

    // Pinchy's review, P1: the profile authority must never sign unattended or behind a token.
    #[test]
    fn a_wallet_key_cannot_be_auto_approved() {
        let auto =
            format!("[keys.p]\nclass = \"wallet\"\npubkey = \"{KEY}\"\napproval = \"auto\"\n");
        assert!(parse(&auto).is_err());
        let confirm =
            format!("[keys.p]\nclass = \"wallet\"\npubkey = \"{KEY}\"\napproval = \"confirm\"\n");
        assert!(parse(&confirm).is_ok());
        let opted_in = format!(
            "[keys.p]\nclass = \"wallet\"\npubkey = \"{KEY}\"\napproval = \"auto\"\nallow_unattended = true\n"
        );
        assert!(parse(&opted_in).is_ok(), "an explicit opt-in is honoured");
        let session_auto =
            format!("[keys.s]\nclass = \"session\"\npubkey = \"{KEY}\"\napproval = \"auto\"\n");
        assert!(parse(&session_auto).is_ok());
    }

    #[test]
    fn a_serve_token_cannot_reach_a_wallet_key() {
        let hash = "0".repeat(64);
        let with = |key: &str| {
            format!(
                "[keys.p]\nclass = \"wallet\"\npubkey = \"{KEY}\"\n[keys.s]\nclass = \"session\"\npubkey = \"{KEY}\"\n[serve]\n[[serve.tokens]]\nname = \"agent\"\nsha256 = \"{hash}\"\nkeys = [\"{key}\"]\n"
            )
        };
        assert!(
            parse(&with("p")).is_err(),
            "a token must not grant the wallet key"
        );
        assert!(parse(&with("s")).is_ok());
    }

    #[test]
    fn game_programs_exclude_the_utility_programs() {
        let c = parse(&format!(
            "[keys.s]\nclass = \"session\"\npubkey = \"{KEY}\"\n"
        ))
        .unwrap();
        let games: Vec<String> = c
            .game_programs(c.key("s").unwrap())
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            games,
            [
                "C4SAgeKLgb3pTLWhVr6NRwWyYFuTR7ZeSXFrzoLwfMzF",
                "C4PRoFNroxxzdgeCoM31LJjYRg7kT6ymogSTAT99iD1u",
                "C4FACQA1PpNRKrjQ2862ABNR42DTz7EzGj1uhTNFASwP",
            ]
        );
    }

    #[test]
    fn rejects_unknown_cluster_and_fields() {
        assert!(parse("cluster = \"mainnet\"").is_err());
        assert!(parse("rpc = \"x\"").is_err());
        assert!(
            parse(&format!(
                "[keys.Bad]\nclass = \"session\"\npubkey = \"{KEY}\""
            ))
            .is_err()
        );
    }
}
