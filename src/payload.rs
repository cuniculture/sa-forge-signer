//! forge-mcp `build_*` payload (version 1): an instruction list, not a serialized transaction.

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zeroize::Zeroizing;

use crate::config::parse_address;

#[derive(Deserialize)]
struct Raw {
    version: u32,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    warnings: Vec<String>,
    transaction: RawTx,
}

#[derive(Deserialize)]
struct RawTx {
    instructions: Vec<RawIx>,
    fee_payer: String,
}

#[derive(Deserialize)]
struct RawIx {
    program_id: String,
    accounts: Vec<RawMeta>,
    data: Vec<u8>,
}

#[derive(Deserialize)]
struct RawMeta {
    pubkey: String,
    is_signer: bool,
    is_writable: bool,
}

pub struct Payload {
    pub summary: String,
    pub warnings: Vec<String>,
    pub instructions: Vec<Instruction>,
    pub fee_payer: Address,
    /// Ephemeral new-account keypairs. Secrets: never log or serialize.
    pub partial_signers: Vec<Keypair>,
    /// sha256 of the payload JSON without `partial_signers`, for the audit log.
    pub hash: String,
}

impl Payload {
    /// Parses payload JSON. The caller should hold `text` in a `Zeroizing` buffer.
    pub fn parse(text: &str) -> Result<Self> {
        let mut value: serde_json::Value =
            serde_json::from_str(text).context("payload is not valid JSON")?;
        let mut secrets: Vec<Zeroizing<String>> = match value
            .as_object_mut()
            .and_then(|o| o.remove("partial_signers"))
        {
            None | Some(serde_json::Value::Null) => Vec::new(),
            Some(serde_json::Value::Array(items)) => items
                .into_iter()
                .map(|v| match v {
                    serde_json::Value::String(s) => Ok(Zeroizing::new(s)),
                    _ => bail!("partial_signers must be strings"),
                })
                .collect::<Result<_>>()?,
            Some(_) => bail!("partial_signers must be an array"),
        };
        let hash = hex(&Sha256::digest(serde_json::to_vec(&value)?));
        let raw: Raw = serde_json::from_value(value).context("payload has an unexpected shape")?;
        if raw.version != 1 {
            bail!("unsupported payload version {}", raw.version);
        }
        let partial_signers = secrets
            .iter_mut()
            .enumerate()
            .map(|(i, b64)| {
                let bytes = Zeroizing::new(
                    base64::engine::general_purpose::STANDARD
                        .decode(b64.as_bytes())
                        .with_context(|| format!("partial signer {i} is not base64"))?,
                );
                Keypair::try_from(bytes.as_slice())
                    .map_err(|_| anyhow::anyhow!("partial signer {i} is not a 64-byte keypair"))
            })
            .collect::<Result<Vec<_>>>()?;

        let instructions = raw
            .transaction
            .instructions
            .into_iter()
            .map(|ix| {
                Ok(Instruction {
                    program_id: parse_address("program_id", &ix.program_id)?,
                    accounts: ix
                        .accounts
                        .into_iter()
                        .map(|m| {
                            let pubkey = parse_address("account", &m.pubkey)?;
                            Ok(if m.is_writable {
                                AccountMeta::new(pubkey, m.is_signer)
                            } else {
                                AccountMeta::new_readonly(pubkey, m.is_signer)
                            })
                        })
                        .collect::<Result<_>>()?,
                    data: ix.data,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if instructions.is_empty() {
            bail!("payload has no instructions");
        }
        Ok(Self {
            summary: raw.summary,
            warnings: raw.warnings,
            instructions,
            fee_payer: parse_address("fee_payer", &raw.transaction.fee_payer)?,
            partial_signers,
            hash,
        })
    }

    pub fn partial_pubkeys(&self) -> Vec<Address> {
        self.partial_signers.iter().map(Signer::pubkey).collect()
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYER: &str = "7JJhMrnvgqxS6MW59QQcr2Ki1NjZ7SrAjST4YtAFE8zR";

    fn sample(partial: &str) -> String {
        format!(
            r#"{{"version":1,"summary":"s","warnings":[],"game_address":"x",
            "transaction":{{"blockhash":"x","fee_payer":"{PAYER}","signers":["{PAYER}"],
            "instructions":[{{"program_id":"ComputeBudget111111111111111111111111111111","accounts":[],"data":[2,64,66,15,0]}}]}},
            "partial_signers":[{partial}]}}"#
        )
    }

    #[test]
    fn parses_and_hashes_without_secrets() {
        let kp = Keypair::new();
        let b64 = base64::engine::general_purpose::STANDARD.encode(kp.to_bytes());
        let with = Payload::parse(&sample(&format!("\"{b64}\""))).unwrap();
        let without = Payload::parse(&sample("")).unwrap();
        assert_eq!(with.partial_pubkeys(), vec![kp.pubkey()]);
        assert_eq!(with.hash, without.hash);
        assert_eq!(with.instructions.len(), 1);
    }

    #[test]
    fn rejects_bad_payloads() {
        assert!(Payload::parse(&sample("\"bm90LWEta2V5\"")).is_err());
        assert!(Payload::parse(&sample("").replace("\"version\":1", "\"version\":2")).is_err());
    }
}
