//! Minimal Solana JSON-RPC client: only the calls the signer needs.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde_json::{Value, json};
use solana_address::Address;
use solana_hash::Hash;

#[derive(Debug)]
pub enum RpcError {
    /// The request may or may not have reached the node.
    Transport(String),
    /// The node answered with a JSON-RPC error.
    Node { code: i64, message: String },
    /// The node answered with something unexpected.
    Shape(String),
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "RPC transport error: {e}"),
            Self::Node { code, message, .. } => write!(f, "RPC error {code}: {message}"),
            Self::Shape(e) => write!(f, "unexpected RPC response: {e}"),
        }
    }
}

impl std::error::Error for RpcError {}

type Result<T> = std::result::Result<T, RpcError>;

pub struct Simulation {
    pub err: Option<Value>,
    pub logs: Vec<String>,
    pub units: Option<u64>,
    /// Lamports after simulation for each requested account, in order.
    pub post_lamports: Vec<Option<u64>>,
}

/// What a landed transaction did, from its own metadata.
pub struct TxMeta {
    pub fee: Option<u64>,
    /// The fee payer's (account 0) lamport change from this transaction alone.
    pub payer_change: Option<i64>,
    pub logs: Vec<String>,
}

pub struct Status {
    pub slot: u64,
    pub err: Option<Value>,
    pub confirmation: Option<String>,
}

pub struct Rpc {
    url: String,
    agent: ureq::Agent,
}

const COMMITMENT: &str = "confirmed";

impl Rpc {
    pub fn new(url: &str) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .http_status_as_error(false)
            .build();
        Self {
            url: url.to_owned(),
            agent: ureq::Agent::new_with_config(config),
        }
    }

    fn call(&self, method: &str, params: &Value) -> Result<Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let mut resp = self
            .agent
            .post(&self.url)
            .send_json(&body)
            .map_err(|e| RpcError::Transport(e.to_string()))?;
        let status = resp.status();
        let mut value: Value = resp
            .body_mut()
            .read_json()
            .map_err(|e| RpcError::Transport(format!("HTTP {status}: {e}")))?;
        if let Some(err) = value.get("error") {
            return Err(RpcError::Node {
                code: err.get("code").and_then(Value::as_i64).unwrap_or_default(),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        value
            .get_mut("result")
            .map(Value::take)
            .ok_or_else(|| RpcError::Shape(format!("{method}: no result")))
    }

    pub fn genesis_hash(&self) -> Result<String> {
        str_field(&self.call("getGenesisHash", &json!([]))?, "getGenesisHash")
    }

    /// Returns a fresh blockhash and its last valid block height.
    pub fn latest_blockhash(&self) -> Result<(Hash, u64)> {
        let v = self.call("getLatestBlockhash", &json!([{"commitment": COMMITMENT}]))?;
        let value = v.get("value").unwrap_or(&Value::Null);
        let hash = value
            .get("blockhash")
            .and_then(Value::as_str)
            .and_then(|s| Hash::from_str(s).ok())
            .ok_or_else(|| RpcError::Shape("getLatestBlockhash: blockhash".to_owned()))?;
        let height = u64_field(value.get("lastValidBlockHeight"), "lastValidBlockHeight")?;
        Ok((hash, height))
    }

    pub fn block_height(&self) -> Result<u64> {
        u64_field(
            Some(&self.call("getBlockHeight", &json!([{"commitment": COMMITMENT}]))?),
            "getBlockHeight",
        )
    }

    pub fn balance(&self, address: &Address) -> Result<u64> {
        let v = self.call(
            "getBalance",
            &json!([address.to_string(), {"commitment": COMMITMENT}]),
        )?;
        u64_field(v.get("value"), "getBalance")
    }

    /// Whether each account exists on-chain.
    pub fn accounts_exist(&self, addresses: &[Address]) -> Result<Vec<bool>> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<String> = addresses.iter().map(ToString::to_string).collect();
        let v = self.call("getMultipleAccounts", &json!([keys, {"commitment": COMMITMENT, "encoding": "base64", "dataSlice": {"offset": 0, "length": 0}}]),
        )?;
        let list = v
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| RpcError::Shape("getMultipleAccounts: value".to_owned()))?;
        if list.len() != addresses.len() {
            return Err(RpcError::Shape("getMultipleAccounts: length".to_owned()));
        }
        Ok(list.iter().map(|a| !a.is_null()).collect())
    }

    pub fn fee_for_message(&self, message_b64: &str) -> Result<Option<u64>> {
        let v = self.call(
            "getFeeForMessage",
            &json!([message_b64, {"commitment": COMMITMENT}]),
        )?;
        Ok(v.get("value").and_then(Value::as_u64))
    }

    /// Simulates a base64 transaction. Unsigned transactions need `sig_verify = false`.
    pub fn simulate(
        &self,
        tx_b64: &str,
        sig_verify: bool,
        accounts: &[Address],
    ) -> Result<Simulation> {
        let keys: Vec<String> = accounts.iter().map(ToString::to_string).collect();
        let v = self.call(
            "simulateTransaction",
            &json!([tx_b64, {
                "encoding": "base64",
                "commitment": COMMITMENT,
                "sigVerify": sig_verify,
                "replaceRecentBlockhash": !sig_verify,
                "accounts": {"encoding": "base64", "addresses": keys},
            }]),
        )?;
        let value = v.get("value").unwrap_or(&Value::Null);
        Ok(Simulation {
            err: value.get("err").filter(|e| !e.is_null()).cloned(),
            logs: value
                .get("logs")
                .and_then(Value::as_array)
                .map(|l| {
                    l.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            units: value.get("unitsConsumed").and_then(Value::as_u64),
            post_lamports: value
                .get("accounts")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|x| x.get("lamports").and_then(Value::as_u64))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// Sends a signed base64 transaction without preflight (it was simulated already).
    pub fn send(&self, tx_b64: &str) -> Result<String> {
        let v = self.call(
            "sendTransaction",
            &json!([tx_b64, {"encoding": "base64", "skipPreflight": true, "maxRetries": 0}]),
        )?;
        str_field(&v, "sendTransaction")
    }

    pub fn signature_status(&self, signature: &str) -> Result<Option<Status>> {
        let v = self.call("getSignatureStatuses", &json!([[signature]]))?;
        let Some(s) = v
            .get("value")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
        else {
            return Err(RpcError::Shape("getSignatureStatuses: value".to_owned()));
        };
        if s.is_null() {
            return Ok(None);
        }
        Ok(Some(Status {
            slot: u64_field(s.get("slot"), "slot")?,
            err: s.get("err").filter(|e| !e.is_null()).cloned(),
            confirmation: s
                .get("confirmationStatus")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }))
    }
}

/// The calls the send-and-confirm loop needs; a trait so the loop can be tested without a node.
pub trait Chain {
    fn send(&self, tx_b64: &str) -> Result<String>;
    fn signature_status(&self, signature: &str) -> Result<Option<Status>>;
    fn block_height(&self) -> Result<u64>;
    fn transaction_meta(&self, signature: &str) -> Result<Option<TxMeta>>;
}

impl Chain for Rpc {
    fn send(&self, tx_b64: &str) -> Result<String> {
        Self::send(self, tx_b64)
    }
    fn signature_status(&self, signature: &str) -> Result<Option<Status>> {
        Self::signature_status(self, signature)
    }
    fn block_height(&self) -> Result<u64> {
        Self::block_height(self)
    }
    fn transaction_meta(&self, signature: &str) -> Result<Option<TxMeta>> {
        Self::transaction_meta(self, signature)
    }
}

impl Rpc {
    /// `None` until the node can serve the transaction.
    pub fn transaction_meta(&self, signature: &str) -> Result<Option<TxMeta>> {
        let v = self.call(
            "getTransaction",
            &json!([signature, {
                "encoding": "json",
                "commitment": COMMITMENT,
                "maxSupportedTransactionVersion": 0,
            }]),
        )?;
        Ok(tx_meta(&v))
    }
}

pub fn tx_meta(v: &Value) -> Option<TxMeta> {
    let meta = v.get("meta")?;
    let first = |field: &str| {
        meta.get(field)
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_u64)
    };
    Some(TxMeta {
        fee: meta.get("fee").and_then(Value::as_u64),
        payer_change: first("preBalances")
            .zip(first("postBalances"))
            .and_then(|(pre, post)| delta(pre, post)),
        logs: meta
            .get("logMessages")
            .and_then(Value::as_array)
            .map(|l| {
                l.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

pub fn delta(pre: u64, post: u64) -> Option<i64> {
    i64::try_from(post)
        .ok()?
        .checked_sub(i64::try_from(pre).ok()?)
}

fn str_field(v: &Value, what: &str) -> Result<String> {
    v.as_str()
        .map(str::to_owned)
        .ok_or_else(|| RpcError::Shape(what.to_owned()))
}

fn u64_field(v: Option<&Value>, what: &str) -> Result<u64> {
    v.and_then(Value::as_u64)
        .ok_or_else(|| RpcError::Shape(what.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_uses_this_transactions_own_balances() {
        let v = json!({"meta": {"fee": 5000, "preBalances": [1_000_000, 7], "postBalances": [995_000, 7],
            "logMessages": ["Program log: hi"]}});
        let m = tx_meta(&v).unwrap();
        assert_eq!(m.fee, Some(5000));
        assert_eq!(m.payer_change, Some(-5000));
        assert_eq!(m.logs, vec!["Program log: hi".to_owned()]);
        assert!(tx_meta(&Value::Null).is_none());
    }

    #[test]
    fn balance_delta() {
        assert_eq!(delta(1_000, 900), Some(-100));
        assert_eq!(delta(0, u64::MAX), None);
    }
}
