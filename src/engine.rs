//! The check and sign pipeline.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use solana_hash::Hash;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zeroize::Zeroizing;

use crate::audit::{Audit, Entry};
use crate::checks::{self, Policy, Refusal, refuse as refusal};
use crate::config::{Approval, Config, KeyConfig};
use crate::keystore::KeyStore;
use crate::payload::Payload;
use crate::rpc::{Chain, Rpc, RpcError, Status, delta};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// `check` only: every check and the simulation passed.
    Ok,
    Refused,
    SimulationFailed,
    Confirmed,
    /// Landed with a program error.
    Failed,
    /// Proven not landed: the finalized block height passed the blockhash's last valid height and
    /// a full-history lookup from a node at least that current found no trace. Safe to rebuild.
    Expired,
    /// Sent but not resolved; check the signature before retrying.
    Unknown,
}

impl Outcome {
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(match self {
            Self::Ok | Self::Confirmed => 0,
            Self::Refused => 10,
            Self::SimulationFailed => 11,
            Self::Failed => 12,
            Self::Expired => 13,
            Self::Unknown => 14,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub outcome: Outcome,
    pub key: Option<String>,
    pub signature: Option<String>,
    pub slot: Option<u64>,
    pub explorer: Option<String>,
    pub detail: Option<String>,
    /// The check that refused the payload.
    pub failed_check: Option<&'static str>,
    /// The program's own error message, from the logs.
    pub program_error: Option<String>,
    pub error: Option<Value>,
    pub checks: Vec<&'static str>,
    pub compute_units: Option<u64>,
    pub fee: Option<u64>,
    pub balance_change: Option<i64>,
    /// Builder-supplied, not verified.
    pub summary: String,
    pub warnings: Vec<String>,
    pub payload_hash: String,
    pub logs: Vec<String>,
}

impl Report {
    fn new(payload: &Payload, key: &KeyConfig) -> Self {
        Self {
            outcome: Outcome::Ok,
            key: Some(key.name.clone()),
            signature: None,
            slot: None,
            explorer: None,
            detail: None,
            failed_check: None,
            program_error: None,
            error: None,
            checks: Vec::new(),
            compute_units: None,
            fee: None,
            balance_change: None,
            summary: payload.summary.clone(),
            warnings: payload.warnings.clone(),
            payload_hash: payload.hash.clone(),
            logs: Vec::new(),
        }
    }

    fn refused(mut self, r: &Refusal) -> Self {
        self.outcome = Outcome::Refused;
        self.detail = Some(r.to_string());
        self.failed_check = Some(r.check);
        self
    }
}

pub enum Mode {
    Check,
    Sign { intent: Option<String> },
}

const MINUTE: u64 = 60;
const DAY: u64 = 86_400;
const POLL: Duration = Duration::from_secs(1);
const MAX_RPC_FAILURES: u32 = 60;
/// Longest a sign waits to prove an outcome. Expiry is proven against the finalized tip, which
/// trails the confirmed one, so this covers a blockhash's ~150-block life plus finalization; a
/// stalled or lagging RPC that never lets either proof complete ends here as `unknown`.
pub const CONFIRM_DEADLINE: Duration = Duration::from_secs(150);
const META_ATTEMPTS: u32 = 10;

pub fn run(cfg: &Config, key_name: Option<&str>, payload_arg: &str, mode: &Mode) -> Result<Report> {
    let text = read_payload(payload_arg)?;
    let (report, sent, secrets) = execute(cfg, key_name, &text, mode, None)?;
    drop(text);
    // Payloads with partial signers hold secrets; remove them once sent.
    if sent && secrets && payload_arg != "-" {
        std::fs::remove_file(payload_arg).with_context(|| format!("removing {payload_arg}"))?;
    }
    Ok(report)
}

/// Checks and, in sign mode, signs payload JSON. `allowed` limits the usable keys (a serve token).
/// Returns the report, whether it was sent, and whether the payload carried partial signers.
pub fn execute(
    cfg: &Config,
    key_name: Option<&str>,
    text: &str,
    mode: &Mode,
    allowed: Option<&[String]>,
) -> Result<(Report, bool, bool)> {
    let payload = Payload::parse(text)?;
    let key = match key_name {
        Some(n) => cfg.key(n)?,
        None => cfg.key_for_pubkey(&payload.fee_payer)?,
    };
    let signing = matches!(mode, Mode::Sign { .. });
    let (report, sent) = if allowed.is_some_and(|keys| !keys.contains(&key.name)) {
        let r = refusal(
            "authorized",
            format!("this token may not use key {:?}", key.name),
        );
        (Report::new(&payload, key).refused(&r), false)
    } else {
        pipeline(cfg, key, &payload, mode)?
    };
    if signing {
        let entry = Entry {
            ts: now(),
            key: key.name.clone(),
            command: "sign".to_owned(),
            payload_hash: payload.hash.clone(),
            programs: program_ids(&payload),
            summary: payload.summary.clone(),
            intent: match mode {
                Mode::Sign { intent } => intent.clone(),
                Mode::Check => None,
            },
            outcome: serde_json::to_value(report.outcome)?
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            detail: report.detail.clone(),
            signature: report.signature.clone(),
            slot: report.slot,
            balance_change: report.balance_change,
            ..Entry::default()
        };
        Audit::new(&cfg.state_dir).append(entry)?;
    }
    Ok((report, sent, !payload.partial_signers.is_empty()))
}

/// Checks that need no key. Returns the compiled message, its blockhash and last valid block height.
fn preflight(
    cfg: &Config,
    rpc: &Rpc,
    key: &KeyConfig,
    payload: &Payload,
    signing: bool,
    passed: &mut Vec<&'static str>,
) -> Result<Result<(Message, Hash, u64), Refusal>> {
    if payload.fee_payer != key.pubkey {
        return Ok(Err(refusal(
            "fee_payer",
            format!(
                "payload fee payer {} is not key {:?} ({})",
                payload.fee_payer, key.name, key.pubkey
            ),
        )));
    }
    if signing && key.approval == Approval::Deny {
        return Ok(Err(refusal(
            "approval",
            format!("key {:?} is set to deny", key.name),
        )));
    }
    let genesis = rpc.genesis_hash()?;
    if genesis != cfg.cluster.genesis_hash {
        return Ok(Err(refusal(
            "chain",
            format!("RPC genesis hash {genesis} is not {}", cfg.cluster.name),
        )));
    }
    passed.push("chain");

    let (blockhash, last_valid) = rpc.latest_blockhash()?;
    let message =
        Message::new_with_blockhash(&payload.instructions, Some(&payload.fee_payer), &blockhash);
    let partial = payload.partial_pubkeys();
    let allowed = cfg.allowed_programs(key)?;
    let policy = Policy {
        signer: &key.pubkey,
        allowed_programs: &allowed,
        transfer_to: &key.transfer_to,
        partial_signers: &partial,
    };
    match checks::structural(&message, &policy) {
        Ok(checks) => passed.extend(checks),
        Err(r) => return Ok(Err(r)),
    }
    if let Some(i) = rpc.accounts_exist(&partial)?.iter().position(|e| *e) {
        let who = partial.get(i).map(ToString::to_string).unwrap_or_default();
        return Ok(Err(refusal(
            "new_accounts",
            format!("partial signer {who} already exists on-chain"),
        )));
    }
    passed.push("new_accounts");
    if signing {
        if let Err(r) = limits(&Audit::new(&cfg.state_dir).entries()?, key, now()) {
            return Ok(Err(r));
        }
        passed.push("limits");
    }
    Ok(Ok((message, blockhash, last_valid)))
}

fn pipeline(
    cfg: &Config,
    key: &KeyConfig,
    payload: &Payload,
    mode: &Mode,
) -> Result<(Report, bool)> {
    let mut report = Report::new(payload, key);
    let signing = matches!(mode, Mode::Sign { .. });
    let rpc = Rpc::new(&cfg.rpc_url);
    let (message, blockhash, mut last_valid) =
        match preflight(cfg, &rpc, key, payload, signing, &mut report.checks)? {
            Ok(v) => v,
            Err(r) => return Ok((report.refused(&r), false)),
        };

    let keypair = if signing {
        Some(load_key(cfg, key)?)
    } else {
        None
    };
    let signers = signers_for(keypair.as_ref(), &payload.partial_signers);
    let mut tx = build(message.clone(), &signers, blockhash)?;
    let pre = rpc.balance(&key.pubkey)?;
    let mut sim = rpc.simulate(&encode(&tx)?, signing, &[key.pubkey])?;
    // A slow preflight can outlive the blockhash on the simulating node; every key is here, so re-sign once.
    if signing && sim.err.as_ref().and_then(Value::as_str) == Some("BlockhashNotFound") {
        let (hash, valid) = rpc.latest_blockhash()?;
        let fresh =
            Message::new_with_blockhash(&payload.instructions, Some(&payload.fee_payer), &hash);
        tx = build(fresh, &signers, hash)?;
        last_valid = valid;
        sim = rpc.simulate(&encode(&tx)?, signing, &[key.pubkey])?;
    }
    report.compute_units = sim.units;
    report.fee = rpc
        .fee_for_message(&b64(&message.serialize()))
        .ok()
        .flatten();
    report.balance_change = sim
        .post_lamports
        .first()
        .copied()
        .flatten()
        .and_then(|post| delta(pre, post));
    if let Some(err) = sim.err {
        report.outcome = Outcome::SimulationFailed;
        report.program_error = program_error(&sim.logs);
        report.detail.clone_from(&report.program_error);
        report.error = Some(err);
        report.logs = sim.logs;
        return Ok((report, false));
    }
    report.checks.push("simulation");
    if !signing {
        report.logs = sim.logs;
        return Ok((report, false));
    }

    let (tx, last_valid) = if key.approval == Approval::Confirm {
        if !confirm(&report, key)? {
            return Ok((
                report.refused(&refusal("approval", "not approved".to_owned())),
                false,
            ));
        }
        // Approval can outlast a blockhash; re-sign the same instructions with a fresh one.
        let (hash, last_valid) = rpc.latest_blockhash()?;
        let message =
            Message::new_with_blockhash(&payload.instructions, Some(&payload.fee_payer), &hash);
        (build(message, &signers, hash)?, last_valid)
    } else {
        (tx, last_valid)
    };
    report.checks.push("approval");
    let explorer = cfg.cluster.explorer_tx;
    send_and_confirm(
        &rpc,
        &tx,
        last_valid,
        report,
        explorer,
        POLL,
        CONFIRM_DEADLINE,
    )
    .map(|r| (r, true))
}

fn send_and_confirm(
    chain: &impl Chain,
    tx: &Transaction,
    last_valid: u64,
    mut report: Report,
    explorer: &str,
    poll: Duration,
    deadline: Duration,
) -> Result<Report> {
    let started = std::time::Instant::now();
    let wire = encode(tx)?;
    let signature = tx
        .signatures
        .first()
        .map(ToString::to_string)
        .context("transaction has no signature")?;
    report.signature = Some(signature.clone());
    report.explorer = Some(format!("{explorer}{signature}"));
    if let Err(e) = chain.send(&wire) {
        report.detail = Some(format!("send: {e}"));
    }
    let mut failures: u32 = 0;
    let mut polls: u32 = 0;
    // A landed status (confirmed or finalized) ends the wait from either lookup. `Expired` needs
    // proof, never mere silence: the finalized height must be past last_valid (no fork can still
    // include the transaction), and a full-history lookup from a node at least as far as that
    // finalized slot must find nothing. An error, a lagging node, or a merely processed status is
    // not proof; the loop keeps waiting and, at the deadline, reports `unknown`.
    report.outcome = loop {
        std::thread::sleep(poll);
        polls = polls.saturating_add(1);
        match chain.signature_status(&signature) {
            Ok(Some(st)) if st.landed() => break landed_outcome(&mut report, st),
            Ok(_) => {}
            Err(e) => failures = note_failure(failures, &mut report, &e),
        }
        match chain.finalized() {
            Ok(tip) if tip.block_height > last_valid => {
                match chain.signature_status_history(&signature) {
                    Ok(h) => match h.status {
                        Some(st) if st.landed() => break landed_outcome(&mut report, st),
                        None if h.context_slot >= tip.slot => break Outcome::Expired,
                        // Processed but unconfirmed, or a node behind the finalized tip.
                        _ => {}
                    },
                    Err(e) => failures = note_failure(failures, &mut report, &e),
                }
            }
            Ok(_) => {}
            Err(e) => failures = note_failure(failures, &mut report, &e),
        }
        if failures >= MAX_RPC_FAILURES {
            break Outcome::Unknown;
        }
        if started.elapsed() >= deadline {
            report.detail = Some(format!(
                "no proven outcome within {}s; look up the signature before retrying",
                deadline.as_secs()
            ));
            break Outcome::Unknown;
        }
        if polls.is_multiple_of(3) {
            let _ = chain.send(&wire);
        }
    };
    report.balance_change = None;
    if matches!(report.outcome, Outcome::Confirmed | Outcome::Failed) {
        // This transaction's own effect; a balance diff would include parallel transactions.
        for _ in 0..META_ATTEMPTS {
            if let Ok(Some(meta)) = chain.transaction_meta(&signature) {
                report.balance_change = meta.payer_change;
                report.fee = meta.fee.or(report.fee);
                if report.outcome == Outcome::Failed {
                    report.program_error = program_error(&meta.logs);
                }
                report.logs = meta.logs;
                break;
            }
            std::thread::sleep(poll);
        }
    }
    Ok(report)
}

fn landed_outcome(report: &mut Report, st: Status) -> Outcome {
    report.slot = Some(st.slot);
    match st.err {
        Some(err) => {
            report.error = Some(err);
            Outcome::Failed
        }
        None => Outcome::Confirmed,
    }
}

fn note_failure(failures: u32, report: &mut Report, e: &RpcError) -> u32 {
    report.detail = Some(e.to_string());
    failures.saturating_add(1)
}

/// Signing uses the key and the payload's partial signers; `check` has no key and simulates unsigned.
fn signers_for<'a>(key: Option<&'a Keypair>, partial: &'a [Keypair]) -> Vec<&'a Keypair> {
    key.map_or_else(Vec::new, |k| std::iter::once(k).chain(partial).collect())
}

fn build(message: Message, signers: &[&Keypair], blockhash: Hash) -> Result<Transaction> {
    let mut tx = Transaction::new_unsigned(message);
    if !signers.is_empty() {
        tx.try_sign(signers, blockhash).context("signing")?;
    }
    Ok(tx)
}

fn load_key(cfg: &Config, key: &KeyConfig) -> Result<Keypair> {
    let kp = KeyStore::new(&cfg.key_dir).load(&key.name)?;
    if kp.pubkey() != key.pubkey {
        bail!(
            "key file for {:?} has pubkey {}, but the config says {}",
            key.name,
            kp.pubkey(),
            key.pubkey
        );
    }
    Ok(kp)
}

/// Asks on the controlling terminal, never on stdin, so an agent piping input cannot approve.
fn confirm(report: &Report, key: &KeyConfig) -> Result<bool> {
    let Ok(mut tty) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
    else {
        return Ok(false);
    };
    let spend = report
        .balance_change
        .map_or_else(|| "unknown".to_owned(), |d| format!("{d} lamports"));
    write!(
        tty,
        "\nsa-forge-signer: approve a signature with {:?} ({:?} key)?\n  summary (from the builder, not verified): {}\n  simulated balance change: {spend}\n  compute units: {}\nType 'yes' to sign: ",
        key.name,
        key.class,
        report.summary,
        report
            .compute_units
            .map_or_else(|| "unknown".to_owned(), |u| u.to_string()),
    )?;
    tty.flush()?;
    let mut answer = String::new();
    BufReader::new(tty).read_line(&mut answer)?;
    Ok(answer.trim() == "yes")
}

fn limits(entries: &[Entry], key: &KeyConfig, now: u64) -> Result<(), Refusal> {
    let mine = || {
        entries
            .iter()
            .filter(|e| e.key == key.name && e.command == "sign")
    };
    let recent = mine()
        .filter(|e| e.ts >= now.saturating_sub(MINUTE))
        .count();
    if recent >= usize::try_from(key.rate_limit_per_minute).unwrap_or(usize::MAX) {
        return Err(refusal(
            "limits",
            format!("rate limit: {recent} signs in the last minute"),
        ));
    }
    let spent = mine()
        .filter(|e| e.ts >= now.saturating_sub(DAY))
        .filter_map(|e| e.balance_change)
        .filter(|d| *d < 0)
        .fold(0_u64, |acc, d| acc.saturating_add(d.unsigned_abs()));
    if spent >= key.daily_lamport_cap {
        return Err(refusal(
            "limits",
            format!(
                "daily cap: {spent} of {} lamports spent in 24 h",
                key.daily_lamport_cap
            ),
        ));
    }
    Ok(())
}

fn read_payload(arg: &str) -> Result<Zeroizing<String>> {
    let mut text = Zeroizing::new(String::new());
    if arg == "-" {
        std::io::stdin()
            .read_to_string(&mut text)
            .context("reading the payload from stdin")?;
    } else {
        let meta = std::fs::symlink_metadata(arg).with_context(|| format!("reading {arg}"))?;
        if !meta.file_type().is_file() {
            bail!("{arg} is not a regular file");
        }
        std::fs::File::open(arg)?.read_to_string(&mut text)?;
    }
    Ok(text)
}

fn program_ids(payload: &Payload) -> Vec<String> {
    let mut ids: Vec<String> = payload
        .instructions
        .iter()
        .map(|i| i.program_id.to_string())
        .collect();
    ids.dedup();
    ids
}

fn encode(tx: &Transaction) -> Result<String> {
    Ok(b64(
        &wincode::serialize(tx).map_err(|e| anyhow::anyhow!("serializing: {e}"))?
    ))
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The program's own message: a logged error, else the runtime's "failed:" line.
fn program_error(logs: &[String]) -> Option<String> {
    logs.iter()
        .find_map(|l| {
            l.strip_prefix("Program log: ")
                .filter(|m| m.contains("Error"))
                .map(str::to_owned)
        })
        .or_else(|| logs.iter().rev().find(|l| l.contains(" failed: ")).cloned())
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KeyClass;
    use solana_address::Address;

    fn key() -> KeyConfig {
        KeyConfig {
            name: "k".into(),
            class: KeyClass::Session,
            pubkey: Address::new_from_array([1; 32]),
            profile: None,
            approval: Approval::Auto,
            transfer_to: vec![],
            extra_programs: vec![],
            rate_limit_per_minute: 2,
            daily_lamport_cap: 1_000,
        }
    }

    fn entry(ts: u64, change: i64) -> Entry {
        Entry {
            ts,
            key: "k".into(),
            command: "sign".into(),
            balance_change: Some(change),
            ..Entry::default()
        }
    }

    #[test]
    fn rate_limit_and_daily_cap() {
        let k = key();
        assert!(limits(&[entry(100, -1)], &k, 120).is_ok());
        assert!(limits(&[entry(100, -1), entry(110, -1)], &k, 120).is_err());
        assert!(limits(&[entry(10, -600), entry(20, -500)], &k, 5_000).is_err());
        assert!(limits(&[entry(10, -600), entry(20, -500)], &k, 10 + DAY + 20).is_ok());
    }

    #[test]
    fn check_builds_unsigned_even_with_partial_signers() {
        let payer = Keypair::new();
        let partial = [Keypair::new()];
        let ix = solana_instruction::Instruction {
            program_id: Address::new_from_array([9; 32]),
            accounts: vec![solana_instruction::AccountMeta::new(
                partial[0].pubkey(),
                true,
            )],
            data: vec![],
        };
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        // The old behaviour: partial signers alone cannot sign a message that needs the fee payer.
        let partial_only: Vec<&Keypair> = partial.iter().collect();
        assert!(build(message.clone(), &partial_only, Hash::default()).is_err());
        // check: no key, so nothing signs.
        assert!(signers_for(None, &partial).is_empty());
        assert!(
            build(
                message.clone(),
                &signers_for(None, &partial),
                Hash::default()
            )
            .is_ok()
        );
        // sign: the key first, then the partial signers.
        let both = signers_for(Some(&payer), &partial);
        assert_eq!(both.len(), 2);
        assert!(build(message, &both, Hash::default()).is_ok());
    }

    #[test]
    fn program_error_prefers_the_logged_message() {
        let logs = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            program_error(&logs(&[
                "Program X invoke [1]",
                "Program log: StarFrameError: Cooldown active",
                "Program X failed: custom program error: 0x51890015",
            ])),
            Some("StarFrameError: Cooldown active".to_owned())
        );
        assert_eq!(
            program_error(&logs(&["Program X failed: custom program error: 0x1"])),
            Some("Program X failed: custom program error: 0x1".to_owned())
        );
        assert_eq!(program_error(&logs(&["Program X success"])), None);
    }

    use crate::rpc::{Finalized, HistoryStatus, Status, TxMeta};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    type R<T> = std::result::Result<T, RpcError>;

    /// A scripted chain: each queue is consumed in order, then the default repeats.
    #[derive(Default)]
    struct Fake {
        statuses: RefCell<VecDeque<R<Option<Status>>>>,
        history: RefCell<VecDeque<R<HistoryStatus>>>,
        tips: RefCell<VecDeque<R<Finalized>>>,
        /// Repeated once `tips` is empty (default: height 0, never past `last_valid`).
        steady_tip: Cell<Option<(u64, u64)>>,
        meta: RefCell<Option<TxMeta>>,
        sends: Cell<u32>,
    }

    impl Chain for Fake {
        fn send(&self, _: &str) -> R<String> {
            self.sends.set(self.sends.get().saturating_add(1));
            Ok("sig".into())
        }
        fn signature_status(&self, _: &str) -> R<Option<Status>> {
            self.statuses.borrow_mut().pop_front().unwrap_or(Ok(None))
        }
        fn signature_status_history(&self, _: &str) -> R<HistoryStatus> {
            self.history
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok(HistoryStatus {
                    context_slot: 0,
                    status: None,
                }))
        }
        fn finalized(&self) -> R<Finalized> {
            self.tips.borrow_mut().pop_front().unwrap_or_else(|| {
                let (slot, block_height) = self.steady_tip.get().unwrap_or((0, 0));
                Ok(Finalized { slot, block_height })
            })
        }
        fn transaction_meta(&self, _: &str) -> R<Option<TxMeta>> {
            Ok(self.meta.borrow_mut().take())
        }
    }

    fn status(confirmation: &str, err: Option<Value>) -> Status {
        Status {
            slot: 42,
            err,
            confirmation: Some(confirmation.into()),
        }
    }

    fn landed(err: Option<Value>) -> Status {
        status("confirmed", err)
    }

    const fn tip(slot: u64, block_height: u64) -> Finalized {
        Finalized { slot, block_height }
    }

    const fn seen(context_slot: u64, status: Option<Status>) -> HistoryStatus {
        HistoryStatus {
            context_slot,
            status,
        }
    }

    fn meta(logs: &[&str]) -> TxMeta {
        TxMeta {
            fee: Some(5000),
            payer_change: Some(-5000),
            logs: logs.iter().map(|l| (*l).to_owned()).collect(),
        }
    }

    fn blank() -> Report {
        Report {
            outcome: Outcome::Ok,
            key: None,
            signature: None,
            slot: None,
            explorer: None,
            detail: None,
            failed_check: None,
            program_error: None,
            error: None,
            checks: vec![],
            compute_units: None,
            fee: None,
            balance_change: Some(-1),
            summary: String::new(),
            warnings: vec![],
            payload_hash: String::new(),
            logs: vec![],
        }
    }

    /// `last_valid` is 100 in every test; the deadline is short so stuck cases end quickly.
    fn confirm_with(chain: &Fake) -> Report {
        let kp = Keypair::new();
        let ix = solana_instruction::Instruction {
            program_id: Address::new_from_array([9; 32]),
            accounts: vec![],
            data: vec![],
        };
        let tx = build(
            Message::new(&[ix], Some(&kp.pubkey())),
            &[&kp],
            Hash::default(),
        )
        .unwrap();
        send_and_confirm(
            chain,
            &tx,
            100,
            blank(),
            "x/",
            Duration::ZERO,
            Duration::from_millis(200),
        )
        .unwrap()
    }

    #[test]
    fn outcome_confirmed_uses_the_transactions_own_meta() {
        let chain = Fake::default();
        chain
            .statuses
            .borrow_mut()
            .extend([Ok(None), Ok(Some(landed(None)))]);
        *chain.meta.borrow_mut() = Some(meta(&["Program log: ok"]));
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Confirmed);
        assert_eq!(
            (r.slot, r.balance_change, r.fee),
            (Some(42), Some(-5000), Some(5000))
        );
        assert!(r.signature.is_some() && r.program_error.is_none());
    }

    #[test]
    fn outcome_failed_on_chain_reports_the_program_error() {
        let chain = Fake::default();
        chain.statuses.borrow_mut().push_back(Ok(Some(landed(Some(
            serde_json::json!({"InstructionError": [0, {"Custom": 1}]}),
        )))));
        *chain.meta.borrow_mut() = Some(meta(&[
            "Program log: AnchorError: nope",
            "Program X failed: custom program error: 0x1",
        ]));
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Failed);
        assert_eq!(r.outcome.exit_code(), ExitCode::from(12));
        assert_eq!(r.program_error.as_deref(), Some("AnchorError: nope"));
        assert!(r.error.is_some());
    }

    #[test]
    fn outcome_expired_only_with_proof_from_a_current_node() {
        let chain = Fake::default();
        chain
            .tips
            .borrow_mut()
            .extend([Ok(tip(500, 10)), Ok(tip(600, 101))]);
        chain.history.borrow_mut().push_back(Ok(seen(600, None)));
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Expired);
        assert_eq!(r.outcome.exit_code(), ExitCode::from(13));
        assert_eq!(r.balance_change, None);
    }

    #[test]
    fn outcome_confirmed_when_it_lands_in_the_last_valid_block() {
        let chain = Fake::default();
        chain.tips.borrow_mut().push_back(Ok(tip(600, 101)));
        chain
            .history
            .borrow_mut()
            .push_back(Ok(seen(600, Some(landed(None)))));
        assert_eq!(confirm_with(&chain).outcome, Outcome::Confirmed);
    }

    // Pinchy's review, P1: a history lookup from a node behind the finalized tip proves nothing.
    #[test]
    fn a_lagging_status_node_never_proves_expiry() {
        let chain = Fake::default();
        chain.steady_tip.set(Some((600, 101)));
        for _ in 0..10_000 {
            chain.history.borrow_mut().push_back(Ok(seen(550, None)));
        }
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Unknown);
        assert!(
            r.detail
                .is_some_and(|d| d.contains("look up the signature"))
        );
    }

    // Pinchy's review, P1: an RPC error on the final status lookup is not absence.
    #[test]
    fn a_failed_final_lookup_is_not_expiry() {
        let chain = Fake::default();
        chain.steady_tip.set(Some((600, 101)));
        for _ in 0..10_000 {
            chain
                .history
                .borrow_mut()
                .push_back(Err(RpcError::Transport("reset".into())));
        }
        assert_eq!(confirm_with(&chain).outcome, Outcome::Unknown);
    }

    // Pinchy's review, P1: a processed status can still be dropped; it is not "landed" on either path.
    #[test]
    fn a_processed_status_is_neither_landed_nor_expired() {
        let chain = Fake::default();
        chain.steady_tip.set(Some((600, 101)));
        for _ in 0..10_000 {
            chain
                .statuses
                .borrow_mut()
                .push_back(Ok(Some(status("processed", None))));
            chain
                .history
                .borrow_mut()
                .push_back(Ok(seen(600, Some(status("processed", None)))));
        }
        assert_eq!(confirm_with(&chain).outcome, Outcome::Unknown);
    }

    // Pinchy's review, P1: a responsive RPC whose tip never moves must not hold a sign forever.
    #[test]
    fn a_stalled_chain_ends_at_the_deadline() {
        let chain = Fake::default();
        chain.steady_tip.set(Some((500, 10)));
        let started = std::time::Instant::now();
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Unknown);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn outcome_unknown_after_persistent_rpc_failures_and_rebroadcasts() {
        let chain = Fake::default();
        let err = || RpcError::Transport("down".into());
        for _ in 0..MAX_RPC_FAILURES {
            chain.statuses.borrow_mut().push_back(Err(err()));
            chain.tips.borrow_mut().push_back(Err(err()));
        }
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Unknown);
        assert_eq!(r.outcome.exit_code(), ExitCode::from(14));
        assert!(chain.sends.get() > 1, "rebroadcasts while waiting");
        assert!(r.detail.is_some_and(|d| d.contains("down")));
    }
}
