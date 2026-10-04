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

use crate::audit::{Audit, Entry, KeyLock};
use crate::checks::{self, Policy, Refusal, refuse as refusal};
use crate::config::{Approval, Config, KeyConfig};
use crate::keystore::KeyStore;
use crate::payload::Payload;
use crate::rpc::{Chain, Rpc, RpcError, Simulation, Status, delta};

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
    /// Sent but not proven landed. This includes a transaction whose blockhash has expired with
    /// no status found: through an RPC that may answer from several nodes, absence is never
    /// proof that it did not land. Reconcile the signature and the on-chain state before retrying.
    Unknown,
}

impl Outcome {
    pub fn exit_code(self) -> ExitCode {
        ExitCode::from(match self {
            Self::Ok | Self::Confirmed => 0,
            Self::Refused => 10,
            Self::SimulationFailed => 11,
            Self::Failed => 12,
            // 13 was `expired`, which the signer no longer reports (see `Unknown`).
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
/// Audit command of the entry written before a transaction is sent.
const SIGN_INTENT: &str = "sign-intent";
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
    // Held until this function returns, after the final audit entry: no other sign with this key,
    // in this process or another, can pass the limit check in between.
    let _lock = if signing {
        Some(KeyLock::acquire(&cfg.state_dir, &key.name)?)
    } else {
        None
    };
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
    if let Err(r) = ata_owners(cfg, rpc, &message, &policy)? {
        return Ok(Err(r));
    }
    passed.push("ata_owners");
    if signing {
        // An early refusal only; the binding check is `within_cap` after the final simulation.
        if let Err(r) = limits(&Audit::new(&cfg.state_dir).entries()?, key, now()) {
            return Ok(Err(r));
        }
        passed.push("limits");
    }
    Ok(Ok((message, blockhash, last_valid)))
}

/// An associated token account created for an owner other than the signing key or its transfer
/// destinations must belong to a game account: an account owned by one of the cluster's built-in
/// game programs (a character, a cargo cache), never one only a key's `extra_programs` owns. Its rent then stays where only game logic can move it, rather than
/// in a wallet the requester could close the account from and reclaim the rent.
fn ata_owners(
    cfg: &Config,
    rpc: &Rpc,
    message: &Message,
    policy: &Policy<'_>,
) -> Result<Result<(), Refusal>> {
    let owners = match checks::ata_owners(message, policy) {
        Ok(o) => o,
        Err(r) => return Ok(Err(r)),
    };
    if owners.is_empty() {
        return Ok(Ok(()));
    }
    let games = cfg.game_programs()?;
    for (who, program) in owners.iter().zip(rpc.account_owners(&owners)?) {
        if !program.is_some_and(|p| games.contains(&p)) {
            return Ok(Err(refusal(
                "ata_owners",
                format!(
                    "a token account would be created for {who}, which is neither this key, one of its transfer destinations, nor an account of a game program"
                ),
            )));
        }
    }
    Ok(Ok(()))
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
    let mut tx = build(message, &signers, blockhash)?;
    let pre = rpc.balance(&key.pubkey)?;
    let mut sim = rpc.simulate(&encode(&tx)?, signing, &[key.pubkey])?;
    // A slow preflight can outlive the blockhash on the simulating node; every key is here, so re-sign once.
    if signing && sim.err.as_ref().and_then(Value::as_str) == Some("BlockhashNotFound") {
        (tx, last_valid, sim) = fresh_simulated(&rpc, payload, &signers, &key.pubkey)?;
    }
    report.compute_units = sim.units;
    // The fee of the transaction actually built, which a blockhash rebuild replaces.
    report.fee = rpc
        .fee_for_message(&b64(&tx.message.serialize()))
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
        match after_approval(&rpc, payload, &signers, &key.pubkey, report)? {
            Ok((fresh, last_valid, r)) => {
                report = r;
                (fresh, last_valid)
            }
            Err(failed) => return Ok((failed, false)),
        }
    } else {
        (tx, last_valid)
    };
    report.checks.push("approval");
    // The cap binds here, under the key lock, against the simulation of the exact transaction
    // about to be sent: what is already spent or reserved plus this transaction's own spend.
    let reserve = match cap_gate(&Audit::new(&cfg.state_dir).entries()?, key, &report, now()) {
        Ok(r) => r,
        Err(r) => return Ok((report.refused(&r), false)),
    };
    report.checks.push("cap");
    // Durable before anything is sent: if this process dies mid-confirmation, the intent (with
    // this transaction's reservation) is what the limits and the operator see.
    Audit::new(&cfg.state_dir).append(Entry {
        ts: now(),
        key: key.name.clone(),
        command: SIGN_INTENT.to_owned(),
        payload_hash: payload.hash.clone(),
        programs: program_ids(payload),
        summary: payload.summary.clone(),
        intent: match mode {
            Mode::Sign { intent } => intent.clone(),
            Mode::Check => None,
        },
        outcome: "pending".to_owned(),
        signature: tx.signatures.first().map(ToString::to_string),
        balance_change: Some(0_i64.saturating_sub_unsigned(reserve)),
        ..Entry::default()
    })?;
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
    // A landed status (confirmed or finalized) ends the wait from either lookup. Nothing proves
    // the opposite: once the finalized height is past last_valid, waiting cannot change the
    // outcome, but an empty status may come from a node other than the one that reported the
    // height, or one with incomplete history. So that ends the wait as `unknown`, never `expired`.
    report.outcome = loop {
        std::thread::sleep(poll);
        polls = polls.saturating_add(1);
        match chain.signature_status(&signature) {
            Ok(Some(st)) if st.landed() => break landed_outcome(&mut report, st),
            Ok(_) => {}
            Err(e) => failures = note_failure(failures, &mut report, &e),
        }
        match chain.finalized_height() {
            Ok(height) if height > last_valid => match chain.signature_status_history(&signature) {
                Ok(Some(st)) if st.landed() => break landed_outcome(&mut report, st),
                Ok(_) => {
                    report.detail = Some(format!(
                        "blockhash expired (finalized height {height} is past {last_valid}) and the RPC reports no landed status; that does not prove it never landed: look up the signature and check the on-chain state before retrying"
                    ));
                    break Outcome::Unknown;
                }
                Err(e) => failures = note_failure(failures, &mut report, &e),
            },
            Ok(_) => {}
            Err(e) => failures = note_failure(failures, &mut report, &e),
        }
        if failures >= MAX_RPC_FAILURES {
            report.detail = Some(format!(
                "{}; look up the signature and check the on-chain state before retrying",
                report.detail.as_deref().unwrap_or("RPC failures")
            ));
            break Outcome::Unknown;
        }
        if started.elapsed() >= deadline {
            report.detail = Some(format!(
                "no proven outcome within {}s; look up the signature and check the on-chain state before retrying",
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
        // Bounded by the same deadline; without metadata the intent's reservation is charged.
        for _ in 0..META_ATTEMPTS {
            if started.elapsed() >= deadline {
                break;
            }
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

/// The two calls a fresh rebuild needs; a trait so the rebuild can be tested without a node.
pub trait Fresh {
    fn balance(&self, address: &solana_address::Address) -> std::result::Result<u64, RpcError>;
    fn fee_for_message(&self, message_b64: &str) -> std::result::Result<Option<u64>, RpcError>;
    fn latest_blockhash(&self) -> std::result::Result<(Hash, u64), RpcError>;
    fn simulate_signed(
        &self,
        tx_b64: &str,
        accounts: &[solana_address::Address],
    ) -> std::result::Result<Simulation, RpcError>;
}

impl Fresh for Rpc {
    fn balance(&self, address: &solana_address::Address) -> std::result::Result<u64, RpcError> {
        Self::balance(self, address)
    }
    fn fee_for_message(&self, message_b64: &str) -> std::result::Result<Option<u64>, RpcError> {
        Self::fee_for_message(self, message_b64)
    }
    fn latest_blockhash(&self) -> std::result::Result<(Hash, u64), RpcError> {
        Self::latest_blockhash(self)
    }
    fn simulate_signed(
        &self,
        tx_b64: &str,
        accounts: &[solana_address::Address],
    ) -> std::result::Result<Simulation, RpcError> {
        self.simulate(tx_b64, true, accounts)
    }
}

/// Approval can outlast a blockhash, so the approved instructions are re-signed with a fresh one
/// and that exact transaction is simulated before it may be sent: it is new bytes. Its own
/// simulated spend and fee replace the earlier ones, so the cap check and the reservation see
/// what is sent. A failure comes back as the report to return (`SimulationFailed`, nothing sent).
fn after_approval(
    chain: &impl Fresh,
    payload: &Payload,
    signers: &[&Keypair],
    payer: &solana_address::Address,
    mut report: Report,
) -> Result<std::result::Result<(Transaction, u64, Report), Report>> {
    let pre = chain.balance(payer)?;
    let (tx, last_valid, sim) = fresh_simulated(chain, payload, signers, payer)?;
    report.compute_units = sim.units;
    report.balance_change = sim
        .post_lamports
        .first()
        .copied()
        .flatten()
        .and_then(|post| delta(pre, post));
    report.fee = chain
        .fee_for_message(&b64(&tx.message.serialize()))
        .ok()
        .flatten();
    if let Some(err) = sim.err {
        report.outcome = Outcome::SimulationFailed;
        report.program_error = program_error(&sim.logs);
        report.detail = Some(format!(
            "after approval: {}",
            report
                .program_error
                .clone()
                .unwrap_or_else(|| err.to_string())
        ));
        report.error = Some(err);
        report.logs = sim.logs;
        return Ok(Err(report));
    }
    Ok(Ok((tx, last_valid, report)))
}

/// Re-signs the payload's instructions with a fresh blockhash and simulates that exact
/// transaction. Returns the transaction, its last valid block height, and its own simulation, so
/// what is sent is always what was simulated.
fn fresh_simulated(
    chain: &impl Fresh,
    payload: &Payload,
    signers: &[&Keypair],
    payer: &solana_address::Address,
) -> Result<(Transaction, u64, Simulation)> {
    let (hash, last_valid) = chain.latest_blockhash()?;
    let message =
        Message::new_with_blockhash(&payload.instructions, Some(&payload.fee_payer), &hash);
    let tx = build(message, signers, hash)?;
    let sim = chain.simulate_signed(&encode(&tx)?, &[*payer])?;
    Ok((tx, last_valid, sim))
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

/// Rate and daily-spend limits from the audit log.
///
/// Every attempt counts toward the rate: final `sign` entries, plus intents that never got one
/// (the process died mid-sign). Spend counts what each sent transaction cost when that is known
/// (confirmed or failed, with metadata). When it is not known (the outcome is unknown, the
/// metadata never arrived, or the process died), the intent's simulated spend is charged as a
/// reservation, and with no simulation figure the whole daily cap is: an unresolved transaction
/// may have landed, so it is never free. Returns the lamports spent or reserved in the last 24 h.
fn limits(entries: &[Entry], key: &KeyConfig, now: u64) -> Result<u64, Refusal> {
    let mine: Vec<&Entry> = entries.iter().filter(|e| e.key == key.name).collect();
    let finals = || mine.iter().filter(|e| e.command == "sign");
    let resolved = |sig: &str| finals().any(|e| e.signature.as_deref() == Some(sig));
    let orphan_intents = || {
        mine.iter().filter(|e| {
            e.command == SIGN_INTENT && e.signature.as_deref().is_none_or(|s| !resolved(s))
        })
    };
    let recent = finals()
        .chain(orphan_intents())
        .filter(|e| e.ts >= now.saturating_sub(MINUTE))
        .count();
    if recent >= usize::try_from(key.rate_limit_per_minute).unwrap_or(usize::MAX) {
        return Err(refusal(
            "limits",
            format!("rate limit: {recent} signs in the last minute"),
        ));
    }
    let cap = key.daily_lamport_cap;
    let reservation = |sig: Option<&str>| -> u64 {
        let intent = mine
            .iter()
            .find(|e| e.command == SIGN_INTENT && sig.is_some() && e.signature.as_deref() == sig);
        match intent.map(|e| e.balance_change) {
            Some(Some(d)) => spend(d),
            _ => cap,
        }
    };
    let day = |e: &&&Entry| e.ts >= now.saturating_sub(DAY);
    let mut spent: u64 = 0;
    for e in finals().filter(day) {
        let cost = match e.outcome.as_str() {
            "confirmed" | "failed" => e
                .balance_change
                .map_or_else(|| reservation(e.signature.as_deref()), spend),
            // `expired` appears only in older logs, from a proof that could be wrong.
            "unknown" | "expired" => reservation(e.signature.as_deref()),
            // Refused or failed simulation: never sent.
            _ => 0,
        };
        spent = spent.saturating_add(cost);
    }
    for e in orphan_intents().filter(day) {
        spent = spent.saturating_add(e.balance_change.map_or(cap, spend));
    }
    if spent >= cap {
        return Err(refusal(
            "limits",
            format!("daily cap: {spent} of {cap} lamports spent or reserved in 24 h"),
        ));
    }
    Ok(spent)
}

/// The final limit check, made under the key lock against the simulation of the exact
/// transaction about to be sent. Returns that transaction's reservation.
fn cap_gate(entries: &[Entry], key: &KeyConfig, report: &Report, now: u64) -> Result<u64, Refusal> {
    let reserve = reservation(report).ok_or_else(|| {
        refusal(
            "limits",
            "the simulation did not report this key's balance, or the RPC gave no fee estimate, so the spend cannot be bounded"
                .to_owned(),
        )
    })?;
    within_cap(limits(entries, key, now)?, reserve, key.daily_lamport_cap)?;
    Ok(reserve)
}

/// This transaction's reservation: its simulated spend plus its fee. Both must be known: the
/// simulated balance usually already includes the fee, so adding it again over-reserves by one
/// fee, but a missing fee is never assumed to be zero.
fn reservation(report: &Report) -> Option<u64> {
    Some(spend(report.balance_change?).saturating_add(report.fee?))
}

/// Refuses a transaction whose reservation would take the 24 h total past the cap.
fn within_cap(spent: u64, reserve: u64, cap: u64) -> Result<(), Refusal> {
    let total = spent.saturating_add(reserve);
    if total > cap {
        return Err(refusal(
            "limits",
            format!(
                "daily cap: {spent} lamports spent or reserved in 24 h, plus {reserve} for this transaction, exceeds {cap}"
            ),
        ));
    }
    Ok(())
}

/// Lamports spent by a balance change (gains spend nothing).
const fn spend(delta: i64) -> u64 {
    if delta < 0 { delta.unsigned_abs() } else { 0 }
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
            allow_unattended: false,
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
            outcome: "confirmed".into(),
            balance_change: Some(change),
            ..Entry::default()
        }
    }

    fn intent(ts: u64, sig: &str, reserved: Option<i64>) -> Entry {
        Entry {
            ts,
            key: "k".into(),
            command: SIGN_INTENT.into(),
            outcome: "pending".into(),
            signature: Some(sig.into()),
            balance_change: reserved,
            ..Entry::default()
        }
    }

    fn sign_final(ts: u64, sig: &str, outcome: &str, change: Option<i64>) -> Entry {
        Entry {
            ts,
            key: "k".into(),
            command: "sign".into(),
            outcome: outcome.into(),
            signature: Some(sig.into()),
            balance_change: change,
            ..Entry::default()
        }
    }

    fn roomy() -> KeyConfig {
        KeyConfig {
            rate_limit_per_minute: 100,
            ..key()
        }
    }

    // Pinchy's review, P1: a spend whose outcome is not known still reserves its simulated cost.
    #[test]
    fn unresolved_spends_are_charged_their_reservation() {
        let k = roomy(); // daily cap 1_000
        // Unknown outcome: the intent's simulated -600 is charged; with another -500 that is over.
        let unknown = [
            intent(10, "a", Some(-600)),
            sign_final(11, "a", "unknown", None),
            entry(12, -500),
        ];
        assert!(limits(&unknown, &k, 100).is_err());
        // Confirmed without metadata: same.
        let no_meta = [
            intent(10, "a", Some(-600)),
            sign_final(11, "a", "confirmed", None),
            entry(12, -500),
        ];
        assert!(limits(&no_meta, &k, 100).is_err());
        // The process died after sending: the orphan intent is charged.
        let orphan = [intent(10, "a", Some(-600)), entry(12, -500)];
        assert!(limits(&orphan, &k, 100).is_err());
        // No simulated figure to reserve: the whole cap is charged.
        let blind = [intent(10, "a", None)];
        assert!(limits(&blind, &k, 100).is_err());
        // `expired` from an older log rested on a proof that could be wrong: charged too.
        let expired = [
            intent(10, "a", Some(-600)),
            sign_final(11, "a", "expired", None),
            entry(12, -500),
        ];
        assert!(limits(&expired, &k, 100).is_err());
        // Never sent: nothing is charged.
        let refused = [sign_final(11, "a", "refused", None), entry(12, -500)];
        assert_eq!(limits(&refused, &k, 100), Ok(500));
        // Known cost replaces the reservation.
        let known = [
            intent(10, "a", Some(-600)),
            sign_final(11, "a", "confirmed", Some(-5)),
            entry(12, -500),
        ];
        assert!(limits(&known, &k, 100).is_ok());
    }

    fn simulated(change: Option<i64>, fee: Option<u64>) -> Report {
        Report {
            balance_change: change,
            fee,
            ..blank()
        }
    }

    // Pinchy's re-review, P1-2: the cap must count the transaction about to be sent.
    #[test]
    fn the_cap_counts_the_transaction_about_to_be_sent() {
        let k = KeyConfig {
            daily_lamport_cap: 50_000_000,
            ..roomy()
        };
        let past = [entry(10, -49_000_000)];
        // Pinchy's example: 49M spent, a 40M spend would end at 89M.
        let r = cap_gate(&past, &k, &simulated(Some(-40_000_000), Some(0)), 100).unwrap_err();
        assert!(r.detail.contains("40000000 for this transaction"), "{r}");
        // Exactly reaching the cap is allowed; one lamport more is not.
        assert_eq!(
            cap_gate(&past, &k, &simulated(Some(-995_000), Some(5_000)), 100),
            Ok(1_000_000)
        );
        assert!(cap_gate(&past, &k, &simulated(Some(-995_001), Some(5_000)), 100).is_err());
        // No simulated balance: the spend cannot be bounded, so nothing is signed.
        assert!(cap_gate(&[], &k, &simulated(None, Some(5_000)), 100).is_err());
        // A gain spends only the fee.
        assert_eq!(
            cap_gate(&[], &k, &simulated(Some(10), Some(5_000)), 100),
            Ok(5_000)
        );
        // Pinchy's re-review of 2f942bf, P2: no fee estimate is not a zero fee.
        assert!(cap_gate(&[], &k, &simulated(Some(-1), None), 100).is_err());
    }

    #[test]
    fn an_orphan_intent_counts_toward_the_rate() {
        let k = key(); // 2 per minute
        assert!(limits(&[intent(100, "a", Some(-1))], &k, 120).is_ok());
        assert!(
            limits(&[intent(100, "a", Some(-1)), entry(110, -1)], &k, 120).is_err(),
            "an attempt whose final entry never arrived is still an attempt"
        );
    }

    // Pinchy's review, P1: concurrent signs with one key must not all pass the limit check.
    #[test]
    fn the_key_lock_serializes_signs_across_threads() {
        use std::sync::mpsc;
        let dir = std::env::temp_dir().join(format!("sa-forge-signer-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let held = KeyLock::acquire(&dir, "k").unwrap();
        let (tx, rx) = mpsc::channel();
        let dir2 = dir.clone();
        let waiter = std::thread::spawn(move || {
            let _second = KeyLock::acquire(&dir2, "k").unwrap();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "a second sign must wait while the first holds the key"
        );
        // A different key is not blocked.
        assert!(KeyLock::acquire(&dir, "other").is_ok());
        drop(held);
        assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok());
        waiter.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
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

    use crate::rpc::{Simulation, Status, TxMeta};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    type R<T> = std::result::Result<T, RpcError>;

    /// A scripted chain: each queue is consumed in order, then the default repeats.
    #[derive(Default)]
    struct Fake {
        statuses: RefCell<VecDeque<R<Option<Status>>>>,
        history: RefCell<VecDeque<R<Option<Status>>>>,
        tips: RefCell<VecDeque<R<u64>>>,
        /// Finalized height repeated once `tips` is empty (default 0, never past `last_valid`).
        steady_tip: Cell<u64>,
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
        fn signature_status_history(&self, _: &str) -> R<Option<Status>> {
            self.history.borrow_mut().pop_front().unwrap_or(Ok(None))
        }
        fn finalized_height(&self) -> R<u64> {
            self.tips
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(self.steady_tip.get()))
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

    // Pinchy's re-review, P1-1: behind a load balancer, node A can report a finalized height past
    // last_valid while node B, with an older root or incomplete history, finds no status for a
    // transaction that landed on A's chain. No pair of answers like that may become `expired`.
    #[test]
    fn an_expired_blockhash_with_no_status_is_unknown_not_expired() {
        let chain = Fake::default();
        chain.tips.borrow_mut().extend([Ok(10), Ok(101)]);
        chain.history.borrow_mut().push_back(Ok(None));
        let started = std::time::Instant::now();
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Unknown);
        assert_eq!(r.outcome.exit_code(), ExitCode::from(14));
        assert!(
            r.detail
                .is_some_and(|d| d.contains("does not prove it never landed"))
        );
        assert_eq!(r.balance_change, None);
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "past last_valid, waiting cannot help: it ends at once"
        );
    }

    #[test]
    fn outcome_confirmed_when_it_lands_in_the_last_valid_block() {
        let chain = Fake::default();
        chain.tips.borrow_mut().push_back(Ok(101));
        chain.history.borrow_mut().push_back(Ok(Some(landed(None))));
        assert_eq!(confirm_with(&chain).outcome, Outcome::Confirmed);
    }

    // Pinchy's review, P1: an RPC error on the final status lookup is not absence.
    #[test]
    fn a_failed_final_lookup_is_not_expiry() {
        let chain = Fake::default();
        chain.steady_tip.set(101);
        for _ in 0..10_000 {
            chain
                .history
                .borrow_mut()
                .push_back(Err(RpcError::Transport("reset".into())));
        }
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Unknown);
        assert!(
            r.detail
                .is_some_and(|d| d.contains("look up the signature"))
        );
    }

    // Pinchy's review, P1: a processed status can still be dropped; it is not "landed".
    #[test]
    fn a_processed_status_is_not_landed() {
        let chain = Fake::default();
        chain.steady_tip.set(101);
        for _ in 0..10_000 {
            chain
                .statuses
                .borrow_mut()
                .push_back(Ok(Some(status("processed", None))));
            chain
                .history
                .borrow_mut()
                .push_back(Ok(Some(status("processed", None))));
        }
        assert_eq!(confirm_with(&chain).outcome, Outcome::Unknown);
    }

    // Pinchy's review, P1: a responsive RPC whose tip never moves must not hold a sign forever.
    #[test]
    fn a_stalled_chain_ends_at_the_deadline() {
        let chain = Fake::default();
        chain.steady_tip.set(10);
        let started = std::time::Instant::now();
        let r = confirm_with(&chain);
        assert_eq!(r.outcome, Outcome::Unknown);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A node for the post-approval rebuild: hands out a fresh blockhash and records exactly
    /// which transaction it was asked to simulate.
    struct Rebuild {
        hash: Hash,
        sim_err: Option<Value>,
        /// The key's balance before, and as simulated after, the rebuilt transaction.
        lamports: (u64, Option<u64>),
        /// The fee the node quotes for the rebuilt message.
        fee: Option<u64>,
        fee_asked: RefCell<Vec<String>>,
        simulated: RefCell<Vec<String>>,
    }

    impl Rebuild {
        fn new(sim_err: Option<Value>, lamports: (u64, Option<u64>)) -> Self {
            Self {
                hash: Hash::new_from_array([5; 32]),
                sim_err,
                lamports,
                fee: Some(5_000),
                fee_asked: RefCell::new(vec![]),
                simulated: RefCell::new(vec![]),
            }
        }
    }

    impl Fresh for Rebuild {
        fn balance(&self, _: &Address) -> R<u64> {
            Ok(self.lamports.0)
        }
        fn fee_for_message(&self, message_b64: &str) -> R<Option<u64>> {
            self.fee_asked.borrow_mut().push(message_b64.to_owned());
            Ok(self.fee)
        }
        fn latest_blockhash(&self) -> R<(Hash, u64)> {
            Ok((self.hash.clone(), 777))
        }
        fn simulate_signed(&self, tx_b64: &str, _: &[Address]) -> R<Simulation> {
            self.simulated.borrow_mut().push(tx_b64.to_owned());
            Ok(Simulation {
                err: self.sim_err.clone(),
                logs: vec!["Program log: Error: would fail".into()],
                units: Some(1),
                post_lamports: vec![self.lamports.1],
            })
        }
    }

    fn approved_payload(payer: &Keypair) -> Payload {
        let text = crate::transfer::fund_payload(
            &payer.pubkey(),
            &Address::new_from_array([2; 32]),
            1,
            "fund",
        )
        .to_string();
        Payload::parse(&text).unwrap()
    }

    // Pinchy's review, P1: the post-approval transaction is new bytes and must itself be simulated.
    #[test]
    fn after_approval_sends_only_the_transaction_it_simulated() {
        let payer = Keypair::new();
        let payload = approved_payload(&payer);
        let node = Rebuild::new(None, (1_000, Some(990)));
        let (tx, last_valid, _) =
            after_approval(&node, &payload, &[&payer], &payer.pubkey(), blank())
                .unwrap()
                .unwrap();
        assert_eq!(last_valid, 777);
        assert_eq!(
            tx.message.recent_blockhash, node.hash,
            "uses the fresh blockhash"
        );
        assert_eq!(
            node.simulated.borrow().as_slice(),
            [encode(&tx).unwrap()],
            "the returned transaction is exactly the one simulated"
        );
    }

    // Pinchy's re-review, P2: the reservation and the cap check use the rebuilt transaction's own
    // simulated spend, not the one shown at approval.
    #[test]
    fn after_approval_replaces_the_simulated_spend() {
        let payer = Keypair::new();
        let payload = approved_payload(&payer);
        // blank() carries an approval-time spend of -1.
        let spent = Rebuild::new(None, (1_000, Some(400)));
        let (tx, _, r) = after_approval(&spent, &payload, &[&payer], &payer.pubkey(), blank())
            .unwrap()
            .unwrap();
        assert_eq!((r.balance_change, r.compute_units), (Some(-600), Some(1)));
        // Pinchy's re-review of 2f942bf, P2: the fee is quoted for the rebuilt message itself.
        assert_eq!(r.fee, Some(5_000));
        assert_eq!(
            spent.fee_asked.borrow().as_slice(),
            [b64(&tx.message.serialize())]
        );
        // No balance in the new simulation: nothing stale is kept, so `cap_gate` refuses.
        let blind = Rebuild::new(None, (1_000, None));
        let (_, _, r) = after_approval(&blind, &payload, &[&payer], &payer.pubkey(), blank())
            .unwrap()
            .unwrap();
        assert_eq!(r.balance_change, None);
        assert!(cap_gate(&[], &roomy(), &r, 100).is_err());
    }

    #[test]
    fn after_approval_refuses_to_send_when_the_new_simulation_fails() {
        let payer = Keypair::new();
        let payload = approved_payload(&payer);
        let node = Rebuild::new(
            Some(serde_json::json!({"InstructionError": [0, {"Custom": 7}]})),
            (1_000, Some(990)),
        );
        let report = after_approval(&node, &payload, &[&payer], &payer.pubkey(), blank())
            .unwrap()
            .unwrap_err();
        assert_eq!(report.outcome, Outcome::SimulationFailed);
        assert!(
            report
                .detail
                .is_some_and(|d| d.starts_with("after approval"))
        );
        assert_eq!(node.simulated.borrow().len(), 1);
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
