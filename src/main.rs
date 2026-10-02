//! sa-forge-signer: a thin, self-hosted signer for agents playing SAGE C4 on Z.ink. Unofficial.

mod audit;
mod checks;
mod cluster;
mod config;
mod engine;
mod keystore;
mod payload;
mod rpc;
mod serve;
mod transfer;

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use solana_signer::Signer;

use crate::audit::Audit;
use crate::config::{Config, KeyClass};
use crate::engine::Mode;
use crate::keystore::KeyStore;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Config file [default: `$SA_FORGE_SIGNER_CONFIG`, else `~/.config/sa-forge-signer/config.toml`]
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run every check and simulate; never signs. Prints a JSON report.
    Check {
        /// Configured key to check against [default: the key matching the payload's fee payer]
        #[arg(long)]
        key: Option<String>,
        /// Payload file, or '-' for stdin
        payload: String,
    },
    /// Check, simulate, sign, send and confirm. Prints a JSON report; exit code per outcome.
    Sign {
        /// Configured key to sign with [default: the key matching the payload's fee payer]
        #[arg(long)]
        key: Option<String>,
        /// Why this is being signed, recorded in the audit log
        #[arg(long)]
        intent: Option<String>,
        /// Payload file, or '-' for stdin
        payload: String,
    },
    /// Manage keys in the key store
    #[command(subcommand)]
    Key(KeyCommand),
    /// Read the audit log
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Run the long-running signer: HTTP at /v1/check and /v1/sign, MCP at /mcp (see [serve])
    Serve,
    /// Manage bearer tokens for `serve`
    #[command(subcommand)]
    Token(TokenCommand),
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Create a token: writes it to a new 0600 file and prints only its sha256 and a config snippet
    New {
        name: String,
        /// File to write the token to (must not exist)
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Generate a key; prints only its pubkey and a config snippet
    New {
        name: String,
        #[arg(long, value_enum)]
        class: KeyClass,
    },
    /// Show a configured key's pubkey, class, approval and balance
    Show { name: String },
    /// Build an unsigned payload that funds a configured key with ZINK; sign it with `sign`
    Fund {
        /// The configured key to fund
        name: String,
        /// Amount in ZINK, e.g. 0.05
        #[arg(long)]
        zink: String,
        /// Paying key: a configured key name or a base58 pubkey (its signer must list the key in `transfer_to`)
        #[arg(long)]
        from: String,
        /// Write the payload here (must not exist) instead of stdout
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Zero and delete a key file. Remove the key from the profile first (`build_remove_profile_key`)
    Destroy {
        name: String,
        /// Destroy even though the key still holds ZINK (it is lost)
        #[arg(long)]
        abandon_balance: bool,
    },
}

#[derive(Subcommand)]
enum AuditCommand {
    /// Verify the hash chain
    Verify,
    /// Show the most recent entries as JSON lines
    Tail {
        #[arg(short, default_value_t = 10)]
        n: usize,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let path = match cli.config {
        Some(p) => p,
        None => config::default_path()?,
    };
    match cli.command {
        Command::Check { key, payload } => {
            let cfg = Config::load(&path, true)?;
            report(&engine::run(&cfg, key.as_deref(), &payload, &Mode::Check)?)
        }
        Command::Sign {
            key,
            intent,
            payload,
        } => {
            let cfg = Config::load(&path, true)?;
            report(&engine::run(
                &cfg,
                key.as_deref(),
                &payload,
                &Mode::Sign { intent },
            )?)
        }
        Command::Key(cmd) => key_command(&path, cmd),
        Command::Serve => serve::run(Config::load(&path, true)?).map(|()| ExitCode::SUCCESS),
        Command::Token(TokenCommand::New { name, out }) => {
            let hash = keystore::create_token(&out)?;
            println!("{hash}");
            eprintln!(
                "\nToken written to {}. Add to {}, listing the keys it may use:\n\n[[serve.tokens]]\nname = \"{name}\"\nsha256 = \"{hash}\"\nkeys = []",
                out.display(),
                path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Audit(cmd) => {
            let cfg = Config::load(&path, true)?;
            let audit = Audit::new(&cfg.state_dir);
            match cmd {
                AuditCommand::Verify => match audit.verify()? {
                    Ok(n) => {
                        println!("ok: {n} entries");
                        Ok(ExitCode::SUCCESS)
                    }
                    Err(e) => {
                        println!("broken: {e}");
                        Ok(ExitCode::FAILURE)
                    }
                },
                AuditCommand::Tail { n } => {
                    let entries = audit.entries()?;
                    for e in entries.iter().skip(entries.len().saturating_sub(n)) {
                        println!("{}", serde_json::to_string(e)?);
                    }
                    Ok(ExitCode::SUCCESS)
                }
            }
        }
    }
}

fn key_command(path: &std::path::Path, cmd: KeyCommand) -> Result<ExitCode> {
    match cmd {
        KeyCommand::New { name, class } => {
            let cfg = Config::load(path, false)?;
            let pubkey = KeyStore::new(&cfg.key_dir).create(&name)?;
            let class = match class {
                KeyClass::Session => "session",
                KeyClass::Wallet => "wallet",
            };
            println!("{pubkey}");
            eprintln!(
                "\nAdd to {}:\n\n[keys.{name}]\nclass = \"{class}\"\npubkey = \"{pubkey}\"",
                path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        KeyCommand::Fund {
            name,
            zink,
            from,
            out,
        } => {
            let cfg = Config::load(path, true)?;
            let to = cfg.key(&name)?.pubkey;
            let payer = match cfg.key(&from) {
                Ok(k) => k.pubkey,
                Err(_) => config::parse_address("--from", &from)?,
            };
            let lamports = transfer::parse_zink(&zink)?;
            let summary = format!("Fund key {name} ({to}) with {zink} ZINK from {payer}");
            let text = serde_json::to_string_pretty(&transfer::fund_payload(
                &payer, &to, lamports, &summary,
            ))?;
            match out {
                Some(p) => {
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&p)
                        .with_context(|| {
                            format!("creating {} (it may already exist)", p.display())
                        })?;
                    std::io::Write::write_all(&mut f, text.as_bytes())?;
                    eprintln!("{summary}\nwrote {}", p.display());
                }
                None => println!("{text}"),
            }
            Ok(ExitCode::SUCCESS)
        }
        KeyCommand::Destroy {
            name,
            abandon_balance,
        } => {
            let cfg = Config::load(path, true)?;
            let key = cfg.key(&name)?;
            let balance = rpc::Rpc::new(&cfg.rpc_url)
                .balance(&key.pubkey)
                .with_context(|| format!("reading the balance of {}", key.pubkey))?;
            if balance > 0 && !abandon_balance {
                bail!(
                    "{name} ({}) still holds {balance} lamports; move them out first, or pass --abandon-balance",
                    key.pubkey
                );
            }
            KeyStore::new(&cfg.key_dir).destroy(&name)?;
            eprintln!(
                "destroyed the key file for {name} ({}). Also remove it from the profile (build_remove_profile_key) \
                 and delete [keys.{name}] from {}.",
                key.pubkey,
                path.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        KeyCommand::Show { name } => {
            let cfg = Config::load(path, true)?;
            let key = cfg.key(&name)?;
            let file = match KeyStore::new(&cfg.key_dir).load(&name) {
                Ok(kp) if kp.pubkey() == key.pubkey => "ok".to_owned(),
                Ok(kp) => format!("MISMATCH: file holds {}", kp.pubkey()),
                Err(e) => format!("unavailable: {e:#}"),
            };
            let balance = rpc::Rpc::new(&cfg.rpc_url)
                .balance(&key.pubkey)
                .map_or_else(|e| format!("unavailable: {e}"), |l| format!("{l} lamports"));
            println!(
                "name:     {}\npubkey:   {}\nclass:    {:?}\napproval: {:?}\nprofile:  {}\nkey file: {file}\nbalance:  {balance}",
                key.name,
                key.pubkey,
                key.class,
                key.approval,
                key.profile
                    .map_or_else(|| "-".to_owned(), |p| p.to_string())
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn report(r: &engine::Report) -> Result<ExitCode> {
    println!("{}", serde_json::to_string_pretty(r)?);
    Ok(r.outcome.exit_code())
}
