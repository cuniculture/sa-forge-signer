//! Structural checks on the compiled message. None decode game instructions.

use std::fmt;
use std::str::FromStr;

use solana_address::Address;
use solana_message::Message;
use solana_message::compiled_instruction::CompiledInstruction;

use crate::cluster::{ASSOCIATED_TOKEN_PROGRAM, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM, TOKEN_PROGRAM};

#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub check: &'static str,
    pub detail: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

pub const fn refuse(check: &'static str, detail: String) -> Refusal {
    Refusal { check, detail }
}

pub struct Policy<'a> {
    pub signer: &'a Address,
    pub allowed_programs: &'a [Address],
    pub transfer_to: &'a [Address],
    pub partial_signers: &'a [Address],
}

// Public System Program instruction index. Only Transfer is allowed at the top level: forge-mcp
// builds no top-level System instruction (new accounts are created inside the game programs), and
// every account-creating form (CreateAccount, CreateAccountWithSeed, Assign, Allocate) can fund or
// take over an account whose keypair the requester holds, moving lamports outside the signer.
const SYS_TRANSFER: u32 = 2;

// Associated Token Account program instructions that only create an account (rent from the fee
// payer, owned by the token program). RecoverNested (2) moves tokens and is refused.
const ATA_CREATE: u8 = 0;
const ATA_CREATE_IDEMPOTENT: u8 = 1;
// Account positions in both create forms: payer, new account, owner (wallet), mint, system, token.
const ATA_OWNER: usize = 2;
const ATA_ACCOUNTS: usize = 6;

/// Runs every check that needs only the message; returns the names of the checks passed.
pub fn structural(message: &Message, policy: &Policy<'_>) -> Result<Vec<&'static str>, Refusal> {
    fee_payer(message, policy)?;
    programs(message, policy)?;
    tokens(message)?;
    system(message, policy)?;
    signers(message, policy)?;
    Ok(vec!["fee_payer", "programs", "tokens", "system", "signers"])
}

fn fee_payer(message: &Message, policy: &Policy<'_>) -> Result<(), Refusal> {
    match message.account_keys.first() {
        Some(k) if k == policy.signer => Ok(()),
        Some(k) => Err(refuse(
            "fee_payer",
            format!("fee payer {k} is not the signing key {}", policy.signer),
        )),
        None => Err(refuse("fee_payer", "message has no accounts".to_owned())),
    }
}

fn programs(message: &Message, policy: &Policy<'_>) -> Result<(), Refusal> {
    for (i, ix) in message.instructions.iter().enumerate() {
        let program = program_of(message, ix)
            .ok_or_else(|| refuse("programs", format!("instruction {i} has no program id")))?;
        if !policy.allowed_programs.contains(program) {
            return Err(refuse(
                "programs",
                format!("instruction {i} calls {program}, which is not allowed"),
            ));
        }
    }
    Ok(())
}

/// Token programs are never called at the top level, whatever the key's `extra_programs` say: their
/// transfers, approvals and authority changes move assets with no destination rule here, and the
/// daily cap counts lamports only. Token movement in play happens inside SAGE, which checks its own
/// accounts. The ATA program may only create accounts.
fn tokens(message: &Message) -> Result<(), Refusal> {
    let parse = |s: &str| Address::from_str(s).map_err(|e| refuse("tokens", e.to_string()));
    let token = parse(TOKEN_PROGRAM)?;
    let token_2022 = parse(TOKEN_2022_PROGRAM)?;
    let ata = parse(ASSOCIATED_TOKEN_PROGRAM)?;
    for (i, ix) in message.instructions.iter().enumerate() {
        let Some(program) = program_of(message, ix) else {
            continue;
        };
        if program == &token || program == &token_2022 {
            return Err(refuse(
                "tokens",
                format!(
                    "instruction {i} calls token program {program} directly, which is not allowed"
                ),
            ));
        }
        if program == &ata {
            // An empty data field is the legacy Create.
            let tag = ix.data.first().copied().unwrap_or(ATA_CREATE);
            if ix.data.len() > 1 || !matches!(tag, ATA_CREATE | ATA_CREATE_IDEMPOTENT) {
                return Err(refuse(
                    "tokens",
                    format!(
                        "instruction {i} is associated-token instruction {tag}; only create is allowed"
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// The owners of associated token accounts the message creates, other than the signing key and its
/// transfer destinations. Each is a rent recipient no destination rule covers, so the caller must
/// check it on-chain (see `engine::ata_owners`).
pub fn ata_owners(message: &Message, policy: &Policy<'_>) -> Result<Vec<Address>, Refusal> {
    let ata = Address::from_str(ASSOCIATED_TOKEN_PROGRAM)
        .map_err(|e| refuse("ata_owners", e.to_string()))?;
    let mut out: Vec<Address> = Vec::new();
    for (i, ix) in message.instructions.iter().enumerate() {
        if program_of(message, ix) != Some(&ata) {
            continue;
        }
        let owner = (ix.accounts.len() >= ATA_ACCOUNTS)
            .then(|| account_of(message, ix, ATA_OWNER))
            .flatten()
            .ok_or_else(|| {
                refuse(
                    "ata_owners",
                    format!("instruction {i} is missing associated-token accounts"),
                )
            })?;
        if owner != policy.signer && !policy.transfer_to.contains(owner) && !out.contains(owner) {
            out.push(*owner);
        }
    }
    Ok(out)
}

fn system(message: &Message, policy: &Policy<'_>) -> Result<(), Refusal> {
    let system = Address::from_str(SYSTEM_PROGRAM).map_err(|e| refuse("system", e.to_string()))?;
    for (i, ix) in message.instructions.iter().enumerate() {
        if program_of(message, ix) != Some(&system) {
            continue;
        }
        let tag = ix
            .data
            .get(..4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| refuse("system", format!("instruction {i} is too short")))?;
        let account = |n: usize| account_of(message, ix, n);
        match tag {
            SYS_TRANSFER => match account(1) {
                Some(to) if policy.transfer_to.contains(to) => {}
                Some(to) => {
                    return Err(refuse(
                        "system",
                        format!(
                            "instruction {i} transfers to {to}, which is not an allowed destination"
                        ),
                    ));
                }
                None => {
                    return Err(refuse(
                        "system",
                        format!("instruction {i} is missing an account"),
                    ));
                }
            },
            other => {
                return Err(refuse(
                    "system",
                    format!("instruction {i} is System instruction {other}, which is not allowed"),
                ));
            }
        }
    }
    Ok(())
}

fn signers(message: &Message, policy: &Policy<'_>) -> Result<(), Refusal> {
    for p in policy.partial_signers {
        if p == policy.signer {
            return Err(refuse(
                "signers",
                "a partial signer is the signing key".to_owned(),
            ));
        }
        let required = message
            .account_keys
            .iter()
            .enumerate()
            .any(|(i, k)| k == p && message.is_signer(i));
        if !required {
            return Err(refuse(
                "signers",
                format!("partial signer {p} is not a signer of the transaction"),
            ));
        }
    }
    for (i, k) in message.account_keys.iter().enumerate() {
        if message.is_signer(i) && k != policy.signer && !policy.partial_signers.contains(k) {
            return Err(refuse(
                "signers",
                format!("{k} must sign, but it is neither the signing key nor a partial signer"),
            ));
        }
    }
    Ok(())
}

fn program_of<'m>(message: &'m Message, ix: &CompiledInstruction) -> Option<&'m Address> {
    message.account_keys.get(usize::from(ix.program_id_index))
}

fn account_of<'m>(message: &'m Message, ix: &CompiledInstruction, n: usize) -> Option<&'m Address> {
    ix.accounts
        .get(n)
        .and_then(|&k| message.account_keys.get(usize::from(k)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_instruction::{AccountMeta, Instruction};

    fn addr(n: u8) -> Address {
        Address::new_from_array([n; 32])
    }

    fn system_ix(tag: u32, accounts: Vec<AccountMeta>) -> Instruction {
        let mut data = tag.to_le_bytes().to_vec();
        data.extend_from_slice(&[0; 8]);
        Instruction {
            program_id: Address::from_str(SYSTEM_PROGRAM).unwrap(),
            accounts,
            data,
        }
    }

    fn run(
        ixs: &[Instruction],
        payer: &Address,
        partial: &[Address],
        to: &[Address],
    ) -> Result<Vec<&'static str>, Refusal> {
        let message = Message::new(ixs, Some(payer));
        let allowed = [Address::from_str(SYSTEM_PROGRAM).unwrap(), addr(9)];
        structural(
            &message,
            &Policy {
                signer: &addr(1),
                allowed_programs: &allowed,
                transfer_to: to,
                partial_signers: partial,
            },
        )
    }

    fn game_ix() -> Instruction {
        Instruction {
            program_id: addr(9),
            accounts: vec![AccountMeta::new_readonly(addr(1), true)],
            data: vec![1],
        }
    }

    #[test]
    fn passes_plain_game_instruction() {
        assert!(run(&[game_ix()], &addr(1), &[], &[]).is_ok());
    }

    #[test]
    fn refuses_foreign_fee_payer() {
        assert_eq!(
            run(&[game_ix()], &addr(2), &[], &[]).unwrap_err().check,
            "fee_payer"
        );
    }

    #[test]
    fn refuses_unlisted_program() {
        let ix = Instruction {
            program_id: addr(7),
            accounts: vec![],
            data: vec![],
        };
        assert_eq!(
            run(&[ix], &addr(1), &[], &[]).unwrap_err().check,
            "programs"
        );
    }

    #[test]
    fn transfer_only_to_allowed_destinations() {
        let ix = system_ix(
            SYS_TRANSFER,
            vec![
                AccountMeta::new(addr(1), true),
                AccountMeta::new(addr(3), false),
            ],
        );
        assert_eq!(
            run(std::slice::from_ref(&ix), &addr(1), &[], &[])
                .unwrap_err()
                .check,
            "system"
        );
        assert!(run(&[ix], &addr(1), &[], &[addr(3)]).is_ok());
    }

    // Pinchy's review, P0: a requester-held new keypair must not be fundable or assignable at the top
    // level, by any account-creating System instruction, partial signer or not.
    #[test]
    fn refuses_every_account_creating_system_instruction() {
        const CREATE_ACCOUNT: u32 = 0;
        const ASSIGN: u32 = 1;
        const CREATE_WITH_SEED: u32 = 3;
        const ALLOCATE: u32 = 8;
        let payer_and_new = || {
            vec![
                AccountMeta::new(addr(1), true),
                AccountMeta::new(addr(4), true),
            ]
        };
        for (tag, accounts) in [
            (CREATE_ACCOUNT, payer_and_new()),
            (CREATE_WITH_SEED, payer_and_new()),
            (ASSIGN, vec![AccountMeta::new(addr(4), true)]),
            (ALLOCATE, vec![AccountMeta::new(addr(4), true)]),
        ] {
            let ix = system_ix(tag, accounts);
            let refusal = run(&[ix], &addr(1), &[addr(4)], &[]).unwrap_err();
            assert_eq!(
                refusal.check, "system",
                "System instruction {tag} must be refused"
            );
        }
    }

    fn token_ix(program: &str, data: Vec<u8>) -> Instruction {
        Instruction {
            program_id: Address::from_str(program).unwrap(),
            accounts: vec![
                AccountMeta::new(addr(1), true),
                AccountMeta::new(addr(3), false),
            ],
            data,
        }
    }

    fn run_allowing(ixs: &[Instruction], extra: &[&str]) -> Result<Vec<&'static str>, Refusal> {
        let message = Message::new(ixs, Some(&addr(1)));
        let mut allowed = vec![Address::from_str(SYSTEM_PROGRAM).unwrap(), addr(9)];
        allowed.extend(extra.iter().map(|p| Address::from_str(p).unwrap()));
        structural(
            &message,
            &Policy {
                signer: &addr(1),
                allowed_programs: &allowed,
                transfer_to: &[],
                partial_signers: &[],
            },
        )
    }

    // Pinchy's review, P0: SPL movement had no destination rule. Token programs are refused at the top
    // level even when a key's extra_programs lists them.
    #[test]
    fn refuses_direct_token_program_calls_even_when_listed() {
        const TRANSFER: u8 = 3;
        for program in [TOKEN_PROGRAM, TOKEN_2022_PROGRAM] {
            let ix = token_ix(program, vec![TRANSFER, 1, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(
                run_allowing(&[ix], &[program]).unwrap_err().check,
                "tokens",
                "{program} must be refused at the top level"
            );
        }
    }

    #[test]
    fn associated_token_program_may_only_create() {
        const RECOVER_NESTED: u8 = 2;
        for data in [vec![], vec![ATA_CREATE], vec![ATA_CREATE_IDEMPOTENT]] {
            let ix = token_ix(ASSOCIATED_TOKEN_PROGRAM, data.clone());
            assert!(
                run_allowing(&[ix], &[ASSOCIATED_TOKEN_PROGRAM]).is_ok(),
                "ATA create {data:?} is allowed"
            );
        }
        for data in [vec![RECOVER_NESTED], vec![ATA_CREATE_IDEMPOTENT, 0]] {
            let ix = token_ix(ASSOCIATED_TOKEN_PROGRAM, data.clone());
            assert_eq!(
                run_allowing(&[ix], &[ASSOCIATED_TOKEN_PROGRAM])
                    .unwrap_err()
                    .check,
                "tokens",
                "ATA instruction {data:?} must be refused"
            );
        }
    }

    fn ata_create(owner: Address) -> Instruction {
        Instruction {
            program_id: Address::from_str(ASSOCIATED_TOKEN_PROGRAM).unwrap(),
            accounts: vec![
                AccountMeta::new(addr(1), true),
                AccountMeta::new(addr(20), false),
                AccountMeta::new_readonly(owner, false),
                AccountMeta::new_readonly(addr(21), false),
                AccountMeta::new_readonly(Address::from_str(SYSTEM_PROGRAM).unwrap(), false),
                AccountMeta::new_readonly(Address::from_str(TOKEN_PROGRAM).unwrap(), false),
            ],
            data: vec![ATA_CREATE_IDEMPOTENT],
        }
    }

    fn owners_to_verify(ixs: &[Instruction], to: &[Address]) -> Result<Vec<Address>, Refusal> {
        ata_owners(
            &Message::new(ixs, Some(&addr(1))),
            &Policy {
                signer: &addr(1),
                allowed_programs: &[],
                transfer_to: to,
                partial_signers: &[],
            },
        )
    }

    // Pinchy's re-review, P1-3: creating a token account pays its rent to whoever owns it. The
    // signing key and its transfer destinations are covered already; any other owner is returned
    // for the on-chain game-account check, once even if repeated.
    #[test]
    fn ata_owners_other_than_the_key_and_its_destinations_need_checking() {
        assert_eq!(owners_to_verify(&[ata_create(addr(1))], &[]), Ok(vec![]));
        assert_eq!(
            owners_to_verify(&[ata_create(addr(3))], &[addr(3)]),
            Ok(vec![])
        );
        assert_eq!(
            owners_to_verify(&[ata_create(addr(7)), ata_create(addr(7)), game_ix()], &[]),
            Ok(vec![addr(7)])
        );
        let mut short = ata_create(addr(7));
        short.accounts.truncate(2);
        assert_eq!(
            owners_to_verify(&[short], &[]).unwrap_err().check,
            "ata_owners"
        );
    }

    #[test]
    fn spl_token_is_not_in_the_default_program_list() {
        assert!(
            crate::cluster::ZINK_TESTNET
                .programs
                .iter()
                .all(|(_, p)| *p != TOKEN_PROGRAM && *p != TOKEN_2022_PROGRAM)
        );
    }

    #[test]
    fn refuses_assigning_the_signing_key() {
        let ix = system_ix(1, vec![AccountMeta::new(addr(1), true)]); // Assign
        assert_eq!(run(&[ix], &addr(1), &[], &[]).unwrap_err().check, "system");
    }

    #[test]
    fn refuses_nonce_and_other_system_instructions() {
        let ix = system_ix(4, vec![AccountMeta::new(addr(5), false)]);
        assert_eq!(run(&[ix], &addr(1), &[], &[]).unwrap_err().check, "system");
    }

    #[test]
    fn refuses_unknown_required_signer_and_stray_partial() {
        let ix = Instruction {
            program_id: addr(9),
            accounts: vec![AccountMeta::new(addr(6), true)],
            data: vec![],
        };
        assert_eq!(run(&[ix], &addr(1), &[], &[]).unwrap_err().check, "signers");
        assert_eq!(
            run(&[game_ix()], &addr(1), &[addr(8)], &[])
                .unwrap_err()
                .check,
            "signers"
        );
        assert_eq!(
            run(&[game_ix()], &addr(1), &[addr(1)], &[])
                .unwrap_err()
                .check,
            "signers"
        );
    }
}
