//! Structural checks on the compiled message. None decode game instructions.

use std::fmt;
use std::str::FromStr;

use solana_address::Address;
use solana_message::Message;
use solana_message::compiled_instruction::CompiledInstruction;

use crate::cluster::SYSTEM_PROGRAM;

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

// Public System Program instruction indices.
const SYS_CREATE_ACCOUNT: u32 = 0;
const SYS_ASSIGN: u32 = 1;
const SYS_TRANSFER: u32 = 2;
const SYS_CREATE_ACCOUNT_WITH_SEED: u32 = 3;
const SYS_ALLOCATE: u32 = 8;

/// Runs every check that needs only the message; returns the names of the checks passed.
pub fn structural(message: &Message, policy: &Policy<'_>) -> Result<Vec<&'static str>, Refusal> {
    fee_payer(message, policy)?;
    programs(message, policy)?;
    system(message, policy)?;
    signers(message, policy)?;
    Ok(vec!["fee_payer", "programs", "system", "signers"])
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
        let new_account = |n: usize, what: &str| match account(n) {
            Some(a) if policy.partial_signers.contains(a) => Ok(()),
            Some(a) => Err(refuse(
                "system",
                format!("instruction {i} {what} {a}, which is not a new account from this payload"),
            )),
            None => Err(refuse(
                "system",
                format!("instruction {i} is missing an account"),
            )),
        };
        match tag {
            SYS_CREATE_ACCOUNT => new_account(1, "creates")?,
            SYS_ASSIGN => new_account(0, "assigns")?,
            SYS_ALLOCATE => new_account(0, "allocates")?,
            SYS_CREATE_ACCOUNT_WITH_SEED => {}
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

    #[test]
    fn create_account_needs_a_partial_signer() {
        let ix = system_ix(
            SYS_CREATE_ACCOUNT,
            vec![
                AccountMeta::new(addr(1), true),
                AccountMeta::new(addr(4), true),
            ],
        );
        assert!(run(std::slice::from_ref(&ix), &addr(1), &[addr(4)], &[]).is_ok());
        assert_eq!(run(&[ix], &addr(1), &[], &[]).unwrap_err().check, "system");
    }

    #[test]
    fn refuses_assigning_the_signing_key() {
        let ix = system_ix(SYS_ASSIGN, vec![AccountMeta::new(addr(1), true)]);
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
