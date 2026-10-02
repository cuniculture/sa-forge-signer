//! Funding payloads: a plain System Program transfer in the same JSON shape forge-mcp returns.

use anyhow::{Result, bail};
use serde_json::{Value, json};
use solana_address::Address;

use crate::cluster::SYSTEM_PROGRAM;

const DECIMALS: usize = 9;
const SYS_TRANSFER: u32 = 2;

/// Parses a decimal ZINK amount ("0.05", "1", "2.5") into lamports, exactly.
pub fn parse_zink(amount: &str) -> Result<u64> {
    let (whole, frac) = amount.split_once('.').unwrap_or((amount, ""));
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    if whole.is_empty() && frac.is_empty() || !digits(whole) || !digits(frac) {
        bail!("{amount:?} is not a ZINK amount");
    }
    if frac.len() > DECIMALS {
        bail!("{amount:?} has more than {DECIMALS} decimals");
    }
    let lamports: u64 = format!("{whole}{frac:0<DECIMALS$}")
        .parse()
        .map_err(|_| anyhow::anyhow!("{amount:?} is too large"))?;
    if lamports == 0 {
        bail!("the amount must be more than 0");
    }
    Ok(lamports)
}

/// An unsigned payload moving `lamports` from `from` (fee payer and signer) to `to`.
pub fn fund_payload(from: &Address, to: &Address, lamports: u64, summary: &str) -> Value {
    let mut data = SYS_TRANSFER.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    json!({
        "version": 1,
        "summary": summary,
        "warnings": [],
        "transaction": {
            "instructions": [{
                "program_id": SYSTEM_PROGRAM,
                "accounts": [
                    {"pubkey": from.to_string(), "is_signer": true, "is_writable": true},
                    {"pubkey": to.to_string(), "is_signer": false, "is_writable": true},
                ],
                "data": data,
            }],
            "signers": [from.to_string()],
            "fee_payer": from.to_string(),
        },
        "partial_signers": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::{Policy, structural};
    use crate::payload::Payload;
    use solana_message::Message;
    use std::str::FromStr;

    #[test]
    fn parses_zink_exactly() {
        assert_eq!(parse_zink("1").unwrap(), 1_000_000_000);
        assert_eq!(parse_zink("0.05").unwrap(), 50_000_000);
        assert_eq!(parse_zink("2.5").unwrap(), 2_500_000_000);
        assert_eq!(parse_zink(".5").unwrap(), 500_000_000);
        assert_eq!(parse_zink("0.000000001").unwrap(), 1);
        assert_eq!(parse_zink("18446744073.709551615").unwrap(), u64::MAX);
        for bad in [
            "",
            ".",
            "0",
            "0.0",
            "-1",
            "1e3",
            "1.0000000001",
            "abc",
            "1.2.3",
            "18446744073.709551616",
        ] {
            assert!(parse_zink(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn fund_payload_parses_and_passes_the_transfer_rule() {
        let from = Address::new_from_array([1; 32]);
        let to = Address::new_from_array([2; 32]);
        let text = fund_payload(&from, &to, 50_000_000, "fund").to_string();
        let p = Payload::parse(&text).unwrap();
        assert_eq!(p.fee_payer, from);
        assert_eq!(p.instructions[0].data[4..], 50_000_000_u64.to_le_bytes());
        let message = Message::new(&p.instructions, Some(&from));
        let allowed = [Address::from_str(SYSTEM_PROGRAM).unwrap()];
        let policy = |dests: &[Address]| {
            structural(
                &message,
                &Policy {
                    signer: &from,
                    allowed_programs: &allowed,
                    transfer_to: dests,
                    partial_signers: &[],
                },
            )
        };
        assert!(policy(&[to]).is_ok());
        assert!(
            policy(&[]).is_err(),
            "a key without the destination listed must refuse"
        );
    }
}
