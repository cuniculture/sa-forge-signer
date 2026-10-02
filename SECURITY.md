# Security

## Threat model

| Threat | Control |
|---|---|
| The agent reads the key file and skips every check | Keys and config are unreadable by the agent's OS user (separate user or container). Key files must be 0600 in a 0700 directory or the signer refuses to load them. |
| A buggy or malicious payload (from the builder, a hand-written file or a prompt injection) | The structural checks in the README, simulation before sending, `confirm` for `wallet` keys, then the on-chain key limits. |
| A wrong or swapped RPC URL | The RPC's genesis hash must match the cluster profile. |
| Private keys inside payloads (`partial_signers`) | Never logged; the audit log hashes the payload without them; the payload file is deleted once sent. |
| Approval spoofed by the agent | `confirm` reads only from the controlling terminal (`/dev/tty`), never stdin. Without a terminal it refuses. |
| A stolen session key | On-chain scope, narrow permission mask, short expiry and a small ZINK balance. These hold even if the signer host is compromised. |
| A stolen wallet key (Path A) | Nothing on-chain limits it. Keep only working balances in it. |
| Another local process or a web page calls `serve` | Every route but `/health` needs a bearer token; config stores only its sha256 and the keys it may use. Host and Origin must be an allowed host. |
| A restart mid-sign | `serve` drains running requests on SIGTERM/SIGINT (up to 80 s) before exiting; a dropped connection during `sign` means `unknown`, not failed. |
| Double actions after a timeout | `sign` resolves to `expired` (safe to rebuild) or `unknown` (check the signature first), never a guess. |

## Not covered

- SPL Token instructions are allowed by program id, so a payload could move tokens from a token account the signing key owns. Session keys should never hold tokens.
- A `wallet` key set to `auto` can sign a profile key grant (for example an attacker's key): the chain accepts it because the key is authorised. Keep `wallet` keys on `confirm` unless they are testnet burners.
- The daily cap measures the fee payer's balance, not spending from the profile vault; only on-chain permissions limit that.

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability" on this repository.
