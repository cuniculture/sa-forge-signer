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
| A restart mid-sign | `serve` drains running requests on SIGTERM/SIGINT (up to 160 s) before exiting; a dropped connection during `sign` means `unknown`, not failed. |
| Double actions after a timeout | `sign` reports `expired` only with proof that the transaction can no longer land (finalized height past its last valid height, and a full-history lookup from a current node finds nothing); anything less is `unknown` (check the signature first). |
| Concurrent signs racing the limits | Signs with one key are serialized by a file lock, and every send is recorded as an intent with its simulated spend before it leaves; unresolved spends are charged that reservation. |

## Not covered

- Token movement inside an allowed program (SAGE moving cargo or ATLAS by CPI) is limited only by on-chain permissions; the signer refuses direct token-program instructions but does not decode game instructions.
- The signer does not decode what a profile grant gives away. A `wallet` key therefore cannot be `auto` or reachable through `serve` unless it sets `allow_unattended = true`; do that only for a throwaway testnet key.
- The daily cap measures the fee payer's lamports, not token or profile-vault spending; only on-chain permissions limit those.
- The audit log's hash chain detects edited entries, not truncation or a rewrite by someone who can write `state_dir`: keep that directory out of agents' reach, and copy the latest hash elsewhere if you need an anchor. `summary` and `intent` are caller-supplied and recorded as given; do not put secrets in them.

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability" on this repository.
