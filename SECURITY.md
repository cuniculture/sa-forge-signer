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
| A restart mid-sign | `serve` drains running requests on SIGTERM/SIGINT (up to 220 s) before exiting; a dropped connection during `sign` means `unknown`, not failed. |
| Double actions after a timeout | Nothing short of a landed status is reported as final: an expired blockhash with no status found is `unknown`, since an RPC cannot prove absence (see below). Callers must reconcile the signature and the on-chain state before retrying (README, "Retrying safely"). |
| A transaction that takes the key past its daily cap | The cap is checked under the key lock, after the final simulation, against spent-or-reserved plus this transaction's simulated spend and fee; with no simulated balance the sign is refused. |
| Concurrent signs racing the limits | Signs with one key are serialized by a file lock, and every send is recorded as an intent with its reservation before it leaves; unresolved spends are charged that reservation. |
| Rent paid out through token-account creation | Associated Token may create accounts only for the signing key, its transfer destinations, or an existing account owned by a game program. |

## Not covered

- Token movement inside an allowed program (SAGE moving cargo or ATLAS by CPI) is limited only by on-chain permissions; the signer refuses direct token-program instructions but does not decode game instructions.
- The signer does not decode what a profile grant gives away. A `wallet` key therefore cannot be `auto` or reachable through `serve` unless it sets `allow_unattended = true`; do that only for a throwaway testnet key.
- The daily cap measures the fee payer's lamports, not token or profile-vault spending; only on-chain permissions limit those.
- **The RPC is trusted for outcomes.** The genesis check stops a wrong cluster, not a dishonest or inconsistent node. No RPC answer can prove that a transaction never landed: a load balancer can serve the finalized height and the status lookup from different nodes, and a node can lack history. The signer therefore never reports a transaction as not landed. A lying RPC can still report a false `confirmed`, or a simulation that hides a spend. Use an RPC you trust, and keep the key's ZINK balance small.
- **Rent for game-owned token accounts.** A token account created for a game account (for example another player's character or cargo cache) holds its rent where only the game program can move it. A requester can direct that rent into game accounts they control, if the game has an instruction that closes such accounts back to them. It is bounded by the daily cap and is about 0.002 ZINK per account.
- **Wall-clock bounds.** The 150 s confirmation deadline does not include the checks and simulations before sending, and each RPC call may take up to 15 s. A stalled RPC can make one sign take a few minutes.
- The audit log's hash chain detects edited entries, not truncation or a rewrite by someone who can write `state_dir`: keep that directory out of agents' reach, and copy the latest hash elsewhere if you need an anchor. `summary` and `intent` are caller-supplied and recorded as given; do not put secrets in them.

## Repairing the audit log

A crash during an append can leave a partial last line. Every later read then fails, and every sign with every key fails until the line is repaired. Repair it without losing what the log proves:

1. Stop the service and any CLI signs.
2. Copy `state_dir/audit.jsonl` somewhere safe.
3. Run `sa-forge-signer audit verify`. The error names the first unreadable line.
4. If that line is the last one and is a cut-off JSON fragment, move it into a separate file next to the log (for example `audit.jsonl.partial-2026-10-02`) rather than deleting it, and leave every earlier line unchanged. Run `audit verify` again; it should pass. If any line other than the last fails, the log was edited: stop and investigate, do not repair.
5. Reconcile before signing again. A cut-off `sign-intent` means nothing was sent: the intent is written before the send, and the send never happens if that write fails. A cut-off final `sign` entry means the transaction was sent. Its intent is still in the log as an orphan and keeps its reservation charged for 24 h. Look up that intent's `signature` and re-read the on-chain state before retrying the action.

Do not delete or rewrite earlier entries, including orphan intents: they are what keeps unresolved spends charged.

## Reporting

Report vulnerabilities privately through GitHub's "Report a vulnerability" on this repository.
