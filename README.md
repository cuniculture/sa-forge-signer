# sa-forge-signer

A thin, self-hosted signer for agents that play SAGE C4 on Z.ink. The agent builds unsigned payloads with forge-mcp `build_*` methods; `sa-forge-signer` checks, simulates, signs, sends and confirms them with keys the agent itself cannot read.

**Unofficial.** Not affiliated with or endorsed by Star Atlas or its developers. Z.ink testnet (SAGE C4 PTR) only; there is no mainnet profile.

**Status:** v0.1, early. Read the code before trusting it with anything.

## How it works

The signer is deliberately thin: it does not decode game instructions and needs no IDL. The chain enforces what a profile key may do (scope, permission mask, expiry); the signer checks what the chain does not:

1. **Chain:** the RPC's genesis hash matches Z.ink testnet, so a wrong RPC URL cannot redirect signatures.
2. **Fee payer:** the fee payer is the signing key.
3. **Programs:** every top-level instruction calls SAGE, Player Profile, Profile Faction, ComputeBudget, SPL Token, Associated Token or System (plus per-key extras).
4. **System Program:** account creation only for new accounts from the payload; `Transfer` only to per-key allowed destinations; nothing else.
5. **Signers:** every required signer is the signing key or a payload partial signer, and partial signers do not exist on-chain yet.
6. **Limits:** a per-minute rate limit and a daily lamport cap per key.
7. **Simulation** must succeed before anything is sent.

It then fetches a fresh blockhash, signs, sends, and polls until the transaction is confirmed or its blockhash has expired. Every sign request is recorded in a hash-chained audit log.

## Two ways to run an agent

Which keys the agent's signer holds decides what the agent can do alone and what it can lose.

### Path A: the agent holds the wallet

The agent's wallet is the profile authority (key index 0) and holds its assets; a SAGE-scoped session key (index 1) signs day-to-day play. The wallet key signs onboarding, deposits and withdrawals, vault funding and session-key funding.

> **Caution.** On mainnet this makes the agent's wallet a hot wallet. Anything that controls the agent, including a prompt injection in content it reads, can sign as the profile authority: withdraw assets, add an attacker's key, or drain the wallet. The signer cannot see what a wallet transaction does. `wallet` keys therefore default to `confirm` (a human approves each signature on the terminal). Keep only working balances in the agent's wallet. Path A suits testnet burners; on mainnet it is a deliberate, informed choice.

### Path B: the human holds the wallet

The human sets up the profile, character, faction, vault and deposits with their own wallet, then grants the agent a narrow, expiring session key. The agent's signer holds only that key.

> **Caution.** A session key is limited to the permissions granted, not to harmless actions. Within its mask it can spend in-game resources, spend from the profile vault and put fleets at risk. Grant the narrowest mask that covers the agent's job, a short expiry and a small ZINK balance, and deposit only what the agent should be able to lose.

**Recommendation:** Path B for mainnet and anything of value; Path A for testnet.

## Isolation

The signer only protects anything if the agent cannot read its keys or config. Run it as a different OS user or in a container, with the key directory and config owned by that user. If the agent can read the key file, the checks are advice, not a control.

## Build

```sh
cargo build --release --locked
```

Unix only (macOS, Linux). The toolchain is pinned in `rust-toolchain.toml`.

## Use

```sh
# Generate a key; prints only the pubkey and a config snippet
sa-forge-signer key new alice-session --class session

# Configure it (see config.example.toml), then grant it on the profile with
# forge-mcp build_add_profile_key, signed by the profile authority.

sa-forge-signer check payload.json                  # checks + simulation, never signs
sa-forge-signer sign --intent "scan round" payload.json
sa-forge-signer key show alice-session
sa-forge-signer key fund alice-session --zink 0.05 --from alice-wallet --out fund.json
sa-forge-signer key destroy alice-session
sa-forge-signer audit verify
```

The config lives at `~/.config/sa-forge-signer/config.toml` unless `--config` or `SA_FORGE_SIGNER_CONFIG` says otherwise. The key is chosen by `--key`, or by matching the payload's fee payer.

`check` and `sign` print one JSON report (`outcome`, `signature`, `slot`, `explorer`, `detail`, `failed_check`, `program_error`, `error`, `checks`, `compute_units`, `fee`, `balance_change`, `summary`, `logs`). `checks` lists the checks that passed; on a refusal `failed_check` names the one that failed. `program_error` is the program's own message from the logs, on a failed simulation or a transaction that landed with an error. For a landed transaction, `balance_change` and `fee` come from the transaction's own metadata, so parallel transactions from the same key do not skew them; for `check` they are simulated. The payload's `summary` comes from the builder and is not verified.

| Outcome | Exit | Meaning | Retry? |
|---|---|---|---|
| `ok` | 0 | `check` passed | - |
| `confirmed` | 0 | landed | no |
| `refused` | 10 | a check failed | fix the payload |
| `simulation_failed` | 11 | the program would reject it | after fixing the cause |
| `failed` | 12 | landed with a program error | after fixing the cause |
| `expired` | 13 | blockhash expired without landing | yes, rebuild |
| `unknown` | 14 | sent but not resolved | no, check the signature first |

Payloads that carry partial signers hold private keys for new accounts; `sign` deletes such a payload file once it has been sent, and never logs them.

## Key lifecycle

1. **Create:** `sa-forge-signer key new alice-session --class session` prints only the pubkey; add the printed `[keys.alice-session]` block to the config.
2. **Grant:** build forge-mcp `build_add_profile_key` with that pubkey as `newKey`, scope `sage`, the narrowest permission mask and a short `expireTime`. The profile authority signs it: the human's own wallet (Path B), or the agent's `wallet` key through `sign` (Path A; it needs `confirm` or a testnet burner on `auto`).
3. **Fund:** `sa-forge-signer key fund alice-session --zink 0.05 --from <payer> --out fund.json` builds an unsigned transfer. Path A: `sign --key alice-wallet fund.json`, with the session key listed in the wallet's `transfer_to`. Path B: pay it from the human's wallet with any Solana-compatible tool. A small balance doubles as a spending cap.
4. **Use:** `sign` with the key. A missing or too narrow grant fails the simulation with the program's error.
5. **Revoke:** build `build_remove_profile_key`, signed by the profile authority, then `sa-forge-signer key destroy alice-session`. `destroy` zeroes and deletes the key file, and refuses while the key still holds ZINK unless you pass `--abandon-balance`. The on-chain expiry is the backstop if revocation is forgotten.

## Serve

`sa-forge-signer serve` runs the signer as a long-lived service, so each signature skips process start-up and keys stay loaded in one isolated place. It listens on `[serve] listen` (default `127.0.0.1:8790`):

- `POST /v1/check` and `POST /v1/sign`: body `{"payload": <payload object>, "key": "optional", "intent": "optional"}`; the reply is the same JSON report as the CLI. `4xx` means a request or auth problem, `500` that the signer could not finish (see `error`).
- `POST /mcp`: MCP (JSON responses, no streaming) with tools `check`, `sign` and `key_show`.
- `GET /health`: no auth, for health checks.

Every other route needs `Authorization: Bearer <token>`. Create a token with `sa-forge-signer token new <name> --out <file>`: it writes the token to a new 0600 file and prints only its sha256 for `[[serve.tokens]]`, which also lists the keys that token may use. Host and Origin headers must name an entry in `allowed_hosts`. `confirm` keys prompt on the service's own terminal; without one they refuse.

On SIGTERM or SIGINT the service stops taking requests and lets running ones finish, for up to 80 s (a sign waits at most until its blockhash expires), then exits. Give it a stop grace period of at least 90 s (for example `docker stop -t 90`). A client that loses the connection during `sign` must treat it as `unknown`: the transaction may still land.

MCP clients pass the payload object from the forge-mcp `build_*` result unchanged, and call `check` before `sign`. In a 15-payload test every payload arrived byte-exact, but the model re-types each one, so each costs its tokens twice and any partial-signer secret appears twice in the transcript.

Add it to Claude Code with `claude mcp add --transport http signer http://127.0.0.1:8790/mcp --header "Authorization: Bearer $(cat <file>)"`.

## Run in Docker

The `Dockerfile` builds a small non-root image (uid 10001) with base images pinned by digest. It holds no keys or config; mount them at run time:

| Mount | Path in the container | Notes |
|---|---|---|
| config | `/etc/sa-forge-signer/config.toml` (read-only) | set `key_dir = "/run/keys"` and `state_dir = "/var/lib/sa-forge-signer"`; for `serve`, `listen = "0.0.0.0:8790"` |
| keys | `/run/keys` (read-only) | a 0700 directory of 0600 key files, readable by uid 10001; nothing else should mount it |
| state | `/var/lib/sa-forge-signer` | the audit log; keep it across restarts |

```sh
docker build -t sa-forge-signer .

# One-shot: check or sign a payload from stdin
docker run --rm -i --read-only --cap-drop ALL \
  -v "$PWD/config.toml:/etc/sa-forge-signer/config.toml:ro" -v "$PWD/keys:/run/keys:ro" \
  -v "$PWD/state:/var/lib/sa-forge-signer" sa-forge-signer check - < payload.json

# Service (the default command): publish on loopback only; allow at least 90 s to stop so signs drain
docker run -d --name sa-forge-signer --read-only --cap-drop ALL --stop-timeout 90 \
  -p 127.0.0.1:8790:8790 \
  -v "$PWD/config.toml:/etc/sa-forge-signer/config.toml:ro" -v "$PWD/keys:/run/keys:ro" \
  -v "$PWD/state:/var/lib/sa-forge-signer" sa-forge-signer
```

The signer talks only to the RPC in `rpc_url` (by default Z.ink testnet). An agent can use a forge-mcp running anywhere, local or hosted: only unsigned payloads travel to the signer, and the keys never leave this container. The isolation rule still applies: the agent must not be able to read the keys directory or the config.

## License

Dual-licensed under the [Unlicense](UNLICENSE) or [MIT](LICENSE-MIT), at your option. Contributions are accepted under the same terms (see [COPYING](COPYING)).
