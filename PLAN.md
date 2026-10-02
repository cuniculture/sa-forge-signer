# Plan

Work tracked in this repository. Update it in the same change as the work it tracks.

## Next

1. **Cargo's native minimum publish age (not before 2026-11-19).** Rust 1.100 (due 2026-11-12) stabilises `registry.global-min-publish-age`; on 1.98 the key only warns. Wait until the release is itself at least 7 days old (later if a point release follows), then:
   - bump `rust-toolchain.toml` to 1.100.x, and the `Dockerfile`'s `RUST_IMAGE` tag and digest to match (`scripts/ci/docker-toolchain.sh` fails until they agree);
   - add `.cargo/config.toml` with `[registry]` `global-min-publish-age = "7 days"`;
   - remove `scripts/ci/crate-age.sh` and its line in `scripts/ci/check.sh`, and drop "dependency age" from the `check` recipe comment in the justfile (Cargo enforces it at resolve time instead);
   - confirm `cargo update` then respects the age and `just check` and CI still pass.

## Backlog

- **`check` previews the sign-only checks:** today `check` skips the rate limit, the daily cap and approval, so a clean `check` can still be refused by `sign`. Evaluate the limits (they only read the audit log) and refuse a `deny` key in `check` too, and note in the report when a `confirm` key would need a human to approve.
- **`serve` thread cap:** one thread per request is unbounded today; cap concurrent requests and answer the rest with 503.
- **SPL Token authority check:** refuse top-level SPL Token `Transfer` / `Approve` (and their `Checked` forms) whose authority is the signing key, using the public SPL Token instruction layout. Today such instructions pass on program id alone, so a hand-written payload could move tokens from a token account the key owns.
- **Key stores:** an encrypted-file backend (age, passphrase at `serve` start) and macOS Keychain / Secret Service backends, for running outside a container. Check first whether a Keychain item can be isolated from other processes of the same user.
- **Local-validator integration tests:** prove the outcomes that only fake-chain unit tests cover today: `failed` (exit 12, landed with a program error), `expired` (exit 13), and the one-time re-sign on `BlockhashNotFound`.
- **Releases:** reproducible builds, releases with checksums, attestations and an SBOM, and an external review before any mainnet use.
