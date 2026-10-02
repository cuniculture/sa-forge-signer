#!/usr/bin/env bash
# The lint gate shared by `just check` and CI: fmt, clippy, tests, shellcheck, advisories, dependency age.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
shellcheck scripts/ci/*.sh scripts/git-review/*.sh
scripts/ci/docker-toolchain.sh
cargo audit
scripts/ci/crate-age.sh
