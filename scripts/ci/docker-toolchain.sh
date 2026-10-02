#!/usr/bin/env bash
# Fails if the Dockerfile's Rust image tag differs from rust-toolchain.toml's channel.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
toolchain="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
image="$(sed -n 's/^ARG RUST_IMAGE=rust:\([0-9.]*\)-.*$/\1/p' Dockerfile)"
if [ -z "$toolchain" ] || [ -z "$image" ]; then
    printf 'error: could not read the toolchain (%s) or the Dockerfile Rust tag (%s)\n' "$toolchain" "$image" >&2
    exit 1
fi
if [ "$toolchain" != "$image" ]; then
    printf 'error: rust-toolchain.toml says %s but the Dockerfile builds with rust:%s\n' "$toolchain" "$image" >&2
    exit 1
fi
printf 'ok: Dockerfile and rust-toolchain.toml both use Rust %s\n' "$toolchain"
