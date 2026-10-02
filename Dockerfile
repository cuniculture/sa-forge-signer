# syntax=docker/dockerfile:1
# sa-forge-signer in a container: non-root, no keys or config in the image.
# Mount at run time: config /etc/sa-forge-signer/config.toml (ro), keys /run/keys (0700 dir, 0600 files),
# state /var/lib/sa-forge-signer (the audit log). See README "Run in Docker".

# Base images are pinned by digest. The Rust tag must match rust-toolchain.toml (scripts/ci/check.sh checks it).
ARG RUST_IMAGE=rust:1.98.1-slim-trixie@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7
ARG RUNTIME_IMAGE=debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

FROM ${RUST_IMAGE} AS builder
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
    && install -m 0755 target/release/sa-forge-signer /usr/local/bin/sa-forge-signer

FROM ${RUNTIME_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 signer \
    && useradd --system --uid 10001 --gid signer --no-create-home --shell /usr/sbin/nologin signer \
    && install -d -o signer -g signer -m 0700 /var/lib/sa-forge-signer /run/keys \
    && install -d -m 0755 /etc/sa-forge-signer
COPY --from=builder /usr/local/bin/sa-forge-signer /usr/local/bin/sa-forge-signer
USER 10001:10001
EXPOSE 8790
ENTRYPOINT ["/usr/local/bin/sa-forge-signer", "--config", "/etc/sa-forge-signer/config.toml"]
CMD ["serve"]
