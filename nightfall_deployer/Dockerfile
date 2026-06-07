# syntax=docker/dockerfile:1-labs
FROM ghcr.io/foundry-rs/foundry:v1.3.1 AS foundry
FROM rust:1.88.0 AS builder

COPY ./configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates

WORKDIR /app
RUN mkdir -p bin
COPY --exclude=configuration/bin/*  . .
RUN mkdir -p configuration/bin/keys configuration/bin/nova_keys
COPY configuration/bin/keys/ configuration/bin/keys/
COPY configuration/bin/nova_key[s]/ configuration/bin/nova_keys/
RUN --mount=type=cache,id=cargo-registry-v4,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git-v4,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target-client-v4,target=/app/target,sharing=private \
    cargo build --package nightfall_deployer --release && \
    mv /app/target/release/nightfall_deployer /app/bin/deployer
FROM node:20-slim AS node_tooling
RUN npm i -g @openzeppelin/upgrades-core@^1.37.0

FROM rust:1.88.0
WORKDIR /app
COPY ./configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates
COPY --from=node_tooling /usr/local/bin/ /usr/local/bin/
COPY --from=node_tooling /usr/local/lib/node_modules/ /usr/local/lib/node_modules/

# Copy application binaries and configuration
COPY --from=builder /app/bin/deployer bin/
COPY --from=builder /app/blockchain_assets blockchain_assets/
COPY --from=builder /app/configuration/bin/keys configuration/bin/keys/
COPY --from=builder /app/configuration/bin/nova_keys configuration/bin/nova_keys/
COPY .env *.env nightfall.toml foundry.toml ./
COPY --from=foundry /usr/local/bin/forge ./forge

ENV PATH=/app:$PATH
RUN mkdir -p nightfall_deployer/blockchain_assets && \
    ln -s /app/blockchain_assets /app/nightfall_deployer/blockchain_assets

CMD ["/app/bin/deployer"]
