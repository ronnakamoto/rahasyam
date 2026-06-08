FROM rust:1.88.0 AS builder

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates

WORKDIR /app
RUN mkdir bin
COPY . .
RUN --mount=type=cache,id=cargo-registry-v4,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git-v4,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target-client-v4,target=/app/target,sharing=private \
    cargo build --package nightfall_proposer --features ultra-honk-v1 --release && \
    mv /app/target/release/nightfall_proposer /app/bin/proposer
FROM rust:1.88.0
WORKDIR /app

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates

# Node.js runtime + UltraHonk sidecar. The proposer verifies per-transaction
# (client) UltraHonk proofs off-chain by shelling out to the bb.js sidecar.
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/*
COPY ultrahonk_sidecar/package.json ultrahonk_sidecar/package-lock.json ultrahonk_sidecar/
RUN cd ultrahonk_sidecar && npm ci --omit=dev
COPY ultrahonk_sidecar/*.mjs ultrahonk_sidecar/nightfish_honk_client_tx.json ultrahonk_sidecar/
ENV ULTRAHONK_SIDECAR_DIR=/app/ultrahonk_sidecar

# Copy application binaries and configuration
COPY --from=builder /app/bin/proposer bin/
RUN mkdir -p configuration/bin/keys configuration/bin/nova_keys
COPY configuration/bin/keys/ configuration/bin/keys/
COPY configuration/bin/nova_key[s]/ configuration/bin/nova_keys/
COPY .env *.env nightfall.toml ./

EXPOSE 3000
CMD ["/app/bin/proposer"]
