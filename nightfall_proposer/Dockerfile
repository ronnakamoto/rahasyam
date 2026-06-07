FROM rust:1.88.0 AS builder

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates

WORKDIR /app
RUN mkdir bin
COPY . .
RUN --mount=type=cache,id=cargo-registry-v4,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git-v4,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target-client-v4,target=/app/target,sharing=private \
    cargo build --package nightfall_proposer --features nova-v1 --release && \
    mv /app/target/release/nightfall_proposer /app/bin/proposer
FROM rust:1.88.0
WORKDIR /app

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates
# Copy application binaries and configuration
COPY --from=builder /app/bin/proposer bin/
RUN mkdir -p configuration/bin/keys configuration/bin/nova_keys
COPY configuration/bin/keys/ configuration/bin/keys/
COPY configuration/bin/nova_key[s]/ configuration/bin/nova_keys/
COPY .env *.env nightfall.toml ./

EXPOSE 3000
CMD ["/app/bin/proposer"]
