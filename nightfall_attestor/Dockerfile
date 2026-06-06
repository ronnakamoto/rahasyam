FROM rust:1.88.0 AS builder

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates

WORKDIR /app
RUN mkdir bin
COPY . .
RUN --mount=type=cache,id=cargo-registry-v4,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git-v4,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target-attestor-v4,target=/app/target,sharing=private \
    cargo build --package nightfall_attestor --release && \
    mv /app/target/release/nightfall_attestor /app/bin/attestor
FROM rust:1.88.0
WORKDIR /app

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates
# Copy application binary and configuration. The attestation service
# only needs nightfall.toml (for the attestor key + bind/log config) and
# the deployed addresses (mounted at runtime); it does not load the Nova
# proving keys for the Stage-1 (structural-binding) signing path.
COPY --from=builder /app/bin/attestor bin/
COPY .env *.env nightfall.toml ./

EXPOSE 3001
CMD ["/app/bin/attestor"]
