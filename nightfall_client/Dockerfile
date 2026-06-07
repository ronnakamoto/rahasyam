# syntax=docker/dockerfile:1-labs
FROM rust:1.88.0 AS builder

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates

WORKDIR /app
RUN mkdir bin
COPY --exclude=configuration/bin/*  . .
RUN mkdir -p configuration/bin/keys configuration/bin/nova_keys
COPY configuration/bin/keys/ configuration/bin/keys/
COPY configuration/bin/nova_key[s]/ configuration/bin/nova_keys/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo build --package nightfall_client --features nova-v1 --release && \
    mv /app/target/release/nightfall_client /app/bin/client
FROM rust:1.88.0
WORKDIR /app

COPY configuration/trust/ZscalerRootCertificate-2048-SHA256-Feb2025.pem /usr/local/share/ca-certificates/zscaler-root-feb2025.crt
RUN chmod 644 /usr/local/share/ca-certificates/zscaler-root-feb2025.crt && update-ca-certificates

# Copy application binaries and configuration
COPY --from=builder /app/bin/client bin/
RUN mkdir -p configuration/bin/keys configuration/bin/nova_keys
COPY configuration/bin/keys/ configuration/bin/keys/
COPY configuration/bin/nova_key[s]/ configuration/bin/nova_keys/
COPY .env *.env nightfall.toml ./

EXPOSE 3000
CMD ["/app/bin/client"]