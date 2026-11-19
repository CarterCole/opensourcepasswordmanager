# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1.90-slim AS builder

# perl (full modules incl. FindBin) and make are needed to build vendored
# OpenSSL (pulled in by the openssl crate); gcc ships in the rust image.
RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev perl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN cargo build --release --bin secretd

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/secretd /usr/local/bin/secretd
# The server loads migrations at runtime from CARGO_MANIFEST_DIR/migrations
# (baked in as /app at build time), so ship them at that same path.
COPY --from=builder /app/migrations /app/migrations

EXPOSE 8200

ENTRYPOINT ["secretd"]
