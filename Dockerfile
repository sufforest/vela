# vela homeserver — production image.
#
# Build:
#   docker build -t vela .
#
# Run:
#   docker run -v ./vela.toml:/etc/vela/vela.toml:ro -v vela_data:/data \
#     -p 8008:8008 vela --config /etc/vela/vela.toml
#
# For a full production stack (vela + Caddy + Prometheus + Grafana),
# see tools/deploy/docker-compose.yml.

# --- Build stage ---------------------------------------------------------

FROM rust:1.90-slim-bookworm AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libclang-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache cargo registry + dependencies by copying manifests first.
COPY Cargo.toml Cargo.lock ./
COPY vela-core/Cargo.toml vela-core/
COPY vela-store/Cargo.toml vela-store/
COPY vela-api/Cargo.toml vela-api/
COPY vela-server/Cargo.toml vela-server/

# Stub sources so the workspace resolves for the dep-build step.
RUN mkdir -p vela-core/src vela-store/src vela-api/src vela-server/src \
    && echo "" > vela-core/src/lib.rs \
    && echo "" > vela-store/src/lib.rs \
    && echo "" > vela-api/src/lib.rs \
    && echo "fn main() {}" > vela-server/src/main.rs \
    && cargo build --release --bin vela --bin vela-backup || true

# Now copy real sources and build for real.
COPY vela-core/ vela-core/
COPY vela-store/ vela-store/
COPY vela-api/ vela-api/
COPY vela-server/ vela-server/

RUN touch vela-core/src/lib.rs vela-store/src/lib.rs vela-api/src/lib.rs vela-server/src/main.rs \
    && cargo build --release --bin vela --bin vela-backup

# --- Runtime stage -------------------------------------------------------

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vela        /usr/local/bin/vela
COPY --from=builder /build/target/release/vela-backup /usr/local/bin/vela-backup

EXPOSE 8008
VOLUME /data

HEALTHCHECK --interval=10s --timeout=2s --retries=3 \
    CMD curl -fs http://localhost:8008/_matrix/client/versions || exit 1

ENTRYPOINT ["/usr/local/bin/vela"]
CMD ["--config", "/etc/vela/vela.toml"]
