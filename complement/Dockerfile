# Vela homeserver image for Matrix Complement compliance tests.
#
# Build (from the vela/ directory):
#   docker build -t vela-complement -f complement/Dockerfile .
#
# Run via Complement:
#   export COMPLEMENT_BASE_IMAGE=vela-complement:latest
#   cd /path/to/complement && go test -v ./tests

# --- Build stage ---------------------------------------------------------

FROM rust:1.93-slim-bookworm AS builder

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
COPY tools/vela-admin/Cargo.toml tools/vela-admin/
COPY vela-extensions/Cargo.toml vela-extensions/
COPY tools/testing/interop/Cargo.toml tools/testing/interop/

# Create stub sources so the workspace resolves for the dep-build step.
# vela-extensions is a workspace member but not a dependency of the vela binary,
# so it isn't compiled here (no wasmtime in the image build).
RUN mkdir -p vela-core/src vela-store/src vela-api/src vela-server/src tools/vela-admin/src vela-extensions/src tools/testing/interop/src \
    && echo "" > vela-core/src/lib.rs \
    && echo "" > vela-store/src/lib.rs \
    && echo "" > vela-api/src/lib.rs \
    && echo "" > vela-extensions/src/lib.rs \
    && echo "" > tools/testing/interop/src/lib.rs \
    && echo "fn main() {}" > vela-server/src/main.rs \
    && echo "fn main() {}" > tools/vela-admin/src/main.rs \
    && cargo build --release --bin vela || true

# Now copy the real sources and build for real.
COPY vela-core/ vela-core/
COPY vela-store/ vela-store/
COPY vela-api/ vela-api/
COPY vela-server/ vela-server/
COPY tools/vela-admin/ tools/vela-admin/
COPY vela-extensions/ vela-extensions/

RUN touch vela-core/src/lib.rs vela-store/src/lib.rs vela-api/src/lib.rs vela-server/src/main.rs \
              vela-extensions/src/lib.rs \
    && cargo build --release --bin vela

# --- Runtime stage -------------------------------------------------------

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/vela /usr/local/bin/vela
COPY complement/entrypoint.sh /entrypoint.sh
COPY complement/server.tls.conf /etc/vela/server.tls.conf
RUN chmod +x /entrypoint.sh

# Complement expects CS-API on 8008 and federation on 8448.
EXPOSE 8008 8448

# vela's actual cold-start is ~400ms (TLS keygen ~300ms + binary boot ~100ms).
# A long --start-period or --interval here multiplies across every Complement
# Deploy() — and the suite Deploys ~150 times. We tightened these to keep
# the test wall time honest: 200ms poll catches "ready" within one tick of
# vela actually binding, instead of waiting up to 1s for the next health probe.
HEALTHCHECK --start-period=0s --interval=200ms --timeout=2s --retries=50 \
    CMD curl -fs http://localhost:8008/_matrix/client/versions || exit 1

ENTRYPOINT ["/entrypoint.sh"]
