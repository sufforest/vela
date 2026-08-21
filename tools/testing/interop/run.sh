#!/usr/bin/env bash
# vela <-> Synapse federation interop rig.
#
# Boots BOTH homeservers locally — vela as the freshly-built release binary
# on the host, Synapse from its official Docker image — federates them over
# loopback TLS, and runs the differential test suite in ./tests.
#
# Topology (why the server names look odd):
#   vela    server_name = host.docker.internal:8448  -> resolvable from
#           inside the Synapse container (with --add-host host-gateway on
#           Linux; built in on Docker Desktop). vela itself never dials it.
#   synapse server_name = localhost:9448             -> resolvable by vela
#           on the host; the port is mapped into the container.
# Both names carry explicit ports, so per spec both sides connect directly
# (no .well-known / SRV), which is what makes loopback federation work.
#
# TLS: a throwaway CA signs both leafs. vela trusts the CA via
# [server] extra_ca_certs and does full verification of Synapse's cert
# (SAN=localhost). Synapse runs federation_verify_certificates: false so
# vela's cert content doesn't matter. If TLS ever misbehaves, vela's
# [federation] http_peers map is the plain-HTTP escape hatch.
#
# Usage:
#   ./run.sh            build + boot + test + teardown
#   ./run.sh --up-only  boot the rig and print the env exports, no teardown
#   ./run.sh --down     tear down a rig left behind by --up-only
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WORK="${INTEROP_WORKDIR:-$ROOT/target/interop}"
SYNAPSE_IMAGE="${SYNAPSE_IMAGE:-matrixdotorg/synapse:latest}"
CONTAINER=vela-interop-synapse

VELA_CS_PORT=8008
VELA_FED_PORT=8448
SYN_CS_PORT=9008
SYN_FED_PORT=9448
VELA_NAME="host.docker.internal:$VELA_FED_PORT"
SYN_NAME="localhost:$SYN_FED_PORT"

down() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    if [[ -f "$WORK/vela.pid" ]]; then
        kill "$(cat "$WORK/vela.pid")" >/dev/null 2>&1 || true
        rm -f "$WORK/vela.pid"
    fi
}

if [[ "${1:-}" == "--down" ]]; then
    down
    echo "rig torn down"
    exit 0
fi

# ---------------------------------------------------------------- build vela
echo "==> building vela (release)"
cargo build --release --manifest-path "$ROOT/Cargo.toml" -p vela-server

# ------------------------------------------------------------------- workdir
down
# Refuse to wipe a directory this rig didn't create — guards against a
# mistyped INTEROP_WORKDIR pointing at real data. The marker file is laid
# down right after creation below.
if [[ -e "$WORK" && ! -e "$WORK/.vela-interop-rig" ]]; then
    echo "!! $WORK exists but has no .vela-interop-rig marker; refusing to delete it" >&2
    exit 1
fi
rm -rf "$WORK"
mkdir -p "$WORK"/{certs,synapse,vela-db}
touch "$WORK/.vela-interop-rig"

# From here on, any exit (including a failed boot step) tears the rig down;
# --up-only disarms this before returning.
trap down EXIT

# --------------------------------------------------------------------- certs
echo "==> generating throwaway CA + leaf certs"
CERTS="$WORK/certs"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$CERTS/ca.key" \
    -out "$CERTS/ca.pem" -days 7 -subj "/CN=vela-interop-ca" 2>/dev/null
# Synapse leaf: vela verifies this one, so SAN must cover `localhost`.
openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/synapse.key" \
    -out "$CERTS/synapse.csr" -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$CERTS/synapse.csr" -CA "$CERTS/ca.pem" \
    -CAkey "$CERTS/ca.key" -CAcreateserial -days 7 \
    -out "$CERTS/synapse.crt" \
    -extfile <(printf "subjectAltName=DNS:localhost") 2>/dev/null
# vela leaf: Synapse doesn't verify, any cert will do.
openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/vela.key" \
    -out "$CERTS/vela.csr" -subj "/CN=host.docker.internal" 2>/dev/null
openssl x509 -req -in "$CERTS/vela.csr" -CA "$CERTS/ca.pem" \
    -CAkey "$CERTS/ca.key" -CAcreateserial -days 7 \
    -out "$CERTS/vela.crt" \
    -extfile <(printf "subjectAltName=DNS:host.docker.internal") 2>/dev/null

# ----------------------------------------------------------------- vela boot
echo "==> starting vela ($VELA_NAME)"
cat > "$WORK/vela.toml" <<EOF
[server]
name = "$VELA_NAME"
bind = "0.0.0.0"
port = $VELA_CS_PORT
extra_ca_certs = ["$CERTS/ca.pem"]

[server.tls]
port = $VELA_FED_PORT
cert_file = "$CERTS/vela.crt"
key_file = "$CERTS/vela.key"

[database]
path = "$WORK/vela-db"

[federation]
enabled = true
# Loopback peers resolve to private addresses; the SSRF guard would
# (correctly) refuse them in production. This is the documented test knob.
private_ip_block = false

[rate_limit]
enabled = false
EOF
"$ROOT/target/release/vela" --config "$WORK/vela.toml" >"$WORK/vela.log" 2>&1 &
echo $! > "$WORK/vela.pid"

# -------------------------------------------------------------- synapse boot
echo "==> generating Synapse config (signing key) via $SYNAPSE_IMAGE"
docker run --rm \
    -v "$WORK/synapse:/data" \
    -e SYNAPSE_SERVER_NAME="$SYN_NAME" \
    -e SYNAPSE_REPORT_STATS=no \
    "$SYNAPSE_IMAGE" generate >/dev/null

cp "$CERTS/synapse.crt" "$CERTS/synapse.key" "$WORK/synapse/"
cat > "$WORK/synapse/homeserver.yaml" <<EOF
server_name: "$SYN_NAME"
pid_file: /data/homeserver.pid
report_stats: false
signing_key_path: "/data/$SYN_NAME.signing.key"
log_config: "/data/$SYN_NAME.log.config"
media_store_path: /data/media_store
database:
  name: sqlite3
  args:
    database: /data/homeserver.db

listeners:
  - port: $SYN_CS_PORT
    type: http
    tls: false
    bind_addresses: ['0.0.0.0']
    resources: [{names: [client], compress: false}]
  - port: $SYN_FED_PORT
    type: http
    tls: true
    bind_addresses: ['0.0.0.0']
    resources: [{names: [federation], compress: false}]

tls_certificate_path: /data/synapse.crt
tls_private_key_path: /data/synapse.key
# The rig's CA is throwaway; vela's cert is not worth verifying here.
federation_verify_certificates: false
# Direct key fetch only — no matrix.org perspectives on a loopback rig.
trusted_key_servers: []
suppress_key_server_warning: true

enable_registration: true
enable_registration_without_verification: true

# The suite drives both servers hard; stock limits would 429 it.
rc_message: {per_second: 1000, burst_count: 1000}
rc_registration: {per_second: 1000, burst_count: 1000}
rc_login:
  address: {per_second: 1000, burst_count: 1000}
  account: {per_second: 1000, burst_count: 1000}
  failed_attempts: {per_second: 1000, burst_count: 1000}
rc_joins:
  local: {per_second: 1000, burst_count: 1000}
  remote: {per_second: 1000, burst_count: 1000}
rc_invites:
  per_room: {per_second: 1000, burst_count: 1000}
  per_user: {per_second: 1000, burst_count: 1000}
rc_federation:
  window_size: 1000
  sleep_limit: 1000
  sleep_delay: 1
  reject_limit: 1000
  concurrent: 100
EOF
chmod -R a+rwX "$WORK/synapse"

echo "==> starting Synapse ($SYN_NAME)"
# Publish only on loopback: vela (on the host) is the sole consumer of
# both ports, and the rig runs with open registration + no rate limits —
# it has no business being LAN-reachable. (vela's own 8448 must stay on
# 0.0.0.0 so the container can reach it via host-gateway.)
docker run -d --name "$CONTAINER" \
    --add-host host.docker.internal:host-gateway \
    -p "127.0.0.1:$SYN_CS_PORT:$SYN_CS_PORT" -p "127.0.0.1:$SYN_FED_PORT:$SYN_FED_PORT" \
    -v "$WORK/synapse:/data" \
    "$SYNAPSE_IMAGE" >/dev/null

# ------------------------------------------------------------------ wait up
wait_up() {
    local name="$1" url="$2" deadline=$((SECONDS + 120))
    until curl -fsS "$url" >/dev/null 2>&1; do
        if (( SECONDS >= deadline )); then
            echo "!! $name did not come up; recent logs:"
            [[ "$name" == vela ]] && tail -30 "$WORK/vela.log" || docker logs --tail 30 "$CONTAINER"
            exit 1
        fi
        sleep 1
    done
    echo "    $name is up"
}
wait_up vela "http://127.0.0.1:$VELA_CS_PORT/_matrix/client/versions"
wait_up synapse "http://127.0.0.1:$SYN_CS_PORT/_matrix/client/versions"

export INTEROP_VELA_CS="http://127.0.0.1:$VELA_CS_PORT"
export INTEROP_SYNAPSE_CS="http://127.0.0.1:$SYN_CS_PORT"
export INTEROP_VELA_NAME="$VELA_NAME"
export INTEROP_SYNAPSE_NAME="$SYN_NAME"

if [[ "${1:-}" == "--up-only" ]]; then
    trap - EXIT
    echo "rig is up; to drive it yourself:"
    echo "  export INTEROP_VELA_CS=$INTEROP_VELA_CS"
    echo "  export INTEROP_SYNAPSE_CS=$INTEROP_SYNAPSE_CS"
    echo "  export INTEROP_VELA_NAME=$INTEROP_VELA_NAME"
    echo "  export INTEROP_SYNAPSE_NAME=$INTEROP_SYNAPSE_NAME"
    echo "tear down with: $0 --down"
    exit 0
fi

# --------------------------------------------------------------------- test
echo "==> running interop suite"
status=0
cargo test --manifest-path "$ROOT/Cargo.toml" -p vela-interop -- --nocapture || status=$?
if (( status != 0 )); then
    # Snapshot Synapse's logs before teardown removes the container.
    docker logs "$CONTAINER" > "$WORK/synapse.log" 2>&1 || true
    echo "!! suite failed — logs: $WORK/vela.log, $WORK/synapse.log"
    echo "!! divergence evidence (if any): $ROOT/target/interop-evidence/"
fi
exit "$status"
