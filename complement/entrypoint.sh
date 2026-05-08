#!/bin/sh
# Complement entrypoint for Vela.
#
# Complement starts a fresh container per test run, mounting its CA at
# /complement/ca/ca.{crt,key} and passing SERVER_NAME as an environment
# variable. We generate a server TLS cert signed by that CA, write a
# vela.toml, and exec the server.

set -eu

: "${SERVER_NAME:?SERVER_NAME env var must be set by Complement}"

CONF_DIR="${CONF_DIR:-/conf}"
DATA_DIR="${DATA_DIR:-/data}"
CA_CRT="${CA_CRT:-/complement/ca/ca.crt}"
CA_KEY="${CA_KEY:-/complement/ca/ca.key}"

mkdir -p "$CONF_DIR" "$DATA_DIR"

# --- Generate TLS cert signed by Complement CA --------------------------
# Standard Complement-runtime pattern: openssl CSR + sign with the mounted
# CA. SAN covers SERVER_NAME plus localhost fallback.
#
# Only generate if one doesn't already exist (speeds up container reuse).
if [ ! -f "$CONF_DIR/server.tls.crt" ]; then
    echo "[vela-complement] generating TLS cert for SERVER_NAME=$SERVER_NAME"

    # Replace placeholder in the template with the actual SERVER_NAME.
    sed "s/__SERVER_NAME__/$SERVER_NAME/g" /etc/vela/server.tls.conf \
        > "$CONF_DIR/server.tls.conf"

    openssl genrsa -out "$CONF_DIR/server.tls.key" 2048 2>/dev/null

    openssl req -new \
        -config "$CONF_DIR/server.tls.conf" \
        -key "$CONF_DIR/server.tls.key" \
        -out "$CONF_DIR/server.tls.csr" \
        -subj "/CN=$SERVER_NAME" \
        -reqexts SAN 2>/dev/null

    openssl x509 -req \
        -in "$CONF_DIR/server.tls.csr" \
        -CA "$CA_CRT" \
        -CAkey "$CA_KEY" \
        -set_serial 1 \
        -out "$CONF_DIR/server.tls.crt" \
        -extfile "$CONF_DIR/server.tls.conf" \
        -extensions SAN 2>/dev/null

    rm -f "$CONF_DIR/server.tls.csr"
fi

# --- Write vela.toml ----------------------------------------------------

cat > "$CONF_DIR/vela.toml" <<EOF
[server]
name = "$SERVER_NAME"
bind = "0.0.0.0"
port = 8008
# Trust the Complement CA for outbound federation: all test homeservers'
# certs chain to this CA, not to a public root.
extra_ca_certs = ["$CA_CRT"]

[server.tls]
port = 8448
cert_file = "$CONF_DIR/server.tls.crt"
key_file = "$CONF_DIR/server.tls.key"

[database]
path = "$DATA_DIR"

# Complement registers many users from the test runner's IP; the
# production rate-limit defaults would cascade-fail unrelated tests.
[rate_limit]
enabled = false
EOF

# Append [[appservices]] sections for any registration files Complement
# mounted at /complement/appservice/*.yaml. tests using
# BlueprintHSWithApplicationService land here; everything else has an
# empty directory and skips this loop.
if [ -d /complement/appservice ]; then
    for reg in /complement/appservice/*.yaml; do
        [ -f "$reg" ] || continue
        echo "[vela-complement] registering appservice $reg"
        echo "" >> "$CONF_DIR/vela.toml"
        echo "[[appservice]]" >> "$CONF_DIR/vela.toml"
        echo "registration = \"$reg\"" >> "$CONF_DIR/vela.toml"
    done
fi

echo "[vela-complement] starting vela with config $CONF_DIR/vela.toml"
exec /usr/local/bin/vela --config "$CONF_DIR/vela.toml"
