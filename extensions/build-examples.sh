#!/usr/bin/env bash
# Build the example plugins to `.wasm` components. Needs:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-tools   (or a prebuilt binary)
# The outputs are gitignored, not committed — run this before the host
# example test (`cargo test -p vela-extensions --features wasmtime-runtime`), and
# to produce a component to hand an operator. CI runs it for you.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build() {
    local crate="$1" out="$2"
    cargo build --release --target wasm32-unknown-unknown --locked \
        --manifest-path "$here/Cargo.toml" -p "$crate"
    local core="$here/target/wasm32-unknown-unknown/release/${crate//-/_}.wasm"
    # No WASI imports → no adapter needed.
    wasm-tools component new "$core" -o "$out"
    echo "wrote $out"
}

build keyword-filter "$here/examples/keyword-filter/keyword-filter.wasm"
build room-policy "$here/examples/room-policy/room-policy.wasm"
