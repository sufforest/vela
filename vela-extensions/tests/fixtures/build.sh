#!/usr/bin/env bash
# Rebuild the committed test-fixture components. Run from anywhere; needs:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-tools
# The outputs are committed so host tests need no wasm toolchain.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_one() {
    local crate="$1" out="$2"
    cargo build --release --target wasm32-unknown-unknown \
        --manifest-path "$here/$crate/Cargo.toml"
    local core="$here/$crate/target/wasm32-unknown-unknown/release/${crate//-/_}.wasm"
    # No WASI imports → no adapter needed to turn the core module into a component.
    wasm-tools component new "$core" -o "$here/$out"
    echo "wrote $here/$out"
}

build_one spam-guest spam_guest.wasm
build_one emit-guest emit_guest.wasm
build_one kv-guest kv_guest.wasm
