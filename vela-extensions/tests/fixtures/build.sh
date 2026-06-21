#!/usr/bin/env bash
# Build the test-fixture components from the guest crates. Run from anywhere; needs:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-tools   (or a prebuilt binary)
# The outputs are gitignored, not committed — run this before the feature-gated
# tests (`cargo test -p vela-extensions --features wasmtime-runtime`,
# `cargo test -p vela-api --features extensions`). CI runs it for you.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build_one() {
    local crate="$1" out="$2"
    cargo build --release --target wasm32-unknown-unknown --locked \
        --manifest-path "$here/$crate/Cargo.toml"
    local core="$here/$crate/target/wasm32-unknown-unknown/release/${crate//-/_}.wasm"
    # No WASI imports → no adapter needed to turn the core module into a component.
    wasm-tools component new "$core" -o "$here/$out"
    echo "wrote $here/$out"
}

build_one spam-guest spam_guest.wasm
build_one emit-guest emit_guest.wasm
build_one kv-guest kv_guest.wasm
build_one register-guest register_guest.wasm
build_one media-guest media_guest.wasm
build_one profile-guest profile_guest.wasm
build_one room-create-guest room_create_guest.wasm
