#!/usr/bin/env bash
# Build the example plugins to committed `.wasm` components. Needs:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-tools
# The built artifacts are committed so the host integration tests (and operators)
# have a ready component without a wasm toolchain.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

build() {
    local crate="$1" out="$2"
    cargo build --release --target wasm32-unknown-unknown \
        --manifest-path "$here/Cargo.toml" -p "$crate"
    local core="$here/target/wasm32-unknown-unknown/release/${crate//-/_}.wasm"
    # No WASI imports → no adapter needed.
    wasm-tools component new "$core" -o "$out"
    echo "wrote $out"
}

build keyword-filter "$here/examples/keyword-filter/keyword-filter.wasm"
