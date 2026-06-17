#!/usr/bin/env bash
# Rebuild the committed test-fixture component. Run from anywhere; needs:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-tools
# The output `spam_guest.wasm` is committed so host tests need no wasm toolchain.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cargo build --release --target wasm32-unknown-unknown \
    --manifest-path "$here/spam-guest/Cargo.toml"

core="$here/spam-guest/target/wasm32-unknown-unknown/release/spam_guest.wasm"

# No WASI imports → no adapter needed to turn the core module into a component.
wasm-tools component new "$core" -o "$here/spam_guest.wasm"
echo "wrote $here/spam_guest.wasm"
