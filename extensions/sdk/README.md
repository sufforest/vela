# vela-extension-sdk

Write sandboxed WASM extensions for the [vela](https://github.com/sufforest/vela)
Matrix homeserver in Rust.

A vela extension is a WASM component that vela loads at runtime and runs at a
server decision point — today, on locally-sent events. It runs **sandboxed**
(memory-isolated, with per-call CPU/memory/wall-clock budgets) and gets no host
access it isn't granted, so an operator can run one without trusting its author.

## Write one

```rust
use serde::Deserialize;
use vela_extension_sdk::{export_plugin, Decision, Event, Plugin};

#[derive(Deserialize, Default)]
struct Config {
    banned: Vec<String>,
}

struct KeywordFilter;

impl Plugin for KeywordFilter {
    fn check_event(ev: &Event) -> Decision {
        let cfg: Config = ev.config();
        match ev.message_body() {
            Some(body) if cfg.banned.iter().any(|w| body.contains(w)) => {
                Decision::block("message contains a blocked term")
            }
            _ => Decision::allow(),
        }
    }
}

export_plugin!(KeywordFilter);
```

`Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
# Not yet published to crates.io — use a git or path dependency for now:
vela-extension-sdk = { git = "https://github.com/sufforest/vela" }
serde = { version = "1", features = ["derive"] }
```

See [`examples/keyword-filter`](../examples/keyword-filter) for the full version.

## The API

`Plugin` has two hooks — implement either or both; the unused one defaults to a
no-op, and the operator's `points` config decides which the host invokes.

- **`Plugin::check_event(&Event) -> Decision`** — the sync decision hook (default:
  allow). Runs on the request path; a block rejects the send or soft-fails an
  inbound federated event.
- **`Plugin::on_event(&Event, &Caps)`** — the async observation hook (default:
  no-op). Runs off the request path after persist; no return (an observer can't
  block). Delivery is at-least-once, so make it idempotent.
- **`Caps`** — the host-capabilities handle:
  - `caps.log(msg)` (and `.debug` / `.warn` / `.error` / `.trace`) — write a line
    to vela's log, tagged with your plugin name; truncated and rate-limited by the
    host, so it's safe to call freely. Always available.
  - `caps.emit(room_id, event_type, &content)` / `caps.send_text(room_id, body)` —
    post an event into a room as your `@_ext_<name>` bot, returning the new
    event's id. Needs the operator-granted `emit-event` capability and only works
    from `on_event`; the bot must be invited to the room with power level, or you
    get `EmitError::Unauthorized`. Allowed types: message, reaction, redaction;
    rate-capped per plugin.
  - `caps.kv_get(key)` / `kv_set(key, val)` / `kv_set_ttl(key, val, ttl_ms)` /
    `kv_delete(key)` (plus `kv_get_json` / `kv_set_json`) — your plugin's private
    key→value store (needs the `kv` capability). Works from **both** hooks, so
    `check_event` can be stateful (rate-limit, dedup). Keys/values are
    size-capped and a per-plugin byte quota applies (`KvError::QuotaExceeded`);
    use a TTL on counters/markers so they self-clean.
- **`Event`** — `room_id()`, `sender()`, `event_type()`, `origin()`,
  `event()` (the full event as parsed JSON), `message_body()` (`content.body`
  if present), and `config::<T>()` / `try_config::<T>()` to read your
  operator-supplied config block as a typed struct.
- **`Decision`** — `allow()`, `block(reason)`, or `block_with(errcode, reason)`
  for a custom Matrix errcode.

## Build

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-tools                       # once

cargo build --release --target wasm32-unknown-unknown
wasm-tools component new \
    target/wasm32-unknown-unknown/release/my_plugin.wasm \
    -o my-plugin.wasm
```

`my-plugin.wasm` is a Component-Model component — hand it to an operator.

## Install into vela

The operator points vela at the file in `vela.toml`:

```toml
[[extensions.plugin]]
name = "keyword-filter"
wasm_path = "/etc/vela/plugins/keyword-filter.wasm"
event_types = ["m.room.message"]      # optional scope; omit for all events
fail_policy = "open"                   # "open" (allow on error) | "closed" (block)
config = { banned = ["spam"] }         # handed to your plugin verbatim
```

vela must be built with `--features extensions` (the release Docker image is).
See the [extensions guide](../../vela-extensions/README.md) for the full config
reference and the security model.

## Limits & semantics

- Your plugin is **stateless** — a fresh instance per call; nothing persists in
  memory between events.
- Per call it gets a **fuel** (≈ instruction) budget, a **memory** cap, and an
  optional **wall-clock** deadline. Exceeding any traps the call, which the host
  resolves via your `fail_policy`.
- A `block` on a **federated** event is soft-failed by the host (never a
  hard-reject) — you just return a verdict; vela applies origin policy.
