# vela-extension-sdk

Write sandboxed WASM extensions for the [vela](https://github.com/sufforest/vela)
Matrix homeserver in Rust.

A vela extension is a WASM component that vela loads at runtime and runs at a
server decision, observation, or read-path point — on local sends and inbound
federated events, at registration and login, at media upload, profile changes and
room creation, and as a `/sync` timeline filter. It runs **sandboxed**
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
- **`Plugin::check_registration(&Registration) -> Decision`** — the signup
  decision hook at `/register` (default: allow). `Registration` gives
  `username()`, `kind()`, `client_ip()` (an opaque rate-limit token per the
  operator's tier), and `config()`. The `kv` capability works here, so a stateful
  per-IP rate-limiter is a few lines.
- **`Plugin::check_login(&Login) -> Decision`** — the login decision hook
  (default: allow), at `/login` before the password is verified. `Login` gives
  `username()`, `login_type()`, `client_ip()` (an opaque rate-limit token per the
  operator's tier), `kv()`, and `config()`. Use it for anti-brute-force / IP
  policy; a per-IP attempt counter with `kv` is a few lines. A block keys on
  username/IP, not the auth result, so it never leaks credential validity.
- **`Plugin::check_media_upload(&Media) -> Decision`** — the media-upload decision
  hook (default: allow), after the bytes are stored but before the upload is
  downloadable. `Media` gives `content_type()`, `filename()`, `size()`,
  `uploader()`, `sha256()` (computed in-stream — a hash, not the bytes), and
  `config()`. Match known-bad hashes or enforce type/size policy; a block deletes
  the stored bytes. Media in E2EE rooms is encrypted before upload, so you only see
  ciphertext there. The `kv` capability works here too (hash blocklists, quotas).
- **`Plugin::check_profile_update(&Profile) -> Decision`** — the profile-update
  decision hook (default: allow), when a user sets their own display name or
  avatar, before it's persisted. `Profile` gives `user_id()`, `field()` (a
  `ProfileField`), `value()` (the proposed value, `None` when clearing — for an
  avatar the mxc:// URI, not the image), and `config()`. Use it for
  anti-impersonation and name/avatar policy; the `kv` capability works here too
  (per-user churn limits).
- **`Plugin::check_room_create(&RoomCreate) -> Decision`** — the room-create
  decision hook (default: allow), at `createRoom` before anything is persisted.
  `RoomCreate` gives `creator()`, `room_id()`, `room_version()`, `preset()`,
  `visibility()`, `name()`, `topic()`, `alias_localpart()`, `invite()` (the
  invited users), `is_direct()`, and `config()`. Use it for anti-spam, invite-bomb
  caps, no-public-rooms, and alias policy; the `kv` capability works here too
  (per-creator rate limits), so a config block can drive declarative rules.
- **`Plugin::filter_sync_event(&SyncEvent) -> bool`** — the read-path filter
  (default: `true` = show), as `/sync` builds a user's timeline. Return `false` to
  hide the event from this viewer. It shapes the live `/sync` view, **not** access:
  a hidden event is still fetchable via `/messages`/`/context`/`/event`, so use it
  for view-shaping, not isolation (block at write time for real removal).
  `SyncEvent` gives `viewer()` (the user syncing), `room_id()`, `event_type()`,
  `sender()`, `event()` (parsed JSON), `message_body()`, and `config()`. It runs on
  the `/sync` hot path per delivered timeline event, so keep it cheap and scope it
  with `event_types`; the `kv` capability works here too.
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
  - `caps.kv()` (a [`Kv`] handle: `.get` / `.set` / `.set_ttl` / `.delete` /
    `.get_json` / `.set_json`), plus the `caps.kv_get(...)` etc. shorthands — your
    plugin's private key→value store (needs the `kv` capability). Keys/values are
    size-capped and a per-plugin byte quota applies (`KvError::QuotaExceeded`);
    use a TTL on counters/markers so they self-clean.
- **`Kv` from any decision hook** — kv isn't on_event-only. Every decision
  context exposes the same store via `.kv()` — `event.kv()`, `reg.kv()`,
  `media.kv()`, `profile.kv()`, `room.kv()` — so a `check_*` hook can be stateful
  (a rate-limit, dedup, or per-user counter is a few lines). Same `Kv` API as
  `caps.kv()`.
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
