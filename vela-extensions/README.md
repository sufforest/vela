# vela extensions

Run **sandboxed, untrusted** policy plugins at vela's server-discretion points.
Plugins are WASM components loaded at runtime — written in any language that
targets the Component Model (Rust today, via
[`vela-extension-sdk`](../extensions/sdk)) — isolated and resource-limited, so an
operator can run one without trusting its author. No other major homeserver
offers this; Synapse's modules run with full server privileges.

This README is the operator reference; the plugin-author guide is the
[SDK README](../extensions/sdk/README.md).

## Enabling it

Extensions are **opt-in at build time** so a default build stays wasmtime-free:

- The release **Docker image is built with `--features extensions`** — nothing
  to do.
- Building the binary yourself: `cargo build -p vela-server --features extensions`.
  Without the feature, the runtime is a no-op (all events allowed) and vela logs
  a warning at startup if any plugins are configured.

## Configuration

Each `[[extensions.plugin]]` block loads one component:

```toml
[[extensions.plugin]]
name = "keyword-filter"                # for logs, errors, metrics
wasm_path = "/etc/vela/plugins/keyword-filter.wasm"
event_types = ["m.room.message"]       # optional; omit to run for all events
points = ["check_event"]               # which hooks: check_event and/or on_event
fail_policy = "open"                   # "open" (default) | "closed"
fuel = 50000000                        # per-call CPU budget (≈ instructions)
wall_ms = 100                          # per-call wall-clock budget; 0 disables
memory_pages = 256                     # linear-memory cap, 64 KiB pages
config = { banned = ["spam"] }         # opaque JSON, handed to the plugin
```

| field | default | meaning |
|---|---|---|
| `name` | — (required) | identifier in logs/errors/metrics |
| `wasm_path` | — (required) | path to the `.wasm` component |
| `event_types` | all | only invoke for these event types |
| `points` | `["check_event"]` | hooks the plugin binds: `check_event` (sync decision) and/or `on_event` (async observation) |
| `fail_policy` | `open` | on trap/timeout: `open` allows, `closed` blocks |
| `fuel` | 50,000,000 | per-call instruction budget |
| `wall_ms` | 100 | per-call wall-clock budget (ms); `0` = off |
| `memory_pages` | 256 | linear-memory cap (× 64 KiB) |
| `config` | `{}` | opaque config passed to the plugin |

A missing file, an unknown `fail_policy`, or an invalid component **aborts
startup** — a misconfigured policy never silently no-ops.

## Reloading (SIGHUP)

Send the server **`SIGHUP`** (`kill -HUP <pid>`, or `systemctl reload` with an
`ExecReload`) to re-read `[extensions]` and swap the plugin set in **without a
restart** — picking up added/removed plugins, changed knobs, and updated `.wasm`
files. The swap is atomic and lock-free; in-flight sends finish on the plugin
set they started with.

If the new config is bad (missing file, invalid component, malformed TOML) the
error is logged and the **current plugin set is kept** — a reload never disarms
moderation. (Unix only; on other platforms, restart to reload.)

## What plugins can do

Two extension points (a plugin binds either or both via `points`):

- **`check_event`** — the sync decision hook, on **local sends** (message and
  state events, after auth, before persist — a block rejects the send with the
  plugin's errcode/reason, HTTP 403) and **inbound federated events** (a block
  soft-fails — see below). Returns *allow* or *block*.
- **`on_event`** — the async observation hook, on **local sends** (after the
  event is persisted, off the request path). No verdict — an observer can't
  block — for audit, metrics, and (as host capabilities land) automation. Each
  persisted event is put on a durable queue that a background worker drains and
  hands to every `on_event` plugin. Delivery is **best-effort**: at-least-once
  once an event is queued (a crash between running an observer and clearing the
  entry re-runs it on restart), so observers should be **idempotent**. The queue
  is **bounded** — a stalled or far-behind observer sheds its oldest backlog
  rather than growing on disk without limit — and a trapping, panicking, or slow
  observer is sandbox-bounded and can't stall the queue behind it.

Plugins are **stateless** and get only the **host capabilities** you grant — no
network, disk, or syscalls. Today the one capability is **logging**: a plugin can
write a line to vela's log, emitted at the `vela::extensions::plugin` target and
tagged with the plugin's name (so you can filter or route it), with the message
truncated and the line count per call bounded so a chatty plugin can't flood the
log. Otherwise a plugin sees only the event and its own config. (`emit-event` and
a small `kv` store are planned as further capabilities.)

## Security model

- **Sandboxed:** memory-isolated; a plugin cannot read host memory or other
  plugins' memory.
- **Bounded:** every call has a fuel (CPU), memory, and optional wall-clock
  budget; exceeding any traps the call.
- **Fail policy:** a trapping/erroring plugin is resolved per its `fail_policy` —
  `open` favors availability, `closed` favors safety.
- **Multiple plugins** at a point are **block-if-any** (any block wins).
- **Federation:** the decision hook also runs on **inbound federated events**. A
  block there is **soft-failed**, never hard-rejected: the event is still stored
  and still served to peer servers (so the room DAG stays consistent across the
  federation), but it's hidden from your local clients (`/sync` and `/event`).
  That's the only spec-safe moderation across federation — you can't make a
  remote server un-send an event, but you can keep it from your users.

## Writing a plugin

See the [SDK README](../extensions/sdk/README.md) and the
[`keyword-filter` example](../extensions/examples/keyword-filter).
