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
points = ["check_event"]               # check_event/on_event/check_registration/check_media_upload/check_profile_update/check_room_create
capabilities = []                      # host caps to grant, e.g. ["emit-event"]
client_ip = "none"                     # check_registration IP tier: none|hashed|full
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
| `points` | `["check_event"]` | hooks the plugin binds: `check_event` (decision on events), `on_event` (async observation), `check_registration` (decision at signup), `check_media_upload` (decision at media upload), `check_profile_update` (decision at a profile change), `check_room_create` (decision at room creation) |
| `capabilities` | `[]` | host capabilities to grant (least-privilege): `emit-event` (post as its bot), `kv` (private key→value store). `logging` is always on |
| `client_ip` | `"none"` | what a `check_registration` plugin sees of the client IP: `none`, `hashed` (a rate-limit token, no PII), or `full` (raw IP) |
| `fail_policy` | `open` | on trap/timeout: `open` allows, `closed` blocks |
| `fuel` | 50,000,000 | per-call instruction budget |
| `wall_ms` | 100 | per-call wall-clock budget (ms); `0` = off |
| `memory_pages` | 256 | linear-memory cap (× 64 KiB) |
| `config` | `{}` | opaque config passed to the plugin |

A missing file, an unknown `fail_policy`, or an invalid component **aborts
startup** — a misconfigured policy never silently no-ops.

**Capability check.** At load, vela inspects what each plugin's code actually
imports and reconciles it against your grant. If a plugin needs a capability you
didn't grant, startup aborts with an error that names it and the fix — e.g.
*"plugin 'room-policy': requires the `kv` capability … add `kv` to this plugin's
`capabilities`"* — instead of a cryptic instantiation failure. A capability you
grant but the plugin never uses is harmless and just logged. The component is the
source of truth (the Component Model drops imports a plugin doesn't reference), so
this can't be fooled by a stale or mistaken declaration — you always see exactly
what a plugin can reach for.

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

Six extension points (a plugin binds any of them via `points`):

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
- **`check_registration`** — the sync decision hook at **`/register`**, before
  the account is created (anti-spam signup). The plugin sees the requested
  username, the registration method, and — per its `client_ip` tier — an IP token
  for rate-limiting; a block rejects the signup (403, plugin's errcode). The `kv`
  capability works here, so a stateful rate-limiter is natural. The IP comes from
  `X-Forwarded-For`, so it's only trustworthy behind a **reverse proxy that
  overwrites that header** — a directly-exposed server lets clients spoof it, and
  since a plugin can *block* on it, only grant the `hashed`/`full` IP tiers when
  you're behind such a proxy. The `hashed` tier gives a per-client rate-limit key
  that reveals no actual IP.
- **`check_media_upload`** — the sync decision hook at media upload, after the
  bytes are stored but **before** the upload is downloadable; a block deletes the
  stored bytes and rejects the upload (403, plugin's errcode). The plugin sees the
  **content type, filename, size, uploader, and a SHA-256** computed in-stream — a
  hash, not the bytes — so it can match known-bad hashes or enforce type/size
  policy without the raw content. Media in E2EE rooms is encrypted before upload,
  so a plugin only ever sees *ciphertext* there; this scans cleartext uploads. The
  `kv` capability works here, so a hash blocklist or per-uploader quota is natural.
- **`check_profile_update`** — the sync decision hook when a user sets their own
  display name or avatar (the `/profile` endpoints), **before** the change is
  persisted or propagated; a block rejects it (403, plugin's errcode). The plugin
  sees the user, which field (display name / avatar), and the proposed value — for
  an avatar that's the **mxc:// URI**, not the image (image scanning is
  `check_media_upload`'s job). Use it for anti-impersonation and name/avatar
  policy. Local only: a remote user's profile change arrives as an `m.room.member`
  event and is a `check_event` concern. The `kv` capability works here (per-user
  churn limits).
- **`check_room_create`** — the sync decision hook at **`POST /createRoom`**,
  before anything is persisted; a block rejects the creation (403, plugin's
  errcode). The plugin sees the creator, the resolved preset, the requested
  visibility (so a no-public-rooms rule keys on it), name/topic, the alias
  localpart, the invite list (an invite-bomb signal), and `is_direct`. Use it for
  anti-spam, invite-bomb caps, no-public-rooms, and alias policy. Local only:
  rooms federate via joins, not creation. The `kv` capability works here (per-creator
  rate limits) — the [`room-policy` example](../extensions/examples/room-policy)
  drives all of these from a declarative config block.

Plugins are **stateless** and get only the **host capabilities** you grant — no
network, disk, or syscalls. Granted least-privilege per plugin via `capabilities`:

- **`logging`** (always on) — write a line to vela's log at the
  `vela::extensions::plugin` target, tagged with the plugin's name (so you can
  filter or route it); the message is truncated and the per-call line count
  bounded so a chatty plugin can't flood the log. Pure output.
- **`emit-event`** (grant with `capabilities = ["emit-event"]`, needs the
  `on_event` point) — post an event into a room as the plugin's own bot user,
  `@_ext_<name>`. The bot is a real, passwordless user; **invite it** to a room
  and give it power level for it to act there — emits go through normal room
  authorization, so an un-invited bot just gets rejected (no auth bypass). v1
  allows messages, reactions, and redactions (no state events); emits are
  rate-capped per plugin, and a plugin never observes its own emitted events
  (loop protection). Use it for auto-responders, moderation actions, and bots.
- **`kv`** (grant with `capabilities = ["kv"]`) — a small private key→value
  store, `get`/`set`/`delete` over opaque bytes, with an optional per-key TTL.
  Each plugin gets its own isolated namespace (it can't read another's). Works
  from **both** points, so a `check_event` can be **stateful** — rate-limit a
  user, dedup, count toward a threshold. Bounded: per-op size caps and a
  per-plugin byte quota (`quota-exceeded` when full); set a TTL on counters and
  dedup markers so they self-clean. Use it to give a bot memory.

Otherwise a plugin sees only the event and its own config.

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
