# vela-extensions — design

A sandboxed, language-agnostic WASM extension platform for vela. It lets
operators run **untrusted** policy/automation logic safely at the points the
Matrix spec leaves to server discretion — something no major homeserver
offers (Synapse's modules run unsandboxed with full privileges).

This document is the durable record of the design and the decisions behind
it. Build from this, not from memory.

## Thesis

vela is spec-mature, so the next frontier is **platform capability, not spec
surface**. Extend the server at its decision points (moderation, then
automation/bots) with code that **can't compromise the host**, in any
language that targets WASM, hot-loadable and resource-limited.

## The boundary (what is and isn't an extension)

- **Core (main repo) = mechanism + correctness + interop.** Anything the
  spec mandates or that federation/clients depend on being uniform: state
  resolution, auth rules, the event DAG, CS/SS endpoints, `/sync`, E2EE.
  These can never be plugins.
- **Extensions = policy at the spec's discretion points.** The spec is full
  of "the server MAY reject / determines / implementation-specific" — that
  is the entire extension surface. Plugins fill server discretion; they
  never alter protocol mechanics.

Litmus test: *if getting it wrong breaks federation or another client → core;
if it's a choice the spec lets the server make → extension.*

Extensions are **purely server-side**: no client changes, works with every
existing Matrix client. (A specific extension that wants new client-visible
surface is the exception, not the rule.)

## Runtime decision: wasmtime + Component Model, behind an optional feature

We evaluated wasmi (pure-Rust interpreter) vs wasmtime (JIT). The tradeoff:

| | wasmi (interpreter) | wasmtime (JIT) |
|---|---|---|
| Heavy-compute exec | slow | **~3–20× faster** |
| Tiny/short calls | ~equal | edge invisible |
| Dependency surface | **~5 crates** | ~60–70 crates (Cranelift, regalloc2…) |
| MSRV | conservative | bumps aggressively |
| Binary size | ~1–3 MB | ~15–40 MB |
| Component Model / WIT | no | **yes** |
| Untrusted-code track record | conservative (no codegen TCB) | **production-proven** (Fastly, fuzzed + Cranelift formal verif) |

We chose **wasmtime + the Component Model**, for these reasons:

- **Two of wasmi's wins don't apply to vela.** Binary size is irrelevant for a
  server Docker image; MSRV pressure is a non-issue because our toolchain is
  kept current. The remaining real cost of wasmtime is **dependency/audit
  surface** — which we neutralize below.
- **The migration trigger is in our roadmap, not hypothetical.** The full
  vision *includes* a heavy-compute code-judge vertical **and** a
  multi-language SDK — both are exactly the reasons to be on wasmtime. Starting
  on wasmi would mean shipping a migration we already know we'll need.
- **The Component Model is the ABI.** wasmtime + WIT means the host↔guest
  marshaling is **generated** (`wasmtime::component::bindgen!`) instead of
  hand-rolled over linear memory, and the **multi-language SDK comes for free**.
  wasmtime-with-a-hand-rolled-ABI would be the worst of both worlds (pays
  wasmtime's cost, still migrates the ABI later), so we commit fully to the
  Component Model.
- **The JIT-for-untrusted-code surface is real but industry-proven.** Fastly
  runs untrusted WASM on wasmtime at scale; Cranelift is heavily fuzzed with
  formal-verification work on its codegen. Less conservative than an
  interpreter, not reckless.

### Optional dependency (this is what makes the cost acceptable)

The runtime is gated behind a **default-on `wasmtime-runtime` Cargo feature**,
plumbed through the whole chain (`vela-server/extensions` →
`vela-api/extensions` → `vela-extensions/wasmtime-runtime`). So:

- **Feature on (shipped image):** full sandboxed extension platform.
- **Feature off (`--no-default-features`):** the crate still compiles its
  *types* (`Verdict`, `EventContext`, `PluginConfig`, `Runtime`) with **zero
  wasmtime/Cranelift crates**, and `Runtime` degrades to a **no-op that returns
  `Allow`**. A security-minded operator gets a wasmtime-free binary.

Call sites stay unconditional — `runtime.check_event(&ctx)` compiles either
way; feature-off it's a no-op the optimizer deletes. No `#[cfg]` at call sites.

The dependency surface is therefore **opt-out, not unconditional** — which
removes wasmtime's one cost that actually bit us. `wit-bindgen` is **not** a
host dependency (the host uses wasmtime's built-in `component::bindgen!`); it
belongs only in the guest SDK (PR3).

## Architecture (built for the end state, in stages)

```
event ─→ Dispatcher ──┬─ sync decision points  (inline, bounded, fail-open)
                      └─ async observation/action  (worker pool, off hot path)
                              │
             Plugin (wasmtime component, stateless)  ←─ WIT interface
                              │
                       Capabilities (host registry, per-plugin least-privilege)
                              │
                       Host-backed state (KV)  ·  Metrics  ·  Scope routing
```

### Typed extension points (registry, not one hardcoded hook)
- **Decision** (sync, returns verdict): `check_event` (send/receive),
  `check_registration`, `check_invite`, `check_join`, `check_room_create`.
- **Observation** (async, no verdict): `on_event` — bots, automation, audit.
- **Transform** (returns modified content): redact/annotate.
- **Action**: emit events (bots), triggered by observation.

Adding a point is a registry entry — the dispatcher, ABI, and core don't
change.

### Capability registry (extensibility + least privilege)
The host exposes a versioned registry of named capabilities; each plugin's
**manifest** declares the points it binds, its **scope**, the
**capabilities** it needs, and a **config schema**. Grants are per-plugin.
Full-vision capabilities: `input/context` · `verdict` · `emit-event` (with an
identity + loop-protection model) · `kv-state` (scoped, host-backed) ·
`http-fetch` (allowlisted, gated, off by default) · `timer` · `query`
(read state/membership, gated) · `log/metrics`. **The platform grows by
adding capabilities/points, never by changing the dispatcher or interface.**

### Performance (the central scaling decision)
- **Sync decision path (critical path):** inline, but with **scoped
  activation** (manifest declares event types/rooms → skip everything else),
  a tight **fuel + memory budget**, **fail-open**, and **serialize the event
  once**, shared across interested plugins, only when any is interested.
  **Field projection** from the manifest → serialize only requested fields.
  JSON marshaling — not wasmi execution — is the real cost; these gates kill
  it.
- **Async observation/action path:** dispatched to a **worker pool**, never
  blocking send/receive. Bots / code-judge / heavy work run here.

### State + scaling
Plugin instances are **ephemeral and stateless**; *all* persistent state is
host-mediated via the `kv` capability (scoped per-plugin / per-room). This
makes instances freely poolable (warm pools, sized to concurrency; no
per-call instantiation) and is the stateless-compute + external-state scaling
pattern.

### Scope routing
Plugins are scoped global / per-room / per-space; the dispatcher routes by
scope. Enables per-space policy and community modules without core changes,
and bounds fan-out.

### Federation (invariant)
The dispatcher is **origin-aware**. A `block` verdict means **reject** for
local-origin events (safe — we just refuse to originate), but **soft-fail**
for inbound federated events (store in the DAG, hide from local `/sync` +
current state). **A plugin must never hard-reject an inbound federated
event** — that would hole the DAG and diverge room state from the federation.
Observation/action on federated events = read + emit (DAG-safe).

### Observability (first-class)
Per-plugin metrics (invocations, blocks, timeouts, traps, latency, fuel),
tracing spans per dispatch, a health view. Fail-open *requires* this or
broken plugins are invisible.

## Host↔guest interface (WIT / Component Model)

The contract is a **WIT interface**; the host generates bindings with
`wasmtime::component::bindgen!` and the guest with `wit-bindgen`. No
hand-rolled linear-memory marshaling, no `alloc`/packed-`u64` dance — the
Component Model lifts typed records across the boundary.

```wit
// wit/extension.wit (illustrative; the source of truth is the .wit file)
package vela:extension@0.1.0;

interface decision {
    enum origin { local, federation }

    record event-context {
        event: string,        // canonical JSON of the PDU
        room-id: string,
        sender: string,
        event-type: string,
        origin: origin,
        plugin-config: string // opaque JSON handed back verbatim
    }

    variant verdict {
        allow,
        block(block-reason),
    }
    record block-reason { errcode: string, reason: string }

    check-event: func(ctx: event-context) -> verdict;
}

world plugin { export decision; }
```

JSON still rides inside `event`/`plugin-config` as strings (the PDU is
schemaless), but the *interface* is typed and versioned by the WIT package
version — interface evolution is a WIT change, not a wire-format hack.

## Semantics & invariants

- **Multi-plugin** at one point: **block-if-any** (logical AND of allows). A
  timed-out / fail-open plugin does not override another's block.
- **Stateless instances** — no durable state in linear memory; use `kv`.
- **Fail policy** on trap / fuel-out / error: `fail_open` (default) |
  `fail_closed`, per-plugin.
- **Federation:** never hard-reject inbound; soft-fail only.
- **CPU bounding:** wasmtime offers both **fuel** (≈ instruction count,
  deterministic) and **epoch interruption** (wall-clock-ish, set a deadline and
  bump an epoch from a timer thread). We use **fuel** for the deterministic
  per-call budget and can add an epoch deadline as a wall-clock backstop —
  having both is a concrete win over an interpreter's fuel-only metering.

## Staged plan (each stage = a real slice of the end state)

1. **PR1 — the crate core:** the WIT interface + `component::bindgen!`,
   wasmtime runtime behind the **`wasmtime-runtime` feature** (types + no-op
   `Runtime` compile without it), `Plugin` (component load/instantiate, fuel +
   memory limits via `StoreLimits`, fail policy), `Runtime` dispatch for
   `check_event` with multi-plugin block-if-any + scoped activation, config
   types, **adversarial sandbox tests** (infinite loop → fuel trap; memory bomb
   → cap; trap/garbage → fail policy) + happy path. Self-contained — no vela-api
   wiring. Test fixtures are real components (a tiny Rust guest compiled to a
   component, or hand-authored component WAT).
2. **PR2 — wire the sync decision path:** `ServerConfig.extensions`,
   vela-server config loading, the `check_event` call site on **local send**;
   per-plugin metrics. Harness integration test.
3. **PR3 — SDK + example:** `vela-extension-sdk` + an example plugin compiled
   to real `.wasm`; operator docs.
4. **PR4+ — async path + capabilities:** worker pool, `kv-state`,
   `emit-event` (identity + loop protection) → action hooks/bots; then
   federation soft-fail, scope routing, `http-fetch`/`timer`/`query`, the
   multi-language typed SDK; re-evaluate wasmtime if heavy-compute arrives.

## Explicitly deferred (so we don't sleepwalk into them)

`emit-event` carries an identity + re-entrancy/loop-protection design bigger
than "add callbacks." Federation soft-fail is a deliberate vertical, not a
freebie. Arbitrary-nested-WASM execution is intentionally **not** a host
capability — a code-judge bundles its own interpreter, bounded by the generic
sandbox limits (proves the capability set is general).
