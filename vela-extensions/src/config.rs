//! Per-plugin settings. The server config (`[extensions]`) maps onto these;
//! the runtime is configured purely from them so it stays independent of how
//! vela parses its config file.

use serde_json::Value;

/// What to do when a plugin traps, runs out of fuel, or errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPolicy {
    /// Treat the failure as `allow` — availability over safety. Default: a
    /// broken moderation plugin must never take the server down.
    Open,
    /// Treat the failure as `block` — safety over availability.
    Closed,
}

/// One loaded plugin.
#[derive(Clone)]
pub struct PluginConfig {
    pub name: String,
    /// Compiled WASM bytes (the loader reads these from disk; tests pass them
    /// inline).
    pub wasm: Vec<u8>,
    pub fail_policy: FailPolicy,
    /// Per-call CPU budget. wasmtime meters *fuel* (≈ executed instructions),
    /// not wall-clock time — see `DESIGN.md`.
    pub fuel: u64,
    /// Per-call wall-clock budget in milliseconds, enforced via wasmtime epoch
    /// interruption as a backstop to `fuel` (fuel bounds work, not time — a
    /// fuel-cheap-but-slow call could still stall the send path). `0` disables
    /// the wall-clock deadline. Resolution is the epoch tick (~10ms).
    pub wall_ms: u64,
    /// Max linear-memory size in 64 KiB WASM pages.
    pub memory_pages: u32,
    /// Scoped activation: only invoke for these event types. `None` = all.
    pub event_types: Option<Vec<String>>,
    /// Opaque config handed verbatim to the guest as `plugin_config`.
    pub config: Value,
}
