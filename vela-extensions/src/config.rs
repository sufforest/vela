//! Per-plugin settings. The server config (`[extensions]`) maps onto these;
//! the runtime is configured purely from them so it stays independent of how
//! vela parses its config file.

use serde_json::Value;

/// Which extension points a plugin binds. The runtime only invokes a plugin at
/// the points it binds — a decision-only plugin is never called on the async
/// observation path, and vice versa. Defaults to `check_event` only (the
/// original decision behavior), so existing configs are unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Points {
    /// Sync decision hook on local send / federation receive.
    pub check_event: bool,
    /// Async observation hook, off the hot path.
    pub on_event: bool,
    /// Sync decision hook at user registration (anti-spam signup).
    pub check_registration: bool,
    /// Sync decision hook at media upload (content/MIME/hash policy).
    pub check_media_upload: bool,
    /// Sync decision hook at a profile update (display name / avatar policy).
    pub check_profile_update: bool,
    /// Sync decision hook at room creation (anti-spam / invite-bomb / alias policy).
    pub check_room_create: bool,
    /// Read-path filter: per-viewer timeline event visibility at `/sync`.
    pub filter_sync_event: bool,
}

impl Default for Points {
    fn default() -> Self {
        Points {
            check_event: true,
            on_event: false,
            check_registration: false,
            check_media_upload: false,
            check_profile_update: false,
            check_room_create: false,
            filter_sync_event: false,
        }
    }
}

/// Host capabilities granted to a plugin — the only things it can do to the
/// world beyond returning a verdict / observing. **Least privilege: everything
/// is off by default** and the operator opts in per plugin. `logging` is not
/// here because it's always granted (harmless, pure output); the gated
/// capabilities are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities {
    /// `emit-event`: post events as the plugin's `@_ext_<name>` bot user.
    pub emit_event: bool,
    /// `kv`: a small per-plugin key→value store (get/set/delete, TTL, quota).
    pub kv: bool,
}

/// How much of the client IP a registration plugin may see — least-privilege,
/// per plugin. The host gives the plugin the rate-limit *key*, not the
/// *identity*, unless `Full` is explicitly granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientIpTier {
    /// No IP. Username + method only.
    #[default]
    None,
    /// A non-reversible HMAC token: a perfect rate-limit key, reveals nothing
    /// about the address. The recommended setting for rate-limiters.
    Hashed,
    /// The raw IP, for reputation/geo — the operator's explicit choice.
    Full,
}

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
    /// Which extension points this plugin binds (decision / observation).
    pub points: Points,
    /// Host capabilities the operator granted this plugin (least-privilege).
    pub capabilities: Capabilities,
    /// How much of the client IP a `check_registration` plugin sees.
    pub client_ip: ClientIpTier,
    /// Opaque config handed verbatim to the guest as `plugin_config`.
    pub config: Value,
}
