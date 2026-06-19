//! The `emit-event` capability seam.
//!
//! vela-extensions defines the *interface* a plugin's `emit-event` calls into;
//! vela-api implements it (it owns the send machinery) and injects it into the
//! [`Runtime`](crate::Runtime). This keeps the sandbox crate free of any
//! dependency on the homeserver internals — the same pattern every host-service
//! capability (`kv`, `query`, …) will follow.
//!
//! These types compile in both feature states (the trait is public API and
//! vela-server injects an emitter regardless of the `wasmtime-runtime` feature);
//! only the wasmtime binding that *calls* the trait is feature-gated.

#[cfg(feature = "wasmtime-runtime")]
use std::sync::Mutex;
#[cfg(feature = "wasmtime-runtime")]
use std::time::Instant;

use serde_json::Value;

/// One event a plugin asked to emit. `plugin` (passed separately to
/// [`EventEmitter::emit`]) names the calling plugin so the host can resolve its
/// bot identity.
#[derive(Debug, Clone)]
pub struct EmitRequest {
    pub room_id: String,
    pub event_type: String,
    /// Event content as a JSON object (already validated to be an object).
    pub content: Value,
    /// Present => state event. v1 rejects this before reaching the emitter.
    pub state_key: Option<String>,
}

/// Why an emit failed. Mirrors the WIT `emit-error` variant.
#[derive(Debug, Clone)]
pub enum EmitError {
    /// The plugin's bot isn't joined / lacks power level in the room.
    Unauthorized,
    /// Not granted, called off `on_event`, disallowed type, or malformed content.
    NotPermitted(String),
    /// This plugin's emit rate cap tripped.
    RateLimited,
    /// Internal failure (persist/lock) — logged host-side.
    Internal,
}

/// Host service backing `emit-event`. Implemented by vela-api, injected into the
/// `Runtime`. `plugin` is the calling plugin's configured name; the
/// implementation resolves it to a `@_ext_<name>` bot and emits as that user
/// through normal room authorization. Must be cheap to share (`Arc<dyn …>`).
pub trait EventEmitter: Send + Sync {
    fn emit(&self, plugin: &str, req: EmitRequest) -> Result<String, EmitError>;
}

/// Per-plugin token-bucket cap on emits, so a buggy or hostile granted plugin
/// (or a loop that slips past the observation-enqueue skip) can't flood a room.
/// Shared across a plugin's invocations.
#[cfg(feature = "wasmtime-runtime")]
pub(crate) struct EmitLimiter {
    inner: Mutex<Bucket>,
    rate_per_sec: f64,
    burst: f64,
}

#[cfg(feature = "wasmtime-runtime")]
struct Bucket {
    tokens: f64,
    last: Instant,
}

#[cfg(feature = "wasmtime-runtime")]
impl EmitLimiter {
    pub(crate) fn new(rate_per_sec: f64, burst: f64) -> Self {
        EmitLimiter {
            inner: Mutex::new(Bucket {
                tokens: burst,
                last: Instant::now(),
            }),
            rate_per_sec,
            burst,
        }
    }

    /// Try to spend one token. Refills by elapsed time up to `burst`.
    pub(crate) fn try_acquire(&self) -> bool {
        let mut b = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * self.rate_per_sec).min(self.burst);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Event types a plugin may emit in v1: a message, a reaction, or a redaction.
/// No state events — a plugin can't forge membership / power-level / create
/// events to escalate. State-key-bearing emits are rejected before this check.
#[cfg(feature = "wasmtime-runtime")]
pub(crate) fn emit_type_allowed(event_type: &str) -> bool {
    matches!(
        event_type,
        "m.room.message" | "m.reaction" | "m.room.redaction"
    )
}

#[cfg(all(test, feature = "wasmtime-runtime"))]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_messages_reactions_redactions_only() {
        assert!(emit_type_allowed("m.room.message"));
        assert!(emit_type_allowed("m.reaction"));
        assert!(emit_type_allowed("m.room.redaction"));
        // No state events — these would let a plugin escalate.
        assert!(!emit_type_allowed("m.room.member"));
        assert!(!emit_type_allowed("m.room.power_levels"));
        assert!(!emit_type_allowed("m.room.create"));
        assert!(!emit_type_allowed("m.room.topic"));
    }

    #[test]
    fn limiter_allows_burst_then_throttles() {
        // burst 3, refill 0/s → first 3 pass, 4th fails.
        let lim = EmitLimiter::new(0.0, 3.0);
        assert!(lim.try_acquire());
        assert!(lim.try_acquire());
        assert!(lim.try_acquire());
        assert!(!lim.try_acquire(), "burst exhausted, no refill → throttled");
    }
}
