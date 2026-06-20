//! Test fixture exercising the `kv` host capability. The `plugin-config`
//! substring selects behavior so one component drives every kv test.
//!
//! check_event:
//!   "ratelimit" → a stateful decision: count calls in kv, Block after the 3rd
//!                 (proves kv works on the decision hot path)
//!   (else)      → Allow
//!
//! on_event (substring):
//!   "kv_set"    → set b"k" = b"v"
//!   "kv_bigkey" → set with a 300-byte key (host must reject — over the cap)
//!   (else)      → nothing

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{
    BlockReason, EventContext as DecCtx, Guest, Verdict,
};
use exports::vela::extension::observation::{EventContext as ObsCtx, Guest as ObsGuest};
use vela::extension::kv;

struct Component;

impl Guest for Component {
    fn check_registration(
        _ctx: exports::vela::extension::decision::RegistrationContext,
    ) -> Verdict {
        Verdict::Allow
    }

    fn check_event(ctx: DecCtx) -> Verdict {
        if !ctx.plugin_config.contains("ratelimit") {
            return Verdict::Allow;
        }
        // Stateful: read a 1-byte counter, increment, store, block past 3.
        let n = match kv::get(b"count") {
            Ok(Some(v)) if !v.is_empty() => v[0],
            _ => 0,
        };
        let next = n.saturating_add(1);
        let _ = kv::set(b"count", &[next], None);
        if next > 3 {
            Verdict::Block(BlockReason {
                errcode: "M_LIMIT_EXCEEDED".to_string(),
                reason: "rate limit exceeded".to_string(),
            })
        } else {
            Verdict::Allow
        }
    }
}

impl ObsGuest for Component {
    fn on_event(ctx: ObsCtx) {
        let cfg = ctx.plugin_config.as_str();
        if cfg.contains("kv_bigkey") {
            // 300-byte key, over the 256 cap — the host must reject it.
            let big = [b'x'; 300];
            let _ = kv::set(&big, b"v", None);
            return;
        }
        if cfg.contains("kv_set") {
            let _ = kv::set(b"k", b"v", None);
        }
    }
}

export!(Component);
