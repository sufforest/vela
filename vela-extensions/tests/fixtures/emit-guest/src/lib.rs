//! Test fixture exercising the `emit-event` host capability. Its `on_event`
//! emits back into the room it observed; the `plugin-config` substring selects
//! what it tries to emit, so one component drives every host-side emit test
//! (grant, allowlist, state-event rejection, rate cap).
//!
//! Modes (substring in plugin-config):
//!   "emit_message" → emit one m.room.message            (the happy path)
//!   "emit_state"   → emit with a state-key              (host must reject)
//!   "emit_member"  → emit a disallowed type m.room.member (host must reject)
//!   "emit_flood"   → emit 100 messages                  (host rate-caps it)
//!   (default)      → emit nothing

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{EventContext as DecCtx, Guest, Verdict};
use exports::vela::extension::observation::{EventContext as ObsCtx, Guest as ObsGuest};
use vela::extension::emit::{emit_event, NewEvent};

struct Component;

impl Guest for Component {
    fn check_event(_ctx: DecCtx) -> Verdict {
        // Decision-irrelevant; this fixture is about observation + emit.
        Verdict::Allow
    }
}

impl ObsGuest for Component {
    fn on_event(ctx: ObsCtx) {
        let cfg = ctx.plugin_config.as_str();
        let msg = |room: String| NewEvent {
            room_id: room,
            event_type: "m.room.message".to_string(),
            content: r#"{"msgtype":"m.text","body":"hello from the plugin"}"#.to_string(),
            state_key: None,
        };

        if cfg.contains("emit_flood") {
            for _ in 0..100 {
                let _ = emit_event(&msg(ctx.room_id.clone()));
            }
            return;
        }
        if cfg.contains("emit_state") {
            // A state event — the host must reject this (no state emits in v1).
            let _ = emit_event(&NewEvent {
                room_id: ctx.room_id.clone(),
                event_type: "m.room.topic".to_string(),
                content: "{}".to_string(),
                state_key: Some(String::new()),
            });
            return;
        }
        if cfg.contains("emit_member") {
            // A disallowed (non-allowlisted) type — the host must reject it.
            let _ = emit_event(&NewEvent {
                room_id: ctx.room_id.clone(),
                event_type: "m.room.member".to_string(),
                content: "{}".to_string(),
                state_key: None,
            });
            return;
        }
        if cfg.contains("emit_message") {
            let _ = emit_event(&msg(ctx.room_id));
        }
    }
}

export!(Component);
