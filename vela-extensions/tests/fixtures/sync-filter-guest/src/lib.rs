//! Test fixture for the `filter_sync_event` read-path point. The `plugin-config`
//! substring selects behavior:
//!   "hide_sender"    → hide events whose sender contains "evil"
//!   "hide_for_alice" → hide ALL events when the viewer contains "alice"
//!   (else)           → show

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{
    EventContext as DecCtx, Guest, MediaContext, ProfileContext, RegistrationContext,
    RoomCreateContext, SyncEventContext, Verdict,
};
use exports::vela::extension::observation::{EventContext as ObsCtx, Guest as ObsGuest};

struct Component;

impl Guest for Component {
    fn check_event(_ctx: DecCtx) -> Verdict {
        Verdict::Allow
    }

    fn check_registration(_ctx: RegistrationContext) -> Verdict {
        Verdict::Allow
    }

    fn check_media_upload(_ctx: MediaContext) -> Verdict {
        Verdict::Allow
    }

    fn check_profile_update(_ctx: ProfileContext) -> Verdict {
        Verdict::Allow
    }

    fn check_room_create(_ctx: RoomCreateContext) -> Verdict {
        Verdict::Allow
    }

    fn filter_sync_event(ctx: SyncEventContext) -> bool {
        let cfg = ctx.plugin_config.as_str();
        // Hide events from a flagged sender (per-event, sender-based).
        if cfg.contains("hide_sender") && ctx.sender.contains("evil") {
            return false;
        }
        // Hide everything from a specific viewer (per-viewer policy).
        if cfg.contains("hide_for_alice") && ctx.viewer.contains("alice") {
            return false;
        }
        true
    }
}

impl ObsGuest for Component {
    fn on_event(_ctx: ObsCtx) {}
}

export!(Component);
