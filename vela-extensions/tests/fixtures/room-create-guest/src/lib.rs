//! Test fixture for the `check_room_create` point. The `plugin-config`
//! substring selects behavior:
//!   "block_public"  → block a room whose requested visibility is "public"
//!   "block_name"    → block a room whose name contains "evil"
//!   "max_invites_2" → block a creation inviting more than 2 users
//!   (else)          → allow

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{
    BlockReason, EventContext as DecCtx, Guest, MediaContext, ProfileContext, RegistrationContext,
    RoomCreateContext, Verdict,
};
use exports::vela::extension::observation::{EventContext as ObsCtx, Guest as ObsGuest};

struct Component;

fn blocked(reason: &str) -> Verdict {
    Verdict::Block(BlockReason {
        errcode: "M_FORBIDDEN".to_string(),
        reason: reason.to_string(),
    })
}

impl Guest for Component {
    // Login point unused by this fixture — default allow.
    fn check_login(
        _ctx: exports::vela::extension::decision::LoginContext,
    ) -> Verdict {
        Verdict::Allow
    }

    // Read-path sync filter unused by this fixture — show everything.
    fn filter_sync_event(
        _ctx: exports::vela::extension::decision::SyncEventContext,
    ) -> bool {
        true
    }

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

    fn check_room_create(ctx: RoomCreateContext) -> Verdict {
        let cfg = ctx.plugin_config.as_str();
        if cfg.contains("block_public") && ctx.visibility.as_deref() == Some("public") {
            return blocked("public rooms are not allowed on this server");
        }
        if cfg.contains("block_name") && ctx.name.as_deref().is_some_and(|n| n.contains("evil")) {
            return blocked("room name contains a banned term");
        }
        if cfg.contains("max_invites_2") && ctx.invite.len() > 2 {
            return blocked("too many invites at creation");
        }
        Verdict::Allow
    }
}

impl ObsGuest for Component {
    fn on_event(_ctx: ObsCtx) {}
}

export!(Component);
