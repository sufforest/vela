//! Test fixture for the `check_profile_update` point. The `plugin-config`
//! substring selects behavior:
//!   "block_name"   → block a display-name whose value contains "evil"
//!   "block_avatar" → block an avatar-url whose value isn't an mxc:// URI
//!   (else)         → allow

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{
    BlockReason, EventContext as DecCtx, Guest, MediaContext, ProfileContext, ProfileField,
    RegistrationContext, Verdict,
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

    // Room-create point unused by this fixture — default allow.
    fn check_room_create(
        _ctx: exports::vela::extension::decision::RoomCreateContext,
    ) -> Verdict {
        Verdict::Allow
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

    fn check_profile_update(ctx: ProfileContext) -> Verdict {
        let cfg = ctx.plugin_config.as_str();
        let value = ctx.value.unwrap_or_default();
        if cfg.contains("block_name")
            && ctx.field == ProfileField::DisplayName
            && value.contains("evil")
        {
            return blocked("display name contains a banned term");
        }
        if cfg.contains("block_avatar")
            && ctx.field == ProfileField::AvatarUrl
            && !value.starts_with("mxc://")
        {
            return blocked("avatar must be an mxc:// URI");
        }
        Verdict::Allow
    }
}

impl ObsGuest for Component {
    fn on_event(_ctx: ObsCtx) {}
}

export!(Component);
