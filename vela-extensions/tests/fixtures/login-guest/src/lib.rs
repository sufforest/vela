//! Test fixture for the `check_login` point. The `plugin-config` substring
//! selects behavior:
//!   "block_user" → block a username containing "banned"
//!   "block_ip"   → block when the IP token contains "evil"
//!   (else)       → allow

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{
    BlockReason, EventContext as DecCtx, Guest, LoginContext, MediaContext, ProfileContext,
    RegistrationContext, RoomCreateContext, SyncEventContext, Verdict,
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

    fn filter_sync_event(_ctx: SyncEventContext) -> bool {
        true
    }

    fn check_login(ctx: LoginContext) -> Verdict {
        let cfg = ctx.plugin_config.as_str();
        if cfg.contains("block_user") && ctx.username.contains("banned") {
            return blocked("this account is locked");
        }
        if cfg.contains("block_ip")
            && ctx.client_ip.as_deref().is_some_and(|ip| ip.contains("evil"))
        {
            return blocked("too many attempts from this address");
        }
        Verdict::Allow
    }
}

impl ObsGuest for Component {
    fn on_event(_ctx: ObsCtx) {}
}

export!(Component);
