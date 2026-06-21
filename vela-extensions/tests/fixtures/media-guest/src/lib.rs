//! Test fixture for the `check_media_upload` point. The `plugin-config`
//! substring selects behavior:
//!   "block_exe"  → block content_type "application/x-msdownload"
//!   "block_hash" → block a specific sha256 (the hash of b"bad")
//!   (else)       → allow

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{
    BlockReason, EventContext as DecCtx, Guest, MediaContext, RegistrationContext, Verdict,
};
use exports::vela::extension::observation::{EventContext as ObsCtx, Guest as ObsGuest};

// SHA-256 of b"bad" (lowercase hex) — the fixture's "known-bad" entry.
const BAD_SHA256: &str = "2f05d4b689d270cafb02285f35f44866f7dc8a2d368a3f9d1124373eeab31fb1";

struct Component;

fn blocked(reason: &str) -> Verdict {
    Verdict::Block(BlockReason {
        errcode: "M_FORBIDDEN".to_string(),
        reason: reason.to_string(),
    })
}

impl Guest for Component {
    // Room-create point unused by this fixture — default allow.
    fn check_room_create(
        _ctx: exports::vela::extension::decision::RoomCreateContext,
    ) -> Verdict {
        Verdict::Allow
    }

    // Profile point unused by this fixture — default allow.
    fn check_profile_update(
        _ctx: exports::vela::extension::decision::ProfileContext,
    ) -> Verdict {
        Verdict::Allow
    }

    fn check_event(_ctx: DecCtx) -> Verdict {
        Verdict::Allow
    }

    fn check_registration(_ctx: RegistrationContext) -> Verdict {
        Verdict::Allow
    }

    fn check_media_upload(ctx: MediaContext) -> Verdict {
        let cfg = ctx.plugin_config.as_str();
        if cfg.contains("block_exe") && ctx.content_type == "application/x-msdownload" {
            return blocked("executable uploads are not allowed");
        }
        if cfg.contains("block_hash") && ctx.sha256 == BAD_SHA256 {
            return blocked("content matches a known-bad hash");
        }
        Verdict::Allow
    }
}

impl ObsGuest for Component {
    fn on_event(_ctx: ObsCtx) {}
}

export!(Component);
