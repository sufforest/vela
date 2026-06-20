//! Test fixture for the `check_registration` point. The `plugin-config`
//! substring selects behavior:
//!   "block_spam" → block a username containing "spam"
//!   "ip_present" → allow iff a client-ip token was exposed (else block) — lets a
//!                  test verify the per-plugin `client_ip` tier (none withholds,
//!                  hashed/full expose)
//!   (else)       → allow

wit_bindgen::generate!({
    path: "../../../wit/extension.wit",
    world: "plugin",
});

use exports::vela::extension::decision::{
    BlockReason, EventContext as DecCtx, Guest, RegistrationContext, Verdict,
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
    fn check_media_upload(
        _ctx: exports::vela::extension::decision::MediaContext,
    ) -> Verdict {
        Verdict::Allow
    }

    fn check_event(_ctx: DecCtx) -> Verdict {
        Verdict::Allow
    }

    fn check_registration(ctx: RegistrationContext) -> Verdict {
        let cfg = ctx.plugin_config.as_str();
        if cfg.contains("block_spam") && ctx.username.contains("spam") {
            return blocked("spammy username");
        }
        if cfg.contains("ip_present") {
            return match ctx.client_ip {
                Some(_) => Verdict::Allow,
                None => blocked("no client ip exposed"),
            };
        }
        Verdict::Allow
    }
}

impl ObsGuest for Component {
    fn on_event(_ctx: ObsCtx) {}
}

export!(Component);
