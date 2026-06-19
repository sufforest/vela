//! Example vela extension: block messages whose body contains an operator-
//! configured term. Stateless — a good template for content moderation.
//!
//! Configure it in `vela.toml`:
//!
//! ```toml
//! [[extensions.plugin]]
//! name = "keyword-filter"
//! wasm_path = "/etc/vela/plugins/keyword-filter.wasm"
//! event_types = ["m.room.message"]
//! config = { banned = ["spam", "buy now"], errcode = "M_FORBIDDEN" }
//! ```

use serde::Deserialize;
use vela_extension_sdk::{export_plugin, Caps, Decision, Event, Plugin};

#[derive(Deserialize, Default)]
// Reject mistyped keys so a config typo surfaces (the SDK traps on invalid
// config) instead of silently leaving the blocklist empty.
#[serde(deny_unknown_fields)]
struct Config {
    /// Terms that cause a block. Matched case-insensitively as substrings.
    #[serde(default)]
    banned: Vec<String>,
    /// Optional Matrix errcode to return on a block; defaults to `M_FORBIDDEN`.
    errcode: Option<String>,
}

struct KeywordFilter;

impl Plugin for KeywordFilter {
    fn check_event(ev: &Event) -> Decision {
        // Only inspect textual message bodies; everything else passes through.
        let Some(body) = ev.message_body() else {
            return Decision::allow();
        };
        let cfg: Config = ev.config();
        let body = body.to_lowercase();

        // Skip empty terms — `contains("")` is always true and would block all.
        if cfg
            .banned
            .iter()
            .filter(|w| !w.is_empty())
            .any(|w| body.contains(&w.to_lowercase()))
        {
            // Deliberately generic — don't echo which term matched, so the
            // blocklist can't be probed from the error.
            let reason = "message contains a blocked term";
            match cfg.errcode {
                Some(code) => Decision::block_with(code, reason),
                None => Decision::block(reason),
            }
        } else {
            Decision::allow()
        }
    }

    // Observation runs off the request path, so it can do the bookkeeping the
    // decision hook shouldn't: here, log a banned-term hit (attributed to this
    // plugin in vela's log) without leaking which term to the sender. Enable it
    // with `points = ["check_event", "on_event"]`.
    fn on_event(ev: &Event, caps: &Caps) {
        let Some(body) = ev.message_body() else {
            return;
        };
        let cfg: Config = ev.config();
        let body = body.to_lowercase();
        if cfg
            .banned
            .iter()
            .filter(|w| !w.is_empty())
            .any(|w| body.contains(&w.to_lowercase()))
        {
            caps.log(format!(
                "blocked-term hit from {} in {}",
                ev.sender(),
                ev.room_id()
            ));
        }
    }
}

export_plugin!(KeywordFilter);
