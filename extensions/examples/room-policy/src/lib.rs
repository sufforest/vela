//! `room-policy` — a first-party example plugin that enforces room-creation
//! policy from **declarative config**, no server-side rule engine. It binds the
//! `check_room_create` point and reads its rules from the operator's `config`
//! block, so an admin gets config-driven policy without writing any WASM:
//!
//! ```toml
//! [[extensions.plugin]]
//! name = "room-policy"
//! wasm_path = "/etc/vela/plugins/room-policy.wasm"
//! points = ["check_room_create"]
//! capabilities = ["kv"]                       # needed only for the rate limit
//! config = { deny_public = true, max_rooms_per_user_per_day = 10, max_invites = 50, banned_alias_substrings = ["official", "admin"] }
//! ```
//!
//! Every rule is optional — omit a field to turn it off.

use serde::Deserialize;
use vela_extension_sdk::{export_plugin, Decision, Plugin, RoomCreate};

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Config {
    /// Block any room requesting public directory visibility.
    deny_public: bool,
    /// Cap rooms one user may create per rolling 24h (needs the `kv` capability).
    max_rooms_per_user_per_day: Option<u32>,
    /// Cap users invited in a single createRoom (invite-bomb guard).
    max_invites: Option<usize>,
    /// Reject an alias localpart containing any of these (case-insensitive).
    banned_alias_substrings: Vec<String>,
}

struct RoomPolicy;

impl Plugin for RoomPolicy {
    fn check_room_create(room: &RoomCreate) -> Decision {
        let cfg: Config = room.config();

        if cfg.deny_public && room.visibility() == Some("public") {
            return Decision::block("public rooms are not allowed on this server");
        }

        if let Some(max) = cfg.max_invites {
            if room.invite().len() > max {
                return Decision::block("too many invitations in a single room creation");
            }
        }

        if let Some(localpart) = room.alias_localpart() {
            let lower = localpart.to_lowercase();
            if cfg
                .banned_alias_substrings
                .iter()
                .any(|b| lower.contains(&b.to_lowercase()))
            {
                return Decision::block("that room alias is not allowed");
            }
        }

        // Per-creator rolling-24h creation cap, backed by kv + TTL. This call
        // makes the component import the `kv` capability, so the operator MUST
        // grant `capabilities = ["kv"]` or the plugin won't instantiate (kv isn't
        // optional for this plugin). A blocked attempt doesn't bump the counter or
        // refresh the TTL, so it can't extend its own lockout — the window is 24h
        // from the last *successful* create.
        if let Some(max) = cfg.max_rooms_per_user_per_day {
            let kv = room.kv();
            let key = format!("rooms:{}", room.creator());
            let count: u32 = kv.get_json(key.as_bytes()).ok().flatten().unwrap_or(0);
            if count >= max {
                return Decision::block("daily room-creation limit reached");
            }
            let _ = kv.set_json(key.as_bytes(), &(count + 1), 24 * 60 * 60 * 1000);
        }

        Decision::allow()
    }
}

export_plugin!(RoomPolicy);
