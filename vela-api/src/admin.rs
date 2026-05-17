//! Server admin via an internal bot + private admin room (vela-specific).
//!
//! Operators administer the homeserver by chatting with `@admin:<server_name>`
//! (configurable localpart) in a private room that the server creates on
//! first boot. Membership in that room IS the "admin" permission — there's
//! no `is_admin` column, no HTTP admin API surface.
//!
//! Why no HTTP admin API: every admin op already maps cleanly to an
//! event in the admin room, and the room already carries auth,
//! encryption-on-the-wire (TLS / federation signatures), audit trail
//! (the events themselves), and an existing UI (any Matrix client).
//! Reimplementing a Synapse-style `/_synapse/admin/v1/*` REST surface
//! would duplicate that plumbing with weaker primitives.
//!
//! Bootstrap flow:
//!   1. operator sets `[registration] token = "<bootstrap>"` in vela.toml
//!      and starts vela with `enabled = false`.
//!   2. on first boot, this module creates `@admin:<server_name>` (no
//!      password — login is refused) and a private, unfederated room
//!      named "Admins". The static bootstrap token is seeded into the
//!      `registration_tokens` CF so the same lookup path covers both
//!      bootstrap and post-bootstrap registrations.
//!   3. operator registers their human account via the bootstrap token.
//!      `register.rs` auto-invites them to the admin room iff no admin
//!      exists yet (zero joined / invited members).
//!   4. operator joins from any Matrix client. From there: `!help`,
//!      `!token create`, etc.
//!
//! Admin room security model (state set at creation):
//!   - `m.room.create.content.m.federate = false`     — never federates
//!   - `m.room.join_rules.join_rule = "invite"`        — invite-only
//!   - `m.room.history_visibility = "joined"`          — joined members only
//!   - `m.room.power_levels.users_default = 0`         — regular member PL
//!   - `m.room.power_levels.state_default = 100`       — only highest-PL changes state
//!   - `m.room.power_levels.kick/ban/redact = 100`     — only highest-PL kicks/bans/redacts
//!   - `m.room.power_levels.events_default = 0`        — members can post messages
//!
//! The bot itself is the room creator with v12 infinite power, so it
//! can always send commands' reply notices regardless of PL changes.

use std::sync::Arc;

use serde_json::{Map, Value, json};
use tracing::{info, warn};
use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::{build_event, select_auth_events};
use vela_core::events::content;
use vela_core::events::pdu::Pdu;
use vela_core::events::room_version::RoomVersion;
use vela_core::identifiers::{DeviceId, EventId, Nid, RoomId, UserId};

use crate::auth_check::{InFlightState, authorise_event};
use crate::middleware::error::ApiError;
use crate::rooms::get_or_create_signing_key;
use crate::router::AppState;

/// Default localpart for the admin bot, used when operators don't set
/// `[admin] bot_localpart` in vela.toml. `@admin:<server_name>`.
pub const DEFAULT_BOT_LOCALPART: &str = "admin";

/// Default room name (`m.room.name`) for the admin room.
const ADMIN_ROOM_NAME: &str = "Admins";

/// Default room topic — pure operator-facing copy.
const ADMIN_ROOM_TOPIC: &str = "Server admin commands. Type `!help` for a list.";

/// All admin-room state events MUST be authored at room version 12 so
/// the bot retains infinite PL (v12 makes the creator's PL implicit and
/// uncontestable; pre-v12 rooms would need the bot explicitly listed in
/// `power_levels.users`, which v12 forbids — picking v12 is the simplest
/// model).
const ADMIN_ROOM_VERSION: RoomVersion = RoomVersion::V12;

/// Device-id used for the bot's internal sends. Stable so internal-send
/// transaction-id scoping is deterministic across restarts.
const ADMIN_BOT_DEVICE_ID: &str = "ADMIN_BOT";

/// Membership encoding for "joined" — mirrors the byte set_membership
/// stores. The admin-room membership check is the entire auth model.
const MEMBERSHIP_JOIN: u8 = 1;

/// Returns true iff `user_nid` is a joined member of the admin room.
/// Returns false (not Err) when no admin room exists yet — the "no
/// admin" state can't be authoritatively "this user is an admin".
pub fn is_admin(state: &AppState, user_nid: u64) -> Result<bool, ApiError> {
    let Some(room_nid) = state
        .db
        .get_admin_room_nid()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(false);
    };
    let membership = state
        .db
        .get_membership(room_nid, user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(membership == Some(MEMBERSHIP_JOIN))
}

/// Refuse to register the configured bot localpart. If the operator ever
/// changes `bot_localpart` after the bot already exists under the old
/// name, registering the OLD bot localpart is no longer reserved — only
/// the currently configured one is. That's acceptable: the old bot user
/// is still an internal account (no password), so an attacker can't log
/// in as it; the only window is whether `/register` lets them create a
/// NEW account at the old localpart, which is harmless.
pub fn assert_bot_localpart_not_reserved(
    state: &AppState,
    requested_localpart: &str,
) -> Result<(), ApiError> {
    let reserved = state.config.admin_bot_localpart.as_str();
    if requested_localpart.eq_ignore_ascii_case(reserved) {
        return Err(ApiError(VelaError::Forbidden(format!(
            "the localpart {reserved:?} is reserved for the server admin bot"
        ))));
    }
    Ok(())
}

/// Determine whether the freshly-registered `new_user_nid` should be
/// auto-invited to the admin room. Returns true iff the admin room
/// exists AND has zero joined members AND zero invited members. The
/// first registrant after bootstrap is auto-invited; subsequent
/// registrants never are (existing admins promote via `!promote`).
pub fn should_auto_invite_first_admin(
    state: &AppState,
    new_user_nid: u64,
) -> Result<bool, ApiError> {
    let Some(room_nid) = state
        .db
        .get_admin_room_nid()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(false);
    };
    let bot_nid = state
        .db
        .get_admin_bot_user_nid()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let members = state
        .db
        .get_room_members(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for nid in members {
        // The bot is always a joined member of the admin room (it
        // created it). Ignore it when deciding whether any human admin
        // exists yet.
        if Some(nid) == bot_nid {
            continue;
        }
        if nid == new_user_nid {
            continue;
        }
        // Any other joined member means an admin already exists.
        return Ok(false);
    }
    // Joined members are bot-only (or empty). Also check that nobody is
    // currently invited — covers the race where a previous register call
    // was auto-invited but never accepted, so we don't keep inviting
    // every new registrant until the first one joins.
    let invited = state
        .db
        .get_room_members_by_membership(room_nid, 2)
        .unwrap_or_default();
    Ok(invited.is_empty())
}

/// Boot-time entry point. Run from `main` after the database is open and
/// before the listener binds. Idempotent: if the admin user and admin
/// room already exist, this is a no-op. If only one of the two exists
/// (e.g. operator deleted the room out of band, or the previous boot
/// crashed mid-setup), the missing piece is created.
///
/// Also seeds the static `[registration] token` from `ServerConfig`
/// into the `registration_tokens` CF when no admin exists yet — this
/// lets the same lookup path handle bootstrap and post-bootstrap.
pub async fn bootstrap(state: &AppState) -> Result<(), ApiError> {
    let bot_localpart = state.config.admin_bot_localpart.clone();
    let bot_user_id = UserId::new(&bot_localpart, &state.config.server_name);

    // 1. Bot user: create if missing.
    let bot_user_nid = match state
        .db
        .get_admin_bot_user_nid()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => {
            // Either a fresh DB, or a stale state where the user was
            // pre-seeded by a previous incomplete boot. `create_user`
            // is safe: it returns the existing nid if the user_id is
            // already mapped.
            let nid = state
                .db
                .get_or_create_nid(bot_user_id.as_str())
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            // Stamp a user record with no password (empty hash → login
            // is refused; see login.rs's argon2 parse step).
            if state
                .db
                .get_user(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .is_none()
            {
                state
                    .db
                    .create_user(bot_user_id.as_str(), "")
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            }
            state
                .db
                .create_device(nid, ADMIN_BOT_DEVICE_ID)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            state
                .db
                .set_admin_bot_user_nid(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            info!(user = %bot_user_id, "created admin bot user");
            nid
        }
    };

    // 2. Admin room: create if missing.
    if state
        .db
        .get_admin_room_id()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .is_none()
    {
        let room_id = create_admin_room(state, bot_user_nid, &bot_user_id).await?;
        state
            .db
            .set_admin_room_id(room_id.as_str())
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        info!(room_id = %room_id, "created admin room");
    }

    // 3. Seed the static bootstrap token if no admin exists yet AND the
    //    operator configured one. Seeded as single-use (uses_allowed = 1)
    //    so the first successful registration consumes it; further
    //    registrations need a token minted by the admin via `!token create`.
    //    Idempotent: if the token is already in the CF, we leave the
    //    existing record alone (uses_used may already be > 0).
    if let Some(token) = state.config.registration_token.as_deref()
        && !token.is_empty()
    {
        let room_nid = state
            .db
            .get_admin_room_nid()
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or(0);
        // "no admin exists" = zero joined members other than the bot
        // and zero invited members.
        let members = state
            .db
            .get_room_members(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let invited = state
            .db
            .get_room_members_by_membership(room_nid, 2)
            .unwrap_or_default();
        let has_admin = members.iter().any(|n| *n != bot_user_nid) || !invited.is_empty();
        if !has_admin
            && state
                .db
                .get_registration_token(token)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .is_none()
        {
            state
                .db
                .create_registration_token(token, 1, 0, 0)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            info!("seeded static bootstrap registration token (single-use)");
        }
    }

    Ok(())
}

/// Build the admin room. Mirrors `rooms::create_room` for the events we
/// need but slimmed: no presets, no client-supplied initial_state, no
/// federation invites. The bot is sender + creator everywhere; v12 PL
/// keeps it on top regardless of later state changes.
async fn create_admin_room(
    state: &AppState,
    bot_user_nid: u64,
    bot_user_id: &UserId,
) -> Result<RoomId, ApiError> {
    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;
    let room_version = ADMIN_ROOM_VERSION;
    let sender = bot_user_id.as_str();

    let mut created: Vec<(String, String, EventId)> = Vec::new();
    let mut all_events: Vec<(
        serde_json::Map<String, Value>,
        EventId,
        String,
        Option<String>,
        u64,
    )> = Vec::new();
    let mut depth: u64 = 1;
    let mut prev: Vec<EventId> = vec![];

    // 1. m.room.create — federate=false locks the room to this server.
    //    Spec: m.room.create.content.m.federate; per spec the default is
    //    true, and clients that explicitly set it to false get an
    //    unfederated room.
    let mut create_content_val = content::create_content(room_version);
    create_content_val
        .as_object_mut()
        .unwrap()
        .insert("creator".to_string(), Value::String(sender.to_string()));
    create_content_val
        .as_object_mut()
        .unwrap()
        .insert("m.federate".to_string(), Value::Bool(false));
    let pre_v12_room_id = if room_version.omit_room_id_from_create() {
        None
    } else {
        Some(RoomId::generate_for_server(server_name))
    };
    let (create_ev, create_eid) = build_event(
        "m.room.create",
        Some(""),
        create_content_val,
        sender,
        pre_v12_room_id.as_ref(),
        &[],
        &[],
        depth,
        &signing_key,
        server_name,
        room_version,
    );
    let room_id = match pre_v12_room_id {
        Some(r) => r,
        None => RoomId::from_create_event_id(&create_eid),
    };
    created.push(("m.room.create".into(), "".into(), create_eid.clone()));
    all_events.push((
        create_ev,
        create_eid.clone(),
        "m.room.create".into(),
        Some("".into()),
        depth,
    ));
    prev = vec![create_eid];
    depth += 1;

    // 2. m.room.member — bot joins.
    let member_content = content::member_content_join(None, None);
    let auth = select_auth_for(
        &created,
        "m.room.member",
        sender,
        Some(sender),
        Some(&member_content),
        room_version,
    );
    let (member_ev, member_eid) = build_event(
        "m.room.member",
        Some(sender),
        member_content,
        sender,
        Some(&room_id),
        &prev,
        &auth,
        depth,
        &signing_key,
        server_name,
        room_version,
    );
    created.push(("m.room.member".into(), sender.into(), member_eid.clone()));
    all_events.push((
        member_ev,
        member_eid.clone(),
        "m.room.member".into(),
        Some(sender.into()),
        depth,
    ));
    prev = vec![member_eid];
    depth += 1;

    // 3. m.room.power_levels — only highest-PL changes state / kicks /
    //    bans / redacts. users_default=0, events_default=0 so invited
    //    humans can post commands. v12 gives the bot infinite implicit
    //    power without listing it in `users`.
    let pl_content = admin_room_power_levels();
    emit_state(
        state,
        &mut created,
        &mut all_events,
        &mut prev,
        &mut depth,
        room_version,
        &signing_key,
        server_name,
        sender,
        &room_id,
        "m.room.power_levels",
        "",
        pl_content,
    );

    // 4. m.room.join_rules = invite.
    emit_state(
        state,
        &mut created,
        &mut all_events,
        &mut prev,
        &mut depth,
        room_version,
        &signing_key,
        server_name,
        sender,
        &room_id,
        "m.room.join_rules",
        "",
        content::join_rules_content("invite"),
    );

    // 5. m.room.history_visibility = joined. The default visibility for
    //    `private_chat` is `shared` (members can read history they were
    //    not yet a member during). For the admin room we want strict
    //    `joined` so historical commands aren't visible to a new admin
    //    joining later. Spec: m.room.history_visibility.
    emit_state(
        state,
        &mut created,
        &mut all_events,
        &mut prev,
        &mut depth,
        room_version,
        &signing_key,
        server_name,
        sender,
        &room_id,
        "m.room.history_visibility",
        "",
        content::history_visibility_content("joined"),
    );

    // 6. m.room.name + topic — purely cosmetic.
    emit_state(
        state,
        &mut created,
        &mut all_events,
        &mut prev,
        &mut depth,
        room_version,
        &signing_key,
        server_name,
        sender,
        &room_id,
        "m.room.name",
        "",
        content::name_content(ADMIN_ROOM_NAME),
    );
    emit_state(
        state,
        &mut created,
        &mut all_events,
        &mut prev,
        &mut depth,
        room_version,
        &signing_key,
        server_name,
        sender,
        &room_id,
        "m.room.topic",
        "",
        content::topic_content(ADMIN_ROOM_TOPIC),
    );

    // --- Persist + authorise ---
    let room_nid = state
        .db
        .get_or_create_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut in_flight: InFlightState = std::collections::HashMap::new();
    for (event, event_id, _etype, _skey, _depth) in &all_events {
        authorise_event(state, room_nid, event_id, event, Some(&in_flight))?;
        if let Some(pdu) = Pdu::from_json(event_id.as_str().to_string(), event)
            && let Some(state_key) = pdu.state_key.clone()
        {
            in_flight.insert((pdu.event_type.clone(), state_key), pdu);
        }
    }

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    state
        .db
        .create_room_meta(room_nid, room_id.as_str(), room_version.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut last_stream_pos = 0u64;
    let mut state_event_nids = Vec::new();

    for (event, event_id, etype, skey, evdepth) in &all_events {
        let type_nid = state
            .db
            .get_or_create_nid(etype)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let state_key_nid = if let Some(sk) = skey {
            state
                .db
                .get_or_create_nid(sk)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        } else {
            0
        };

        let event_nid = state.db.next_nid();
        let json_bytes = canonical_json_object(event);
        let prev_nids = resolve_event_nids_in_json(state, event, "prev_events")?;
        let auth_nids = resolve_event_nids_in_json(state, event, "auth_events")?;
        let origin_ts = event
            .get("origin_server_ts")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        last_stream_pos = state
            .db
            .persist_event(
                event_nid,
                event_id.as_str(),
                room_nid,
                type_nid,
                bot_user_nid,
                state_key_nid,
                origin_ts,
                *evdepth,
                &json_bytes,
                &prev_nids,
                &auth_nids,
                skey.is_some(),
                false,
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

        if skey.is_some() {
            state_event_nids.push(event_nid);
        }
    }

    state
        .db
        .set_membership(room_nid, bot_user_nid, MEMBERSHIP_JOIN)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(state, bot_user_nid);

    if !state_event_nids.is_empty() {
        state
            .db
            .persist_state_snapshot(
                room_nid,
                *state_event_nids.last().unwrap(),
                &state_event_nids,
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    let now = now_ms();
    state
        .db
        .update_room_bump(room_nid, now, 0)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(last_stream_pos);
    }

    Ok(room_id)
}

/// PL content for the admin room. `users_default = 0` (regular member
/// PL), `state_default = 100` and kick/ban/redact = 100 — everything
/// destructive is gated to the highest-PL. The bot (v12 creator) has
/// implicit infinite PL and bypasses these gates.
fn admin_room_power_levels() -> Value {
    json!({
        "ban": 100,
        "events": {
            "m.room.name": 100,
            "m.room.power_levels": 100,
            "m.room.history_visibility": 100,
            "m.room.canonical_alias": 100,
            "m.room.avatar": 100,
            "m.room.encryption": 100,
            "m.room.server_acl": 100,
            "m.room.tombstone": 150,
        },
        "events_default": 0,
        "invite": 100,
        "kick": 100,
        "redact": 100,
        "state_default": 100,
        "users": {},
        "users_default": 0,
    })
}

fn select_auth_for(
    created: &[(String, String, EventId)],
    event_type: &str,
    sender: &str,
    state_key: Option<&str>,
    content: Option<&Value>,
    room_version: RoomVersion,
) -> Vec<EventId> {
    let lookup = |et: &str, sk: &str| -> Option<EventId> {
        created
            .iter()
            .rev()
            .find(|(t, k, _)| t == et && k == sk)
            .map(|(_, _, eid)| eid.clone())
    };
    select_auth_events(
        event_type,
        sender,
        state_key,
        content,
        room_version,
        &lookup,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_state(
    _state: &AppState,
    created: &mut Vec<(String, String, EventId)>,
    all_events: &mut Vec<(
        serde_json::Map<String, Value>,
        EventId,
        String,
        Option<String>,
        u64,
    )>,
    prev: &mut Vec<EventId>,
    depth: &mut u64,
    room_version: RoomVersion,
    signing_key: &vela_core::events::sign::ServerSigningKey,
    server_name: &str,
    sender: &str,
    room_id: &RoomId,
    event_type: &str,
    state_key: &str,
    content: Value,
) {
    let auth = select_auth_for(
        created,
        event_type,
        sender,
        Some(state_key),
        Some(&content),
        room_version,
    );
    let (event, event_id) = build_event(
        event_type,
        Some(state_key),
        content,
        sender,
        Some(room_id),
        prev,
        &auth,
        *depth,
        signing_key,
        server_name,
        room_version,
    );
    created.push((
        event_type.to_string(),
        state_key.to_string(),
        event_id.clone(),
    ));
    all_events.push((
        event,
        event_id.clone(),
        event_type.to_string(),
        Some(state_key.to_string()),
        *depth,
    ));
    *prev = vec![event_id];
    *depth += 1;
}

fn resolve_event_nids_in_json(
    state: &AppState,
    event: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Vec<u64>, ApiError> {
    let mut out = Vec::new();
    if let Some(arr) = event.get(field).and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(id) = v.as_str()
                && let Some(nid) = state
                    .db
                    .get_event_nid_by_id(id)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                out.push(nid);
            }
        }
    }
    Ok(out)
}

// =====================================================================
// Command dispatch + handlers
// =====================================================================

/// Maybe dispatch an admin command. Called from `send.rs` after an event
/// is persisted. Cheap on the hot path — short-circuits when:
///   - no admin room exists (fresh deploy pre-bootstrap)
///   - the event's room is not the admin room
///   - the event is not an `m.room.message` with `body` starting with `!`
///   - the sender is the bot itself (avoid infinite reply loops)
///   - the sender is not an admin (silently ignored — avoids leaking
///     the admin room's existence to a probe)
///
/// Runs asynchronously: a command's reply may post another event, which
/// re-enters the send path; we don't want the original send to depend on
/// the reply.
pub fn maybe_dispatch_admin_command(
    state: &AppState,
    room_nid: u64,
    sender_nid: u64,
    event_type: &str,
    content: &Value,
) {
    if event_type != "m.room.message" {
        return;
    }
    // Match on body starting with `!` BEFORE the room/admin lookups so
    // the common case (every non-admin-room message) does no DB work.
    let body = match content
        .get("body")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start())
    {
        Some(b) if b.starts_with('!') => b.to_string(),
        _ => return,
    };
    let msgtype = content
        .get("msgtype")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if msgtype != "m.text" {
        return;
    }

    let admin_room_nid = match state.db.get_admin_room_nid() {
        Ok(Some(n)) => n,
        _ => return,
    };
    if admin_room_nid != room_nid {
        return;
    }
    let bot_nid = state.db.get_admin_bot_user_nid().ok().flatten();
    if Some(sender_nid) == bot_nid {
        return;
    }
    // Auth: sender must be a joined member of the admin room.
    match state.db.get_membership(room_nid, sender_nid) {
        Ok(Some(MEMBERSHIP_JOIN)) => {}
        _ => return,
    }

    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_command(&state, room_nid, sender_nid, &body).await {
            warn!(error = ?e.0, "admin command handler failed");
        }
    });
}

/// Split a command line into argv-style pieces. Whitespace-separated.
/// `key=value` arguments are kept intact (caller parses them). We pick
/// the split-args approach over a full grammar because every command
/// is shallow enough that argc + a tiny per-command parse is clearer
/// than a tokenizer + AST.
fn split_args(line: &str) -> Vec<String> {
    line.split_whitespace().map(|s| s.to_string()).collect()
}

async fn handle_command(
    state: &AppState,
    room_nid: u64,
    sender_nid: u64,
    body: &str,
) -> Result<(), ApiError> {
    let stripped = body.trim_start().trim_start_matches('!').trim();
    let argv = split_args(stripped);
    let Some((cmd, rest)) = argv.split_first() else {
        return Ok(());
    };

    let response: Reply = match cmd.as_str() {
        "help" => cmd_help(),
        "server" => cmd_server(state, sender_nid).await?,
        "users" => cmd_users(state, rest).await?,
        "user" => cmd_user(state, rest).await?,
        "deactivate" => cmd_deactivate(state, sender_nid, rest).await?,
        "promote" => cmd_promote(state, sender_nid, rest).await?,
        "demote" => cmd_demote(state, sender_nid, rest).await?,
        "token" => cmd_token(state, sender_nid, rest).await?,
        "tokens" => cmd_tokens(state).await?,
        other => Reply::plain(format!(
            "unknown command: !{other}\ntype `!help` for the list of commands"
        )),
    };

    send_bot_notice(state, room_nid, response).await
}

/// A reply from the admin bot. Always sent as `m.notice` (per spec,
/// notices are server-originated and clients don't process them for
/// notifications — exactly what we want for command output).
/// Optional HTML body for tabular responses.
struct Reply {
    text: String,
    html: Option<String>,
}

impl Reply {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            html: None,
        }
    }
    fn rich(text: impl Into<String>, html: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            html: Some(html.into()),
        }
    }
}

// --- !help ---
//
// Print every command in a single message. Stable ordering so it
// matches docs.
fn cmd_help() -> Reply {
    let text = "Server admin commands:\n\
        \n\
        !help                                show this help text\n\
        !server                              uptime, version, user count, room count\n\
        !users [page]                        list local users (20 per page)\n\
        !user <mxid>                         show user details\n\
        !deactivate <mxid>                   deactivate account; kicks from rooms\n\
        !promote <mxid>                      invite user to admin room (grant admin)\n\
        !demote <mxid>                       kick user from admin room (revoke admin)\n\
        !token create [uses=N] [expires=24h] mint a registration token\n\
        !tokens                              list registration tokens\n\
        !token revoke <token>                delete a registration token";
    Reply::plain(text)
}

// --- !server ---
//
// Operator-oriented status snapshot.
async fn cmd_server(state: &AppState, _sender_nid: u64) -> Result<Reply, ApiError> {
    let uptime_secs = state.started_at.elapsed().as_secs();
    let user_count = state
        .db
        .list_local_user_ids()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .len();
    let room_count = local_room_count(state)?;
    let version = env!("CARGO_PKG_VERSION");
    Ok(Reply::plain(format!(
        "vela {version}\n\
         server_name: {server}\n\
         uptime: {uptime}s\n\
         local users: {user_count}\n\
         local rooms: {room_count}",
        server = state.config.server_name,
        uptime = uptime_secs,
    )))
}

/// Best-effort count of rooms known locally. Walks the `room_meta` CF.
fn local_room_count(state: &AppState) -> Result<usize, ApiError> {
    let rooms = state
        .db
        .list_room_meta_room_ids()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(rooms.len())
}

// --- !users [page] ---
//
// List local users alphabetically, 20 per page. `page` is 1-based.
const USERS_PAGE_SIZE: usize = 20;

async fn cmd_users(state: &AppState, args: &[String]) -> Result<Reply, ApiError> {
    let page = args
        .first()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&p| p > 0)
        .unwrap_or(1);
    let mut users = state
        .db
        .list_local_user_ids()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    users.sort();
    let total = users.len();
    let total_pages = total.div_ceil(USERS_PAGE_SIZE).max(1);
    let start = (page - 1) * USERS_PAGE_SIZE;
    if start >= total {
        return Ok(Reply::plain(format!(
            "page {page} out of range (have {total_pages})"
        )));
    }
    let end = (start + USERS_PAGE_SIZE).min(total);
    let slice = &users[start..end];

    let mut text = format!(
        "users {start_disp}-{end} of {total} (page {page}/{total_pages}):\n",
        start_disp = start + 1
    );
    for u in slice {
        text.push_str(u);
        text.push('\n');
    }
    let mut html = String::from("<table><thead><tr><th>user_id</th></tr></thead><tbody>");
    for u in slice {
        html.push_str("<tr><td>");
        html.push_str(&html_escape(u));
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table>");
    html.push_str(&format!(
        "<p>page {page} of {total_pages} ({total} users)</p>",
    ));
    Ok(Reply::rich(text, html))
}

// --- !user <mxid> ---
async fn cmd_user(state: &AppState, args: &[String]) -> Result<Reply, ApiError> {
    let Some(mxid) = args.first() else {
        return Ok(Reply::plain("usage: !user <@user:server>"));
    };
    let nid = match state
        .db
        .get_nid(mxid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(Reply::plain(format!("unknown user: {mxid}"))),
    };
    let record = state
        .db
        .get_user(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let deactivated = record
        .as_ref()
        .and_then(|r| r.get("deactivated").and_then(|v| v.as_bool()))
        .unwrap_or(false);
    let devices = state
        .db
        .list_devices(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let device_ids: Vec<String> = devices
        .iter()
        .filter_map(|d| {
            d.get("device_id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect();
    let joined = state
        .db
        .get_user_joined_rooms(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let admin = is_admin(state, nid)?;
    let text = format!(
        "{mxid}\n\
         deactivated: {deactivated}\n\
         admin: {admin}\n\
         devices ({dc}): {dl}\n\
         joined rooms: {rc}",
        dc = device_ids.len(),
        dl = if device_ids.is_empty() {
            "<none>".to_string()
        } else {
            device_ids.join(", ")
        },
        rc = joined.len(),
    );
    Ok(Reply::plain(text))
}

// --- !deactivate <mxid> ---
async fn cmd_deactivate(
    state: &AppState,
    _sender_nid: u64,
    args: &[String],
) -> Result<Reply, ApiError> {
    let Some(mxid) = args.first() else {
        return Ok(Reply::plain("usage: !deactivate <@user:server>"));
    };
    let nid = match state
        .db
        .get_nid(mxid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(Reply::plain(format!("unknown user: {mxid}"))),
    };
    // Refuse to deactivate the bot itself.
    if Some(nid) == state.db.get_admin_bot_user_nid().ok().flatten() {
        return Ok(Reply::plain("refusing to deactivate the admin bot"));
    }
    state
        .db
        .deactivate_user(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    state
        .db
        .delete_user_tokens(nid, None)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Force-leave every joined / invited / knocking room via the
    // existing helper. The helper takes an AuthenticatedUser; build a
    // stand-in for the target so events are signed correctly as
    // "target leaves".
    let device_id = state
        .db
        .list_devices(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .into_iter()
        .find_map(|d| {
            d.get("device_id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| "ADMIN_KICK".to_string());
    let target_user_id = state
        .db
        .resolve_nid(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user disappeared".into())))?;
    let target = crate::middleware::auth::AuthenticatedUser {
        user_nid: nid,
        user_id: target_user_id,
        device_id,
    };
    crate::membership::force_leave_all_rooms_for_deactivation(
        state,
        &target,
        "Deactivated by server admin",
    )
    .await;
    Ok(Reply::plain(format!("deactivated {mxid}")))
}

// --- !promote <mxid> ---
//
// "Make this user an admin" = invite them to the admin room. They join
// from any Matrix client. The admin room's PL is set so only the bot
// can change state — invitees join with users_default = 0 which is
// fine, since admin-ness is defined by membership not PL.
async fn cmd_promote(
    state: &AppState,
    _sender_nid: u64,
    args: &[String],
) -> Result<Reply, ApiError> {
    let Some(mxid) = args.first() else {
        return Ok(Reply::plain("usage: !promote <@user:server>"));
    };
    // Refuse on remote MXIDs — admin room is non-federating, so inviting
    // a remote user is a misconfig.
    let server = mxid.split_once(':').map(|(_, s)| s).unwrap_or("");
    if server != state.config.server_name {
        return Ok(Reply::plain(format!(
            "{mxid} is on another server; admin room is local-only"
        )));
    }
    let target_nid = match state
        .db
        .get_nid(mxid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(Reply::plain(format!("unknown user: {mxid}"))),
    };
    let admin_room_nid = state
        .db
        .get_admin_room_nid()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Store("admin room missing".into())))?;
    // No-op if already joined.
    let cur = state
        .db
        .get_membership(admin_room_nid, target_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if cur == Some(MEMBERSHIP_JOIN) {
        return Ok(Reply::plain(format!("{mxid} is already an admin")));
    }
    let room_id = state
        .db
        .get_admin_room_id()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Store("admin room missing".into())))?;
    let room_id = RoomId::parse(&room_id)
        .map_err(|_| ApiError(VelaError::Store("admin room id malformed".into())))?;
    let bot = bot_auth_user(state)?;
    crate::membership::invite_user_internal(
        state.clone(),
        bot,
        admin_room_nid,
        room_id,
        mxid.clone(),
        false,
    )
    .await?;
    Ok(Reply::plain(format!("invited {mxid} to the admin room")))
}

// --- !demote <mxid> ---
//
// "Revoke admin" = kick from the admin room. Refuses self-kick when the
// target is the last human admin (to avoid stranding the room).
async fn cmd_demote(state: &AppState, sender_nid: u64, args: &[String]) -> Result<Reply, ApiError> {
    let Some(mxid) = args.first() else {
        return Ok(Reply::plain("usage: !demote <@user:server>"));
    };
    let target_nid = match state
        .db
        .get_nid(mxid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(Reply::plain(format!("unknown user: {mxid}"))),
    };
    // Don't demote the bot itself.
    if Some(target_nid) == state.db.get_admin_bot_user_nid().ok().flatten() {
        return Ok(Reply::plain("refusing to demote the admin bot"));
    }
    let admin_room_nid = state
        .db
        .get_admin_room_nid()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Store("admin room missing".into())))?;
    let cur = state
        .db
        .get_membership(admin_room_nid, target_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if cur != Some(MEMBERSHIP_JOIN) && cur != Some(2) {
        return Ok(Reply::plain(format!("{mxid} is not an admin")));
    }
    // Self-demote guard: if target == caller AND caller is the only
    // joined human admin, refuse.
    if target_nid == sender_nid {
        let bot_nid = state.db.get_admin_bot_user_nid().ok().flatten();
        let joined = state
            .db
            .get_room_members(admin_room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let other_humans = joined
            .iter()
            .filter(|&&n| Some(n) != bot_nid && n != target_nid)
            .count();
        if other_humans == 0 {
            return Ok(Reply::plain(
                "refusing to demote yourself; you are the last admin\n\
                 invite another user with `!promote <mxid>` first",
            ));
        }
    }
    let room_id = state
        .db
        .get_admin_room_id()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Store("admin room missing".into())))?;
    let room_id = RoomId::parse(&room_id)
        .map_err(|_| ApiError(VelaError::Store("admin room id malformed".into())))?;
    let bot = bot_auth_user(state)?;
    crate::membership::kick_target_for_admin(
        state.clone(),
        bot,
        admin_room_nid,
        room_id,
        mxid.clone(),
    )
    .await?;
    Ok(Reply::plain(format!("kicked {mxid} from the admin room")))
}

// --- !token create [uses=N] [expires=24h] ---
//
// Mint a fresh random token, persist it, return the string verbatim.
// `uses` and `expires` are k=v args. `uses=0` (default) means unlimited,
// `expires=` empty means never expires.
async fn cmd_token_create(
    state: &AppState,
    sender_nid: u64,
    args: &[String],
) -> Result<Reply, ApiError> {
    let mut uses_allowed: u64 = 0;
    let mut expires_at_ms: u64 = 0;
    for a in args {
        if let Some(v) = a.strip_prefix("uses=") {
            match v.parse::<u64>() {
                Ok(n) => uses_allowed = n,
                Err(_) => return Ok(Reply::plain(format!("invalid uses=: {v:?}"))),
            }
        } else if let Some(v) = a.strip_prefix("expires=") {
            if v.is_empty() {
                expires_at_ms = 0;
            } else {
                match parse_duration(v) {
                    Ok(secs) => {
                        expires_at_ms = now_ms().saturating_add(secs.saturating_mul(1000));
                    }
                    Err(e) => return Ok(Reply::plain(format!("invalid expires=: {e}"))),
                }
            }
        } else {
            return Ok(Reply::plain(format!("unknown arg: {a}")));
        }
    }
    let token = mint_token_string();
    state
        .db
        .create_registration_token(&token, uses_allowed, expires_at_ms, sender_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let uses_disp = if uses_allowed == 0 {
        "unlimited".to_string()
    } else {
        uses_allowed.to_string()
    };
    let exp_disp = if expires_at_ms == 0 {
        "never".to_string()
    } else {
        let secs_left = expires_at_ms.saturating_sub(now_ms()) / 1000;
        format!("in {secs_left}s")
    };
    Ok(Reply::plain(format!(
        "minted token (uses: {uses_disp}, expires: {exp_disp}):\n{token}"
    )))
}

async fn cmd_token(state: &AppState, sender_nid: u64, args: &[String]) -> Result<Reply, ApiError> {
    let Some((sub, rest)) = args.split_first() else {
        return Ok(Reply::plain(
            "usage: !token create [uses=N] [expires=24h] | !token revoke <token>",
        ));
    };
    match sub.as_str() {
        "create" => cmd_token_create(state, sender_nid, rest).await,
        "revoke" => {
            let Some(tok) = rest.first() else {
                return Ok(Reply::plain("usage: !token revoke <token>"));
            };
            state
                .db
                .delete_registration_token(tok)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            Ok(Reply::plain(format!("revoked token {tok}")))
        }
        other => Ok(Reply::plain(format!("unknown subcommand: !token {other}"))),
    }
}

// --- !tokens ---
async fn cmd_tokens(state: &AppState) -> Result<Reply, ApiError> {
    let mut tokens = state
        .db
        .list_registration_tokens()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    tokens.sort_by(|a, b| a.0.cmp(&b.0));
    if tokens.is_empty() {
        return Ok(Reply::plain("no registration tokens"));
    }
    let now = now_ms();
    let mut text = String::from("registration tokens:\n");
    let mut html = String::from(
        "<table><thead><tr><th>token</th><th>uses_left</th><th>expires</th></tr></thead><tbody>",
    );
    for (token, record) in &tokens {
        let uses_allowed = record["uses_allowed"].as_u64().unwrap_or(0);
        let uses_used = record["uses_used"].as_u64().unwrap_or(0);
        let expires_at_ms = record["expires_at_ms"].as_u64().unwrap_or(0);
        let uses_left = if uses_allowed == 0 {
            "unlimited".to_string()
        } else {
            uses_allowed.saturating_sub(uses_used).to_string()
        };
        let expires = if expires_at_ms == 0 {
            "never".to_string()
        } else if expires_at_ms <= now {
            "expired".to_string()
        } else {
            format!("in {}s", (expires_at_ms - now) / 1000)
        };
        text.push_str(&format!(
            "  {token}  uses_left={uses_left}  expires={expires}\n"
        ));
        html.push_str(&format!(
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            html_escape(token),
            html_escape(&uses_left),
            html_escape(&expires),
        ));
    }
    html.push_str("</tbody></table>");
    Ok(Reply::rich(text, html))
}

// --- Token + duration helpers ---

fn mint_token_string() -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes: [u8; 24] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Parse `"24h"`, `"30m"`, `"15s"`, `"7d"`, or a bare second count.
/// Returns seconds.
fn parse_duration(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (num_str, mult): (&str, u64) = if let Some(rest) = s.strip_suffix(['s', 'S']) {
        (rest, 1)
    } else if let Some(rest) = s.strip_suffix(['m', 'M']) {
        (rest, 60)
    } else if let Some(rest) = s.strip_suffix(['h', 'H']) {
        (rest, 3600)
    } else if let Some(rest) = s.strip_suffix(['d', 'D']) {
        (rest, 86400)
    } else {
        (s, 1)
    };
    let n: u64 = num_str
        .parse()
        .map_err(|e| format!("bad number {num_str:?}: {e}"))?;
    Ok(n.saturating_mul(mult))
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

// =====================================================================
// Internal bot send + auth identity
// =====================================================================

fn bot_auth_user(state: &AppState) -> Result<crate::middleware::auth::AuthenticatedUser, ApiError> {
    let bot_nid = state
        .db
        .get_admin_bot_user_nid()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Store("admin bot missing".into())))?;
    let user_id = state
        .db
        .resolve_nid(bot_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Store("admin bot user_id missing".into())))?;
    Ok(crate::middleware::auth::AuthenticatedUser {
        user_nid: bot_nid,
        user_id,
        device_id: ADMIN_BOT_DEVICE_ID.to_string(),
    })
}

/// Post a `m.notice` to the admin room as the bot. Inline send: builds
/// the event, runs auth_check, persists, dispatches sync wake-ups.
async fn send_bot_notice(state: &AppState, room_nid: u64, reply: Reply) -> Result<(), ApiError> {
    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let room_id_str = state
        .db
        .resolve_nid(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Store("admin room id lookup failed".into())))?;
    let room_id = RoomId::parse(&room_id_str)
        .map_err(|_| ApiError(VelaError::Store("admin room id malformed".into())))?;

    let mut content = Map::new();
    content.insert("msgtype".into(), Value::String("m.notice".into()));
    content.insert("body".into(), Value::String(reply.text));
    if let Some(html) = reply.html {
        content.insert(
            "format".into(),
            Value::String("org.matrix.custom.html".into()),
        );
        content.insert("formatted_body".into(), Value::String(html));
    }
    let content_val = Value::Object(content);

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut max_depth: u64 = 0;
    let mut prev_event_ids = Vec::new();
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
        if let Some(id) = state
            .db
            .get_event_id_by_nid(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && let Ok(eid) = EventId::parse(&id)
        {
            prev_event_ids.push(eid);
        }
    }

    let bot = bot_auth_user(state)?;
    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            state
                .db
                .get_event_id_by_nid(en)
                .ok()?
                .and_then(|s| EventId::parse(&s).ok())
        };
        select_auth_events(
            "m.room.message",
            &bot.user_id,
            None,
            Some(&content_val),
            room_version,
            &lookup,
        )
    };
    let (event, event_id) = build_event(
        "m.room.message",
        None,
        content_val,
        &bot.user_id,
        Some(&room_id),
        &prev_event_ids,
        &auth_events,
        max_depth + 1,
        &signing_key,
        server_name,
        room_version,
    );
    authorise_event(state, room_nid, &event_id, &event, None)?;
    let event_nid = state.db.next_nid();
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.message")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let auth_nids: Vec<u64> = auth_events
        .iter()
        .filter_map(|id| state.db.get_event_nid_by_id(id.as_str()).ok().flatten())
        .collect();
    let origin_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            bot.user_nid,
            0,
            origin_ts,
            max_depth + 1,
            &json_bytes,
            &extremity_nids,
            &auth_nids,
            false,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    state
        .db
        .update_room_bump(room_nid, origin_ts, event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }
    Ok(())
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// Re-export the device-id constant so test code can mint tokens for
// the bot.
#[allow(dead_code)]
pub fn admin_bot_device_id() -> &'static str {
    ADMIN_BOT_DEVICE_ID
}

#[allow(dead_code)]
pub(crate) fn admin_bot_device() -> DeviceId {
    DeviceId::new(ADMIN_BOT_DEVICE_ID.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use serde_json::json;

    #[tokio::test]
    async fn bootstrap_creates_bot_and_room() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.expect("bootstrap");
        let bot_nid = state.db.get_admin_bot_user_nid().unwrap().unwrap();
        let room_id = state.db.get_admin_room_id().unwrap().unwrap();
        assert!(room_id.starts_with('!'));
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();
        // Bot is joined to the room.
        assert_eq!(
            state.db.get_membership(room_nid, bot_nid).unwrap(),
            Some(MEMBERSHIP_JOIN)
        );
        // Room is unfederated: m.room.create.content.m.federate = false.
        let type_nid = state.db.get_nid("m.room.create").unwrap().unwrap();
        let sk_nid = state.db.get_nid("").unwrap().unwrap();
        let create_nid = state
            .db
            .get_state_event_nid(room_nid, type_nid, sk_nid)
            .unwrap()
            .unwrap();
        let (_, bytes) = state.db.get_event(create_nid).unwrap().unwrap();
        let ev: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ev["content"]["m.federate"], json!(false));
    }

    #[tokio::test]
    async fn bootstrap_is_idempotent() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.expect("first");
        let bot_nid_a = state.db.get_admin_bot_user_nid().unwrap().unwrap();
        let room_id_a = state.db.get_admin_room_id().unwrap().unwrap();
        bootstrap(&state).await.expect("second");
        assert_eq!(
            state.db.get_admin_bot_user_nid().unwrap().unwrap(),
            bot_nid_a
        );
        assert_eq!(state.db.get_admin_room_id().unwrap().unwrap(), room_id_a);
    }

    #[tokio::test]
    async fn bot_localpart_is_reserved_on_register() {
        let (state, _tmp) = build_test_state();
        let err = assert_bot_localpart_not_reserved(&state, "admin").unwrap_err();
        assert!(matches!(err.0, VelaError::Forbidden(_)));
        // Different localpart is fine.
        assert!(assert_bot_localpart_not_reserved(&state, "alice").is_ok());
    }

    #[tokio::test]
    async fn first_registrant_auto_invited() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        assert!(should_auto_invite_first_admin(&state, alice).unwrap());
    }

    #[tokio::test]
    async fn second_registrant_not_auto_invited() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        // Mark alice as joined directly (simulating that she accepted the invite).
        state.db.set_membership(admin_room, alice, 1).unwrap();
        let bob = state.db.create_user("@bob:example.com", "h").unwrap();
        assert!(!should_auto_invite_first_admin(&state, bob).unwrap());
    }

    #[tokio::test]
    async fn is_admin_tracks_membership() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        assert!(!is_admin(&state, alice).unwrap());
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        state.db.set_membership(admin_room, alice, 1).unwrap();
        assert!(is_admin(&state, alice).unwrap());
    }

    #[tokio::test]
    async fn registration_token_lifecycle() {
        let (state, _tmp) = build_test_state();
        state
            .db
            .create_registration_token("tok-1", 2, 0, 0)
            .unwrap();
        assert!(state.db.consume_registration_token("tok-1").unwrap());
        assert!(state.db.consume_registration_token("tok-1").unwrap());
        // Third use exhausts the token.
        assert!(!state.db.consume_registration_token("tok-1").unwrap());
        // Revoke removes it entirely.
        state.db.delete_registration_token("tok-1").unwrap();
        assert!(!state.db.consume_registration_token("tok-1").unwrap());
    }

    #[tokio::test]
    async fn registration_token_expires() {
        let (state, _tmp) = build_test_state();
        state
            .db
            .create_registration_token("tok-exp", 0, 1, 0)
            .unwrap();
        // Sleep slightly past the 1ms expiry.
        tokio::time::sleep(tokio::time::Duration::from_millis(5)).await;
        assert!(!state.db.consume_registration_token("tok-exp").unwrap());
    }

    #[tokio::test]
    async fn help_lists_commands() {
        let reply = cmd_help();
        assert!(reply.text.contains("!help"));
        assert!(reply.text.contains("!token"));
        assert!(reply.html.is_none());
    }

    #[tokio::test]
    async fn parse_duration_suffixes() {
        assert_eq!(parse_duration("60").unwrap(), 60);
        assert_eq!(parse_duration("30s").unwrap(), 30);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("2h").unwrap(), 7200);
        assert_eq!(parse_duration("1d").unwrap(), 86400);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("nope").is_err());
    }

    #[tokio::test]
    async fn split_args_basic() {
        let v = split_args("token create uses=3 expires=24h");
        assert_eq!(v, vec!["token", "create", "uses=3", "expires=24h"]);
        assert!(split_args("").is_empty());
        assert_eq!(split_args("  one   two  "), vec!["one", "two"]);
    }

    #[tokio::test]
    async fn dispatch_ignores_non_admin_room() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        // Just verifies the early return path: non-admin room → no panic.
        maybe_dispatch_admin_command(
            &state,
            999,
            999,
            "m.room.message",
            &json!({"msgtype": "m.text", "body": "!help"}),
        );
    }

    #[tokio::test]
    async fn dispatch_ignores_non_text_messages() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        state.db.set_membership(admin_room, alice, 1).unwrap();
        // Image upload — must not trigger dispatch.
        maybe_dispatch_admin_command(
            &state,
            admin_room,
            alice,
            "m.room.message",
            &json!({"msgtype": "m.image", "body": "!image.png"}),
        );
        // (No assertion; just verifies the early return path doesn't panic.)
    }

    #[tokio::test]
    async fn cmd_server_returns_uptime_and_counts() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let reply = cmd_server(&state, 0).await.unwrap();
        assert!(reply.text.contains("vela "));
        assert!(reply.text.contains("uptime:"));
        // Bot is one local user.
        assert!(reply.text.contains("local users: 1"));
    }

    #[tokio::test]
    async fn cmd_users_handles_empty_and_paginated() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        // Bot user is the only user; one page expected.
        let reply = cmd_users(&state, &[]).await.unwrap();
        assert!(reply.text.contains("@admin:example.com"));
        // Out-of-range page.
        let reply = cmd_users(&state, &["99".to_string()]).await.unwrap();
        assert!(reply.text.contains("out of range"));
    }

    #[tokio::test]
    async fn cmd_user_reports_unknown_and_known() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let r = cmd_user(&state, &["@nobody:example.com".into()])
            .await
            .unwrap();
        assert!(r.text.contains("unknown user"));
        state.db.create_user("@alice:example.com", "h").unwrap();
        let r = cmd_user(&state, &["@alice:example.com".into()])
            .await
            .unwrap();
        assert!(r.text.contains("@alice:example.com"));
        assert!(r.text.contains("deactivated: false"));
    }

    #[tokio::test]
    async fn cmd_deactivate_marks_user() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        let _ = cmd_deactivate(&state, 0, &["@alice:example.com".into()])
            .await
            .unwrap();
        assert!(state.db.user_is_deactivated(alice).unwrap());
    }

    #[tokio::test]
    async fn cmd_deactivate_refuses_bot() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let r = cmd_deactivate(&state, 0, &["@admin:example.com".into()])
            .await
            .unwrap();
        assert!(r.text.contains("refusing"));
        let bot = state.db.get_admin_bot_user_nid().unwrap().unwrap();
        assert!(!state.db.user_is_deactivated(bot).unwrap());
    }

    #[tokio::test]
    async fn cmd_promote_invites_local_user() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        let r = cmd_promote(&state, 0, &["@alice:example.com".into()])
            .await
            .unwrap();
        assert!(r.text.contains("invited"));
        assert_eq!(state.db.get_membership(admin_room, alice).unwrap(), Some(2));
    }

    #[tokio::test]
    async fn cmd_promote_refuses_remote() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let r = cmd_promote(&state, 0, &["@bob:other.example".into()])
            .await
            .unwrap();
        assert!(r.text.contains("local-only"));
    }

    #[tokio::test]
    async fn cmd_demote_refuses_last_admin_self() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        state.db.set_membership(admin_room, alice, 1).unwrap();
        let r = cmd_demote(&state, alice, &["@alice:example.com".into()])
            .await
            .unwrap();
        assert!(r.text.contains("last admin"));
        // Alice is still joined.
        assert_eq!(state.db.get_membership(admin_room, alice).unwrap(), Some(1));
    }

    #[tokio::test]
    async fn dispatch_ignores_non_admin_sender_in_admin_room() {
        // Non-joined / random user posting `!command` in the admin room
        // is silently ignored (no panic, no reply). We can't easily
        // assert "no reply" because dispatch fires off a tokio task;
        // the check here is that the maybe_dispatch path's early
        // returns don't panic and don't trip auth bypasses.
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        let outsider = state.db.create_user("@mallory:example.com", "h").unwrap();
        // outsider is not a member of the admin room.
        assert!(
            state
                .db
                .get_membership(admin_room, outsider)
                .unwrap()
                .is_none()
        );
        maybe_dispatch_admin_command(
            &state,
            admin_room,
            outsider,
            "m.room.message",
            &json!({"msgtype": "m.text", "body": "!help"}),
        );
        // Yield briefly so any spawned tasks would have a chance to
        // misbehave; the assertion is that the runtime stayed sane.
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn handle_command_replies_with_notice_in_admin_room() {
        // End-to-end: an admin posts `!help`, the bot's reply lands
        // in the room timeline as an m.notice.
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        let alice = state.db.create_user("@alice:example.com", "h").unwrap();
        state.db.set_membership(admin_room, alice, 1).unwrap();
        handle_command(&state, admin_room, alice, "!help")
            .await
            .unwrap();
        // The bot's reply should be the most recent timeline event.
        let extremities = state.db.get_extremities(admin_room).unwrap();
        let latest_nid = *extremities.iter().max().unwrap();
        let (_, bytes) = state.db.get_event(latest_nid).unwrap().unwrap();
        let ev: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(ev["type"], "m.room.message");
        assert_eq!(ev["content"]["msgtype"], "m.notice");
        assert!(ev["content"]["body"].as_str().unwrap().contains("!help"));
        // And it was authored by the bot.
        let bot_nid = state.db.get_admin_bot_user_nid().unwrap().unwrap();
        let bot_user_id = state.db.resolve_nid(bot_nid).unwrap().unwrap();
        assert_eq!(ev["sender"].as_str().unwrap(), bot_user_id);
    }

    #[tokio::test]
    async fn cmd_users_returns_html_for_clients_that_render_it() {
        let (state, _tmp) = build_test_state();
        bootstrap(&state).await.unwrap();
        state.db.create_user("@alice:example.com", "h").unwrap();
        let reply = cmd_users(&state, &[]).await.unwrap();
        let html = reply.html.expect("users reply carries html");
        assert!(html.contains("<table>"));
        assert!(html.contains("@alice:example.com"));
    }

    #[tokio::test]
    async fn cmd_token_create_and_tokens_and_revoke() {
        let (state, _tmp) = build_test_state();
        let r = cmd_token(&state, 0, &["create".into(), "uses=5".into()])
            .await
            .unwrap();
        assert!(r.text.contains("minted token"));
        // Extract the token value from the reply.
        let tok = r.text.lines().last().unwrap().to_string();
        // It must show up in the listing.
        let r = cmd_tokens(&state).await.unwrap();
        assert!(r.text.contains(&tok));
        // Revoke.
        let r = cmd_token(&state, 0, &["revoke".into(), tok.clone()])
            .await
            .unwrap();
        assert!(r.text.contains("revoked"));
        assert!(state.db.get_registration_token(&tok).unwrap().is_none());
    }
}
