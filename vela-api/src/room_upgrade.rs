//! `POST /_matrix/client/v3/rooms/{roomId}/upgrade`
//!
//! Spec: `content/client-server-api/modules/room_upgrades.md`.
//!
//! Creates a replacement room with the same content but the requested
//! `new_version`, copies the spec-recommended "transferable" state events
//! across (power_levels, join_rules, history_visibility, name, topic,
//! avatar, guest_access, server_acl, encryption), and posts a
//! `m.room.tombstone` in the old room pointing at the new.
//!
//! Deliberately out of scope for MVP:
//! - Moving local aliases (the spec recommends; we leave them behind).
//! - Raising the old room's `events_default`/`invite` levels to lock it
//!   (spec says "if possible"; skip until we have a clear story for
//!   cross-server coordination).
//! - Cross-server participation in the upgrade: only rooms we can fully
//!   author locally (we have current state + PL) are upgradeable. Remote
//!   rooms fall back to 403.

use std::sync::Arc;

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::{build_event, select_auth_events};
use vela_core::events::content;
use vela_core::events::room_version::RoomVersion;
use vela_core::events::view::EventView;
use vela_core::identifiers::{EventId, Nid, RoomId};

use crate::auth_check::{InFlightState, authorise_event};
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::rooms::get_or_create_signing_key;
use crate::router::AppState;

/// Types the spec calls out as "transferable" when upgrading. Copied from
/// old room to new room in the order listed so the new room's initial
/// state has the same shape as a freshly-created room.
const TRANSFERABLE_TYPES: &[&str] = &[
    "m.room.server_acl",
    "m.room.encryption",
    "m.room.name",
    "m.room.avatar",
    "m.room.topic",
    "m.room.guest_access",
    "m.room.history_visibility",
    "m.room.join_rules",
    "m.room.power_levels",
];

#[derive(Debug, Deserialize)]
pub struct UpgradeBody {
    pub new_version: String,
    #[serde(default)]
    pub additional_creators: Option<Vec<String>>,
}

#[allow(unused_assignments)]
pub async fn upgrade_room(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(old_room_id_str): Path<String>,
    Json(body): Json<UpgradeBody>,
) -> Result<Json<Value>, ApiError> {
    let room_version = RoomVersion::parse(&body.new_version)
        .ok_or_else(|| ApiError(VelaError::UnsupportedRoomVersion(body.new_version.clone())))?;
    if !room_version.at_least(state.config.minimum_room_version) {
        return Err(ApiError(VelaError::UnsupportedRoomVersion(format!(
            "room version {} is below operator minimum {}",
            room_version.as_str(),
            state.config.minimum_room_version.as_str(),
        ))));
    }

    let old_room_id =
        RoomId::parse(&old_room_id_str).map_err(|e| ApiError(VelaError::BadJson(e.to_string())))?;
    let old_room_nid = state
        .db
        .get_nid(old_room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    // Sender must be joined and able to send `m.room.tombstone`. We use the
    // auth-rules engine's required-power-level calc via a simple threshold
    // check against the PL event.
    if state
        .db
        .get_membership(old_room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        != Some(1)
    {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }
    can_send_tombstone(&state, old_room_nid, &user.user_id)?;

    // Load the transferable state blobs from the old room.
    let transferable = read_transferable_state(&state, old_room_nid)?;

    // Pull old create event so we can propagate `type` (if any) and (for
    // v12+) the `event_id` for the `predecessor` link.
    let old_create = read_old_create(&state, old_room_nid)?;
    let signing_key = get_or_create_signing_key(&state)?;
    let server_name = &state.config.server_name;

    // --- Build the sequence of events for the new room. ---

    let mut created: Vec<(String, String, EventId)> = Vec::new();
    let mut all_events: Vec<PendingEvent> = Vec::new();
    let mut depth: u64 = 1;
    let mut prev: Vec<EventId> = vec![];

    // 1. create — with predecessor + optional additional_creators + optional type.
    let mut create_content = content::create_content(room_version);
    {
        let cc = create_content.as_object_mut().unwrap();
        let mut predecessor = serde_json::Map::new();
        predecessor.insert("room_id".to_string(), json!(old_room_id.as_str()));
        // Newest tombstone event from old room would supply event_id; we
        // omit (spec allows for v12+).
        cc.insert("predecessor".to_string(), Value::Object(predecessor));

        if let Some(t) = old_create.get("content").and_then(|c| c.get("type")) {
            cc.insert("type".to_string(), t.clone());
        }
        if let Some(extra) = body.additional_creators.as_ref() {
            cc.insert(
                "additional_creators".to_string(),
                Value::Array(extra.iter().map(|s| json!(s)).collect()),
            );
        }
    }
    // v12 omits `room_id` from the create event (MSC4291: the room_id IS
    // derived from the create event's id). Pre-v12 must include it.
    // Hardcoding None here makes v11 upgrades fail auth_rules check 1.2
    // ("m.room.create missing room_id (pre-v12)").
    let pre_v12_new_room_id = if room_version.omit_room_id_from_create() {
        None
    } else {
        Some(RoomId::generate_for_server(server_name))
    };
    let (create_ev, create_eid) = build_event(
        "m.room.create",
        Some(""),
        create_content,
        &user.user_id,
        pre_v12_new_room_id.as_ref(),
        &[],
        &[],
        depth,
        &signing_key,
        server_name,
        room_version,
    );
    let new_room_id = match pre_v12_new_room_id {
        Some(r) => r,
        None => RoomId::from_create_event_id(&create_eid),
    };
    created.push(("m.room.create".into(), "".into(), create_eid.clone()));
    all_events.push(PendingEvent {
        event: create_ev,
        event_id: create_eid.clone(),
        event_type: "m.room.create".into(),
        state_key: Some("".into()),
        depth,
    });
    prev = vec![create_eid];
    depth += 1;

    // 2. sender's join.
    let member_content = content::member_content_join(None, None);
    let auth = select_auth_for(
        &created,
        "m.room.member",
        &user.user_id,
        Some(&user.user_id),
        Some(&member_content),
        room_version,
    );
    let (ev, eid) = build_event(
        "m.room.member",
        Some(&user.user_id),
        member_content,
        &user.user_id,
        Some(&new_room_id),
        &prev,
        &auth,
        depth,
        &signing_key,
        server_name,
        room_version,
    );
    created.push(("m.room.member".into(), user.user_id.clone(), eid.clone()));
    all_events.push(PendingEvent {
        event: ev,
        event_id: eid.clone(),
        event_type: "m.room.member".into(),
        state_key: Some(user.user_id.clone()),
        depth,
    });
    prev = vec![eid];
    depth += 1;

    // Collect the set of creators of the new room (sender + additional)
    // so we can strip any creator out of a transferred PL `users` map.
    // MSC4289 forbids creators in `users`; the old room's PL may put the
    // upgrader (now the new creator) there, in which case the transfer
    // has to drop them before they trip auth-rules 10.4.
    let mut new_room_creators: Vec<String> = vec![user.user_id.clone()];
    if let Some(extras) = body.additional_creators.as_ref() {
        for s in extras {
            if !new_room_creators.contains(s) {
                new_room_creators.push(s.clone());
            }
        }
    }

    // 3. Transferable state events, in spec-recommended order.
    for t in TRANSFERABLE_TYPES {
        let Some(mut content) = transferable.get(*t).cloned() else {
            continue;
        };
        if *t == "m.room.power_levels"
            && room_version.creators_have_infinite_power()
            && let Some(users) = content
                .as_object_mut()
                .and_then(|o| o.get_mut("users"))
                .and_then(|v| v.as_object_mut())
        {
            for creator in &new_room_creators {
                users.remove(creator);
            }
        }
        let auth = select_auth_for(
            &created,
            t,
            &user.user_id,
            Some(""),
            Some(&content),
            room_version,
        );
        let (ev, eid) = build_event(
            t,
            Some(""),
            content,
            &user.user_id,
            Some(&new_room_id),
            &prev,
            &auth,
            depth,
            &signing_key,
            server_name,
            room_version,
        );
        created.push((t.to_string(), "".into(), eid.clone()));
        all_events.push(PendingEvent {
            event: ev,
            event_id: eid.clone(),
            event_type: t.to_string(),
            state_key: Some("".into()),
            depth,
        });
        prev = vec![eid];
        depth += 1;
    }

    // --- Authorise the full sequence before persisting. ---
    let new_room_nid = state
        .db
        .get_or_create_nid(new_room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut in_flight: InFlightState = std::collections::HashMap::new();
    for pe in &all_events {
        authorise_event(
            &state,
            new_room_nid,
            &pe.event_id,
            &pe.event,
            Some(&in_flight),
        )?;
        if let Some(sk) = &pe.state_key
            && let Some(pdu) =
                vela_core::events::pdu::Pdu::from_json(pe.event_id.as_str().to_string(), &pe.event)
        {
            in_flight.insert((pe.event_type.clone(), sk.clone()), pdu);
        }
    }

    // --- Persist new room. ---
    let new_lock = state
        .room_locks
        .entry(Nid(new_room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _new_guard = new_lock.lock().await;

    state
        .db
        .create_room_meta(new_room_nid, new_room_id.as_str(), room_version.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut state_event_nids = Vec::new();
    let mut last_stream_pos = 0u64;
    for pe in &all_events {
        let type_nid = state
            .db
            .get_or_create_nid(&pe.event_type)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let state_key_nid = if let Some(sk) = &pe.state_key {
            state
                .db
                .get_or_create_nid(sk)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        } else {
            0
        };
        let event_nid = state.db.next_nid()?;
        let json_bytes = canonical_json_object(&pe.event);
        let prev_nids = resolve_event_nids(&state, &pe.event, "prev_events")?;
        let auth_nids = resolve_event_nids(&state, &pe.event, "auth_events")?;
        let origin_ts = pe
            .event
            .get("origin_server_ts")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        last_stream_pos = state
            .db
            .persist_event(
                event_nid,
                pe.event_id.as_str(),
                new_room_nid,
                type_nid,
                user.user_nid,
                state_key_nid,
                origin_ts,
                pe.depth,
                &json_bytes,
                &prev_nids,
                &auth_nids,
                pe.state_key.is_some(),
                false,
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        if pe.state_key.is_some() {
            state_event_nids.push(event_nid);
        }
    }

    state
        .db
        .set_membership(new_room_nid, user.user_nid, 1)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(&state, user.user_nid);
    if !state_event_nids.is_empty() {
        state
            .db
            .persist_state_snapshot(
                new_room_nid,
                *state_event_nids.last().unwrap(),
                &state_event_nids,
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    state
        .db
        .update_room_bump(new_room_nid, now_ms, 0)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if let Some(sender) = state.room_senders.get(&Nid(new_room_nid)) {
        let _ = sender.send(last_stream_pos);
    }
    drop(_new_guard);

    // --- Send m.room.tombstone in the old room. ---
    send_tombstone(
        &state,
        &user,
        old_room_nid,
        &old_room_id,
        new_room_id.as_str(),
    )
    .await?;

    // --- Carry over per-user push rules from old room → new room. ---
    // Spec MSC1772 §"behaviour" plus Synapse's reference behaviour: when
    // a room is upgraded, every local user's `room`-kind push rule
    // bound to the old room is cloned (same actions) for the new room.
    // Without this clients lose their per-room mute / suppress settings
    // on upgrade.
    if let Err(e) = carry_over_push_rules(
        &state,
        old_room_nid,
        old_room_id.as_str(),
        new_room_id.as_str(),
    ) {
        tracing::warn!(error = %e.0, "push rule carry-over after upgrade failed");
    }

    Ok(Json(json!({"replacement_room": new_room_id.as_str()})))
}

/// For each local member of `old_room_nid`, clone their `global.room`
/// push rule for `old_room_id` so it also targets `new_room_id`. Idempotent.
fn carry_over_push_rules(
    state: &AppState,
    old_room_nid: u64,
    old_room_id: &str,
    new_room_id: &str,
) -> Result<(), ApiError> {
    let server = state.config.server_name.as_str();
    let members = state
        .db
        .get_room_members(old_room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for member_nid in members {
        let Some(user_id) = state
            .db
            .resolve_nid(member_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        if !user_id
            .split_once(':')
            .map(|(_, d)| d == server)
            .unwrap_or(false)
        {
            continue;
        }
        carry_over_push_rules_for_user(state, member_nid, old_room_id, new_room_id)?;
    }
    Ok(())
}

/// Clone a single user's `global.room` push rule for `old_room_id` so
/// it also targets `new_room_id`. Idempotent — no-ops when the user
/// has no rule for old, or already has one for new.
pub(crate) fn carry_over_push_rules_for_user(
    state: &AppState,
    user_nid: u64,
    old_room_id: &str,
    new_room_id: &str,
) -> Result<(), ApiError> {
    let Some(mut stored) = state
        .db
        .get_account_data(user_nid, "m.push_rules")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(());
    };
    let Some(global) = stored
        .as_object_mut()
        .and_then(|s| s.get_mut("global"))
        .and_then(|v| v.as_object_mut())
    else {
        return Ok(());
    };
    let Some(room_rules) = global.get_mut("room").and_then(|v| v.as_array_mut()) else {
        return Ok(());
    };
    let old_rule = room_rules
        .iter()
        .find(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some(old_room_id))
        .cloned();
    let Some(old_rule) = old_rule else {
        return Ok(());
    };
    let already_present = room_rules
        .iter()
        .any(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some(new_room_id));
    if already_present {
        return Ok(());
    }
    let mut new_rule = old_rule;
    if let Some(obj) = new_rule.as_object_mut() {
        obj.insert("rule_id".to_string(), json!(new_room_id));
    }
    room_rules.push(new_rule);
    state
        .db
        .set_account_data(user_nid, "m.push_rules", &stored)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if let Some(sender) = state.user_senders.get(&user_nid) {
        let _ = sender.send(());
    }
    Ok(())
}

struct PendingEvent {
    event: serde_json::Map<String, Value>,
    event_id: EventId,
    event_type: String,
    state_key: Option<String>,
    depth: u64,
}

/// Auth-events selector that looks up from the in-flight `created` list.
fn select_auth_for(
    created: &[(String, String, EventId)],
    event_type: &str,
    sender: &str,
    state_key: Option<&str>,
    content: Option<&Value>,
    room_version: RoomVersion,
) -> Vec<EventId> {
    let lookup = |etype: &str, skey: &str| -> Option<EventId> {
        created
            .iter()
            .rev()
            .find(|(t, sk, _)| t == etype && sk == skey)
            .map(|(_, _, e)| e.clone())
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

fn can_send_tombstone(state: &AppState, room_nid: u64, user_id: &str) -> Result<(), ApiError> {
    // Look up required level for `m.room.tombstone`:
    //   power_levels.events[tombstone] ?? power_levels.state_default ?? 50
    // And sender's current level:
    //   power_levels.users[sender] ?? users_default ?? 0
    // Short-circuit: room creators always pass (v12 infinite power).
    // `read_state_json` returns the full event JSON; PL fields live under
    // `content`, not at the top level. The previous version read top-level
    // and silently fell through to `unwrap_or(0)`, so any non-creator
    // upgrade failed with "insufficient power (0 < 50)".
    let pl = read_state_json(state, room_nid, "m.room.power_levels", "")?;
    let pl_content = pl.as_ref().and_then(|p| p.get("content"));
    let required = pl_content
        .and_then(|c| c.get("events").and_then(|e| e.get("m.room.tombstone")))
        .and_then(|v| v.as_i64())
        .or_else(|| {
            pl_content
                .and_then(|c| c.get("state_default"))
                .and_then(|v| v.as_i64())
        })
        .unwrap_or(50);

    let creators = room_creators(state, room_nid)?;
    if creators.iter().any(|c| c == user_id) {
        return Ok(());
    }
    let user_power = pl_content
        .and_then(|c| c.get("users").and_then(|u| u.get(user_id)))
        .and_then(|v| v.as_i64())
        .or_else(|| {
            pl_content
                .and_then(|c| c.get("users_default"))
                .and_then(|v| v.as_i64())
        })
        .unwrap_or(0);

    if user_power < required {
        return Err(VelaError::Forbidden(format!(
            "insufficient power to upgrade ({user_power} < {required})"
        ))
        .into());
    }
    Ok(())
}

fn room_creators(state: &AppState, room_nid: u64) -> Result<Vec<String>, ApiError> {
    let mut out = Vec::new();
    if let Some(ev) = read_state_json(state, room_nid, "m.room.create", "")? {
        if let Some(s) = ev.sender() {
            out.push(s.to_string());
        }
        if let Some(arr) = ev
            .content()
            .and_then(|c| c.get("additional_creators"))
            .and_then(|v| v.as_array())
        {
            for v in arr {
                if let Some(s) = v.as_str()
                    && !out.iter().any(|x| x == s)
                {
                    out.push(s.to_string());
                }
            }
        }
    }
    Ok(out)
}

fn read_state_json(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Result<Option<Value>, ApiError> {
    let tn = state
        .db
        .get_nid(event_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let sn = state
        .db
        .get_nid(state_key)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (Some(tn), Some(sn)) = (tn, sn) else {
        return Ok(None);
    };
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let Some(event_nid) = event_nid else {
        return Ok(None);
    };
    let Some((_, bytes)) = state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(None);
    };
    Ok(serde_json::from_slice::<Value>(&bytes).ok())
}

fn read_old_create(state: &AppState, room_nid: u64) -> Result<Value, ApiError> {
    read_state_json(state, room_nid, "m.room.create", "")?
        .ok_or_else(|| ApiError(VelaError::NotFound("room has no create event".into())))
}

fn read_transferable_state(
    state: &AppState,
    room_nid: u64,
) -> Result<std::collections::HashMap<String, Value>, ApiError> {
    let mut out = std::collections::HashMap::new();
    for t in TRANSFERABLE_TYPES {
        if let Some(ev) = read_state_json(state, room_nid, t, "")?
            && let Some(content) = ev.get("content")
        {
            out.insert(t.to_string(), content.clone());
        }
    }
    Ok(out)
}

async fn send_tombstone(
    state: &AppState,
    user: &AuthenticatedUser,
    old_room_nid: u64,
    old_room_id: &RoomId,
    replacement_room_id: &str,
) -> Result<(), ApiError> {
    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(old_room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let lock = state
        .room_locks
        .entry(Nid(old_room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let content = json!({
        "body": "This room has been replaced",
        "replacement_room": replacement_room_id,
    });

    let extremity_nids = state
        .db
        .get_extremities(old_room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut max_depth: u64 = 0;
    let mut prev_ids = Vec::new();
    for &enid in &extremity_nids {
        if let Ok(Some(d)) = state.db.get_event_depth(enid)
            && d > max_depth
        {
            max_depth = d;
        }
        if let Ok(Some(id)) = state.db.get_event_id_by_nid(enid)
            && let Ok(eid) = EventId::parse(&id)
        {
            prev_ids.push(eid);
        }
    }

    let lookup = |etype: &str, skey: &str| -> Option<EventId> {
        let tn = state.db.get_nid(etype).ok()??;
        let sn = state.db.get_nid(skey).ok()??;
        let en = state.db.get_state_event_nid(old_room_nid, tn, sn).ok()??;
        let id_str = state.db.get_event_id_by_nid(en).ok()??;
        EventId::parse(&id_str).ok()
    };
    let auth_events = select_auth_events(
        "m.room.tombstone",
        &user.user_id,
        Some(""),
        Some(&content),
        room_version,
        &lookup,
    );

    let depth = max_depth + 1;
    let (event, event_id) = build_event(
        "m.room.tombstone",
        Some(""),
        content,
        &user.user_id,
        Some(old_room_id),
        &prev_ids,
        &auth_events,
        depth,
        &signing_key,
        server_name,
        room_version,
    );

    authorise_event(state, old_room_nid, &event_id, &event, None)?;

    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.tombstone")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_or_create_nid("")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let auth_nids: Vec<u64> = auth_events
        .iter()
        .filter_map(|id| state.db.get_event_nid_by_id(id.as_str()).ok().flatten())
        .collect();
    let origin_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            old_room_nid,
            type_nid,
            user.user_nid,
            skey_nid,
            origin_ts,
            depth,
            &json_bytes,
            &extremity_nids,
            &auth_nids,
            true,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .promote_state_event(old_room_nid, event_nid, type_nid, skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state.federation_sender.broadcast(old_room_nid, event_nid);
    Ok(())
}

fn resolve_event_nids(
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
