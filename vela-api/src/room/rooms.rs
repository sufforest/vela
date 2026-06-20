use std::collections::HashMap;
use std::sync::Arc;

use crate::middleware::json::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::build_event;
use vela_core::events::content;
use vela_core::events::pdu::Pdu;
use vela_core::events::room_version::RoomVersion;
use vela_core::events::sign::ServerSigningKey;
use vela_core::events::view::EventView;
use vela_core::identifiers::{EventId, Nid, RoomId};

use crate::auth_check::{InFlightState, authorise_event};
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct CreateRoomRequest {
    pub name: Option<String>,
    pub topic: Option<String>,
    pub preset: Option<String>,
    pub room_version: Option<String>,
    pub creation_content: Option<Value>,
    pub power_level_content_override: Option<Value>,
    pub invite: Option<Vec<String>>,
    pub is_direct: Option<bool>,
    pub initial_state: Option<Vec<InitialStateEvent>>,
    pub visibility: Option<String>,
    /// Localpart for an alias to bind to the new room; e.g. `"foo"` →
    /// `#foo:server`. When set, we register the alias *and* emit an
    /// `m.room.canonical_alias` state event so the room shows up
    /// correctly in the public-rooms directory.
    pub room_alias_name: Option<String>,
}

#[derive(Deserialize)]
pub struct InitialStateEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub state_key: Option<String>,
    pub content: Value,
}

/// Look up an event_id from the list of created events by (type, state_key).
fn lookup_created(
    created: &[(String, String, EventId)],
    event_type: &str,
    state_key: &str,
) -> Option<EventId> {
    created
        .iter()
        .rev()
        .find(|(t, sk, _)| t == event_type && sk == state_key)
        .map(|(_, _, eid)| eid.clone())
}

/// Select auth events from the list of events created so far.
fn select_auth_from_created(
    event_type: &str,
    sender: &str,
    state_key: Option<&str>,
    content: Option<&Value>,
    room_version: RoomVersion,
    created: &[(String, String, EventId)],
) -> Vec<EventId> {
    let lookup = |et: &str, sk: &str| lookup_created(created, et, sk);
    vela_core::events::builder::select_auth_events(
        event_type,
        sender,
        state_key,
        content,
        room_version,
        &lookup,
    )
}

/// Sandboxed room-create decision hook, run before anything is persisted. No-op
/// when no plugin binds the point. A block rejects the creation (403, plugin's
/// errcode) — anti-spam / invite-bomb / no-public-rooms / alias policy.
fn room_create_gate(
    state: &AppState,
    user: &AuthenticatedUser,
    room_id: &str,
    room_version: &str,
    preset: &str,
    body: &CreateRoomRequest,
) -> Result<(), ApiError> {
    // Lock-free snapshot, like the other decision gates.
    let rt = state.extensions.load();
    if !rt.binds_check_room_create() {
        return Ok(());
    }
    let ctx = vela_extensions::RoomCreate {
        creator: &user.user_id,
        room_id,
        room_version,
        preset,
        visibility: body.visibility.as_deref(),
        name: body.name.as_deref(),
        topic: body.topic.as_deref(),
        alias_localpart: body.room_alias_name.as_deref(),
        invite: body.invite.as_deref().unwrap_or(&[]),
        is_direct: body.is_direct.unwrap_or(false),
    };
    match rt.check_room_create(&ctx) {
        vela_extensions::Decision::Allow => Ok(()),
        vela_extensions::Decision::Block { errcode, reason } => {
            tracing::info!(creator = %user.user_id, room_id, %errcode, %reason, "extension blocked room creation");
            Err(ApiError(VelaError::ExtensionBlocked { errcode, reason }))
        }
    }
}

/// POST /_matrix/client/v3/createRoom
#[allow(unused_assignments)]
pub async fn create_room(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    body_bytes: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    // Parse the body manually so deserialization errors (e.g. a
    // numeric `room_version` instead of a string) surface as
    // 400 M_BAD_JSON rather than axum's default 422 Unprocessable Entity.
    let body: CreateRoomRequest = if body_bytes.is_empty() {
        serde_json::from_slice(b"{}").map_err(|e| ApiError(VelaError::BadJson(e.to_string())))?
    } else {
        serde_json::from_slice(&body_bytes)
            .map_err(|e| ApiError(VelaError::BadJson(e.to_string())))?
    };
    let room_version = match body.room_version.as_deref() {
        Some(v) => RoomVersion::parse(v)
            .ok_or_else(|| ApiError(VelaError::UnsupportedRoomVersion(v.to_string())))?,
        None => RoomVersion::V12,
    };
    if !room_version.at_least(state.config.minimum_room_version) {
        return Err(ApiError(VelaError::UnsupportedRoomVersion(format!(
            "room version {} is below operator minimum {}",
            room_version.as_str(),
            state.config.minimum_room_version.as_str(),
        ))));
    }

    // Up-front structural validation. The auth-rules engine would also
    // reject these at check_auth time, but as 403 M_FORBIDDEN — Complement
    // (and the spec) want 400 M_BAD_JSON for malformed client input.
    if let Some(cc) = body.creation_content.as_ref() {
        validate_creation_content(cc)?;
    }

    let preset = body
        .preset
        .as_deref()
        .unwrap_or(match body.visibility.as_deref() {
            Some("public") => "public_chat",
            _ => "private_chat",
        });

    let (join_rule, history_vis, guest_access) = match preset {
        "private_chat" | "trusted_private_chat" => ("invite", "shared", "can_join"),
        "public_chat" => ("public", "shared", "forbidden"),
        _ => ("invite", "shared", "can_join"),
    };

    let signing_key = get_or_create_signing_key(&state)?;
    let server_name = &state.config.server_name;

    let mut created: Vec<(String, String, EventId)> = Vec::new();
    let mut all_events: Vec<PendingEvent> = Vec::new();
    let mut depth: u64 = 1;
    let mut prev: Vec<EventId> = vec![];

    // Helper to emit a state event, push to tracking, advance DAG
    macro_rules! emit {
        ($etype:expr, $skey:expr, $content:expr, $room_id_opt:expr) => {{
            let auth = select_auth_from_created(
                $etype,
                &user.user_id,
                Some($skey),
                None,
                room_version,
                &created,
            );
            let (ev, eid) = build_event(
                $etype,
                Some($skey),
                $content,
                &user.user_id,
                $room_id_opt,
                &prev,
                &auth,
                depth,
                &signing_key,
                server_name,
                room_version,
            );
            created.push(($etype.to_string(), $skey.to_string(), eid.clone()));
            all_events.push(PendingEvent {
                event: ev,
                event_id: eid.clone(),
                event_type: $etype.to_string(),
                state_key: Some($skey.to_string()),
                depth,
            });
            prev = vec![eid];
            depth += 1;
        }};
    }

    // --- 1. m.room.create (no room_id, no auth) ---
    let mut create_content_val = content::create_content(room_version);
    // Set `content.creator = caller`. MSC4291 removes the field for v12,
    // but most clients (and many integration tests) still read it; the
    // field is harmless on v12 because we authorise off `sender`, not
    // `content.creator`. Caller-supplied `creation_content.creator` is
    // explicitly NOT honoured (a client cannot impersonate another user
    // as the creator).
    create_content_val
        .as_object_mut()
        .unwrap()
        .insert("creator".to_string(), Value::String(user.user_id.clone()));
    if let Some(extra) = &body.creation_content
        && let Some(extra_obj) = extra.as_object()
    {
        let cc = create_content_val.as_object_mut().unwrap();
        for (k, v) in extra_obj {
            if k != "creator" && k != "room_version" {
                cc.insert(k.clone(), v.clone());
            }
        }
    }
    // MSC4289: trusted_private_chat used to grant power 100 to invitees by
    // putting them in power_levels.users. v12 forbids creators-in-users, so
    // we instead promote invitees to `additional_creators` on the create
    // event. Existing entries from `creation_content.additional_creators`
    // are preserved.
    if preset == "trusted_private_chat"
        && let Some(invites) = &body.invite
        && !invites.is_empty()
    {
        let cc = create_content_val.as_object_mut().unwrap();
        let mut existing: Vec<Value> = cc
            .get("additional_creators")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for invitee in invites {
            if !existing.iter().any(|v| v.as_str() == Some(invitee)) {
                existing.push(Value::String(invitee.clone()));
            }
        }
        cc.insert("additional_creators".to_string(), Value::Array(existing));
    }
    // v12 derives room_id from the create event's event_id (so the
    // create has no `room_id` field). Pre-v12 rooms mint a random
    // `!opaque:server` first and the create event carries the field.
    // Build the create accordingly.
    let pre_v12_room_id = if room_version.omit_room_id_from_create() {
        None
    } else {
        Some(RoomId::generate_for_server(server_name))
    };
    let (create_ev, create_eid) = build_event(
        "m.room.create",
        Some(""),
        create_content_val,
        &user.user_id,
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
    all_events.push(PendingEvent {
        event: create_ev,
        event_id: create_eid.clone(),
        event_type: "m.room.create".into(),
        state_key: Some("".into()),
        depth,
    });
    prev = vec![create_eid];
    depth += 1;

    // --- 2. m.room.member (creator join) ---
    let member_content = content::member_content_join(None, None);
    let auth = select_auth_from_created(
        "m.room.member",
        &user.user_id,
        Some(&user.user_id),
        Some(&member_content),
        room_version,
        &created,
    );
    let (member_ev, member_eid) = build_event(
        "m.room.member",
        Some(&user.user_id),
        member_content,
        &user.user_id,
        Some(&room_id),
        &prev,
        &auth,
        depth,
        &signing_key,
        server_name,
        room_version,
    );
    created.push((
        "m.room.member".into(),
        user.user_id.clone(),
        member_eid.clone(),
    ));
    all_events.push(PendingEvent {
        event: member_ev,
        event_id: member_eid.clone(),
        event_type: "m.room.member".into(),
        state_key: Some(user.user_id.clone()),
        depth,
    });
    prev = vec![member_eid];
    depth += 1;

    // --- 3. m.room.power_levels ---
    let mut pl_content = content::power_levels_content(room_version);
    // Preset-specific PL overrides — match synapse's `_presets_dict`. Both
    // private_chat and trusted_private_chat drop the invite floor to 0 so
    // any joined member can invite; public_chat keeps the default 50. The
    // client's `power_level_content_override` (applied below) can layer on
    // top of these preset defaults.
    if matches!(preset, "private_chat" | "trusted_private_chat")
        && let Some(pl_obj) = pl_content.as_object_mut()
    {
        pl_obj.insert("invite".to_string(), json!(0));
    }
    if let Some(ov) = &body.power_level_content_override {
        // v12 (MSC4289): power_levels.users MUST NOT contain a room creator
        // (sender of m.room.create or anyone in additional_creators). The
        // CS-API rejects up-front rather than letting check_auth turn this
        // into a 403. Pre-v12 rooms (where creators don't have implicit
        // infinite power) can legitimately list themselves in `users`.
        if room_version.creators_have_infinite_power() {
            let creators = collect_creators(&user.user_id, body.creation_content.as_ref());
            validate_pl_override_no_creators(ov, &creators)?;
        }
        if let Some(ov_obj) = ov.as_object() {
            let pl = pl_content.as_object_mut().unwrap();
            for (k, v) in ov_obj {
                pl.insert(k.clone(), v.clone());
            }
        }
    }
    emit!("m.room.power_levels", "", pl_content, Some(&room_id));

    // --- 4. Preset events ---
    //
    // Initial_state overrides preset defaults per spec: when the client
    // supplies `m.room.history_visibility` / `m.room.guest_access` /
    // `m.room.join_rules` in initial_state, the preset default for
    // that (type, state_key) is silently SKIPPED so we don't emit two
    // state events for the same key. Without this, Element shows two
    // state-change notices in the room timeline ("made future room
    // history visible to all room members" AND "from the point they
    // are invited") and the preset's earlier event is shadowed by the
    // later one anyway via topological state-res ordering.
    let initial_state_keys: std::collections::HashSet<(String, String)> = body
        .initial_state
        .as_deref()
        .map(|evs| {
            evs.iter()
                .map(|e| {
                    (
                        e.event_type.clone(),
                        e.state_key.clone().unwrap_or_default(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let initial_state_has = |etype: &str, skey: &str| {
        initial_state_keys.contains(&(etype.to_string(), skey.to_string()))
    };

    if !initial_state_has("m.room.join_rules", "") {
        emit!(
            "m.room.join_rules",
            "",
            content::join_rules_content(join_rule),
            Some(&room_id)
        );
    }
    if !initial_state_has("m.room.history_visibility", "") {
        emit!(
            "m.room.history_visibility",
            "",
            content::history_visibility_content(history_vis),
            Some(&room_id)
        );
    }
    // Only emit `m.room.guest_access` when the preset diverges from
    // the spec default of `forbidden` — synapse and continuwuity skip
    // the no-op event for public_chat / preset-default rooms. Emitting
    // it anyway pads the room's prev_events chain with an event that
    // breaks tests counting initial-state events
    // (e.g. TestInboundCanReturnMissingEvents) and is purely
    // redundant with the spec default.
    if guest_access != "forbidden" && !initial_state_has("m.room.guest_access", "") {
        emit!(
            "m.room.guest_access",
            "",
            content::guest_access_content(guest_access),
            Some(&room_id)
        );
    }

    // --- 5. initial_state ---
    let client_supplied_encryption = body
        .initial_state
        .as_ref()
        .map(|ev| ev.iter().any(|e| e.event_type == "m.room.encryption"))
        .unwrap_or(false);
    if let Some(initial) = &body.initial_state {
        for ev in initial {
            let skey = ev.state_key.as_deref().unwrap_or("");
            emit!(&ev.event_type, skey, ev.content.clone(), Some(&room_id));
        }
    }

    // --- 5b. encrypt-by-default policy ---
    // If the client didn't explicitly set m.room.encryption, server
    // policy may inject it. Clients that pass an explicit
    // `m.room.encryption` event ALWAYS win — including the special
    // case of `algorithm: ""` (or other falsy) used to opt out.
    if !client_supplied_encryption
        && should_auto_encrypt(
            state.config.encrypt_by_default,
            preset,
            body.is_direct.unwrap_or(false),
        )
    {
        emit!(
            "m.room.encryption",
            "",
            json!({"algorithm": "m.megolm.v1.aes-sha2"}),
            Some(&room_id)
        );
    }

    // --- 6. name and topic ---
    if let Some(name) = &body.name {
        emit!(
            "m.room.name",
            "",
            content::name_content(name),
            Some(&room_id)
        );
    }
    if let Some(topic) = &body.topic {
        emit!(
            "m.room.topic",
            "",
            content::topic_content(topic),
            Some(&room_id)
        );
    }

    // Sandboxed room-create decision hook — runs once the request is fully
    // resolved but before ANY persistence (the alias write just below is the
    // first DB write), so a block leaves no orphan state — no alias, no nid, no
    // events.
    room_create_gate(
        &state,
        &user,
        room_id.as_str(),
        room_version.as_str(),
        preset,
        &body,
    )?;

    // --- 6b. room_alias_name ---
    // Register the alias and pin it as the canonical alias. The alias
    // record lives in the directory CF (used by /directory/room/...)
    // and the m.room.canonical_alias state event makes it appear in
    // /publicRooms responses.
    let mut canonical_alias: Option<String> = None;
    if let Some(localpart) = body.room_alias_name.as_deref().filter(|s| !s.is_empty()) {
        let alias = format!("#{localpart}:{server_name}");
        // M_EXCLUSIVE: a non-AS caller (or an AS not owning this
        // namespace) cannot claim an alias inside an AS's exclusive
        // alias namespace. Same rule as /directory/room/{alias}.
        if let crate::appservice::exclusive::ExclusiveCheck::Refused(reason) =
            crate::appservice::exclusive::check_alias(
                &state.appservice_registry,
                &alias,
                user.appservice_nid,
            )
        {
            return Err(ApiError(VelaError::Custom {
                status: 400,
                errcode: "M_EXCLUSIVE",
                msg: reason,
            }));
        }
        if state
            .db
            .get_room_alias(&alias)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .is_some()
        {
            return Err(ApiError(VelaError::BadJson(format!(
                "alias already exists: {alias}"
            ))));
        }
        state
            .db
            .set_room_alias_with_creator(&alias, room_id.as_str(), &user.user_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        emit!(
            "m.room.canonical_alias",
            "",
            json!({"alias": alias.clone()}),
            Some(&room_id)
        );
        canonical_alias = Some(alias);
    }
    let _ = canonical_alias;

    // --- 7. Invites from the request body ---
    // Local targets get their member event built into the room's initial
    // state. Remote targets are queued for a federation invite POST after
    // the room is persisted (we don't include their member event in our
    // initial state — the spec invite flow has the recipient server add it).
    let mut local_invitees: Vec<String> = Vec::new();
    let mut remote_invitees: Vec<String> = Vec::new();
    if let Some(invitees) = &body.invite {
        for target in invitees {
            if !is_local_user(target, server_name) {
                remote_invitees.push(target.clone());
                continue;
            }
            // Build the invite member event with full content so auth-event
            // selection picks up join_rules correctly (the `emit!` macro
            // above passes None for content). Propagate the createRoom
            // body's `is_direct` flag into each invitee's member content
            // so DM client UIs can recognise the room on receive.
            let mut member_content = content::member_content_invite();
            if body.is_direct == Some(true)
                && let Some(obj) = member_content.as_object_mut()
            {
                obj.insert("is_direct".to_string(), Value::Bool(true));
            }
            let auth = select_auth_from_created(
                "m.room.member",
                &user.user_id,
                Some(target),
                Some(&member_content),
                room_version,
                &created,
            );
            let (ev, eid) = build_event(
                "m.room.member",
                Some(target),
                member_content,
                &user.user_id,
                Some(&room_id),
                &prev,
                &auth,
                depth,
                &signing_key,
                server_name,
                room_version,
            );
            created.push(("m.room.member".into(), target.clone(), eid.clone()));
            all_events.push(PendingEvent {
                event: ev,
                event_id: eid.clone(),
                event_type: "m.room.member".into(),
                state_key: Some(target.clone()),
                depth,
            });
            prev = vec![eid];
            depth += 1;
            local_invitees.push(target.clone());
        }
    }

    // --- Persist ---
    let room_nid = state
        .db
        .get_or_create_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // --- Authorise pass ---
    // Walk the built sequence in order, building a cumulative in-flight state
    // map. Each state event must pass `check_auth` against the events built
    // before it. Any rejection aborts createRoom with HTTP 403.
    let mut in_flight: InFlightState = HashMap::new();
    for pe in &all_events {
        authorise_event(&state, room_nid, &pe.event_id, &pe.event, Some(&in_flight))?;
        if let Some(sk) = &pe.state_key
            && let Some(pdu) = Pdu::from_json(pe.event_id.as_str().to_string(), &pe.event)
        {
            in_flight.insert((pe.event_type.clone(), sk.clone()), pdu);
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

        let prev_nids = resolve_event_nids_from_json(&state, &pe.event, "prev_events")?;
        let auth_nids = resolve_event_nids_from_json(&state, &pe.event, "auth_events")?;

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
                room_nid,
                type_nid,
                user.user_nid,
                state_key_nid,
                origin_ts,
                pe.depth,
                &json_bytes,
                &prev_nids,
                &auth_nids,
                pe.state_key.is_some(),
                false, // suppress_current_state: createRoom events always update state
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

        if pe.state_key.is_some() {
            state_event_nids.push(event_nid);
        }
    }

    state
        .db
        .set_membership(room_nid, user.user_nid, 1)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(&state, user.user_nid);

    for target in &local_invitees {
        let target_nid = state
            .db
            .get_or_create_nid(target)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        state
            .db
            .set_membership(room_nid, target_nid, 2)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        // Wake the invitee's pending /sync so the invite shows up
        // immediately instead of after their 30s long-poll timeout.
        crate::router::notify_user(&state, target_nid);
    }

    // Stamp a state snapshot at EVERY state event we just persisted,
    // not just the last one. `state_before_event` walks back through
    // prev_events looking for a recorded snapshot; if the only snapshot
    // is at the room's tip, /state and /state_ids return empty for any
    // earlier anchor (notably the join's `prev_event`, which MSC3902
    // and vela-vela federation queries use). The snapshot content
    // (`state_event_nids`) is identical at each step because createRoom
    // applies its events as a coherent block — the same set is the
    // "post-state" at every event in the sequence.
    for &nid in &state_event_nids {
        state
            .db
            .persist_state_snapshot(room_nid, nid, &state_event_nids)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    state
        .db
        .update_room_bump(room_nid, now, 0)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(last_stream_pos);
    }

    // Manual room upgrade: when createRoom carries a
    // `creation_content.predecessor.room_id`, the caller is replacing
    // an old room with this one. Carry over the creator's `room` push
    // rule for the old room so muting/notify settings survive the
    // upgrade. (The /upgrade endpoint does this for all local
    // members; here we only know about the creator until others join,
    // where the do_join path covers them.)
    if let Some(old_room_id) = body
        .creation_content
        .as_ref()
        .and_then(|cc| cc.get("predecessor"))
        .and_then(|p| p.get("room_id"))
        .and_then(|v| v.as_str())
    {
        let _ = crate::room::room_upgrade::carry_over_push_rules_for_user(
            &state,
            user.user_nid,
            old_room_id,
            room_id.as_str(),
        )
        .await;
    }

    // Release the room lock before the remote-invite fan-out below.
    // `emit_membership_event_for_target` re-acquires the same per-room
    // mutex; without this drop the createRoom task deadlocks against
    // itself, the request hangs until the tower-http TimeoutLayer
    // returns 504, and federated tests fail with `context deadline
    // exceeded`. tokio::sync::Mutex is not reentrant.
    drop(_guard);

    // Federate invites to remote users via the regular invite path.
    // emit_membership_event_for_target takes its own lock and reads
    // the create event from current state for auth.
    for target in remote_invitees {
        let user_clone = crate::middleware::auth::AuthenticatedUser {
            user_nid: user.user_nid,
            user_id: user.user_id.clone(),
            device_id: user.device_id.clone(),
            appservice_nid: None,
        };
        if let Err(e) = crate::membership::invite_user_internal(
            state.clone(),
            user_clone,
            room_nid,
            room_id.clone(),
            target.clone(),
            body.is_direct == Some(true),
        )
        .await
        {
            tracing::warn!(
                target = %target,
                error = ?e,
                "createRoom remote invite failed; client can retry via /rooms/{{id}}/invite"
            );
        }
    }

    Ok(Json(json!({"room_id": room_id.as_str()})))
}

/// GET /_matrix/client/v3/rooms/{roomId}/members
///
/// Returns the m.room.member state events for the room. Supports an optional
/// `membership` filter and `not_membership` filter via query string. Per spec,
/// non-joined viewers may be limited to history-visible state, but for now
/// we just gate on current membership being join (matches `/state` access).
pub async fn list_members(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<MembersQuery>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    await_partial_state_clear(&state, room_nid).await;

    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Departed users (leave=0, ban=3) get the member list as of their
    // leave event so they don't see joins that happened after they
    // left. Spec history-visibility rule 2. Membership encoding
    // mirrors federation_receive.rs::set_membership.
    let view_at_leave: Option<u64> = match membership {
        Some(1) => None,
        Some(0) | Some(3) => departed_state_snapshot_nid(&state, room_nid, user.user_nid)?,
        _ => return Err(VelaError::Forbidden("not a member of this room".into()).into()),
    };

    let want = q.membership.as_deref();
    let exclude = q.not_membership.as_deref();

    // Resolve which member events to consider:
    //   - `at` set: look up the room's state snapshot at the event
    //     whose stream_pos == at, and pull the member events from it.
    //     (Spec semantic is "state at this pagination token", not
    //     "member events present in the timeline range [0, at]" —
    //     state events get stream_pos like any other event, but a
    //     prev_batch typically points past the room-create state
    //     events, so walking the timeline up to `at` misses
    //     existing members. TestGetRoomMembersAtPoint relies on
    //     the snapshot interpretation.)
    //   - departed user without `at`: use the snapshot recorded at
    //     their leave event.
    //   - currently joined: use current room state (fast path).
    let member_events: Vec<u64> =
        match (q.at.as_deref().and_then(parse_stream_token), view_at_leave) {
            (Some(at_pos), _) => {
                // Find the most recent STATE event with pos <= at_pos
                // and use its post-state snapshot. Only state events
                // get a recorded snapshot (`promote_state_event` writes
                // it); timeline messages don't. Naively picking the
                // last event in `[0, at_pos]` would land on a message
                // and miss the snapshot, falling back to current state
                // — that's the bug TestGetRoomMembersAtPoint hits when
                // bob joins after the at-token is captured. Walk
                // backwards through the timeline window looking for an
                // event that has a snapshot recorded.
                let snapshot_window = state
                    .db
                    .get_timeline_range(room_nid, 0, at_pos.saturating_add(1), 10_000)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                let mut state_snapshot: Option<Vec<u64>> = None;
                for (_, nid) in snapshot_window.iter().rev() {
                    if let Some(snap) = state
                        .db
                        .get_state_at_event(*nid)
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    {
                        state_snapshot = Some(snap);
                        break;
                    }
                }
                state_snapshot.unwrap_or_else(|| {
                    state
                        .db
                        .get_all_state_event_nids(room_nid)
                        .unwrap_or_default()
                })
            }
            (None, Some(snapshot_owner_event_nid)) => state
                .db
                .get_state_at_event(snapshot_owner_event_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .unwrap_or_default(),
            (None, None) => state
                .db
                .get_all_state_event_nids(room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?,
        };

    let mut chunk = Vec::new();
    for nid in member_events {
        let Some(ev) = crate::room::messages::load_client_event(&state, nid, &room_id)? else {
            continue;
        };
        if ev.event_type() != Some("m.room.member") {
            continue;
        }
        let m = ev.membership().unwrap_or("");
        if let Some(w) = want
            && m != w
        {
            continue;
        }
        if let Some(x) = exclude
            && m == x
        {
            continue;
        }
        chunk.push(ev);
    }
    Ok(Json(json!({"chunk": chunk})))
}

fn parse_stream_token(s: &str) -> Option<u64> {
    s.strip_prefix('s').and_then(|n| n.parse().ok())
}

/// For a departed user (membership=leave|ban), return the NID of
/// their current `m.room.member` event — i.e. their leave/ban event.
/// The state snapshot recorded at this event represents the room as
/// they last saw it. Returns `None` if the member event is missing.
fn departed_state_snapshot_nid(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
) -> Result<Option<u64>, ApiError> {
    let Some(user_id) = state
        .db
        .resolve_nid(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(None);
    };
    let Some(type_nid) = state
        .db
        .get_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(None);
    };
    let Some(sk_nid) = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(None);
    };
    state
        .db
        .get_state_event_nid(room_nid, type_nid, sk_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct MembersQuery {
    pub membership: Option<String>,
    pub not_membership: Option<String>,
    /// Sync token to scope the result to. Honoured: members are
    /// computed by replaying the timeline up to this point. Absent →
    /// current state.
    pub at: Option<String>,
}

/// GET /_matrix/client/v3/rooms/{roomId}/aliases
///
/// Lists local aliases that point at this room. Joined members can always
/// see them; non-members get a 403 unless the room visibility allows it
/// (we don't model visibility separately yet, so we gate on membership).
pub async fn list_room_aliases(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }
    let aliases = state
        .db
        .list_aliases_for_room(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({"aliases": aliases})))
}

/// MSC3902 / MSC3706: block while the room is in partial-state, cap at
/// 30s. Used by `/members` and `/joined_members` — complement uses
/// these endpoints as the canonical "await resync" gates, and any
/// non-blocking implementation hands clients a truncated member set
/// while the filler is still catching up.
///
/// Race-aware: subscribes to the room's wake channel BEFORE the second
/// flag read so a clear that fires between the first read and the
/// subscribe is still observed (the filler's `wake_sync_on_clear`
/// publishes on this same channel). Order: first-check → subscribe →
/// second-check → loop.
///
/// On timeout, falls through and returns whatever the caller would
/// have returned without the wait — better a stale member list than
/// a hung client.
async fn await_partial_state_clear(state: &AppState, room_nid: u64) {
    let (partial, _) = state
        .db
        .get_partial_state_info(room_nid)
        .unwrap_or((false, Vec::new()));
    if !partial {
        return;
    }
    let mut rx = {
        let sender = state
            .room_senders
            .entry(Nid(room_nid))
            .or_insert_with(|| tokio::sync::broadcast::channel::<u64>(64).0);
        sender.value().subscribe()
    };
    let (still_partial, _) = state
        .db
        .get_partial_state_info(room_nid)
        .unwrap_or((false, Vec::new()));
    if !still_partial {
        return;
    }
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(30));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return,
            recv = rx.recv() => {
                // Lagged messages just mean we missed a wake — re-check
                // the flag; if still partial, keep waiting. Closed
                // means the room channel went away; stop waiting.
                match recv {
                    Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        let (still, _) = state
                            .db
                            .get_partial_state_info(room_nid)
                            .unwrap_or((false, Vec::new()));
                        if !still {
                            return;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

/// GET /_matrix/client/v3/rooms/{roomId}/joined_members
pub async fn joined_members(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    await_partial_state_clear(&state, room_nid).await;

    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let member_nids = state
        .db
        .get_room_members(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut joined = serde_json::Map::new();
    let type_member = state
        .db
        .get_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for member_nid in member_nids {
        let user_id = match state
            .db
            .resolve_nid(member_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(s) => s,
            None => continue,
        };
        let mut entry = serde_json::Map::new();
        let mut display_name: Option<String> = None;
        let mut avatar_url: Option<String> = None;

        // Prefer the per-room member event content.
        if let Some(tn) = type_member {
            let skey_nid = state
                .db
                .get_nid(&user_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            if let Some(sn) = skey_nid
                && let Some(event_nid) = state
                    .db
                    .get_state_event_nid(room_nid, tn, sn)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                && let Some((_, bytes)) = state
                    .db
                    .get_event(event_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                && let Ok(ev) = serde_json::from_slice::<Value>(&bytes)
            {
                let content = ev.get("content");
                display_name = content
                    .and_then(|c| c.get("displayname"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
                avatar_url = content
                    .and_then(|c| c.get("avatar_url"))
                    .and_then(|v| v.as_str())
                    .map(String::from);
            }
        }

        // Fall back to the user's profile so the JSON keys are always present
        // (test contracts expect them, even if null).
        if (display_name.is_none() || avatar_url.is_none())
            && let Ok(Some(profile)) = state.db.get_user(member_nid)
        {
            if display_name.is_none() {
                display_name = profile
                    .get("displayname")
                    .and_then(|v| v.as_str())
                    .map(String::from);
            }
            if avatar_url.is_none() {
                avatar_url = profile
                    .get("avatar_url")
                    .and_then(|v| v.as_str())
                    .map(String::from);
            }
        }

        entry.insert(
            "display_name".to_string(),
            display_name.map(Value::String).unwrap_or(Value::Null),
        );
        entry.insert(
            "avatar_url".to_string(),
            avatar_url.map(Value::String).unwrap_or(Value::Null),
        );
        joined.insert(user_id, Value::Object(entry));
    }
    Ok(Json(json!({"joined": joined})))
}

/// POST /_matrix/client/v3/rooms/{roomId}/forget
///
/// Spec: the caller MUST already have left or been banned from the room.
/// We clear the membership index entry and the user_rooms entry so the
/// room no longer surfaces in their `rooms.leave` on sync.
pub async fn forget_room(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    axum::extract::Path(room_id): axum::extract::Path<String>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if matches!(membership, Some(1) | Some(2)) {
        // Spec wants 400 M_UNKNOWN when the caller is still joined or
        // still has a pending invite. M_UNKNOWN normally maps to 500,
        // but for /forget the response status is 400 — use the Uia
        // variant which surfaces a custom (status, body) tuple.
        return Err(ApiError(VelaError::Uia {
            status: 400,
            body: json!({
                "errcode": "M_UNKNOWN",
                "error": "user must leave the room before forgetting",
            })
            .to_string(),
        }));
    }
    state
        .db
        .forget_room(user.user_nid, room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({})))
}

/// GET /_matrix/client/v3/joined_rooms
pub async fn joined_rooms(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let room_nids = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut room_ids = Vec::new();
    for nid in room_nids {
        if let Some(id) = state
            .db
            .resolve_nid(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            room_ids.push(Value::String(id));
        }
    }

    Ok(Json(json!({"joined_rooms": room_ids})))
}

struct PendingEvent {
    event: serde_json::Map<String, Value>,
    event_id: EventId,
    event_type: String,
    state_key: Option<String>,
    depth: u64,
}

fn resolve_event_nids_from_json(
    state: &AppState,
    event: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Vec<u64>, ApiError> {
    let ids = event
        .get(field)
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    let mut nids = Vec::new();
    for id in ids {
        if let Some(nid) = state
            .db
            .get_event_nid_by_id(id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            nids.push(nid);
        }
    }
    Ok(nids)
}

/// Validate `creation_content` from a /createRoom body. Currently checks
/// `additional_creators` per MSC4289: must be a JSON array of valid user IDs
/// (`@localpart:server`). Other keys (room_version, predecessor, ...) are
/// passed through to the create event without validation here.
/// Decide whether `/createRoom` should inject `m.room.encryption`
/// when the client didn't supply one. Public rooms are never
/// auto-encrypted regardless of policy — Megolm's O(N) rekey on join
/// makes E2EE in large public rooms impractical, so the operator
/// must opt those in explicitly.
fn should_auto_encrypt(
    policy: crate::router::EncryptByDefault,
    preset: &str,
    is_direct: bool,
) -> bool {
    use crate::router::EncryptByDefault::*;
    if preset == "public_chat" {
        return false;
    }
    match policy {
        Off => false,
        DmOnly => is_direct,
        PrivateOnly => preset == "private_chat" || preset == "trusted_private_chat",
        All => true, // (public_chat already returned false above)
    }
}

fn validate_creation_content(content: &Value) -> Result<(), ApiError> {
    let obj = match content.as_object() {
        Some(o) => o,
        None => {
            return Err(VelaError::BadJson("creation_content must be an object".into()).into());
        }
    };
    if let Some(extra) = obj.get("additional_creators") {
        let arr = extra.as_array().ok_or_else(|| {
            ApiError(VelaError::BadJson(
                "creation_content.additional_creators must be an array".into(),
            ))
        })?;
        for v in arr {
            let s = v.as_str().ok_or_else(|| {
                ApiError(VelaError::BadJson(
                    "creation_content.additional_creators entry must be a string".into(),
                ))
            })?;
            if !is_valid_user_id_strict(s) {
                return Err(VelaError::BadJson(format!(
                    "creation_content.additional_creators entry is not a valid user ID: {s}"
                ))
                .into());
            }
        }
    }
    Ok(())
}

/// Strict user-ID check used for input validation: `@localpart:server` where
/// `server` looks like a domain (no `$` or other special chars). Mirrors the
/// auth-rule check but flagged as a 400 here since this is request-shape
/// validation, not auth.
fn is_valid_user_id_strict(s: &str) -> bool {
    if !s.starts_with('@') {
        return false;
    }
    let rest = &s[1..];
    let (localpart, domain) = match rest.split_once(':') {
        Some(p) => p,
        None => return false,
    };
    if localpart.is_empty() || domain.is_empty() {
        return false;
    }
    // Domain must be a hostname-shaped string. Allow letters, digits,
    // hyphens, dots, optional port. Reject `$`, spaces, etc.
    let host = domain.split(':').next().unwrap_or("");
    if host.is_empty() {
        return false;
    }
    host.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && !host.starts_with('.')
        && !host.ends_with('.')
}

/// Collect the set of room creators implied by the create event: the
/// caller (sender) plus any `additional_creators` from creation_content.
fn collect_creators(sender: &str, creation_content: Option<&Value>) -> Vec<String> {
    let mut out = vec![sender.to_string()];
    if let Some(cc) = creation_content
        && let Some(arr) = cc.get("additional_creators").and_then(|v| v.as_array())
    {
        for v in arr {
            if let Some(s) = v.as_str()
                && !out.iter().any(|x| x == s)
            {
                out.push(s.to_string());
            }
        }
    }
    out
}

/// MSC4289: `power_levels.users` MUST NOT include any room creator.
fn validate_pl_override_no_creators(ov: &Value, creators: &[String]) -> Result<(), ApiError> {
    let users = match ov.get("users").and_then(|v| v.as_object()) {
        Some(u) => u,
        None => return Ok(()),
    };
    for creator in creators {
        if users.contains_key(creator) {
            return Err(VelaError::BadJson(format!(
                "power_levels.users contains a room creator: {creator}"
            ))
            .into());
        }
    }
    Ok(())
}

fn is_local_user(user_id: &str, server_name: &str) -> bool {
    user_id
        .split_once(':')
        .map(|(_, domain)| domain == server_name)
        .unwrap_or(false)
}

/// Return the server's signing key. Historically this module maintained
/// its own meta-CF-backed key that was separate from the one `main.rs`
/// loads into `AppState::signing_key` — which caused a subtle
/// federation-interop bug where events were signed with one key and
/// `/_matrix/key/v2/server` advertised another. We now always return the
/// AppState key; the meta-CF store is dead code.
pub fn get_or_create_signing_key(state: &AppState) -> Result<ServerSigningKey, ApiError> {
    Ok((*state.signing_key).clone())
}

#[cfg(test)]
mod auto_encrypt_tests {
    use super::should_auto_encrypt;
    use crate::router::EncryptByDefault::*;

    #[test]
    fn off_never_injects() {
        assert!(!should_auto_encrypt(Off, "private_chat", true));
        assert!(!should_auto_encrypt(Off, "public_chat", false));
    }

    #[test]
    fn dm_only_fires_only_for_direct() {
        assert!(should_auto_encrypt(DmOnly, "private_chat", true));
        assert!(!should_auto_encrypt(DmOnly, "private_chat", false));
        assert!(!should_auto_encrypt(DmOnly, "public_chat", true)); // public never
    }

    #[test]
    fn private_only_covers_private_presets() {
        assert!(should_auto_encrypt(PrivateOnly, "private_chat", false));
        assert!(should_auto_encrypt(
            PrivateOnly,
            "trusted_private_chat",
            false
        ));
        assert!(!should_auto_encrypt(PrivateOnly, "public_chat", false));
    }

    #[test]
    fn all_never_injects_for_public() {
        assert!(should_auto_encrypt(All, "private_chat", false));
        assert!(!should_auto_encrypt(All, "public_chat", false));
    }
}

#[cfg(all(test, feature = "extensions"))]
mod room_create_extension_tests {
    use super::create_room;
    use crate::middleware::auth::AuthenticatedUser;
    use crate::test_helpers::build_test_state;
    use axum::extract::State;
    use vela_core::error::VelaError;

    // Gitignored fixture — run vela-extensions/tests/fixtures/build.sh first (CI does).
    const ROOM_CREATE: &[u8] =
        include_bytes!("../../../vela-extensions/tests/fixtures/room_create_guest.wasm");

    fn auth(nid: u64) -> AuthenticatedUser {
        AuthenticatedUser {
            user_nid: nid,
            user_id: "@a:test".into(),
            device_id: "D".into(),
            appservice_nid: None,
        }
    }

    fn load_plugin(state: &crate::router::AppState, mode: &str) {
        let rt = vela_extensions::Runtime::new(vec![vela_extensions::PluginConfig {
            name: "room".into(),
            wasm: ROOM_CREATE.to_vec(),
            fail_policy: vela_extensions::FailPolicy::Closed,
            fuel: 50_000_000,
            wall_ms: 0,
            memory_pages: 256,
            event_types: None,
            points: vela_extensions::Points {
                check_event: false,
                on_event: false,
                check_registration: false,
                check_media_upload: false,
                check_profile_update: false,
                check_room_create: true,
            },
            capabilities: Default::default(),
            client_ip: Default::default(),
            config: serde_json::json!({ "mode": mode }),
        }])
        .expect("room plugin loads");
        state.extensions.store(std::sync::Arc::new(rt));
    }

    /// A room-create plugin blocks a banned room name before anything is
    /// persisted, and a clean creation still goes through.
    #[tokio::test]
    async fn create_room_blocked_by_extension() {
        let (state, _tmp) = build_test_state();
        let nid = state.db.create_user("@a:test", "").expect("create user");
        load_plugin(&state, "block_name");

        // Banned name → blocked before persist. The request also asks for an
        // alias, which must NOT be left behind (the gate runs before the alias
        // write — regression guard for the orphan-alias path).
        let err = create_room(
            State(state.clone()),
            auth(nid),
            axum::body::Bytes::from(r#"{"name":"evil lair","room_alias_name":"evilroom"}"#),
        )
        .await
        .expect_err("banned room name blocked");
        assert!(matches!(err.0, VelaError::ExtensionBlocked { .. }));
        assert!(
            state
                .db
                .get_room_alias("#evilroom:test")
                .expect("alias lookup")
                .is_none(),
            "a blocked creation must not leave an orphan alias"
        );

        // A clean name is allowed and the room is created.
        let ok = create_room(
            State(state.clone()),
            auth(nid),
            axum::body::Bytes::from(r#"{"name":"book club"}"#),
        )
        .await
        .expect("clean room creation allowed");
        assert!(ok.0.get("room_id").is_some(), "created room returns an id");
    }
}
