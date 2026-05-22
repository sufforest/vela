use std::sync::Arc;

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::{build_event_at_ts, select_auth_events};
use vela_core::events::view::EventView;
use vela_core::identifiers::{EventId, Nid, RoomId};

use crate::auth_check::authorise_event;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::rooms::get_or_create_signing_key;
use crate::router::AppState;

/// AS-spec `?ts=` masquerade. Only honoured when the request is
/// authenticated as an appservice; ignored otherwise (matches
/// Synapse, and prevents a regular client from backdating its own
/// events).
#[derive(Deserialize)]
pub struct TsOverride {
    pub ts: Option<u64>,
}

/// PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
pub async fn send_message(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, event_type, txn_id)): Path<(String, String, String)>,
    Query(ts_query): Query<TsOverride>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let ts_override = ts_query.ts.filter(|_| user.appservice_nid.is_some());
    // Spec: event content MUST be a JSON object. Reject any other
    // shape (string, number, array, null, bool) with M_BAD_JSON
    // before doing any room/membership/idempotency work.
    //
    // Also reject content containing JSON numbers outside the
    // [-(2^53)+1, (2^53)-1] safe integer range, or fractional values:
    // Matrix canonical JSON requires integer-only numerics.
    if !content.is_object() {
        return Err(VelaError::BadJson("event content must be a JSON object".into()).into());
    }
    if let Some(field) = find_invalid_number(&content) {
        return Err(VelaError::BadJson(format!(
            "field {field} contains an out-of-range or non-integer numeric value"
        ))
        .into());
    }

    let room_id =
        RoomId::parse(&room_id_str).map_err(|e| ApiError(VelaError::BadJson(e.to_string())))?;

    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    // Check membership (can do outside lock — membership changes are rare)
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    // Acquire room lock — idempotency check must be inside lock to prevent
    // two concurrent requests with the same txn_id from both passing the check
    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Check idempotency (inside lock). Spec scopes the txn_id to
    // (user, device, room, event_type) — same id in a different
    // room or event_type means a fresh request, not a replay.
    let txn_scope = format!("send/{}/{}", room_id.as_str(), event_type);
    if let Some(existing_event_id) = state
        .db
        .get_transaction(user.user_nid, &user.device_id, &txn_scope, &txn_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        return Ok(Json(json!({"event_id": existing_event_id})));
    }

    let signing_key = get_or_create_signing_key(&state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Get forward extremities for prev_events
    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut max_depth: u64 = 0;
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
    }

    let prev_events = resolve_nids_to_event_ids(&state, &extremity_nids)?;
    // Cap at u64::MAX so a prev_event with depth=MAX can't wrap us
    // to 0 and place the new event "before" the room create.
    let depth = max_depth.saturating_add(1);

    // Select auth events from current room state
    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let type_nid = state.db.get_nid(etype).ok()??;
            let skey_nid = state.db.get_nid(skey).ok()??;
            let event_nid = state
                .db
                .get_state_event_nid(room_nid, type_nid, skey_nid)
                .ok()??;
            resolve_nids_to_event_ids(&state, &[event_nid])
                .ok()?
                .into_iter()
                .next()
        };

        select_auth_events(
            &event_type,
            &user.user_id,
            None,
            Some(&content),
            room_version,
            &lookup,
        )
    };

    // Build event
    let (event, event_id) = build_event_at_ts(
        &event_type,
        None,
        content,
        &user.user_id,
        Some(&room_id),
        &prev_events,
        &auth_events,
        depth,
        &signing_key,
        server_name,
        room_version,
        ts_override,
    );

    // Gate: authorise against current room state before persisting.
    authorise_event(&state, room_nid, &event_id, &event, None)?;

    // Persist
    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    enforce_event_size(&json_bytes)?;
    let type_nid = state
        .db
        .get_or_create_nid(&event_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let prev_nids: Vec<u64> = extremity_nids;
    let auth_nids = resolve_event_ids_to_nids(&state, &auth_events)?;

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
            user.user_nid,
            0, // state_key_nid = 0 (not a state event)
            origin_ts,
            depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            false, // not a state event
            false, // suppress_current_state: normal local event
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Index `m.relates_to` so the /relations endpoint can find this child.
    record_relation_if_present(
        &state,
        &event,
        event_nid,
        stream_pos,
        type_nid,
        room_nid,
        user.user_nid,
    )?;

    // Federate to remote servers that have joined members in this room.
    state.federation_sender.broadcast(room_nid, event_nid);

    // Store transaction for idempotency
    state
        .db
        .set_transaction(
            user.user_nid,
            &user.device_id,
            &txn_scope,
            &txn_id,
            event_id.as_str(),
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Record the txn_id alongside the event so reads from the
    // originating device get `unsigned.transaction_id` attached.
    state
        .db
        .set_event_txn_id(event_nid, user.user_nid, &user.device_id, &txn_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Update room bump (messages are bump events)
    state
        .db
        .update_room_bump(room_nid, origin_ts, event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Notify sync
    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }

    crate::push::dispatch_for_event(
        &state,
        room_nid,
        room_id_str.clone(),
        event_id.as_str().to_string(),
        event_nid,
        user.user_nid,
    );

    dispatch_appservice_interest(&state, &room_id_str, &user.user_id, None, event_nid);

    // Admin-bot hook: if this message landed in the admin room and is
    // an `!command`, dispatch it. Short-circuits cheaply when the
    // common path (any non-admin-room message) doesn't match. Runs
    // off the response path: the bot's reply is its own send call.
    let content_for_dispatch = event
        .get("content")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    crate::admin::maybe_dispatch_admin_command(
        &state,
        room_nid,
        user.user_nid,
        &event_type,
        &content_for_dispatch,
    );

    Ok(Json(json!({"event_id": event_id.as_str()})))
}

/// PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
pub async fn send_state_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, event_type, state_key)): Path<(String, String, String)>,
    Query(ts_query): Query<TsOverride>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let ts_override = ts_query.ts.filter(|_| user.appservice_nid.is_some());
    send_state_inner(
        state,
        user,
        room_id_str,
        event_type,
        state_key,
        ts_override,
        content,
    )
    .await
}

/// PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}
pub async fn send_state_event_no_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, event_type)): Path<(String, String)>,
    Query(ts_query): Query<TsOverride>,
    Json(content): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let ts_override = ts_query.ts.filter(|_| user.appservice_nid.is_some());
    send_state_inner(
        state,
        user,
        room_id_str,
        event_type,
        String::new(),
        ts_override,
        content,
    )
    .await
}

async fn send_state_inner(
    state: AppState,
    user: AuthenticatedUser,
    room_id_str: String,
    event_type: String,
    state_key: String,
    ts_override: Option<u64>,
    content: Value,
) -> Result<Json<Value>, ApiError> {
    // Same canonical-JSON integer-range guard we apply on /send.
    // Required for MSC4289's
    // `power_level_cannot_be_set_beyond_max_canonical_JSON_int`
    // sub-test: the spec rejects values outside `[-(2^53)+1, 2^53-1]`.
    if !content.is_object() {
        return Err(VelaError::BadJson("event content must be a JSON object".into()).into());
    }
    if let Some(field) = find_invalid_number(&content) {
        return Err(VelaError::BadJson(format!(
            "field {field} contains an out-of-range or non-integer numeric value"
        ))
        .into());
    }

    let room_id =
        RoomId::parse(&room_id_str).map_err(|e| ApiError(VelaError::BadJson(e.to_string())))?;
    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let signing_key = get_or_create_signing_key(&state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // creators in `users`. Without this we'd let auth-rules reject as
    // 403 M_FORBIDDEN, but per spec/Complement this is a 400 M_BAD_JSON.
    if event_type == "m.room.power_levels" && room_version.creators_have_infinite_power() {
        validate_pl_state_no_creators(&state, room_nid, &content)?;
    }
    // m.room.create can only exist as the room's first event. Re-sending it
    // via the state API has to be a 400 M_BAD_JSON; deferring to auth_rules
    // (which rejects it as "create has prev_events") would surface as 403,
    // and TestMSC4291...CannotSendCreateEvent gates on the status code.
    if event_type == "m.room.create" && state_key.is_empty() {
        return Err(VelaError::BadJson(
            "m.room.create may only be sent as the first event in a room".into(),
        )
        .into());
    }
    // m.room.canonical_alias: spec requires the alias and any alt_aliases
    // to (a) exist locally and (b) point at this room. Failure → 400 M_BAD_ALIAS.
    if event_type == "m.room.canonical_alias" {
        validate_canonical_alias(&state, &room_id_str, &content)?;
    }

    // No-op short-circuit: when a client sends a state event with
    // content identical to the current state, return the existing
    // event_id without minting a new event. Spec phrasing is "SHOULD
    // NOT process … whose content has not changed"; Synapse and
    // Continuwuity follow the optimisation, and the spec
    // `TestInboundCanReturnMissingEvents` "shared" sub-test bakes
    // that behaviour into its expected event count.
    if let Some(existing_event_id) =
        existing_state_event_if_unchanged(&state, room_nid, &event_type, &state_key, &content)
    {
        return Ok(Json(json!({ "event_id": existing_event_id })));
    }

    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut max_depth: u64 = 0;
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
    }

    let prev_events = resolve_nids_to_event_ids(&state, &extremity_nids)?;
    // Cap at u64::MAX so a prev_event with depth=MAX can't wrap us
    // to 0 and place the new event "before" the room create.
    let depth = max_depth.saturating_add(1);

    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let type_nid = state.db.get_nid(etype).ok()??;
            let skey_nid = state.db.get_nid(skey).ok()??;
            let event_nid = state
                .db
                .get_state_event_nid(room_nid, type_nid, skey_nid)
                .ok()??;
            resolve_nids_to_event_ids(&state, &[event_nid])
                .ok()?
                .into_iter()
                .next()
        };
        select_auth_events(
            &event_type,
            &user.user_id,
            Some(&state_key),
            Some(&content),
            room_version,
            &lookup,
        )
    };

    let (event, event_id) = build_event_at_ts(
        &event_type,
        Some(&state_key),
        content,
        &user.user_id,
        Some(&room_id),
        &prev_events,
        &auth_events,
        depth,
        &signing_key,
        server_name,
        room_version,
        ts_override,
    );

    authorise_event(&state, room_nid, &event_id, &event, None)?;

    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    enforce_event_size(&json_bytes)?;
    let type_nid = state
        .db
        .get_or_create_nid(&event_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let state_key_nid = state
        .db
        .get_or_create_nid(&state_key)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let prev_nids: Vec<u64> = extremity_nids;
    let auth_nids = resolve_event_ids_to_nids(&state, &auth_events)?;

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
            user.user_nid,
            state_key_nid,
            origin_ts,
            depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            true,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, state_key_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state.federation_sender.broadcast(room_nid, event_nid);

    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }

    dispatch_appservice_interest(
        &state,
        &room_id_str,
        &user.user_id,
        Some(state_key.as_str()),
        event_nid,
    );

    Ok(Json(json!({"event_id": event_id.as_str()})))
}

/// Run the AS interest filter for one persisted event and enqueue
/// a single-event transaction onto each matching AS's outbox.
/// Best-effort: log enqueue failures but don't fail the originating
/// request — AS delivery is a sideline subsystem.
fn dispatch_appservice_interest(
    state: &AppState,
    room_id: &str,
    sender: &str,
    state_key: Option<&str>,
    event_nid: u64,
) {
    use crate::appservice::interest::{InterestEvent, matching};
    let evt = InterestEvent {
        room_id,
        sender,
        state_key,
    };
    let hits = matching(&state.appservice_registry, &evt);
    if hits.is_empty() {
        return;
    }
    for live in hits {
        if let Err(e) = state.appservice_outbox.enqueue(
            live.appservice.nid,
            vec![event_nid],
            vec![room_id.to_string()],
        ) {
            tracing::warn!(
                appservice = %live.appservice.id,
                error = %e,
                "AS outbox enqueue failed"
            );
        }
    }
}

/// Per-spec maximum size of a single PDU's canonical JSON encoding.
/// Source: `client-server-api/#size-limits` (and identically in
/// `server-server-api`). Events that hash to anything larger MUST
/// be rejected with HTTP 413.
const MAX_EVENT_BYTES: usize = 65_536;

fn enforce_event_size(canonical: &[u8]) -> Result<(), ApiError> {
    if canonical.len() > MAX_EVENT_BYTES {
        return Err(VelaError::EventTooLarge(format!(
            "canonical event JSON is {} bytes, exceeds {} limit",
            canonical.len(),
            MAX_EVENT_BYTES
        ))
        .into());
    }
    Ok(())
}

/// Resolve event NIDs to event IDs via reverse lookup (no recomputation).
fn resolve_nids_to_event_ids(state: &AppState, nids: &[u64]) -> Result<Vec<EventId>, ApiError> {
    let mut ids = Vec::new();
    for &nid in nids {
        if let Some(id_str) = state
            .db
            .get_event_id_by_nid(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            ids.push(
                EventId::parse(&id_str).unwrap_or_else(|_| EventId::from_reference_hash("unknown")),
            );
        }
    }
    Ok(ids)
}

fn resolve_event_ids_to_nids(state: &AppState, ids: &[EventId]) -> Result<Vec<u64>, ApiError> {
    let mut nids = Vec::new();
    for id in ids {
        if let Some(nid) = state
            .db
            .get_event_nid_by_id(id.as_str())
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            nids.push(nid);
        }
    }
    Ok(nids)
}

/// Persist the relation index entry when the event carries `m.relates_to`.
/// Walks the `content.m.relates_to` blob; skips silently if either the
/// referenced parent isn't on disk or the rel_type/event_id are absent.
fn record_relation_if_present(
    state: &AppState,
    event: &serde_json::Map<String, Value>,
    child_event_nid: u64,
    child_stream_pos: u64,
    child_type_nid: u64,
    room_nid: u64,
    child_sender_nid: u64,
) -> Result<(), ApiError> {
    let relates_to = event.get("content").and_then(|c| c.get("m.relates_to"));
    let Some(rel) = relates_to else {
        return Ok(());
    };
    let parent_event_id = match rel.get("event_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(()),
    };
    let rel_type = match rel.get("rel_type").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return Ok(()),
    };
    let parent_nid = match state
        .db
        .get_event_nid_by_id(parent_event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(()),
    };
    let rel_type_nid = state
        .db
        .get_or_create_nid(rel_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    state
        .db
        .record_relation(
            parent_nid,
            child_stream_pos,
            child_event_nid,
            rel_type_nid,
            child_type_nid,
            room_nid,
            child_sender_nid,
            rel_type == "m.thread",
            true,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(())
}

/// Validate an `m.room.canonical_alias` content. Both `alias` (singular)
/// and any `alt_aliases` entry must (a) match the `#localpart:server`
/// grammar and (b) resolve to this room via local alias storage. Spec:
/// `client-server-api/#mroomcanonical_alias`. Format violations surface
/// as `M_INVALID_PARAM`; resolution failures as `M_BAD_ALIAS`.
fn validate_canonical_alias(
    state: &AppState,
    expected_room_id: &str,
    content: &Value,
) -> Result<(), ApiError> {
    let mut to_check: Vec<&str> = Vec::new();
    if let Some(a) = content.get("alias").and_then(|v| v.as_str())
        && !a.is_empty()
    {
        to_check.push(a);
    }
    if let Some(arr) = content.get("alt_aliases").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(a) = v.as_str()
                && !a.is_empty()
            {
                to_check.push(a);
            }
        }
    }
    for alias in &to_check {
        if !is_valid_alias_format(alias) {
            return Err(
                VelaError::InvalidParam(format!("alias is not well-formed: {alias}")).into(),
            );
        }
    }
    for alias in to_check {
        let resolved = state
            .db
            .get_room_alias(alias)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        match resolved.as_deref() {
            None => {
                return Err(VelaError::BadAlias(format!("alias does not exist: {alias}")).into());
            }
            Some(r) if r != expected_room_id => {
                return Err(VelaError::BadAlias(format!(
                    "alias {alias} points at {r}, not this room"
                ))
                .into());
            }
            _ => {}
        }
    }
    Ok(())
}

/// Matrix room alias grammar: `#localpart:server`. We're lenient on
/// what counts as a server (any non-empty suffix after the first `:`)
/// since the resolution step will reject mismatches anyway. The point
/// here is to catch obvious malformed strings — leading sigil missing,
/// no colon — which the spec marks as `M_INVALID_PARAM` rather than
/// `M_BAD_ALIAS`.
fn is_valid_alias_format(alias: &str) -> bool {
    let Some(rest) = alias.strip_prefix('#') else {
        return false;
    };
    let Some((localpart, server)) = rest.split_once(':') else {
        return false;
    };
    !localpart.is_empty() && !server.is_empty()
}

/// Reject a power_levels send whose `users` map contains any room creator.
/// Reads the persisted `m.room.create` event for sender + `additional_creators`.
fn validate_pl_state_no_creators(
    state: &AppState,
    room_nid: u64,
    content: &Value,
) -> Result<(), ApiError> {
    let users = match content.get("users").and_then(|v| v.as_object()) {
        Some(u) => u,
        None => return Ok(()),
    };
    let creators = load_room_creators(state, room_nid)?;
    for creator in &creators {
        if users.contains_key(creator) {
            return Err(VelaError::BadJson(format!(
                "power_levels.users contains a room creator: {creator}"
            ))
            .into());
        }
    }
    Ok(())
}

fn load_room_creators(state: &AppState, room_nid: u64) -> Result<Vec<String>, ApiError> {
    let type_nid = state
        .db
        .get_nid("m.room.create")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_nid("")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (Some(tn), Some(sn)) = (type_nid, skey_nid) else {
        return Ok(Vec::new());
    };
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let Some(en) = event_nid else {
        return Ok(Vec::new());
    };
    let bytes = state
        .db
        .get_event(en)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .map(|(_, b)| b)
        .unwrap_or_default();
    let ev: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let mut out = Vec::new();
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
    Ok(out)
}

/// Walk a JSON value and return the path of the first invalid number
/// encountered. Thin re-export of the vela-core helper so the federation
/// receive path and the CS-API send path share a single source of truth.
fn find_invalid_number(value: &Value) -> Option<String> {
    vela_core::canonical::find_invalid_number_path(value)
}

/// If `(event_type, state_key)` is already in the room's current
/// state with `new_content` equal to the existing event's content,
/// return the existing event_id (so the caller can skip persisting
/// a no-op state event). Otherwise return `None`.
fn existing_state_event_if_unchanged(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
    new_content: &Value,
) -> Option<String> {
    let type_nid = state.db.get_nid(event_type).ok().flatten()?;
    let skey_nid = state.db.get_nid(state_key).ok().flatten()?;
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .ok()
        .flatten()?;
    let (_h, bytes) = state.db.get_event(event_nid).ok().flatten()?;
    let existing: Value = serde_json::from_slice(&bytes).ok()?;
    let existing_content = existing.get("content")?;
    if existing_content == new_content {
        state.db.get_event_id_by_nid(event_nid).ok().flatten()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_format_accepts_well_formed_aliases() {
        assert!(is_valid_alias_format("#room:hs1"));
        assert!(is_valid_alias_format("#with-dashes:server.example.com"));
        assert!(is_valid_alias_format("#unicode-老虎:hs1"));
        // Server portion is anything non-empty — we're lenient by design.
        assert!(is_valid_alias_format("#x:y"));
    }

    #[test]
    fn alias_format_rejects_malformed_aliases() {
        // Missing leading `#`.
        assert!(!is_valid_alias_format("%percent:hs1"));
        assert!(!is_valid_alias_format("nosigil:hs1"));
        // Missing `:` separator.
        assert!(!is_valid_alias_format("#noseparator"));
        // Empty localpart or server.
        assert!(!is_valid_alias_format("#:server"));
        assert!(!is_valid_alias_format("#localpart:"));
        // Bare sigil.
        assert!(!is_valid_alias_format("#"));
        assert!(!is_valid_alias_format(""));
    }

    #[test]
    fn enforce_event_size_passes_under_limit() {
        let small = vec![b'a'; 1024];
        assert!(enforce_event_size(&small).is_ok());

        let exactly_at_limit = vec![b'a'; MAX_EVENT_BYTES];
        assert!(
            enforce_event_size(&exactly_at_limit).is_ok(),
            "the limit itself is allowed; only strictly larger is rejected"
        );
    }

    #[test]
    fn enforce_event_size_rejects_oversize_with_too_large_errcode() {
        let oversize = vec![b'a'; MAX_EVENT_BYTES + 1];
        let err = enforce_event_size(&oversize).expect_err("must reject oversize");
        // Surface as M_TOO_LARGE / 413.
        assert_eq!(err.0.errcode(), "M_TOO_LARGE");
        assert_eq!(err.0.status_code(), 413);
    }

    #[test]
    fn find_invalid_number_flags_unsafe_integer() {
        // 2^53 is just above the JS-safe-integer ceiling.
        let v: Value = serde_json::from_str(r#"{"n": 9007199254740993}"#).unwrap();
        assert_eq!(find_invalid_number(&v), Some("n".to_string()));
    }

    #[test]
    fn find_invalid_number_flags_fractional_value() {
        let v: Value = serde_json::from_str(r#"{"f": 1.5}"#).unwrap();
        assert_eq!(find_invalid_number(&v), Some("f".to_string()));
    }

    #[test]
    fn find_invalid_number_flags_nested_path() {
        let v: Value = serde_json::from_str(r#"{"outer": {"inner": 1.5}}"#).unwrap();
        // Nested paths join with `.`; first failure short-circuits.
        assert_eq!(find_invalid_number(&v), Some("outer.inner".to_string()));
    }

    #[test]
    fn find_invalid_number_passes_safe_values() {
        let v: Value =
            serde_json::from_str(r#"{"a": 1, "b": -42, "c": 9007199254740991}"#).unwrap();
        assert_eq!(find_invalid_number(&v), None);
    }
}
