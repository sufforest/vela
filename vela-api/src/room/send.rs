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

/// AS-spec `?ts=` masquerade plus MSC4140's `?org.matrix.msc4140.delay=<ms>`.
/// `ts` only honoured when the request is authenticated as an
/// appservice; ignored otherwise (matches Synapse, and prevents a
/// regular client from backdating its own events). `delay` (when
/// set) shunts the request into the delayed_events queue instead
/// of sending immediately.
#[derive(Deserialize)]
pub struct TsOverride {
    pub ts: Option<u64>,
    #[serde(rename = "org.matrix.msc4140.delay", default)]
    pub delay: Option<u64>,
}

/// PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
pub async fn send_message(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, event_type, txn_id)): Path<(String, String, String)>,
    Query(ts_query): Query<TsOverride>,
    body: Option<Json<Value>>,
) -> Result<Json<Value>, ApiError> {
    let ts_override = ts_query.ts.filter(|_| user.appservice_nid.is_some());
    // MSC4140 idempotency replays use the same path with no body —
    // accept absence here, but for any non-delay path the body
    // remains required (see the empty-body M_NOT_JSON guard inside
    // `send_message_inner`).
    let content = body.map(|Json(v)| v).unwrap_or(Value::Null);
    if let Some(delay_ms) = ts_query.delay {
        crate::delayed_events::validate_delay_ms(delay_ms, state.config.max_delay_ms)?;
        // MSC4140 idempotency: a re-PUT with the same
        // `(user, device, room, event_type, txn_id)` returns the
        // existing `delay_id` — even when the body is absent (the
        // upstream test exercises this without a JSON body).
        if let Some(existing) = crate::delayed_events::existing_delay_id_for_txn(
            &state,
            user.user_nid,
            &user.device_id,
            &room_id_str,
            &event_type,
            &txn_id,
        ) {
            return Ok(Json(json!({"delay_id": existing})));
        }
        if !content.is_object() {
            return Err(VelaError::BadJson("event content must be a JSON object".into()).into());
        }
        let room_nid = state
            .db
            .get_nid(&room_id_str)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
        let membership = state
            .db
            .get_membership(room_nid, user.user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        if membership != Some(1) {
            return Err(VelaError::Forbidden("not a member of this room".into()).into());
        }
        let id = crate::delayed_events::schedule_message(
            &state,
            &user,
            &room_id_str,
            &event_type,
            &txn_id,
            content,
            delay_ms,
        )?;
        return Ok(Json(json!({"delay_id": id})));
    }
    send_message_inner(
        state,
        user,
        room_id_str,
        event_type,
        txn_id,
        ts_override,
        content,
    )
    .await
}

/// Run the sandboxed extension decision hook for a locally-originated event,
/// just before it is persisted. Returns `Err` (the plugin's errcode/reason,
/// 403) if any plugin blocks. No-op — and no serialization — when no plugins
/// are configured, so the common path is free. Origin is always `Local` here,
/// so a block is a safe hard-reject (we simply refuse to originate the event).
fn local_extension_gate(
    extensions: &vela_extensions::Runtime,
    event: &serde_json::Map<String, Value>,
    room_id: &str,
    sender: &str,
    event_type: &str,
) -> Result<(), ApiError> {
    if !extensions.binds_check_event() {
        return Ok(());
    }
    let event_value = Value::Object(event.clone());
    let ctx = vela_extensions::EventContext {
        event: &event_value,
        room_id,
        sender,
        event_type,
        origin: vela_extensions::Origin::Local,
    };
    let start = std::time::Instant::now();
    let decision = extensions.check_event(&ctx);
    metrics::histogram!("vela_extension_check_duration_seconds")
        .record(start.elapsed().as_secs_f64());
    match decision {
        vela_extensions::Decision::Allow => {
            metrics::counter!("vela_extension_decisions_total", "verdict" => "allow").increment(1);
            Ok(())
        }
        vela_extensions::Decision::Block { errcode, reason } => {
            metrics::counter!("vela_extension_decisions_total", "verdict" => "block").increment(1);
            tracing::info!(
                room_id, sender, event_type, %errcode, %reason,
                "extension blocked local event"
            );
            Err(ApiError(VelaError::ExtensionBlocked { errcode, reason }))
        }
    }
}

/// Whether a sender is a plugin's `@_ext_<name>` bot — the reserved localpart
/// prefix that marks extension-emitted events. The loop-protection guard: such
/// events are never queued for observation, so an emitting plugin can't observe
/// (and re-react to) its own — or another plugin's — output.
fn sender_is_plugin_bot(sender: &str) -> bool {
    sender.starts_with("@_ext_")
}

#[cfg(test)]
mod loop_protection_tests {
    use super::sender_is_plugin_bot;

    #[test]
    fn only_ext_prefixed_senders_are_plugin_bots() {
        // Plugin bots are skipped for observation (loop protection)...
        assert!(sender_is_plugin_bot("@_ext_keyword-filter:example.org"));
        assert!(sender_is_plugin_bot("@_ext_judge:server"));
        // ...and humans, the admin bot, and appservice ghosts are NOT, so their
        // events are still observed.
        assert!(!sender_is_plugin_bot("@alice:example.org"));
        assert!(!sender_is_plugin_bot("@admin:example.org"));
        assert!(!sender_is_plugin_bot("@_telegram_bob:example.org"));
        assert!(!sender_is_plugin_bot("@ext_not_reserved:example.org"));
    }
}

/// Queue a just-persisted local event for the async observation point
/// (`on_event`). No-op — and no serialization — unless some plugin binds
/// `on_event`. Best-effort: the event is already persisted and federated, so a
/// failed enqueue is logged inside the queue, never surfaced to the client.
fn observe_local_event(
    state: &AppState,
    event: &serde_json::Map<String, Value>,
    room_id: &str,
    sender: &str,
    event_type: &str,
) {
    // Loop protection: never feed a plugin bot's own emitted events back into
    // observation, or an emitting plugin would observe its own output and emit
    // again. Plugin bots use the reserved `@_ext_` localpart prefix, so this is
    // an O(1) check with no lookup (and covers cross-plugin loops too).
    if sender_is_plugin_bot(sender) {
        return;
    }
    // Lock-free snapshot, like the decision gate: a concurrent SIGHUP reload
    // can't tear this check.
    if state.extensions.load().binds_on_event() {
        state
            .observe_queue
            .enqueue(&state.db, event, room_id, sender, event_type);
    }
}

pub(crate) async fn send_message_inner(
    state: AppState,
    user: AuthenticatedUser,
    room_id_str: String,
    event_type: String,
    txn_id: String,
    ts_override: Option<u64>,
    content: Value,
) -> Result<Json<Value>, ApiError> {
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

    // Gate: sandboxed extension policy hook (no-op when no plugins configured).
    local_extension_gate(
        // Lock-free snapshot; a concurrent SIGHUP reload can't tear an in-flight call.
        &state.extensions.load(),
        &event,
        room_id.as_str(),
        &user.user_id,
        &event_type,
    )?;

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

    // Observe (async): hand the persisted event to any on_event plugins.
    observe_local_event(&state, &event, room_id.as_str(), &user.user_id, &event_type);

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
        event_id.as_str(),
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
    if let Some(delay_ms) = ts_query.delay {
        return delayed_state_response(
            &state,
            &user,
            &room_id_str,
            &event_type,
            &state_key,
            content,
            delay_ms,
        );
    }
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
    if let Some(delay_ms) = ts_query.delay {
        return delayed_state_response(
            &state,
            &user,
            &room_id_str,
            &event_type,
            "",
            content,
            delay_ms,
        );
    }
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

fn delayed_state_response(
    state: &AppState,
    user: &AuthenticatedUser,
    room_id_str: &str,
    event_type: &str,
    state_key: &str,
    content: Value,
    delay_ms: u64,
) -> Result<Json<Value>, ApiError> {
    crate::delayed_events::validate_delay_ms(delay_ms, state.config.max_delay_ms)?;
    // Membership check up front. The fire-time send_state_inner
    // re-checks, but if the caller isn't currently a member we
    // surface that immediately rather than queuing a doomed event.
    let room_nid = state
        .db
        .get_nid(room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }
    let id = crate::delayed_events::schedule_state(
        state,
        user,
        room_id_str,
        event_type,
        state_key,
        content,
        delay_ms,
    )?;
    Ok(Json(json!({"delay_id": id})))
}

pub(crate) async fn send_state_inner(
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

    // Moderation: a raw m.room.member INVITE via the /state API bypasses the
    // /invite choke point (`emit_membership_event_for_target`), so gate it here
    // too. Join/knock via /state aren't a banned-outsider vector — sending any
    // state event requires already being a joined member (checked just above).
    // Removals (leave / ban / kick) must always be allowed to go through.
    if event_type == "m.room.member"
        && content.get("membership").and_then(|m| m.as_str()) == Some("invite")
    {
        if let Some(reason) = state.moderation.check_user(&state_key) {
            tracing::info!(
                room = %room_id_str, target = %state_key, %reason,
                "moderation: blocked /state invite of banned user"
            );
            return Err(VelaError::Forbidden(
                "This user is subject to a moderation policy on this server".into(),
            )
            .into());
        }
        if let Some(reason) = state.moderation.check_user(&user.user_id) {
            tracing::info!(
                room = %room_id_str, sender = %user.user_id, %reason,
                "moderation: blocked banned user from inviting via /state"
            );
            return Err(VelaError::Forbidden(
                "You are subject to a moderation policy on this server".into(),
            )
            .into());
        }
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
    // MSC3757 owned-state state_key validation. For rooms on the
    // unstable `org.matrix.msc3757.10` version, a state_key beginning
    // with `@` must parse as `@<localpart>:<server>[_<suffix>]`. Any
    // other shape (no `:`, garbage after `:<server>` that isn't the
    // `_` suffix, etc.) is `400 M_BAD_JSON`. The rule-9 owner-check
    // happens later in auth and returns 403 — that's the right
    // distinction the Complement test gates on.
    if room_version.supports_owned_state_events()
        && state_key.starts_with('@')
        && vela_core::auth_rules::owned_state_key_owner(&state_key).is_none()
    {
        return Err(VelaError::BadJson(format!("malformed owned state_key: {state_key}")).into());
    }

    // No-op short-circuit: when a client sends a state event with
    // content identical to the current state, return the existing
    // event_id without minting a new event. Spec phrasing is "SHOULD
    // NOT process … whose content has not changed"; Synapse and
    // Continuwuity follow the optimisation, and the spec
    // `TestInboundCanReturnMissingEvents` "shared" sub-test bakes
    // that behaviour into its expected event count.
    if let Some(existing_event_id) = existing_state_event_if_unchanged(
        &state,
        room_nid,
        &event_type,
        &state_key,
        &user.user_id,
        &content,
    ) {
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

    // Gate: sandboxed extension policy hook (no-op when no plugins configured).
    local_extension_gate(
        // Lock-free snapshot; a concurrent SIGHUP reload can't tear an in-flight call.
        &state.extensions.load(),
        &event,
        room_id.as_str(),
        &user.user_id,
        &event_type,
    )?;

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

    // If a moderation policy rule changed in a watched policy room, recompile
    // the ban list. No-op unless moderation is on and this is a policy room.
    state
        .moderation
        .maybe_refresh(&state.db, room_nid, &event_type);

    // A member event sent through the generic /state path must also maintain
    // the membership index + E2EE/sync side effects — promote_state_event
    // only updates room state, but every read gate keys off the index, so
    // without this a ban/leave via /state would leave the removed user with
    // read + sync access.
    if event_type == "m.room.member"
        && let Some(membership) = event
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str())
    {
        crate::membership::apply_member_event_side_effects(
            &state,
            room_nid,
            state_key_nid,
            membership,
            stream_pos,
        )?;
    }

    state.federation_sender.broadcast(room_nid, event_nid);

    // Observe (async): hand the persisted state event to any on_event plugins.
    observe_local_event(&state, &event, room_id.as_str(), &user.user_id, &event_type);

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

pub(crate) fn enforce_event_size(canonical: &[u8]) -> Result<(), ApiError> {
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

/// Persist the relation index entry when the event carries a parent
/// pointer. Reads `content.m.relates_to` (MSC2675 — the stable shape
/// for replies/threads) OR `content.m.relationship` (MSC2836 — the
/// unstable shape the upstream Complement tests still use). Both
/// carry `{rel_type, event_id}`; skips silently if the referenced
/// parent isn't on disk or either field is missing.
fn record_relation_if_present(
    state: &AppState,
    event: &serde_json::Map<String, Value>,
    child_event_nid: u64,
    child_stream_pos: u64,
    child_type_nid: u64,
    room_nid: u64,
    child_sender_nid: u64,
) -> Result<(), ApiError> {
    let content = event.get("content");
    let relates_to = content
        .and_then(|c| c.get("m.relates_to"))
        .or_else(|| content.and_then(|c| c.get("m.relationship")));
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
    sender: &str,
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
    // Sender match is required: a different user re-PUTting the same
    // content is a NEW state-event request from them, and the full
    // auth check (rule 9, power level, etc.) has to decide whether
    // they're allowed to write at this `(type, state_key)`. Without
    // this guard a low-power user could "set" a high-power event by
    // simply replaying the existing content.
    let existing_sender = existing
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if existing_sender != sender {
        return None;
    }
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

    /// `existing_state_event_if_unchanged` must NOT short-circuit when
    /// a different sender PUTs the same content at the same
    /// `(type, state_key)`. Otherwise low-power users could "set"
    /// state events written by the room creator by replaying the
    /// existing content. MSC3757 TestWithoutOwnedState locks this in.
    #[test]
    fn unchanged_short_circuit_requires_sender_match() {
        use crate::test_helpers::build_test_state;
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let room_id = "!ss:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_id = "@alice:example.com";
        let bob_id = "@bob:example.com";
        let alice_nid = db.get_or_create_nid(alice_id).unwrap();
        let _bob_nid = db.get_or_create_nid(bob_id).unwrap();
        let etype = "com.example.test";
        let skey = "@target:example.com";
        let type_nid = db.get_or_create_nid(etype).unwrap();
        let skey_nid = db.get_or_create_nid(skey).unwrap();

        // Alice writes the initial event with `{"v": 1}`.
        let content = serde_json::json!({"v": 1});
        let body = serde_json::json!({
            "type": etype,
            "sender": alice_id,
            "state_key": skey,
            "room_id": room_id,
            "content": content,
            "origin_server_ts": 1, "depth": 1,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            42,
            "$e1",
            room_nid,
            type_nid,
            alice_nid,
            skey_nid,
            1,
            1,
            &serde_json::to_vec(&body).unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();
        db.promote_state_event(room_nid, 42, type_nid, skey_nid)
            .unwrap();

        // Same sender + same content → short-circuit returns the
        // existing event_id.
        let same =
            existing_state_event_if_unchanged(&state, room_nid, etype, skey, alice_id, &content);
        assert_eq!(same.as_deref(), Some("$e1"));

        // Different sender + same content → no short-circuit. Caller
        // must fall through to the auth path.
        let cross =
            existing_state_event_if_unchanged(&state, room_nid, etype, skey, bob_id, &content);
        assert!(
            cross.is_none(),
            "cross-sender writes must not short-circuit"
        );

        // Same sender + different content → no short-circuit (regular
        // state update).
        let updated = serde_json::json!({"v": 2});
        let changed =
            existing_state_event_if_unchanged(&state, room_nid, etype, skey, alice_id, &updated);
        assert!(changed.is_none());
    }
}

// End-to-end test of the extension gate against a real WASM component. Only
// built when the `extensions` feature is on (otherwise the runtime is the no-op
// stub). The fixture is the same config-driven guest vela-extensions tests use.
#[cfg(all(test, feature = "extensions"))]
mod extension_gate_tests {
    use super::*;

    const SPAM_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vela-extensions/tests/fixtures/spam_guest.wasm"
    ));

    fn spam_runtime() -> vela_extensions::Runtime {
        vela_extensions::Runtime::new(vec![vela_extensions::PluginConfig {
            name: "spam".into(),
            wasm: SPAM_FIXTURE.to_vec(),
            fail_policy: vela_extensions::FailPolicy::Open,
            fuel: 50_000_000,
            wall_ms: 0,
            memory_pages: 256,
            event_types: None,
            points: vela_extensions::Points::default(),
            capabilities: vela_extensions::Capabilities::default(),
            client_ip: vela_extensions::ClientIpTier::default(),
            config: serde_json::json!({ "mode": "allow" }),
        }])
        .expect("runtime loads")
    }

    fn message(body: &str) -> serde_json::Map<String, Value> {
        serde_json::json!({
            "type": "m.room.message",
            "content": { "msgtype": "m.text", "body": body },
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn gate_blocks_a_spam_message_with_forbidden() {
        let rt = spam_runtime();
        match local_extension_gate(
            &rt,
            &message("buy SPAM now"),
            "!r:example.org",
            "@a:example.org",
            "m.room.message",
        ) {
            Err(ApiError(VelaError::ExtensionBlocked { errcode, reason })) => {
                assert_eq!(errcode, "M_FORBIDDEN");
                assert!(!reason.is_empty());
            }
            other => panic!("expected ExtensionBlocked, got {other:?}"),
        }
    }

    #[test]
    fn gate_allows_a_clean_message() {
        let rt = spam_runtime();
        assert!(
            local_extension_gate(
                &rt,
                &message("hello there"),
                "!r:example.org",
                "@a:example.org",
                "m.room.message",
            )
            .is_ok()
        );
    }

    #[test]
    fn empty_runtime_is_a_no_op_even_for_spam() {
        let rt = vela_extensions::Runtime::new(vec![]).expect("empty runtime");
        assert!(
            local_extension_gate(
                &rt,
                &message("SPAM SPAM SPAM"),
                "!r:example.org",
                "@a:example.org",
                "m.room.message",
            )
            .is_ok()
        );
    }
}
