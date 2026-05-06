use std::collections::HashSet;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;
use vela_core::events::view::EventView;
use vela_core::identifiers::Nid;

use crate::messages::load_client_event;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;
use crate::typing::get_typing_users;

const DEFAULT_TIMELINE_LIMIT: usize = 30;

#[derive(Deserialize)]
pub struct SyncQuery {
    pub since: Option<String>,
    pub timeout: Option<u64>,
    #[allow(dead_code)]
    pub full_state: Option<bool>,
    /// Either a previously-uploaded `filter_id` (POST /user/{}/filter) or
    /// inline JSON starting with `{`.
    pub filter: Option<String>,
    /// Per c2s spec: clients pass `set_presence=offline|unavailable` to
    /// suppress the implicit "online" mark that polling /sync otherwise
    /// triggers. Omitted → caller goes online.
    pub set_presence: Option<String>,
}

/// GET /_matrix/client/v3/sync
pub async fn sync(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<SyncQuery>,
) -> Result<Json<Value>, ApiError> {
    let since: Option<u64> = query
        .since
        .as_deref()
        .and_then(|s| s.strip_prefix('s'))
        .and_then(|s| s.parse().ok());

    let timeout_ms = query.timeout.unwrap_or(0);

    // Apply set_presence per spec (default: online). Touch
    // last_active_ms on every poll; only rewrite the `presence` field
    // and federate when the value actually changes — repeated /sync
    // calls with the same effective presence (e.g. polling clients
    // staying online) shouldn't fan out fresh m.presence EDUs.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let want_presence = query.set_presence.as_deref().unwrap_or("online");
    let current_presence = state
        .db
        .get_presence(user.user_nid)
        .ok()
        .flatten()
        .and_then(|v| {
            v.get("presence")
                .and_then(|p| p.as_str())
                .map(str::to_owned)
        });
    if current_presence.as_deref() != Some(want_presence) {
        let mut rec = serde_json::Map::new();
        rec.insert("presence".into(), serde_json::json!(want_presence));
        rec.insert("last_active_ms".into(), serde_json::json!(now));
        let _ = state
            .db
            .set_local_presence(user.user_nid, &Value::Object(rec));
        state
            .federation_sender
            .notify_user_subscribers(user.user_nid);
    } else {
        // No state change — just refresh the activity timestamp.
        let _ = state.db.touch_presence(user.user_nid, now);
    }

    let joined_room_nids = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Subscribe to room channels BEFORE checking DB to avoid the race where
    // a message arrives between "check DB" and "subscribe". If we find events
    // in the DB, we return immediately and the subscriptions are dropped.
    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(1);
    let should_longpoll = timeout_ms > 0 && since.is_some();

    let mut task_handles = Vec::new();

    if should_longpoll {
        for &room_nid in &joined_room_nids {
            let mut rx = {
                let sender = state.room_senders.entry(Nid(room_nid)).or_insert_with(|| {
                    let (tx, _) = tokio::sync::broadcast::channel(64);
                    tx
                });
                sender.value().subscribe()
            };
            let tx = notify_tx.clone();
            let handle = tokio::spawn(async move {
                if rx.recv().await.is_ok() {
                    let _ = tx.send(()).await;
                }
            });
            task_handles.push(handle);
        }

        // Also subscribe to the per-user channel so the long-poll wakes
        // when the user's room list changes (invite accepted, DM created,
        // knock, leave, ban). Without this a pending /sync only learns
        // about new rooms after its 30s timeout.
        let mut user_rx = {
            let sender = state.user_senders.entry(user.user_nid).or_insert_with(|| {
                let (tx, _) = tokio::sync::broadcast::channel(64);
                tx
            });
            sender.value().subscribe()
        };
        let tx = notify_tx.clone();
        let handle = tokio::spawn(async move {
            if user_rx.recv().await.is_ok() {
                let _ = tx.send(()).await;
            }
        });
        task_handles.push(handle);
    }
    drop(notify_tx);

    let filter = resolve_filter(&state, &user, query.filter.as_deref())?;
    let full_state = query.full_state.unwrap_or(false);

    // Now check the DB — any events broadcast after our subscribe() call
    // will be caught by the spawned listener tasks.
    let response = build_sync_response_with_filter(
        &state,
        &user,
        &joined_room_nids,
        since,
        filter.as_ref(),
        full_state,
    )?;

    // A joined room appears in `rooms.join` only when it has new
    // content (timeline / state / ephemeral / account_data) per the
    // unchanged-room rule. So "any joined room is present" is itself
    // the signal that there's new data to deliver — no need to crack
    // open the timeline. This catches typing/receipt-only changes
    // that previously left long-polls hanging until timeout.
    let has_events = response
        .get("rooms")
        .and_then(|r| r.get("join"))
        .and_then(|j| j.as_object())
        .is_some_and(|rooms| !rooms.is_empty());
    let has_invites = response
        .get("rooms")
        .and_then(|r| r.get("invite"))
        .and_then(|i| i.as_object())
        .is_some_and(|m| !m.is_empty());
    let has_leaves = response
        .get("rooms")
        .and_then(|r| r.get("leave"))
        .and_then(|l| l.as_object())
        .is_some_and(|m| !m.is_empty());
    let has_to_device = response
        .get("to_device")
        .and_then(|td| td.get("events"))
        .and_then(|e| e.as_array())
        .is_some_and(|a| !a.is_empty());
    let has_account_data = response
        .get("account_data")
        .and_then(|ad| ad.get("events"))
        .and_then(|e| e.as_array())
        .is_some_and(|a| !a.is_empty());
    let has_device_list_changes = response
        .pointer("/device_lists/changed")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty())
        || response
            .pointer("/device_lists/left")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
    let has_new_data = has_events
        || has_invites
        || has_leaves
        || has_to_device
        || has_account_data
        || has_device_list_changes;

    if has_new_data || !should_longpoll {
        for h in task_handles {
            h.abort();
        }
        return Ok(Json(response));
    }

    // Long-poll: wait for notification or timeout
    let timeout = Duration::from_millis(timeout_ms.min(30_000));

    tokio::select! {
        _ = notify_rx.recv() => {},
        _ = tokio::time::sleep(timeout) => {},
    }

    // Abort all listener tasks regardless of wake reason
    for h in task_handles {
        h.abort();
    }

    // Re-fetch joined rooms: the user_senders wake often fires because the
    // user's membership changed (invite accepted, room created). The
    // snapshot captured before the long-poll is stale in that case; using
    // it would drop the newly-joined room from the response, leaving
    // Element stuck on the old view until a hard refresh.
    let joined_room_nids = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let response = build_sync_response_with_filter(
        &state,
        &user,
        &joined_room_nids,
        since,
        filter.as_ref(),
        full_state,
    )?;
    Ok(Json(response))
}

#[allow(dead_code)]
pub(crate) fn build_sync_response(
    state: &AppState,
    user: &AuthenticatedUser,
    joined_room_nids: &[u64],
    since: Option<u64>,
) -> Result<Value, ApiError> {
    build_sync_response_with_filter(state, user, joined_room_nids, since, None, false)
}

pub(crate) fn build_sync_response_with_filter(
    state: &AppState,
    user: &AuthenticatedUser,
    joined_room_nids: &[u64],
    since: Option<u64>,
    filter: Option<&Value>,
    full_state: bool,
) -> Result<Value, ApiError> {
    let current_pos = state.db.current_stream_position();
    let ignored = load_ignored_users(state, user.user_nid)?;
    let mut join_rooms = serde_json::Map::new();

    let room_filter = filter.and_then(|f| f.get("room"));
    let state_filter = room_filter.and_then(|r| r.get("state"));
    let timeline_filter = room_filter.and_then(|r| r.get("timeline"));
    let lazy_load = crate::filters::lazy_load_members_enabled(state_filter, timeline_filter)
        && !crate::filters::include_redundant_members(state_filter);
    for &room_nid in joined_room_nids {
        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        if let Some(rf) = room_filter
            && !crate::filters::room_passes_filter(&room_id, rf)
        {
            continue;
        }

        // Honour the filter's timeline.limit at DB query time so
        // prev_batch is computed from the trimmed batch (not the
        // pre-trim one — that breaks /messages backward pagination).
        // Cap at DEFAULT_TIMELINE_LIMIT to match the spec-suggested
        // ceiling.
        let timeline_limit = timeline_filter
            .and_then(|tf| tf.get("limit"))
            .and_then(|v| v.as_u64())
            .map(|n| (n as usize).min(DEFAULT_TIMELINE_LIMIT))
            .unwrap_or(DEFAULT_TIMELINE_LIMIT);
        let mut room_data = build_room_sync_for_user(
            state,
            room_nid,
            &room_id,
            since,
            Some(user.user_nid),
            Some(&user.device_id),
            timeline_limit,
        )?;
        if !ignored.is_empty() {
            filter_room_timeline_by_ignored(&mut room_data, &ignored);
        }
        if let Some(tf) = timeline_filter {
            crate::filters::apply_timeline_filter(&mut room_data, tf);
        }
        if lazy_load {
            crate::filters::apply_lazy_load_state(&mut room_data, &user.user_id);
        }

        // Spec: on incremental sync, joined rooms that have no new content
        // since `since` MUST be omitted from `rooms.join` — sending them
        // back wastes bandwidth and confuses clients into thinking the
        // room timeline restarted. `full_state=true` overrides this and
        // forces every joined room to appear.
        if since.is_some() && !full_state && room_is_unchanged(&room_data) {
            continue;
        }
        join_rooms.insert(room_id, room_data);
    }

    let invited_room_nids = state
        .db
        .get_user_invited_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut invite_rooms = serde_json::Map::new();
    for &room_nid in &invited_room_nids {
        if !membership_changed_since(state, user.user_nid, room_nid, since)? {
            continue;
        }
        // Skip invites where the inviter (sender of the recipient's
        // m.room.member invite event) is on the ignored list.
        if !ignored.is_empty()
            && invite_sender_is_ignored(state, room_nid, user.user_nid, &ignored)?
        {
            continue;
        }
        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        let invite_data = build_invite_sync(state, room_nid, &room_id)?;
        invite_rooms.insert(room_id, invite_data);
    }

    let left_room_nids = state
        .db
        .get_user_left_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut leave_rooms = serde_json::Map::new();
    for &room_nid in &left_room_nids {
        if !membership_changed_since(state, user.user_nid, room_nid, since)? {
            continue;
        }
        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        let timeline_limit = timeline_filter
            .and_then(|tf| tf.get("limit"))
            .and_then(|v| v.as_u64())
            .map(|n| (n as usize).min(DEFAULT_TIMELINE_LIMIT))
            .unwrap_or(DEFAULT_TIMELINE_LIMIT);

        let mut leave_data = build_leave_sync(
            state,
            room_nid,
            &room_id,
            user.user_nid,
            &user.user_id,
            since,
            timeline_limit,
        )?;
        if let Some(tf) = timeline_filter {
            crate::filters::apply_timeline_filter(&mut leave_data, tf);
        }
        if let Some(sf) = state_filter {
            crate::filters::apply_state_filter(&mut leave_data, sf);
        }
        leave_rooms.insert(room_id, leave_data);
    }

    let knocked_room_nids = state
        .db
        .get_user_knocked_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut knock_rooms = serde_json::Map::new();
    for &room_nid in &knocked_room_nids {
        if !membership_changed_since(state, user.user_nid, room_nid, since)? {
            continue;
        }
        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        let knock_data = build_knock_sync(state, room_nid, &room_id)?;
        knock_rooms.insert(room_id, knock_data);
    }

    // Global account data. On initial sync we return everything; on
    // incremental sync we stream only entries modified after `since` so
    // clients (Element's cross-signing setup, push rule edits, etc.) see
    // their own writes reflected and can tell the write landed.
    let mut global_account_data: Vec<Value> = match since {
        None => state
            .db
            .get_all_account_data(user.user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .into_iter()
            .map(|(dtype, content)| json!({"type": dtype, "content": content}))
            .collect(),
        Some(since_pos) => state
            .db
            .get_account_data_since(user.user_nid, since_pos)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .into_iter()
            .map(|(dtype, content)| json!({"type": dtype, "content": content}))
            .collect(),
    };

    // Synthesise an `m.push_rules` event on initial sync if the user
    // hasn't customised. Spec mandates the rules always appear in
    // account_data; clients (Element, ESS) rely on this to show
    // notification settings without a separate /pushrules round-trip.
    // For incremental sync we leave this alone — the rules don't
    // change unless the user wrote, in which case the write already
    // produced an account_data event with a stream position past
    // `since`.
    if since.is_none()
        && !global_account_data
            .iter()
            .any(|e| e.get("type").and_then(|v| v.as_str()) == Some("m.push_rules"))
    {
        let global = vela_core::push_rules::default_global_rules();
        global_account_data.push(json!({
            "type": "m.push_rules",
            "content": { "global": global },
        }));
    }

    // To-device messages
    let (to_device_events, to_device_keys) = {
        let msgs = state
            .db
            .get_to_device_messages(user.user_nid, &user.device_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let events: Vec<Value> = msgs.iter().map(|(_, v)| v.clone()).collect();
        let db_keys: Vec<Vec<u8>> = msgs.into_iter().map(|(k, _)| k).collect();
        (events, db_keys)
    };

    // Delete consumed to-device messages
    if !to_device_keys.is_empty() {
        state
            .db
            .delete_to_device_messages(&to_device_keys)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    // E2EE key counts for this device
    let otk_counts = state
        .db
        .count_one_time_keys(user.user_nid, &user.device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .set_sync_position(user.user_nid, &user.device_id, current_pos)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let presence_events = collect_presence_events(state, user.user_nid, joined_room_nids)?;

    // device_lists.changed: users whose device/cross-signing keys changed
    // since `since` (or since 0 on initial sync). Element uses this to
    // decide when to re-query /keys/query; without it, self-signature
    // uploads don't surface and the device stays "unverified".
    // `since` is the highest position already returned to the client
    // (next_batch from the prior /sync). The rest of sync treats it
    // as exclusive — strictly newer events. Match that here by
    // starting one position past `since`, otherwise the long-poll
    // re-serves a change that was already in the prior response.
    let dl_from = since.map(|s| s.saturating_add(1)).unwrap_or(0);
    let device_lists_changed: Vec<String> = {
        let nids = state
            .db
            .get_device_key_changes(user.user_nid, dl_from, current_pos + 1)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let mut out = Vec::new();
        for nid in nids {
            if let Some(uid) = state
                .db
                .resolve_nid(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                out.push(uid);
            }
        }
        out
    };
    // device_lists.left: users we no longer share any room with since
    // `since`. Post-filter the raw "departed from a room I was in"
    // events against current shared-room state — bob may have left
    // the room that triggered the entry but still share another room
    // with us, in which case we do NOT report him as "left".
    let device_lists_left: Vec<String> = {
        let raw = state
            .db
            .get_device_list_left(user.user_nid, dl_from, current_pos + 1)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let our_rooms = state
            .db
            .get_user_joined_rooms(user.user_nid)
            .unwrap_or_default();
        let mut out = Vec::new();
        for nid in raw {
            // Drop the change-side dedup: a user may appear in both
            // changed and left within the same window. Spec says left
            // wins for the "no longer shares" semantic.
            let still_sharing = our_rooms
                .iter()
                .any(|&room_nid| state.db.get_membership(room_nid, nid).ok().flatten() == Some(1));
            if still_sharing {
                continue;
            }
            if let Some(uid) = state
                .db
                .resolve_nid(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                out.push(uid);
            }
        }
        out
    };
    let device_lists_changed: Vec<String> = device_lists_changed
        .into_iter()
        .filter(|u| !device_lists_left.contains(u))
        .collect();

    Ok(json!({
        "next_batch": format!("s{current_pos}"),
        "rooms": {
            "join": join_rooms,
            "invite": invite_rooms,
            "leave": leave_rooms,
            "knock": knock_rooms,
        },
        "presence": {"events": presence_events},
        "account_data": {"events": global_account_data},
        "to_device": {"events": to_device_events},
        "device_lists": {"changed": device_lists_changed, "left": device_lists_left},
        "device_one_time_keys_count": otk_counts,
        "device_unused_fallback_key_types": [],
    }))
}

/// MSC4115: annotate `unsigned.membership` on `ev` with the requesting
/// user's `m.room.member` value as it stood at `event_nid`. Default
/// `"leave"` when the user had no member event yet. No-op when
/// `user_nid` is `None`.
fn attach_membership_for_user(
    state: &AppState,
    ev: &mut Value,
    user_nid: Option<u64>,
    event_nid: u64,
) {
    let Some(uid) = user_nid else { return };
    let membership = crate::messages::membership_at_event(state, 0, uid, event_nid)
        .ok()
        .flatten()
        .unwrap_or_else(|| "leave".to_string());
    let Some(obj) = ev.as_object_mut() else {
        return;
    };
    let unsigned = obj
        .entry("unsigned".to_string())
        .or_insert_with(|| json!({}));
    let Some(unsigned_obj) = unsigned.as_object_mut() else {
        return;
    };
    unsigned_obj.insert("membership".to_string(), json!(membership));
}

/// Attach `unsigned.transaction_id` to `ev` when the requesting
/// `(user_nid, device_id)` matches the originating sender. Used on
/// the local-echo path for /sync timeline events; matches the
/// behaviour of `load_client_event_with_relations` for /event,
/// /messages, and /relations.
fn attach_txn_id_for_user(
    state: &AppState,
    ev: &mut Value,
    user_nid: Option<u64>,
    device_id: Option<&str>,
    event_nid: u64,
) {
    let (Some(uid), Some(did)) = (user_nid, device_id) else {
        return;
    };
    let Ok(Some(txn)) = state.db.get_event_txn_id_for_user(event_nid, uid, did) else {
        return;
    };
    let Some(obj) = ev.as_object_mut() else {
        return;
    };
    let unsigned = obj
        .entry("unsigned".to_string())
        .or_insert_with(|| json!({}));
    let Some(unsigned_obj) = unsigned.as_object_mut() else {
        return;
    };
    unsigned_obj.insert("transaction_id".to_string(), json!(txn));
}

fn build_room_sync_for_user(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    since: Option<u64>,
    user_nid: Option<u64>,
    device_id: Option<&str>,
    timeline_limit: usize,
) -> Result<Value, ApiError> {
    let (state_events, timeline_events, limited, prev_batch) = match since {
        None => {
            let state_nids = state
                .db
                .get_all_state_event_nids(room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

            let mut state_events = Vec::new();
            for nid in &state_nids {
                if let Some(mut ev) = load_client_event(state, *nid, room_id)? {
                    attach_membership_for_user(state, &mut ev, user_nid, *nid);
                    attach_txn_id_for_user(state, &mut ev, user_nid, device_id, *nid);
                    state_events.push(ev);
                }
            }

            let timeline_entries = state
                .db
                .get_timeline_latest(room_nid, timeline_limit)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

            let mut timeline_events = Vec::new();
            let mut first_pos = None;
            for (pos, enid) in &timeline_entries {
                if first_pos.is_none() {
                    first_pos = Some(*pos);
                }
                if let Some(mut ev) = load_client_event(state, *enid, room_id)? {
                    attach_membership_for_user(state, &mut ev, user_nid, *enid);
                    attach_txn_id_for_user(state, &mut ev, user_nid, device_id, *enid);
                    timeline_events.push(ev);
                }
            }

            let prev_batch = first_pos.map(|p| format!("s{p}"));
            (state_events, timeline_events, true, prev_batch)
        }
        Some(since_pos) => {
            // If the user's membership transitioned to `join` *within* this
            // sync window (membership_pos > since), the client has never
            // seen this room before — returning timeline-only would leave
            // them with no state to render (Element then fetches
            // /rooms/{id}/state per event, which can add seconds to the
            // perceived latency after accepting an invite). Treat it like
            // an initial join: return full current state + latest timeline.
            let fresh_join = user_nid
                .and_then(|uid| {
                    state
                        .db
                        .get_user_room_membership_pos(uid, room_nid)
                        .ok()
                        .flatten()
                })
                .map(|pos| pos > since_pos)
                .unwrap_or(false);

            if fresh_join {
                let state_nids = state
                    .db
                    .get_all_state_event_nids(room_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                let mut state_events = Vec::new();
                for nid in &state_nids {
                    if let Some(ev) = load_client_event(state, *nid, room_id)? {
                        state_events.push(ev);
                    }
                }
                let timeline_entries = state
                    .db
                    .get_timeline_latest(room_nid, timeline_limit)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                let mut timeline_events = Vec::new();
                let mut first_pos = None;
                for (pos, enid) in &timeline_entries {
                    if first_pos.is_none() {
                        first_pos = Some(*pos);
                    }
                    if let Some(ev) = load_client_event(state, *enid, room_id)? {
                        timeline_events.push(ev);
                    }
                }
                let prev_batch = first_pos.map(|p| format!("s{p}"));
                (state_events, timeline_events, true, prev_batch)
            } else {
                let timeline_entries = state
                    .db
                    // Spec on /sync timeline filter limit: when the
                    // client supplies one, we must use it both to bound
                    // the events returned AND to compute prev_batch
                    // accurately. Loading 30 events then trimming in a
                    // post-filter pass leaves prev_batch pointing at
                    // the pre-trim batch start, which makes
                    // /messages?from=prev_batch walk past the events
                    // the client already saw and into older state.
                    // get_timeline_range walks ascending — to honour
                    // "most recent N events since `since`", we instead
                    // walk *backwards* from now to the first
                    // `timeline_limit` events strictly newer than
                    // since.
                    .get_timeline_before(room_nid, u64::MAX, timeline_limit.max(1))
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

                // Drop entries at or before `since_pos`; those are
                // already on the client.
                let timeline_entries: Vec<(u64, u64)> = timeline_entries
                    .into_iter()
                    .filter(|(p, _)| *p > since_pos)
                    .collect();
                let limited = timeline_entries.len() >= timeline_limit;

                let mut timeline_events = Vec::new();
                let mut first_pos = None;
                for (pos, enid) in &timeline_entries {
                    if first_pos.is_none() {
                        first_pos = Some(*pos);
                    }
                    if let Some(ev) = load_client_event(state, *enid, room_id)? {
                        timeline_events.push(ev);
                    }
                }

                let prev_batch = first_pos.map(|p| format!("s{p}"));
                (vec![], timeline_events, limited, prev_batch)
            }
        }
    };

    // Ephemeral: typing + receipts
    let mut ephemeral_events = Vec::new();

    // Typing.
    //
    // m.typing is current-state-style: clients want the latest list of
    // typers, not a stream of deltas. But emitting it on every /sync
    // would conflict with the "skip unchanged room" rule (every room
    // would always look "changed") and flood clients with redundant
    // events. Compromise: emit on initial sync, then on incremental
    // sync only when the typing set transitioned (start or stop) at
    // a stream position newer than `since`. The transition pos is
    // bumped by the /typing handler.
    let last_typing_change = state.typing_change_pos.get(&room_nid).map(|v| *v);
    let typing_changed_since = match (since, last_typing_change) {
        (None, _) => true,           // initial sync — always carry the snapshot
        (Some(_), None) => false,    // never transitioned in this process
        (Some(s), Some(p)) => p > s, // a transition happened since the last sync
    };
    if typing_changed_since {
        let typing_user_nids = get_typing_users(state, room_nid);
        let mut user_ids = Vec::new();
        for nid in &typing_user_nids {
            if let Some(uid) = state
                .db
                .resolve_nid(*nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                user_ids.push(Value::String(uid));
            }
        }
        // Even an empty user_ids list is meaningful — it tells clients
        // "no one is typing right now" after a stop transition, which
        // is what TestTyping/Typing_can_be_explicitly_stopped checks.
        ephemeral_events.push(json!({
            "type": "m.typing",
            "content": {"user_ids": user_ids}
        }));
    }

    // Receipts
    let receipts = state
        .db
        .get_room_receipts(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if !receipts.is_empty() {
        let mut content_map = serde_json::Map::new();
        for (receipt_type, user_nid, receipt_val) in &receipts {
            if let (Some(event_id), Some(ts)) = (
                receipt_val.get("event_id").and_then(|v| v.as_str()),
                receipt_val.get("ts").and_then(|v| v.as_u64()),
            ) {
                let user_id = state
                    .db
                    .resolve_nid(*user_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    .unwrap_or_default();

                let event_entry = content_map
                    .entry(event_id.to_string())
                    .or_insert_with(|| json!({}));
                let type_entry = event_entry
                    .as_object_mut()
                    .unwrap()
                    .entry(receipt_type.clone())
                    .or_insert_with(|| json!({}));
                type_entry
                    .as_object_mut()
                    .unwrap()
                    .insert(user_id, json!({"ts": ts}));
            }
        }
        if !content_map.is_empty() {
            ephemeral_events.push(json!({
                "type": "m.receipt",
                "content": content_map
            }));
        }
    }

    let joined_count = state
        .db
        .count_room_members_by_membership(room_nid, 1)
        .unwrap_or(1);
    let invited_count = state
        .db
        .count_room_members_by_membership(room_nid, 2)
        .unwrap_or(0);

    let room_account_data = match user_nid {
        Some(uid) => state
            .db
            .get_all_room_account_data(uid, room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .into_iter()
            .map(|(dtype, content)| json!({"type": dtype, "content": content}))
            .collect::<Vec<_>>(),
        None => Vec::new(),
    };

    // Approximate unread_notifications by counting non-state events
    // newer than the user's m.read receipt that aren't from the user
    // themselves. Highlights aren't matched against push rules yet
    // (full push-rule application is a separate effort), but the
    // notification count alone is enough for clients that only check
    // the room badge — and for TestThreadedReceipts, which expects a
    // positive count when user-2 has unread messages from user-1.
    let (notification_count, highlight_count) = match user_nid {
        Some(uid) => {
            let read_eid = state
                .db
                .get_user_receipt_event_id(room_nid, "m.read", uid)
                .ok()
                .flatten();
            let mut found_receipt = read_eid.is_none();
            let mut count = 0u64;
            let mut highlights = 0u64;
            let user_id_str = state.db.resolve_nid(uid).ok().flatten().unwrap_or_default();
            for ev in &timeline_events {
                if !found_receipt {
                    if ev.get("event_id").and_then(|v| v.as_str()) == read_eid.as_deref() {
                        found_receipt = true;
                    }
                    continue;
                }
                let ev_type = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let sender = ev.get("sender").and_then(|v| v.as_str()).unwrap_or("");
                let is_state = ev.get("state_key").is_some();
                if is_state || sender == user_id_str {
                    continue;
                }
                if matches!(ev_type, "m.room.message" | "m.room.encrypted") {
                    count = count.saturating_add(1);
                    // .m.rule.contains_user_name highlight (partial push-
                    // rules implementation): body containing the user's
                    // MXID flags as a highlight. Doesn't cover
                    // contains_display_name; that needs profile lookup
                    // and is the gap blocking TestThreadedReceipts'
                    // display-name highlight expectations.
                    let body = ev
                        .pointer("/content/body")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !user_id_str.is_empty() && body.contains(&user_id_str) {
                        highlights = highlights.saturating_add(1);
                    }
                }
            }
            (count, highlights)
        }
        None => (0, 0),
    };

    Ok(json!({
        "state": {"events": state_events},
        "timeline": {
            "events": timeline_events,
            "limited": limited,
            "prev_batch": prev_batch.unwrap_or_default(),
        },
        "summary": {
            "m.joined_member_count": joined_count,
            "m.invited_member_count": invited_count,
        },
        "ephemeral": {"events": ephemeral_events},
        "account_data": {"events": room_account_data},
        "unread_notifications": {
            "highlight_count": highlight_count,
            "notification_count": notification_count,
        },
    }))
}

/// Gather `m.presence` EDUs for users the caller shares a room with. We
/// emit one event per distinct peer that has a stored record (self + users
/// with no record are skipped — `format_status` would fabricate `offline`
/// but flooding sync with offlines for everyone serves no purpose).
fn collect_presence_events(
    state: &AppState,
    self_nid: u64,
    joined_room_nids: &[u64],
) -> Result<Vec<Value>, ApiError> {
    let mut peers: HashSet<u64> = HashSet::new();
    for &room_nid in joined_room_nids {
        let members = state
            .db
            .get_room_members(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        for m in members {
            if m != self_nid {
                peers.insert(m);
            }
        }
    }

    let mut events = Vec::new();
    for peer_nid in peers {
        let Some(rec) = state
            .db
            .get_presence(peer_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        let user_id = state
            .db
            .resolve_nid(peer_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();
        events.push(json!({
            "type": "m.presence",
            "sender": user_id,
            "content": crate::presence::format_status(&rec),
        }));
    }
    Ok(events)
}

/// Resolve a `?filter=` parameter into the JSON definition. Accepts inline
/// JSON (`{...}`) or a previously-uploaded filter id. Returns `None` for
/// missing/unknown filters; sync proceeds unfiltered rather than 4xx,
/// since clients in the wild rely on this lenient behaviour.
fn resolve_filter(
    state: &AppState,
    user: &AuthenticatedUser,
    raw: Option<&str>,
) -> Result<Option<Value>, ApiError> {
    let Some(s) = raw else { return Ok(None) };
    if s.starts_with('{') {
        return Ok(serde_json::from_str(s).ok());
    }
    let f = state
        .db
        .get_filter(user.user_nid, s)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(f)
}

/// Load the user's `m.ignored_user_list` global account data and return
/// the set of ignored user IDs (empty when the account data is absent).
fn load_ignored_users(state: &AppState, user_nid: u64) -> Result<HashSet<String>, ApiError> {
    let mut out = HashSet::new();
    let raw = state
        .db
        .get_account_data(user_nid, "m.ignored_user_list")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let Some(v) = raw else { return Ok(out) };
    if let Some(map) = v.get("ignored_users").and_then(|x| x.as_object()) {
        for k in map.keys() {
            out.insert(k.clone());
        }
    }
    Ok(out)
}

/// Drop timeline events whose `sender` is on the ignored list. State,
/// ephemeral, and account_data are untouched — only timeline message
/// events are filtered, which is the behaviour clients expect.
fn filter_room_timeline_by_ignored(room_data: &mut Value, ignored: &HashSet<String>) {
    let Some(events) = room_data
        .pointer_mut("/timeline/events")
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };
    events.retain(|e| e.sender().map(|s| !ignored.contains(s)).unwrap_or(true));
}

/// Check whether the most recent invite for `user_nid` in `room_nid` was
/// sent by an ignored user. Looks at the current `m.room.member` state
/// event for the user.
fn invite_sender_is_ignored(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
    ignored: &HashSet<String>,
) -> Result<bool, ApiError> {
    let user_id = state
        .db
        .resolve_nid(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_default();
    let type_nid = state
        .db
        .get_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (Some(tn), Some(sn)) = (type_nid, skey_nid) else {
        return Ok(false);
    };
    let Some(event_nid) = state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(false);
    };
    let Some((header, _)) = state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(false);
    };
    let sender = state
        .db
        .resolve_nid(header.sender_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_default();
    Ok(ignored.contains(&sender))
}

/// True if the user's membership in `room_nid` should be surfaced in this
/// sync response. On initial sync (`since.is_none()`) always true; on
/// incremental sync, only when the last recorded transition happened after
/// the client's `since` token. Rooms with no recorded transition (possible
/// for entries predating the index, or for incoming federation member events
/// that bypass `set_membership`) are treated as "always include" — a minor
/// over-report that the client can dedupe, better than silently dropping.
fn membership_changed_since(
    state: &AppState,
    user_nid: u64,
    room_nid: u64,
    since: Option<u64>,
) -> Result<bool, ApiError> {
    let since = match since {
        Some(s) => s,
        None => return Ok(true),
    };
    match state
        .db
        .get_user_room_membership_pos(user_nid, room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(pos) => Ok(pos > since),
        None => Ok(true),
    }
}

/// Build the `rooms.invite.{room_id}` payload with stripped state events.
fn build_invite_sync(state: &AppState, room_nid: u64, room_id: &str) -> Result<Value, ApiError> {
    Ok(json!({
        "invite_state": {
            "events": collect_invite_or_knock_stripped(state, room_nid, room_id)?,
        },
    }))
}

/// Build the `rooms.knock.{room_id}` payload with stripped state events.
/// Spec: `rooms.knock.{roomId}.knock_state.events` mirrors `invite_state`.
fn build_knock_sync(state: &AppState, room_nid: u64, room_id: &str) -> Result<Value, ApiError> {
    Ok(json!({
        "knock_state": {
            "events": collect_invite_or_knock_stripped(state, room_nid, room_id)?,
        },
    }))
}

/// Stripped state events that go into `invite_state` / `knock_state`.
///
/// Per MSC4311 (room version 12), the `m.room.create` event MUST be
/// included in full — it carries the data needed to verify the
/// room_id (which v12 derives from a hash of the create event). All
/// other state events are stripped to `type/state_key/sender/content`.
fn collect_invite_or_knock_stripped(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
) -> Result<Vec<Value>, ApiError> {
    static STRIPPED_TYPES: &[&str] = &[
        "m.room.create",
        "m.room.name",
        "m.room.avatar",
        "m.room.canonical_alias",
        "m.room.join_rules",
        "m.room.member",
    ];

    let state_nids = state
        .db
        .get_all_state_event_nids(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut out = Vec::new();
    for nid in state_nids {
        let Some(ev) = load_client_event(state, nid, room_id)? else {
            continue;
        };
        let etype = ev.event_type().unwrap_or("");
        if !STRIPPED_TYPES.contains(&etype) {
            continue;
        }
        if etype == "m.room.create" {
            // MSC4311: full create event, not stripped.
            out.push(ev);
        } else {
            out.push(json!({
                "type": ev.get("type"),
                "state_key": ev.get("state_key"),
                "sender": ev.get("sender"),
                "content": ev.get("content"),
            }));
        }
    }
    Ok(out)
}

/// True when the room sync block has no content to deliver: empty
/// timeline, empty state delta, no ephemeral events, no per-room
/// account data. Such rooms must be omitted from `rooms.join` on
/// incremental sync per spec.
fn room_is_unchanged(room: &Value) -> bool {
    let arr_empty = |ptr: &str| {
        room.pointer(ptr)
            .and_then(|v| v.as_array())
            .is_none_or(|a| a.is_empty())
    };
    arr_empty("/timeline/events")
        && arr_empty("/state/events")
        && arr_empty("/ephemeral/events")
        && arr_empty("/account_data/events")
}

/// Build the `rooms.leave.{room_id}` payload.
///
/// Per spec, a left user's view of the room is **frozen at their leave**:
/// they must not see events sent (or state changed) after that point. The
/// state we expose anchors at the user's leave event, and the timeline
/// stops there too.
///
/// Layout:
/// - `timeline.events` — events up to and including the user's leave,
///   newest-first capped to `timeline_limit`, returned chronologically.
///   For incremental sync, events at or before `since` are also dropped.
/// - `state.events` — state at the start of the timeline (or state at
///   the leave event itself when timeline_limit==0). For incremental
///   sync, the delta against `state-at-since` is emitted instead.
/// - `state.events` excludes events that already appear in
///   `timeline.events` (spec rule: don't duplicate).
///
/// `timeline_limit` is the post-filter cap requested by the client; the
/// caller still applies `timeline_filter`/`state_filter` on top of what
/// we return, which can shrink either array further.
const LEAVE_SCAN_WINDOW: usize = 10_000;

fn build_leave_sync(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    user_nid: u64,
    user_id: &str,
    since: Option<u64>,
    timeline_limit: usize,
) -> Result<Value, ApiError> {
    // Locate the user's leave event. Because the user is currently in the
    // "left" set, the live state entry for `(m.room.member, user_id)` IS
    // the leave event — any subsequent rejoin would have moved them to
    // the joined set.
    let member_type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let user_skey_nid = state
        .db
        .get_or_create_nid(user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let leave_event_nid = state
        .db
        .get_state_event_nid(room_nid, member_type_nid, user_skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Walk room timeline backwards from the latest position, skipping
    // events that were sent AFTER the user left (those belong to other
    // members and must not be visible). Once we hit the leave event we
    // include it and continue collecting older events up to the limit.
    let scan = state
        .db
        .get_timeline_before(room_nid, u64::MAX, LEAVE_SCAN_WINDOW)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut timeline_newest_first: Vec<(u64, u64)> = Vec::new();
    let mut found_leave = leave_event_nid.is_none();
    let mut more_before_first = false;
    for (pos, enid) in scan.iter().rev() {
        if !found_leave {
            if Some(*enid) == leave_event_nid {
                found_leave = true;
            } else {
                continue;
            }
        }
        if let Some(s) = since
            && *pos <= s
        {
            // Already on the client; stop here.
            break;
        }
        if timeline_newest_first.len() >= timeline_limit {
            more_before_first = true;
            break;
        }
        timeline_newest_first.push((*pos, *enid));
    }
    let first_pos = timeline_newest_first.last().map(|(p, _)| *p);
    let prev_batch = first_pos.map(|p| format!("s{p}")).unwrap_or_default();

    // State at the start of the timeline (chronologically). When the
    // timeline is empty we fall back to state-at-leave so the client
    // still sees the room as it was at the moment of departure.
    let state_at_anchor: Vec<u64> = match first_pos {
        Some(p) => {
            // Find the event immediately preceding the timeline's first
            // event in the same room and read its persisted state
            // snapshot. If our timeline starts at the room's create
            // event there's no predecessor — pre-state is empty.
            let predecessor = state
                .db
                .get_timeline_before(room_nid, p, 1)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            match predecessor.last() {
                Some((_, pred_nid)) => state
                    .db
                    .get_state_at_event(*pred_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    .unwrap_or_default(),
                None => Vec::new(),
            }
        }
        None => match leave_event_nid {
            Some(nid) => state
                .db
                .get_state_at_event(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .unwrap_or_default(),
            None => Vec::new(),
        },
    };

    // For incremental sync, emit only the delta against state-at-since
    // (events that became state between `since` and the timeline start).
    let state_to_emit: Vec<u64> = match since {
        Some(since_pos) => {
            let at_since_event = state
                .db
                .get_timeline_before(room_nid, since_pos.saturating_add(1), 1)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            let state_at_since = match at_since_event.last() {
                Some((_, snid)) => state
                    .db
                    .get_state_at_event(*snid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            let since_set: std::collections::HashSet<u64> = state_at_since.into_iter().collect();
            state_at_anchor
                .into_iter()
                .filter(|n| !since_set.contains(n))
                .collect()
        }
        None => state_at_anchor,
    };

    // Don't duplicate state events that are already in the timeline.
    let timeline_set: std::collections::HashSet<u64> =
        timeline_newest_first.iter().map(|(_, n)| *n).collect();

    let mut state_events = Vec::new();
    for nid in &state_to_emit {
        if timeline_set.contains(nid) {
            continue;
        }
        if let Some(ev) = load_client_event(state, *nid, room_id)? {
            state_events.push(ev);
        }
    }

    let mut timeline_events = Vec::new();
    for (_, enid) in timeline_newest_first.iter().rev() {
        if let Some(ev) = load_client_event(state, *enid, room_id)? {
            timeline_events.push(ev);
        }
    }

    let _ = user_nid;

    Ok(json!({
        "state": {"events": state_events},
        "timeline": {
            "events": timeline_events,
            "limited": more_before_first,
            "prev_batch": prev_batch,
        },
        "account_data": {"events": []},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    #[test]
    fn invited_rooms_appear_in_sync_query() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let user_nid = db.get_or_create_nid("@bob:example.com").unwrap();
        let room_nid = db.get_or_create_nid("!room1").unwrap();

        // Before invite: no invited rooms.
        let invited = db.get_user_invited_rooms(user_nid).unwrap();
        assert!(invited.is_empty(), "no invites yet");

        // Set membership to invite (2).
        db.set_membership(room_nid, user_nid, 2).unwrap();

        // Now should appear.
        let invited = db.get_user_invited_rooms(user_nid).unwrap();
        assert_eq!(invited, vec![room_nid], "room should appear after invite");

        // Joined rooms should still be empty.
        let joined = db.get_user_joined_rooms(user_nid).unwrap();
        assert!(joined.is_empty(), "not joined");
    }

    fn fake_user(state: &AppState, user_id: &str) -> AuthenticatedUser {
        let user_nid = state.db.get_or_create_nid(user_id).unwrap();
        AuthenticatedUser {
            user_nid,
            user_id: user_id.to_string(),
            device_id: "DEV".into(),
        }
    }

    #[test]
    fn invite_appears_on_initial_and_disappears_on_incremental_after_pos() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let room_nid = db.get_or_create_nid("!room:example.com").unwrap();
        let user = fake_user(&state, "@bob:example.com");
        db.set_membership(room_nid, user.user_nid, 2).unwrap();

        // Initial sync: invite present.
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        let invites = resp.pointer("/rooms/invite").unwrap().as_object().unwrap();
        assert!(
            invites.contains_key("!room:example.com"),
            "invite missing on initial sync: {invites:?}"
        );

        // Stream pos of the invite.
        let pos = db
            .get_user_room_membership_pos(user.user_nid, room_nid)
            .unwrap()
            .expect("invite transition indexed");

        // Incremental sync from the exact pos of the invite: should be excluded.
        let resp = build_sync_response(&state, &user, &[], Some(pos)).unwrap();
        let invites = resp.pointer("/rooms/invite").unwrap().as_object().unwrap();
        assert!(
            !invites.contains_key("!room:example.com"),
            "stale invite should not reappear on incremental sync"
        );

        // Incremental sync from before pos: invite reappears.
        let resp = build_sync_response(&state, &user, &[], Some(pos - 1)).unwrap();
        let invites = resp.pointer("/rooms/invite").unwrap().as_object().unwrap();
        assert!(invites.contains_key("!room:example.com"));
    }

    /// Persist a state event, allocate a fresh stream pos, and update
    /// the room's snapshot so `get_state_at_event` returns it.
    #[allow(clippy::too_many_arguments)]
    fn persist_state(
        db: &vela_store::db::Database,
        nid: u64,
        eid: &str,
        room_nid: u64,
        room_id: &str,
        type_name: &str,
        sender_nid: u64,
        sender_id: &str,
        state_key: &str,
        content: serde_json::Value,
        ts: u64,
        depth: u64,
        prev: &[u64],
    ) -> u64 {
        let type_nid = db.get_or_create_nid(type_name).unwrap();
        let skey_nid = db.get_or_create_nid(state_key).unwrap();
        let body = serde_json::json!({
            "type": type_name,
            "sender": sender_id,
            "state_key": state_key,
            "room_id": room_id,
            "content": content,
            "origin_server_ts": ts, "depth": depth,
            "prev_events": [], "auth_events": [],
        });
        let pos = db
            .persist_event(
                nid,
                eid,
                room_nid,
                type_nid,
                sender_nid,
                skey_nid,
                ts,
                depth,
                &serde_json::to_vec(&body).unwrap(),
                prev,
                &[],
                true,
                false,
            )
            .unwrap();
        db.promote_state_event(room_nid, nid, type_nid, skey_nid)
            .unwrap();
        pos
    }

    /// Setup that mirrors the Complement TestArchivedRoomsHistory shape:
    /// alice + bob in a room, both joined, alice writes a custom state
    /// `a.madeup.state` with my_key=before, bob leaves, then alice writes
    /// the same state with my_key=after.
    fn build_archive_scenario() -> (AppState, tempfile::TempDir, AuthenticatedUser, String) {
        let (state, tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!leaveroom:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let bob = fake_user(&state, "@bob:example.com");

        persist_state(
            &db,
            100,
            "$create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            101,
            "$alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[100],
        );
        persist_state(
            &db,
            102,
            "$bob_join",
            room_nid,
            &room_id,
            "m.room.member",
            bob.user_nid,
            "@bob:example.com",
            "@bob:example.com",
            serde_json::json!({"membership": "join"}),
            3,
            3,
            &[101],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();
        db.set_membership(room_nid, bob.user_nid, 1).unwrap();

        persist_state(
            &db,
            103,
            "$state_before",
            room_nid,
            &room_id,
            "a.madeup.state",
            alice_nid,
            alice,
            "",
            serde_json::json!({"my_key": "before"}),
            4,
            4,
            &[102],
        );
        persist_state(
            &db,
            104,
            "$bob_leave",
            room_nid,
            &room_id,
            "m.room.member",
            bob.user_nid,
            "@bob:example.com",
            "@bob:example.com",
            serde_json::json!({"membership": "leave"}),
            5,
            5,
            &[103],
        );
        db.set_membership(room_nid, bob.user_nid, 0).unwrap();
        persist_state(
            &db,
            105,
            "$state_after",
            room_nid,
            &room_id,
            "a.madeup.state",
            alice_nid,
            alice,
            "",
            serde_json::json!({"my_key": "after"}),
            6,
            6,
            &[104],
        );

        (state, tmp, bob, room_id)
    }

    /// With timeline_limit=0 the leave room shows state-AT-LEAVE in
    /// `state.events`. The post-leave `$state_after` must not appear.
    #[test]
    fn leave_sync_with_empty_timeline_returns_state_at_leave() {
        let (state, _tmp, bob, room_id) = build_archive_scenario();
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();

        let leave = build_leave_sync(
            &state,
            room_nid,
            &room_id,
            bob.user_nid,
            &bob.user_id,
            None,
            0,
        )
        .unwrap();
        let state_events = leave
            .pointer("/state/events")
            .and_then(|v| v.as_array())
            .unwrap();

        let madeup = state_events
            .iter()
            .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("a.madeup.state"))
            .expect("madeup state event present");
        assert_eq!(
            madeup.pointer("/content/my_key").and_then(|v| v.as_str()),
            Some("before"),
            "state must be at-leave, not current"
        );

        let bob_member = state_events
            .iter()
            .find(|e| {
                e.get("type").and_then(|t| t.as_str()) == Some("m.room.member")
                    && e.get("state_key").and_then(|s| s.as_str()) == Some("@bob:example.com")
            })
            .expect("bob's member event present in state");
        assert_eq!(
            bob_member
                .pointer("/content/membership")
                .and_then(|v| v.as_str()),
            Some("leave"),
        );

        let timeline = leave
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(timeline.is_empty(), "timeline_limit=0 → empty timeline");
    }

    /// With a non-zero limit, the leave room timeline ends at the user's
    /// leave event — events sent after the leave must NOT appear, even if
    /// they're newer than the leave in the room timeline.
    #[test]
    fn leave_sync_timeline_ends_at_leave_event() {
        let (state, _tmp, bob, room_id) = build_archive_scenario();
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();

        let leave = build_leave_sync(
            &state,
            room_nid,
            &room_id,
            bob.user_nid,
            &bob.user_id,
            None,
            10,
        )
        .unwrap();
        let timeline = leave
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .unwrap();

        let last_id = timeline
            .last()
            .and_then(|e| e.get("event_id").and_then(|v| v.as_str()))
            .expect("timeline non-empty");
        assert_eq!(last_id, "$bob_leave", "timeline must end at bob's leave");
        assert!(
            !timeline
                .iter()
                .any(|e| e.get("event_id").and_then(|v| v.as_str()) == Some("$state_after")),
            "post-leave events must not appear in bob's timeline"
        );
    }

    /// Incremental sync where `since` falls just before the leave event:
    /// timeline should be exactly the leave event, and state.events
    /// should be empty (the only state delta is the leave event itself,
    /// which already appears in the timeline).
    #[test]
    fn leave_sync_incremental_emits_leave_in_timeline_and_no_duplicate_state() {
        let (state, _tmp, bob, room_id) = build_archive_scenario();
        let db = &state.db;
        let room_nid = db.get_nid(&room_id).unwrap().unwrap();

        // Find the stream pos of `$state_before` and use it as `since`.
        // The leave event was persisted right after it, so events after
        // that point are exactly the leave + the post-leave state change.
        let scan = db.get_timeline_before(room_nid, u64::MAX, 100).unwrap();
        let state_before_pos = scan
            .iter()
            .find_map(|(pos, nid)| {
                let eid = db.get_event_id_by_nid(*nid).unwrap().unwrap_or_default();
                if eid == "$state_before" {
                    Some(*pos)
                } else {
                    None
                }
            })
            .expect("found $state_before");

        let leave = build_leave_sync(
            &state,
            room_nid,
            &room_id,
            bob.user_nid,
            &bob.user_id,
            Some(state_before_pos),
            10,
        )
        .unwrap();

        let timeline = leave
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .unwrap();
        let ids: Vec<&str> = timeline
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids, vec!["$bob_leave"], "timeline only the leave event");

        let state_events = leave
            .pointer("/state/events")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(
            state_events.is_empty(),
            "state delta should be empty (leave is in timeline already): {state_events:?}"
        );
    }

    /// Per spec, an incremental /sync MUST omit joined rooms with no new
    /// content since `since`. The `full_state=true` form bypasses this.
    #[test]
    fn unchanged_joined_room_omitted_from_incremental_sync() {
        let (state, _tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!quietroom:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let alice_user = AuthenticatedUser {
            user_nid: alice_nid,
            user_id: alice.into(),
            device_id: "DEV".into(),
        };

        persist_state(
            &db,
            200,
            "$create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            201,
            "$alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[200],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        let cur = db.current_stream_position();

        // Initial sync: room must appear (even if "empty" state, alice
        // has never seen it before).
        let resp =
            build_sync_response_with_filter(&state, &alice_user, &[room_nid], None, None, false)
                .unwrap();
        assert!(
            resp.pointer(&format!("/rooms/join/{room_id}")).is_some(),
            "initial sync must include joined rooms"
        );

        // Incremental sync from a token equal to current pos: nothing
        // happened since, so the room must be omitted.
        let resp = build_sync_response_with_filter(
            &state,
            &alice_user,
            &[room_nid],
            Some(cur),
            None,
            false,
        )
        .unwrap();
        let join = resp
            .pointer("/rooms/join")
            .and_then(|v| v.as_object())
            .unwrap();
        assert!(
            !join.contains_key(&room_id),
            "unchanged room must not appear on incremental sync: {join:?}"
        );

        // full_state=true forces the room to be present even when nothing
        // has happened since.
        let resp = build_sync_response_with_filter(
            &state,
            &alice_user,
            &[room_nid],
            Some(cur),
            None,
            true,
        )
        .unwrap();
        assert!(
            resp.pointer(&format!("/rooms/join/{room_id}")).is_some(),
            "full_state=true must always include joined rooms"
        );
    }

    #[test]
    fn leave_appears_on_initial_and_disappears_on_incremental_after_pos() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!leftroom:example.com").unwrap();
        let user = fake_user(&state, "@carol:example.com");
        db.set_membership(room_nid, user.user_nid, 0).unwrap();

        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        let leaves = resp.pointer("/rooms/leave").unwrap().as_object().unwrap();
        assert!(leaves.contains_key("!leftroom:example.com"));

        let pos = db
            .get_user_room_membership_pos(user.user_nid, room_nid)
            .unwrap()
            .unwrap();
        let resp = build_sync_response(&state, &user, &[], Some(pos)).unwrap();
        let leaves = resp.pointer("/rooms/leave").unwrap().as_object().unwrap();
        assert!(
            !leaves.contains_key("!leftroom:example.com"),
            "stale leave should not reappear"
        );
    }

    #[test]
    fn ignored_user_invite_is_dropped_from_sync() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!room12").unwrap();
        let user = fake_user(&state, "@bob:example.com");
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();

        // Persist a create + alice's join + alice-invites-bob member event.
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();
        let bob_skey = db.get_or_create_nid("@bob:example.com").unwrap();

        db.persist_event(
            10,
            "$room12",
            room_nid,
            type_create,
            alice_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.create",
                "sender": "@alice:example.com",
                "state_key": "",
                "room_id": "!room12",
                "content": {"room_version": "12"},
                "origin_server_ts": 1, "depth": 1,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            11,
            "$alice",
            room_nid,
            type_member,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.member",
                "sender": "@alice:example.com", "state_key": "@alice:example.com",
                "room_id": "!room12",
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": ["$room12"], "auth_events": ["$room12"],
            }))
            .unwrap(),
            &[10],
            &[10],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            12,
            "$bob_invite",
            room_nid,
            type_member,
            alice_nid,
            bob_skey,
            3,
            3,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.member",
                "sender": "@alice:example.com", "state_key": "@bob:example.com",
                "room_id": "!room12",
                "content": {"membership": "invite"},
                "origin_server_ts": 3, "depth": 3,
                "prev_events": ["$alice"], "auth_events": ["$alice"],
            }))
            .unwrap(),
            &[11],
            &[11],
            true,
            false,
        )
        .unwrap();
        db.set_membership(room_nid, user.user_nid, 2).unwrap();

        // Without ignoring alice, the invite shows up.
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        assert!(
            resp.pointer("/rooms/invite/!room12").is_some(),
            "invite present pre-ignore"
        );

        // Now bob ignores alice.
        db.set_account_data(
            user.user_nid,
            "m.ignored_user_list",
            &serde_json::json!({
                "ignored_users": {"@alice:example.com": {}}
            }),
        )
        .unwrap();

        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        assert!(
            resp.pointer("/rooms/invite/!room12").is_none(),
            "invite from ignored user should be filtered: {resp:?}"
        );
    }

    #[test]
    fn new_invite_after_since_surfaces_on_incremental() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!fresh:example.com").unwrap();
        let user = fake_user(&state, "@dan:example.com");

        // Client's since token is "now", captured before the invite arrives.
        let since = db.current_stream_position();

        // Now the invite comes in.
        db.set_membership(room_nid, user.user_nid, 2).unwrap();

        let resp = build_sync_response(&state, &user, &[], Some(since)).unwrap();
        let invites = resp.pointer("/rooms/invite").unwrap().as_object().unwrap();
        assert!(
            invites.contains_key("!fresh:example.com"),
            "fresh invite must appear after since={since}"
        );
    }
}
