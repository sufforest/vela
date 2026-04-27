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

    // Now check the DB — any events broadcast after our subscribe() call
    // will be caught by the spawned listener tasks.
    let response =
        build_sync_response_with_filter(&state, &user, &joined_room_nids, since, filter.as_ref())?;

    let has_events = response
        .get("rooms")
        .and_then(|r| r.get("join"))
        .and_then(|j| j.as_object())
        .map(|rooms| {
            rooms.values().any(|room| {
                room.get("timeline")
                    .and_then(|t| t.get("events"))
                    .and_then(|e| e.as_array())
                    .is_some_and(|a| !a.is_empty())
            })
        })
        .unwrap_or(false);
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

    let response =
        build_sync_response_with_filter(&state, &user, &joined_room_nids, since, filter.as_ref())?;
    Ok(Json(response))
}

#[allow(dead_code)]
pub(crate) fn build_sync_response(
    state: &AppState,
    user: &AuthenticatedUser,
    joined_room_nids: &[u64],
    since: Option<u64>,
) -> Result<Value, ApiError> {
    build_sync_response_with_filter(state, user, joined_room_nids, since, None)
}

pub(crate) fn build_sync_response_with_filter(
    state: &AppState,
    user: &AuthenticatedUser,
    joined_room_nids: &[u64],
    since: Option<u64>,
    filter: Option<&Value>,
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

        let mut room_data =
            build_room_sync_for_user(state, room_nid, &room_id, since, Some(user.user_nid))?;
        if !ignored.is_empty() {
            filter_room_timeline_by_ignored(&mut room_data, &ignored);
        }
        if let Some(tf) = timeline_filter {
            crate::filters::apply_timeline_filter(&mut room_data, tf);
        }
        if lazy_load {
            crate::filters::apply_lazy_load_state(&mut room_data, &user.user_id);
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

        let leave_data = build_leave_sync(state, room_nid, &room_id)?;
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
    let device_lists_changed: Vec<String> = {
        let from = since.unwrap_or(0);
        let nids = state
            .db
            .get_device_key_changes(user.user_nid, from, current_pos + 1)
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
        "device_lists": {"changed": device_lists_changed, "left": []},
        "device_one_time_keys_count": otk_counts,
        "device_unused_fallback_key_types": [],
    }))
}

fn build_room_sync_for_user(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    since: Option<u64>,
    user_nid: Option<u64>,
) -> Result<Value, ApiError> {
    let (state_events, timeline_events, limited, prev_batch) = match since {
        None => {
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
                .get_timeline_latest(room_nid, DEFAULT_TIMELINE_LIMIT)
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
                    .get_timeline_latest(room_nid, DEFAULT_TIMELINE_LIMIT)
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
                    .get_timeline_range(room_nid, since_pos + 1, u64::MAX, DEFAULT_TIMELINE_LIMIT)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

                let limited = timeline_entries.len() >= DEFAULT_TIMELINE_LIMIT;

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

    // Typing
    let typing_user_nids = get_typing_users(state, room_nid);
    if !typing_user_nids.is_empty() {
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
        .get_room_members(room_nid)
        .map(|m| m.len())
        .unwrap_or(1);

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

    Ok(json!({
        "state": {"events": state_events},
        "timeline": {
            "events": timeline_events,
            "limited": limited,
            "prev_batch": prev_batch.unwrap_or_default(),
        },
        "summary": {
            "m.joined_member_count": joined_count,
            "m.invited_member_count": 0,
        },
        "ephemeral": {"events": ephemeral_events},
        "account_data": {"events": room_account_data},
        "unread_notifications": {
            "highlight_count": 0,
            "notification_count": 0,
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

    let mut stripped = Vec::new();
    for nid in state_nids {
        if let Some(ev) = load_client_event(state, nid, room_id)? {
            let etype = ev.event_type().unwrap_or("");
            if STRIPPED_TYPES.contains(&etype) {
                stripped.push(json!({
                    "type": ev.get("type"),
                    "state_key": ev.get("state_key"),
                    "sender": ev.get("sender"),
                    "content": ev.get("content"),
                }));
            }
        }
    }

    Ok(json!({
        "invite_state": {
            "events": stripped,
        },
    }))
}

/// Build the `rooms.knock.{room_id}` payload with stripped state events.
/// Spec: `rooms.knock.{roomId}.knock_state.events` mirrors `invite_state`.
fn build_knock_sync(state: &AppState, room_nid: u64, room_id: &str) -> Result<Value, ApiError> {
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

    let mut stripped = Vec::new();
    for nid in state_nids {
        if let Some(ev) = load_client_event(state, nid, room_id)? {
            let etype = ev.event_type().unwrap_or("");
            if STRIPPED_TYPES.contains(&etype) {
                stripped.push(json!({
                    "type": ev.get("type"),
                    "state_key": ev.get("state_key"),
                    "sender": ev.get("sender"),
                    "content": ev.get("content"),
                }));
            }
        }
    }

    Ok(json!({
        "knock_state": {"events": stripped},
    }))
}

/// Build the `rooms.leave.{room_id}` payload.
/// Returns state and timeline events visible to the user at the time they left.
fn build_leave_sync(state: &AppState, room_nid: u64, room_id: &str) -> Result<Value, ApiError> {
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

    Ok(json!({
        "state": {"events": state_events},
        "timeline": {"events": [], "limited": false, "prev_batch": ""},
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
