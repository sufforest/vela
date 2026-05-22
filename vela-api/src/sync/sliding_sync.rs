use std::collections::HashMap;
use std::time::Duration;

use crate::middleware::json::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vela_core::error::VelaError;
use vela_core::identifiers::Nid;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::messages::load_client_event;
use crate::router::AppState;
use crate::sync::typing::get_typing_users;

// --- Request types ---

#[allow(dead_code)]
#[derive(Deserialize, Default)]
pub struct SlidingSyncRequest {
    #[serde(default)]
    pub conn_id: Option<String>,
    pub pos: Option<String>,
    #[serde(default)]
    pub txn_id: Option<String>,
    #[serde(default)]
    pub timeout: Option<u64>,
    #[serde(default)]
    pub lists: HashMap<String, SyncListConfig>,
    #[serde(default)]
    pub room_subscriptions: HashMap<String, RoomSubscription>,
    #[serde(default)]
    pub unsubscribe_rooms: Vec<String>,
    #[serde(default)]
    pub extensions: ExtensionsRequest,
}

#[allow(dead_code)]
#[derive(Deserialize, Default)]
pub struct SyncListConfig {
    pub ranges: Option<Vec<[u64; 2]>>,
    pub range: Option<[u64; 2]>,
    #[serde(default)]
    pub sort: Vec<String>,
    #[serde(default)]
    pub required_state: Vec<[String; 2]>,
    pub timeline_limit: Option<u64>,
    #[serde(default)]
    pub filters: Option<SlidingRoomFilter>,
}

#[allow(dead_code)]
#[derive(Deserialize, Default)]
pub struct SlidingRoomFilter {
    pub is_dm: Option<bool>,
    pub is_encrypted: Option<bool>,
    pub is_invite: Option<bool>,
    pub room_types: Option<Vec<String>>,
    pub not_room_types: Option<Vec<String>>,
    pub room_name_like: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct RoomSubscription {
    #[serde(default)]
    pub required_state: Vec<[String; 2]>,
    pub timeline_limit: Option<u64>,
}

#[derive(Deserialize, Default)]
pub struct ExtensionsRequest {
    #[serde(default)]
    pub to_device: Option<ExtEnabled>,
    #[serde(default)]
    pub e2ee: Option<ExtEnabled>,
    #[serde(default)]
    pub account_data: Option<ExtEnabled>,
    #[serde(default)]
    pub typing: Option<ExtEnabled>,
    #[serde(default)]
    pub receipts: Option<ExtEnabled>,
    /// MSC4308 thread subscriptions sliding-sync extension. Keyed
    /// under `io.element.msc4308.thread_subscriptions` in the wire
    /// payload (`serde(rename)` does the translation).
    #[serde(default, rename = "io.element.msc4308.thread_subscriptions")]
    pub thread_subscriptions: Option<ExtEnabled>,
}

#[derive(Deserialize, Default)]
pub struct ExtEnabled {
    #[serde(default)]
    pub enabled: bool,
}

// --- Query params (Element X sends pos in query string) ---

#[derive(Deserialize, Default)]
pub struct SlidingSyncQuery {
    pub pos: Option<String>,
    pub timeout: Option<u64>,
}

/// POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync
pub async fn sliding_sync(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<SlidingSyncQuery>,
    Json(mut body): Json<SlidingSyncRequest>,
) -> Result<Json<Value>, ApiError> {
    // Element X may send pos in query string
    if body.pos.is_none() {
        body.pos = query.pos;
    }
    let timeout_ms = body.timeout.or(query.timeout).unwrap_or(0);

    let since: Option<u64> = body.pos.as_deref().and_then(|s| s.parse().ok());
    let should_longpoll = timeout_ms > 0 && since.is_some();

    // Get user's joined rooms
    let joined_room_nids = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Subscribe BEFORE building data to avoid race condition
    // (message arriving between data-check and subscribe would be missed)
    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(1);
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
    }
    drop(notify_tx);

    // Build response (helper closure to avoid duplication)
    let build_response = |state: &AppState,
                          since: Option<u64>|
     -> Result<(Map<String, Value>, Map<String, Value>), ApiError> {
        // MSC4186 is_dm filter needs the user's `m.direct` set. Load
        // once; the check per room is then a HashSet lookup.
        let dm_room_ids = load_direct_room_ids(state, user.user_nid)?;
        let mut room_infos: Vec<RoomInfo> = Vec::new();
        for &room_nid in &joined_room_nids {
            let room_id = state
                .db
                .resolve_nid(room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .unwrap_or_default();
            let bump_ts = state
                .db
                .get_room_bump(room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .unwrap_or(0);
            let name = get_room_name(state, room_nid)?;
            let is_dm = dm_room_ids.contains(&room_id);
            let is_encrypted = room_is_encrypted(state, room_nid);
            let room_type = room_create_type(state, room_nid);
            room_infos.push(RoomInfo {
                room_nid,
                room_id,
                bump_ts,
                name,
                membership: "join".to_string(),
                is_dm,
                is_encrypted,
                room_type,
            });
        }
        room_infos.sort_by_key(|r| std::cmp::Reverse(r.bump_ts));

        let mut lists_response: Map<String, Value> = Map::new();
        let mut rooms_response: Map<String, Value> = Map::new();

        build_lists(
            state,
            &body.lists,
            &room_infos,
            since,
            &mut lists_response,
            &mut rooms_response,
            user.user_nid,
        )?;

        // Room subscriptions
        for (room_id, sub) in &body.room_subscriptions {
            if rooms_response.contains_key(room_id) {
                continue;
            }
            if let Some(room_nid) = state
                .db
                .get_nid(room_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                let name = get_room_name(state, room_nid)?;
                let bump_ts = state
                    .db
                    .get_room_bump(room_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    .unwrap_or(0);
                let info = RoomInfo {
                    room_nid,
                    room_id: room_id.clone(),
                    bump_ts,
                    name,
                    membership: "join".to_string(),
                    is_dm: dm_room_ids.contains(room_id),
                    is_encrypted: room_is_encrypted(state, room_nid),
                    room_type: room_create_type(state, room_nid),
                };
                let tl = sub.timeline_limit.unwrap_or(10) as usize;
                let room_data = build_sliding_room(
                    state,
                    &info,
                    tl,
                    &sub.required_state,
                    since,
                    user.user_nid,
                )?;
                rooms_response.insert(room_id.clone(), room_data);
            }
        }

        Ok((lists_response, rooms_response))
    };

    let (mut lists_response, mut rooms_response) = build_response(&state, since)?;

    // Extensions
    let mut extensions: Map<String, Value> = Map::new();

    // to_device extension
    if body
        .extensions
        .to_device
        .as_ref()
        .is_some_and(|e| e.enabled)
    {
        let (events, keys) = {
            let msgs = state
                .db
                .get_to_device_messages(user.user_nid, &user.device_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            let events: Vec<Value> = msgs.iter().map(|(_, v)| v.clone()).collect();
            let db_keys: Vec<Vec<u8>> = msgs.into_iter().map(|(k, _)| k).collect();
            (events, db_keys)
        };
        if !keys.is_empty() {
            state
                .db
                .delete_to_device_messages(&keys)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        }
        extensions.insert(
            "to_device".to_string(),
            json!({
                "next_batch": state.db.current_stream_position().to_string(),
                "events": events,
            }),
        );
    }

    // e2ee extension
    if body.extensions.e2ee.as_ref().is_some_and(|e| e.enabled) {
        let otk_counts = state
            .db
            .count_one_time_keys(user.user_nid, &user.device_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

        extensions.insert(
            "e2ee".to_string(),
            json!({
                "device_one_time_keys_count": otk_counts,
                "device_unused_fallback_key_types": [],
            }),
        );
    }

    // account_data extension
    if body
        .extensions
        .account_data
        .as_ref()
        .is_some_and(|e| e.enabled)
    {
        // Global account_data: always returned in full on initial
        // sync. Incremental syncs return the full set too — the spec
        // doesn't have a stream-position story for global data and
        // re-sending it is cheap (typical user has a handful of
        // entries). The CS-API /sync handler does the same.
        let all = state
            .db
            .get_all_account_data(user.user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let global: Vec<Value> = all
            .into_iter()
            .map(|(dtype, content)| json!({"type": dtype, "content": content}))
            .collect();
        // Per-room account_data: enumerate every room visible in this
        // response, dump its per-room account_data entries. Bounded by
        // the response set the lists/subscriptions just built.
        let mut rooms_acct_data: Map<String, Value> = Map::new();
        for (rid, _) in rooms_response.iter() {
            let Some(room_nid) = state
                .db
                .get_nid(rid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            else {
                continue;
            };
            let entries = state
                .db
                .get_all_room_account_data(user.user_nid, room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            if entries.is_empty() {
                continue;
            }
            let events: Vec<Value> = entries
                .into_iter()
                .map(|(dtype, content)| json!({"type": dtype, "content": content}))
                .collect();
            rooms_acct_data.insert(rid.clone(), json!({"events": events}));
        }
        extensions.insert(
            "account_data".to_string(),
            json!({"global": global, "rooms": rooms_acct_data}),
        );
    }

    // typing extension
    if body.extensions.typing.as_ref().is_some_and(|e| e.enabled) {
        let mut typing_rooms: Map<String, Value> = Map::new();
        for (room_id, _) in &rooms_response {
            if let Some(room_nid) = state
                .db
                .get_nid(room_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                let typers = get_typing_users(&state, room_nid);
                if !typers.is_empty() {
                    let mut user_ids = Vec::new();
                    for nid in typers {
                        if let Some(uid) = state
                            .db
                            .resolve_nid(nid)
                            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                        {
                            user_ids.push(uid);
                        }
                    }
                    typing_rooms.insert(
                        room_id.clone(),
                        json!({"type": "m.typing", "content": {"user_ids": user_ids}}),
                    );
                }
            }
        }
        extensions.insert("typing".to_string(), json!({"rooms": typing_rooms}));
    }

    // receipts extension — emit per-room m.receipt events for every
    // room that appeared in the response. Sliding sync clients can't
    // see receipts via the room timeline like /sync does, so this
    // extension is the only way for them to drive read-state UI.
    if body.extensions.receipts.as_ref().is_some_and(|e| e.enabled) {
        let mut receipt_rooms: Map<String, Value> = Map::new();
        for room_id in rooms_response.keys() {
            if let Some(room_nid) = state
                .db
                .get_nid(room_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                && let Some(ev) =
                    crate::sync::build_receipts_event(&state, room_nid, user.user_nid)?
            {
                receipt_rooms.insert(room_id.clone(), ev);
            }
        }
        extensions.insert("receipts".to_string(), json!({"rooms": receipt_rooms}));
    }

    // MSC4308 thread subscriptions extension. On initial sync return
    // every subscription. On incremental sync return only those whose
    // state changed strictly after `since` — clients keep their own
    // local mirror and want a delta.
    if body
        .extensions
        .thread_subscriptions
        .as_ref()
        .is_some_and(|e| e.enabled)
    {
        let subs = state
            .db
            .iter_thread_subscriptions(user.user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let mut subscribed: Map<String, Value> = Map::new();
        for (room_nid, thread_root, sub_state, pos) in subs {
            if sub_state == 0 {
                continue;
            }
            if let Some(s) = since
                && pos <= s
            {
                continue;
            }
            let Some(room_id) = state
                .db
                .resolve_nid(room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            else {
                continue;
            };
            let automatic = sub_state == 2;
            let entry = json!({
                "bump_stamp": pos,
                "automatic": automatic,
            });
            subscribed
                .entry(room_id)
                .or_insert_with(|| Value::Object(Map::new()))
                .as_object_mut()
                .unwrap()
                .insert(thread_root, entry);
        }
        let mut payload: Map<String, Value> = Map::new();
        if !subscribed.is_empty() {
            payload.insert("subscribed".into(), Value::Object(subscribed));
        }
        extensions.insert(
            "io.element.msc4308.thread_subscriptions".to_string(),
            Value::Object(payload),
        );
    }

    // Check if incremental sync has new timeline events
    let has_new_timeline = since.is_some()
        && rooms_response.values().any(|r| {
            r.get("timeline")
                .and_then(|t| t.as_array())
                .is_some_and(|a| !a.is_empty())
        });

    let has_to_device = extensions
        .get("to_device")
        .and_then(|td| td.get("events"))
        .and_then(|e| e.as_array())
        .is_some_and(|a| !a.is_empty());

    // Long-poll: wait if incremental sync has no new data
    if !has_new_timeline && !has_to_device && should_longpoll {
        let timeout = Duration::from_millis(timeout_ms.min(30_000));
        tokio::select! {
            _ = notify_rx.recv() => {},
            _ = tokio::time::sleep(timeout) => {},
        }
        // Abort listener tasks after wakeup
        for h in &task_handles {
            h.abort();
        }

        // Rebuild everything after waking — lists, rooms, AND extensions
        let (new_lists, new_rooms) = build_response(&state, since)?;
        lists_response = new_lists;
        rooms_response = new_rooms;

        // Rebuild to_device (may have arrived during long-poll)
        if body
            .extensions
            .to_device
            .as_ref()
            .is_some_and(|e| e.enabled)
        {
            let msgs = state
                .db
                .get_to_device_messages(user.user_nid, &user.device_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            let events: Vec<Value> = msgs.iter().map(|(_, v)| v.clone()).collect();
            let db_keys: Vec<Vec<u8>> = msgs.into_iter().map(|(k, _)| k).collect();
            if !db_keys.is_empty() {
                state
                    .db
                    .delete_to_device_messages(&db_keys)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            }
            extensions.insert(
                "to_device".to_string(),
                json!({
                    "next_batch": state.db.current_stream_position().to_string(),
                    "events": events,
                }),
            );
        }

        // Rebuild typing
        if body.extensions.typing.as_ref().is_some_and(|e| e.enabled) {
            let mut typing_rooms: Map<String, Value> = Map::new();
            for (room_id, _) in &rooms_response {
                if let Some(room_nid) = state
                    .db
                    .get_nid(room_id)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                {
                    let typers = get_typing_users(&state, room_nid);
                    if !typers.is_empty() {
                        let mut user_ids = Vec::new();
                        for nid in typers {
                            if let Some(uid) = state
                                .db
                                .resolve_nid(nid)
                                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                            {
                                user_ids.push(uid);
                            }
                        }
                        typing_rooms.insert(
                            room_id.clone(),
                            json!({"type": "m.typing", "content": {"user_ids": user_ids}}),
                        );
                    }
                }
            }
            extensions.insert("typing".to_string(), json!({"rooms": typing_rooms}));
        }
    }

    // Abort any remaining listener tasks (early return or non-longpoll path)
    for h in &task_handles {
        h.abort();
    }

    let final_pos = state.db.current_stream_position();

    let mut response = json!({
        "pos": final_pos.to_string(),
        "lists": lists_response,
        "rooms": rooms_response,
        "extensions": extensions,
    });

    if let Some(txn_id) = &body.txn_id {
        response
            .as_object_mut()
            .unwrap()
            .insert("txn_id".to_string(), json!(txn_id));
    }

    Ok(Json(response))
}

// --- Helpers ---

struct RoomInfo {
    room_nid: u64,
    room_id: String,
    bump_ts: u64,
    name: Option<String>,
    membership: String,
    /// MSC4186 filter inputs. Populated once per request; the filter
    /// path is a cheap field check.
    is_dm: bool,
    is_encrypted: bool,
    /// `m.room.create.content.type` (`m.space` for spaces; `None` for
    /// regular rooms).
    room_type: Option<String>,
}

fn build_lists(
    state: &AppState,
    lists: &HashMap<String, SyncListConfig>,
    room_infos: &[RoomInfo],
    since: Option<u64>,
    lists_response: &mut Map<String, Value>,
    rooms_response: &mut Map<String, Value>,
    user_nid: u64,
) -> Result<(), ApiError> {
    for (list_name, list_config) in lists {
        let mut sorted: Vec<&RoomInfo> = apply_filters(room_infos, &list_config.filters);
        sort_rooms(&mut sorted, state, user_nid, &list_config.sort);
        let total_count = sorted.len();

        // MSC4186 lists support multiple ranges per list (e.g. "show
        // rows 0-20 AND 100-120"). Collect every range in the request;
        // emit one SYNC op per range. `range` (singular) is the
        // legacy single-range field; `ranges` is the plural form.
        let ranges: Vec<[u64; 2]> = list_config
            .ranges
            .clone()
            .or_else(|| list_config.range.map(|r| vec![r]))
            .unwrap_or_else(|| vec![[0, 20]]);
        let timeline_limit = list_config.timeline_limit.unwrap_or(10) as usize;

        let mut ops = Vec::new();
        for range in &ranges {
            let start = range[0] as usize;
            let end = (range[1] as usize + 1).min(total_count);
            if start >= total_count {
                continue;
            }
            let mut room_ids_in_range = Vec::new();
            for info in &sorted[start..end] {
                room_ids_in_range.push(Value::String(info.room_id.clone()));

                if !rooms_response.contains_key(&info.room_id) {
                    let room_data = build_sliding_room(
                        state,
                        info,
                        timeline_limit,
                        &list_config.required_state,
                        since,
                        user_nid,
                    )?;
                    rooms_response.insert(info.room_id.clone(), room_data);
                }
            }
            ops.push(json!({
                "op": "SYNC",
                "range": [start, end.saturating_sub(1)],
                "room_ids": room_ids_in_range,
            }));
        }

        lists_response.insert(
            list_name.clone(),
            json!({
                "count": total_count,
                "ops": ops,
            }),
        );
    }
    Ok(())
}

/// Apply the per-list `sort` ordering. Each entry is a tag; the
/// first entry is the primary sort, subsequent entries are tie-
/// breakers. Spec recognises `by_recency` (bump_ts DESC) and
/// `by_name` (name ASC, case-insensitive); empty / unknown entries
/// degrade to `by_recency`. `by_notification_level` is a Synapse-
/// specific extension some clients pass; treat it as a no-op stable
/// sort that callers can layer on top.
fn sort_rooms(rooms: &mut Vec<&RoomInfo>, _state: &AppState, _user_nid: u64, sort: &[String]) {
    if sort.is_empty() {
        rooms.sort_by_key(|r| std::cmp::Reverse(r.bump_ts));
        return;
    }
    // Apply tiebreakers in reverse — Rust's sort is stable, so each
    // later pass preserves the order from earlier passes when the
    // current key compares equal.
    for tag in sort.iter().rev() {
        match tag.as_str() {
            "by_name" => rooms.sort_by(|a, b| {
                let an = a.name.as_deref().unwrap_or("").to_lowercase();
                let bn = b.name.as_deref().unwrap_or("").to_lowercase();
                an.cmp(&bn)
            }),
            // Default: recency. Anything we don't recognise also
            // falls back here so a misconfigured client still gets
            // a sensible ordering.
            _ => rooms.sort_by_key(|r| std::cmp::Reverse(r.bump_ts)),
        }
    }
}

/// Read the user's `m.direct` global account_data and collect every
/// room_id flagged as a DM. Spec shape:
/// `{ "<other_user>": ["!room1", "!room2"], ... }`.
fn load_direct_room_ids(
    state: &AppState,
    user_nid: u64,
) -> Result<std::collections::HashSet<String>, ApiError> {
    let mut out = std::collections::HashSet::new();
    let v = state
        .db
        .get_account_data(user_nid, "m.direct")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let Some(v) = v else { return Ok(out) };
    if let Some(map) = v.as_object() {
        for arr in map.values() {
            if let Some(arr) = arr.as_array() {
                for v in arr {
                    if let Some(s) = v.as_str() {
                        out.insert(s.to_string());
                    }
                }
            }
        }
    }
    Ok(out)
}

/// `true` iff the room currently has an `m.room.encryption` state
/// event. Cheap state-event existence check, doesn't decode the
/// content.
fn room_is_encrypted(state: &AppState, room_nid: u64) -> bool {
    let Ok(Some(tn)) = state.db.get_nid("m.room.encryption") else {
        return false;
    };
    let Ok(Some(sn)) = state.db.get_nid("") else {
        return false;
    };
    state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .ok()
        .flatten()
        .is_some()
}

/// `m.room.create.content.type` — `"m.space"` for spaces, `None` for
/// regular rooms. Filters use this for `room_types`/`not_room_types`.
fn room_create_type(state: &AppState, room_nid: u64) -> Option<String> {
    let tn = state.db.get_nid("m.room.create").ok().flatten()?;
    let sn = state.db.get_nid("").ok().flatten()?;
    let enid = state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .ok()
        .flatten()?;
    let (_h, bytes) = state.db.get_event(enid).ok().flatten()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("content")?
        .get("type")?
        .as_str()
        .map(|s| s.to_string())
}

fn apply_filters<'a>(
    rooms: &'a [RoomInfo],
    filters: &Option<SlidingRoomFilter>,
) -> Vec<&'a RoomInfo> {
    let filters = match filters {
        Some(f) => f,
        None => return rooms.iter().collect(),
    };

    rooms
        .iter()
        .filter(|r| {
            if let Some(name_like) = &filters.room_name_like {
                match &r.name {
                    Some(name) => {
                        if !name.to_lowercase().contains(&name_like.to_lowercase()) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }
            if let Some(want) = filters.is_dm
                && r.is_dm != want
            {
                return false;
            }
            if let Some(want) = filters.is_encrypted
                && r.is_encrypted != want
            {
                return false;
            }
            // is_invite tri-state. `lists` only gather joined rooms
            // today, so every entry has `membership == "join"` —
            // `is_invite=true` always yields empty; `is_invite=false`
            // is implicitly satisfied by the gathering shape. The
            // explicit checks below are forward-compatible for when
            // we extend room_infos to include invite/knock rooms.
            if filters.is_invite == Some(true) && r.membership != "invite" {
                return false;
            }
            if filters.is_invite == Some(false) && r.membership == "invite" {
                return false;
            }
            if let Some(want) = &filters.room_types {
                let actual = r.room_type.as_deref();
                let want_match = want.iter().any(|t| {
                    if t == "null" {
                        actual.is_none()
                    } else {
                        Some(t.as_str()) == actual
                    }
                });
                if !want_match {
                    return false;
                }
            }
            if let Some(not_want) = &filters.not_room_types {
                let actual = r.room_type.as_deref();
                let blocked = not_want.iter().any(|t| {
                    if t == "null" {
                        actual.is_none()
                    } else {
                        Some(t.as_str()) == actual
                    }
                });
                if blocked {
                    return false;
                }
            }
            true
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn build_sliding_room(
    state: &AppState,
    info: &RoomInfo,
    timeline_limit: usize,
    required_state: &[[String; 2]],
    since: Option<u64>,
    user_nid: u64,
) -> Result<Value, ApiError> {
    let room_nid = info.room_nid;
    let room_id = &info.room_id;
    let is_initial = since.is_none();

    // Timeline
    let timeline_entries = if let Some(since_pos) = since {
        state
            .db
            .get_timeline_range(room_nid, since_pos + 1, u64::MAX, timeline_limit)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    } else {
        state
            .db
            .get_timeline_latest(room_nid, timeline_limit)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    };

    let limited = timeline_entries.len() >= timeline_limit;

    let mut timeline = Vec::new();
    let mut prev_batch = None;
    for (i, (pos, enid)) in timeline_entries.iter().enumerate() {
        if i == 0 {
            prev_batch = Some(format!("{pos}"));
        }
        if let Some(ev) = load_client_event(state, *enid, room_id)? {
            timeline.push(ev);
        }
    }

    // Required state
    let mut state_events = Vec::new();
    if is_initial || !required_state.is_empty() {
        for [event_type, state_key] in required_state {
            // Wildcard support
            if event_type == "*" && state_key == "*" {
                let all_nids = state
                    .db
                    .get_all_state_event_nids(room_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                for nid in all_nids {
                    if let Some(ev) = load_client_event(state, nid, room_id)? {
                        state_events.push(ev);
                    }
                }
                break;
            }

            if let (Some(type_nid), Some(skey_nid)) = (
                state
                    .db
                    .get_nid(event_type)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?,
                state
                    .db
                    .get_nid(state_key)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?,
            ) && let Some(enid) = state
                .db
                .get_state_event_nid(room_nid, type_nid, skey_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                && let Some(ev) = load_client_event(state, enid, room_id)?
            {
                state_events.push(ev);
            }
        }
    }

    // Member counts. count_room_members_by_membership uses internal
    // membership encoding: 1 = join, 2 = invite. Falls back to 1/0 so
    // an empty room (shouldn't happen post-create) doesn't produce a
    // confusing zero-joined response.
    let joined_count = state
        .db
        .count_room_members_by_membership(room_nid, 1)
        .unwrap_or(1);
    let invited_count = state
        .db
        .count_room_members_by_membership(room_nid, 2)
        .unwrap_or(0);

    // Unread counts mirror /sync semantics. Sliding sync clients show
    // the same badge on a room tile as /sync clients do, so they need
    // the same per-batch evaluation against the user's read receipts.
    let (notification_count, highlight_count, _thread_counts) =
        crate::sync::compute_unread_counts(state, room_nid, user_nid, &timeline, false)?;

    let mut room = json!({
        "initial": is_initial,
        "limited": limited,
        "required_state": state_events,
        "timeline": timeline,
        "notification_count": notification_count,
        "highlight_count": highlight_count,
        "joined_count": joined_count,
        "invited_count": invited_count,
        "membership": info.membership,
    });

    let obj = room.as_object_mut().unwrap();
    if let Some(name) = &info.name {
        obj.insert("name".to_string(), json!(name));
    }
    if let Some(pb) = prev_batch {
        obj.insert("prev_batch".to_string(), json!(pb));
    }
    // num_live = count of events that happened after the connection was established
    // On initial sync (no since), all events are historical → num_live = 0
    // On incremental sync, all returned events are live
    let num_live = if since.is_some() { timeline.len() } else { 0 };
    if num_live > 0 {
        obj.insert("num_live".to_string(), json!(num_live));
    }
    obj.insert("bump_stamp".to_string(), json!(info.bump_ts));

    Ok(room)
}

fn get_room_name(state: &AppState, room_nid: u64) -> Result<Option<String>, ApiError> {
    let type_nid = state
        .db
        .get_nid("m.room.name")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_nid("")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let (Some(tn), Some(sn)) = (type_nid, skey_nid)
        && let Some(enid) = state
            .db
            .get_state_event_nid(room_nid, tn, sn)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        && let Some((_, json_bytes)) = state
            .db
            .get_event(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        && let Ok(ev) = serde_json::from_slice::<Value>(&json_bytes)
    {
        return Ok(ev
            .get("content")
            .and_then(|c| c.get("name"))
            .and_then(|n| n.as_str())
            .map(|s| s.to_string()));
    }
    Ok(None)
}
