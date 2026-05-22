use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::middleware::json::Json;
use axum::extract::{Query, State};
use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vela_core::error::VelaError;
use vela_core::identifiers::Nid;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::messages::load_client_event;
use crate::router::AppState;
use crate::sync::typing::get_typing_users;

// --- Per-connection snapshot cache (DELTA op support) ---

/// One client's view of a sliding-sync list, as we last sent it.
/// Held inside `SlidingSyncCache`. Next request diffs against this
/// to emit DELETE/INSERT ops instead of always re-sending the full
/// window with SYNC.
#[derive(Default)]
pub struct ListSnapshot {
    /// Room ids in their previous response order. Index = position
    /// the client knows them at.
    pub room_ids: Vec<String>,
    /// Fingerprint of the request shape (filters + sort + ranges)
    /// that produced this snapshot. A mismatch on the next request
    /// means the client changed the query — emit a fresh SYNC.
    pub shape_fingerprint: u64,
}

/// Per-(user, conn_id) cache of all lists' snapshots.
///
/// `subscribed_rooms` is the MSC4186 sticky subscription set —
/// rooms the client said it wanted via `room_subscriptions` on a
/// prior request stay subscribed until explicitly named in
/// `unsubscribe_rooms`. Without a `conn_id`, subscriptions reset
/// per request (matches earlier behaviour).
#[derive(Default)]
pub struct ConnSnapshot {
    pub lists: HashMap<String, ListSnapshot>,
    pub subscribed_rooms: HashMap<String, StickySubscription>,
    pub last_used: Option<Instant>,
}

/// What we remember about a sticky subscription. We can't store the
/// original `RoomSubscription` because it isn't `Clone`; store its
/// fields directly.
#[derive(Clone)]
pub struct StickySubscription {
    pub required_state: Vec<[String; 2]>,
    pub timeline_limit: usize,
}

/// Shared cache held on AppState. Cheap to clone (Arcs); eviction
/// is lazy on read via `last_used`.
#[derive(Default)]
pub struct SlidingSyncCache {
    inner: DashMap<(u64, String), Arc<std::sync::Mutex<ConnSnapshot>>>,
}

/// Snapshots idle longer than this are evicted on next access. 30
/// minutes covers a phone going to sleep then waking; longer would
/// pile up state for disconnected clients.
const SNAPSHOT_TTL: Duration = Duration::from_secs(30 * 60);

impl SlidingSyncCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the snapshot for `(user, conn_id)`, evicting it if
    /// stale. Always returns a clonable handle the caller mutates in
    /// place. Uses a sync Mutex because the snapshot is only touched
    /// from synchronous code (diff + write); no `await` is held
    /// across the guard.
    pub fn get_or_init(&self, user_nid: u64, conn_id: &str) -> Arc<std::sync::Mutex<ConnSnapshot>> {
        let key = (user_nid, conn_id.to_string());
        // Atomic get-or-insert via DashMap's entry API. Two threads
        // racing on the same key both see the same Arc.
        let arc = self
            .inner
            .entry(key.clone())
            .or_insert_with(|| {
                Arc::new(std::sync::Mutex::new(ConnSnapshot {
                    last_used: Some(Instant::now()),
                    ..Default::default()
                }))
            })
            .clone();
        // Stale check + refresh. Hold the snapshot's own lock so an
        // in-flight long-poll keeps refreshing it; only evict if
        // genuinely past TTL.
        let stale = {
            let mut snap = arc.lock().unwrap();
            let past_ttl = snap
                .last_used
                .map(|t| t.elapsed() > SNAPSHOT_TTL)
                .unwrap_or(false);
            if !past_ttl {
                snap.last_used = Some(Instant::now());
            }
            past_ttl
        };
        if stale {
            // Evict only if the map still holds the same Arc — a
            // concurrent insert could have replaced it.
            self.inner
                .remove_if(&key, |_, existing| Arc::ptr_eq(existing, &arc));
            return self.get_or_init(user_nid, conn_id);
        }
        arc
    }
}

/// Stable hash over the request shape (filters + sort + ranges) so
/// the next request can detect whether the client changed the query.
/// A mismatch invalidates DELTA diffing and forces SYNC.
fn list_shape_fingerprint(cfg: &SyncListConfig) -> u64 {
    // serde_json::to_string is stable for our config (HashMap fields
    // only contain non-key-ordered Vecs/Options). Hash the JSON.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let blob = json!({
        "ranges": cfg.ranges,
        "range": cfg.range,
        "sort": cfg.sort,
        "required_state": cfg.required_state,
        "timeline_limit": cfg.timeline_limit,
        "filters": cfg.filters.as_ref().map(|f| json!({
            "is_dm": f.is_dm,
            "is_encrypted": f.is_encrypted,
            "is_invite": f.is_invite,
            "room_types": f.room_types,
            "not_room_types": f.not_room_types,
            "room_name_like": f.room_name_like,
        })),
    });
    blob.to_string().hash(&mut h);
    h.finish()
}

/// MSC4186 DELTA op computation. Given the previous response's
/// ordered room_ids for a list-range and the new ordered room_ids,
/// emit the minimal DELETE/INSERT sequence that transforms one into
/// the other.
///
/// Algorithm — two passes:
/// 1. DELETE rooms that disappeared (high→low, so positions stay
///    valid as we apply).
/// 2. Walk the new list. For each target position, if the working
///    state's room matches, advance; otherwise emit DELETE+INSERT
///    for the moved/new room.
///
/// This is correct but not always minimal — a pure reorder produces
/// up to N DELETE/INSERT pairs. For the common case of "one room
/// jumped to the top" it emits exactly one DELETE + one INSERT.
fn compute_list_ops(prev: &[String], new: &[String], range_start: usize) -> Vec<Value> {
    if prev == new {
        return Vec::new();
    }
    let new_set: std::collections::HashSet<&str> = new.iter().map(|s| s.as_str()).collect();
    let mut working: Vec<String> = prev.to_vec();
    let mut ops: Vec<Value> = Vec::new();

    // Pass 1: delete rooms not in `new`, high→low.
    let to_delete: Vec<usize> = working
        .iter()
        .enumerate()
        .filter_map(|(i, r)| (!new_set.contains(r.as_str())).then_some(i))
        .collect();
    for &i in to_delete.iter().rev() {
        ops.push(json!({"op": "DELETE", "index": range_start + i}));
        working.remove(i);
    }

    // Pass 2: walk new[], emit ops to align working with new.
    for (j, target) in new.iter().enumerate() {
        match working.get(j) {
            Some(here) if here == target => continue,
            _ => {
                if let Some(pos) = working.iter().position(|r| r == target) {
                    ops.push(json!({"op": "DELETE", "index": range_start + pos}));
                    working.remove(pos);
                }
                ops.push(json!({
                    "op": "INSERT",
                    "index": range_start + j,
                    "room_id": target,
                }));
                working.insert(j, target.clone());
            }
        }
    }
    ops
}

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

    // Per-connection snapshot for DELTA op emission. Only enabled
    // when the client supplies a `conn_id`. Two clients of the same
    // user with different conn_ids each get their own snapshot.
    let snapshot_arc = body
        .conn_id
        .as_ref()
        .map(|cid| state.sliding_sync_cache.get_or_init(user.user_nid, cid));

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

        let mut snapshot_guard = snapshot_arc.as_ref().map(|a| a.lock().unwrap());
        build_lists(
            state,
            &body.lists,
            &room_infos,
            since,
            &mut lists_response,
            &mut rooms_response,
            user.user_nid,
            snapshot_guard.as_deref_mut(),
        )?;

        // Compute effective subscription set. MSC4186: subscriptions
        // are sticky across requests with the same conn_id. Without
        // a conn_id (snapshot_guard is None), behave per-request.
        // If a room appears in BOTH unsubscribe_rooms and
        // room_subscriptions, unsubscribe wins everywhere — both in
        // the sticky set and in this response.
        let effective_subs: HashMap<String, StickySubscription> =
            match snapshot_guard.as_deref_mut() {
                Some(snap) => {
                    for (rid, sub) in &body.room_subscriptions {
                        snap.subscribed_rooms.insert(
                            rid.clone(),
                            StickySubscription {
                                required_state: sub.required_state.clone(),
                                timeline_limit: sub.timeline_limit.unwrap_or(10) as usize,
                            },
                        );
                    }
                    for rid in &body.unsubscribe_rooms {
                        snap.subscribed_rooms.remove(rid);
                    }
                    snap.subscribed_rooms.clone()
                }
                None => body
                    .room_subscriptions
                    .iter()
                    .filter(|(rid, _)| !body.unsubscribe_rooms.contains(rid))
                    .map(|(rid, sub)| {
                        (
                            rid.clone(),
                            StickySubscription {
                                required_state: sub.required_state.clone(),
                                timeline_limit: sub.timeline_limit.unwrap_or(10) as usize,
                            },
                        )
                    })
                    .collect(),
            };
        drop(snapshot_guard);

        // Emit room data for every effective subscription not
        // already present via list windows.
        for (room_id, sub) in &effective_subs {
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
                let room_data = build_sliding_room(
                    state,
                    &info,
                    sub.timeline_limit,
                    &sub.required_state,
                    since,
                    user.user_nid,
                )?;
                rooms_response.insert(room_id.clone(), room_data);
            }
        }
        // Honour unsubscribe_rooms: drop them from this response
        // even if they appeared via a list. Spec says the client
        // doesn't want the data.
        for rid in &body.unsubscribe_rooms {
            rooms_response.remove(rid);
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

#[allow(clippy::too_many_arguments)]
fn build_lists(
    state: &AppState,
    lists: &HashMap<String, SyncListConfig>,
    room_infos: &[RoomInfo],
    since: Option<u64>,
    lists_response: &mut Map<String, Value>,
    rooms_response: &mut Map<String, Value>,
    user_nid: u64,
    snapshot: Option<&mut ConnSnapshot>,
) -> Result<(), ApiError> {
    let mut snapshot_writes: Vec<(String, ListSnapshot)> = Vec::new();
    // Lists that became multi-range this request — clear their
    // prior snapshot so the NEXT single-range request emits a
    // fresh SYNC rather than diffing against state the client no
    // longer holds.
    let mut snapshot_clears: Vec<String> = Vec::new();
    // Clone the prev snapshot data eagerly so we can mutate the
    // snapshot freely after the loop. The fingerprint + room_ids
    // are the only fields we read, and they're cheap to clone.
    let prev_lists: HashMap<String, ListSnapshot> = match snapshot.as_ref() {
        Some(s) => s
            .lists
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    ListSnapshot {
                        room_ids: v.room_ids.clone(),
                        shape_fingerprint: v.shape_fingerprint,
                    },
                )
            })
            .collect(),
        None => HashMap::new(),
    };
    for (list_name, list_config) in lists {
        let mut sorted: Vec<&RoomInfo> = apply_filters(room_infos, &list_config.filters);
        sort_rooms(&mut sorted, state, user_nid, &list_config.sort);
        let total_count = sorted.len();

        // MSC4186 lists support multiple ranges per list (e.g. "show
        // rows 0-20 AND 100-120"). DELTA ops are only emitted for
        // the single-range case — multi-range diffing across
        // discontiguous windows requires per-range snapshots and
        // isn't worth the complexity for the rare client that asks.
        let ranges: Vec<[u64; 2]> = list_config
            .ranges
            .clone()
            .or_else(|| list_config.range.map(|r| vec![r]))
            .unwrap_or_else(|| vec![[0, 20]]);
        let timeline_limit = list_config.timeline_limit.unwrap_or(10) as usize;

        let fingerprint = list_shape_fingerprint(list_config);
        let single_range = ranges.len() == 1;

        let mut ops = Vec::new();
        // Track new room_ids in the (single) range so we can update
        // the snapshot at the end. For multi-range we still build
        // ops, but skip snapshot update — next request will be a
        // fresh SYNC.
        let mut new_room_ids_for_snapshot: Vec<String> = Vec::new();
        for range in &ranges {
            let start = range[0] as usize;
            let end = (range[1] as usize + 1).min(total_count);
            if start >= total_count {
                continue;
            }
            let mut room_ids_in_range: Vec<String> = Vec::new();
            for info in &sorted[start..end] {
                room_ids_in_range.push(info.room_id.clone());

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

            // DELTA path: only when single-range and shape matches.
            let delta_ops = if single_range {
                prev_lists
                    .get(list_name)
                    .filter(|prev| prev.shape_fingerprint == fingerprint)
                    .map(|prev| compute_list_ops(&prev.room_ids, &room_ids_in_range, start))
            } else {
                None
            };
            if let Some(d) = delta_ops {
                ops.extend(d);
            } else {
                ops.push(json!({
                    "op": "SYNC",
                    "range": [start, end.saturating_sub(1)],
                    "room_ids": room_ids_in_range
                        .iter()
                        .map(|s| Value::String(s.clone()))
                        .collect::<Vec<_>>(),
                }));
            }
            if single_range {
                new_room_ids_for_snapshot = room_ids_in_range;
            }
        }
        if single_range {
            snapshot_writes.push((
                list_name.clone(),
                ListSnapshot {
                    room_ids: new_room_ids_for_snapshot,
                    shape_fingerprint: fingerprint,
                },
            ));
        } else {
            snapshot_clears.push(list_name.clone());
        }

        lists_response.insert(
            list_name.clone(),
            json!({
                "count": total_count,
                "ops": ops,
            }),
        );
    }
    if let Some(snap) = snapshot {
        for name in snapshot_clears {
            snap.lists.remove(&name);
        }
        for (name, list_snap) in snapshot_writes {
            snap.lists.insert(name, list_snap);
        }
        snap.last_used = Some(Instant::now());
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(slice: &[&str]) -> Vec<String> {
        slice.iter().map(|s| s.to_string()).collect()
    }

    /// Replay a sequence of DELETE/INSERT ops on a working list to
    /// verify the ops actually transform `prev` into `new` — a real
    /// client would do the same on its side.
    fn apply_ops(prev: &[String], ops: &[Value]) -> Vec<String> {
        let mut working = prev.to_vec();
        for op in ops {
            let kind = op.get("op").and_then(|v| v.as_str()).unwrap();
            let index = op.get("index").and_then(|v| v.as_u64()).unwrap() as usize;
            match kind {
                "DELETE" => {
                    working.remove(index);
                }
                "INSERT" => {
                    let rid = op.get("room_id").and_then(|v| v.as_str()).unwrap();
                    working.insert(index, rid.to_string());
                }
                other => panic!("unexpected op {other}"),
            }
        }
        working
    }

    #[test]
    fn diff_identical_emits_no_ops() {
        let a = ids(&["!r1:e", "!r2:e", "!r3:e"]);
        assert!(compute_list_ops(&a, &a, 0).is_empty());
    }

    #[test]
    fn diff_append() {
        let prev = ids(&["!a", "!b"]);
        let new = ids(&["!a", "!b", "!c"]);
        let ops = compute_list_ops(&prev, &new, 0);
        assert_eq!(apply_ops(&prev, &ops), new);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn diff_remove_middle() {
        let prev = ids(&["!a", "!b", "!c"]);
        let new = ids(&["!a", "!c"]);
        let ops = compute_list_ops(&prev, &new, 0);
        assert_eq!(apply_ops(&prev, &ops), new);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn diff_room_jumps_to_top() {
        // Most common real case: bump_ts moves !c to position 0.
        let prev = ids(&["!a", "!b", "!c", "!d"]);
        let new = ids(&["!c", "!a", "!b", "!d"]);
        let ops = compute_list_ops(&prev, &new, 0);
        assert_eq!(apply_ops(&prev, &ops), new);
        // 1 DELETE + 1 INSERT.
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn diff_full_reverse_is_correct_if_verbose() {
        let prev = ids(&["!a", "!b", "!c", "!d"]);
        let new = ids(&["!d", "!c", "!b", "!a"]);
        let ops = compute_list_ops(&prev, &new, 0);
        assert_eq!(apply_ops(&prev, &ops), new);
    }

    #[test]
    fn diff_honours_range_start_offset() {
        let prev = ids(&["!a", "!b"]);
        let new = ids(&["!b", "!a"]);
        let ops = compute_list_ops(&prev, &new, 50);
        // Apply against the prev list AT POSITION 50, simulated as a
        // 50-empty prefix.
        let mut padded = vec!["pad".to_string(); 50];
        padded.extend(prev.iter().cloned());
        let result = apply_ops(&padded, &ops);
        assert_eq!(&result[50..], new.as_slice());
    }

    #[test]
    fn diff_empty_to_full_is_all_inserts() {
        let prev: Vec<String> = vec![];
        let new = ids(&["!a", "!b", "!c"]);
        let ops = compute_list_ops(&prev, &new, 0);
        assert!(ops.iter().all(|o| o["op"] == "INSERT"));
        assert_eq!(apply_ops(&prev, &ops), new);
    }

    #[test]
    fn diff_full_to_empty_is_all_deletes() {
        let prev = ids(&["!a", "!b", "!c"]);
        let new: Vec<String> = vec![];
        let ops = compute_list_ops(&prev, &new, 0);
        assert!(ops.iter().all(|o| o["op"] == "DELETE"));
        assert_eq!(apply_ops(&prev, &ops), new);
    }

    fn cfg(ranges: Option<Vec<[u64; 2]>>, sort: Vec<String>) -> SyncListConfig {
        SyncListConfig {
            ranges,
            range: None,
            sort,
            required_state: Vec::new(),
            timeline_limit: None,
            filters: None,
        }
    }

    #[test]
    fn fingerprint_stable_for_same_config() {
        let a = cfg(Some(vec![[0, 20]]), vec!["by_recency".to_string()]);
        let b = cfg(Some(vec![[0, 20]]), vec!["by_recency".to_string()]);
        assert_eq!(list_shape_fingerprint(&a), list_shape_fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_when_range_changes() {
        let a = cfg(Some(vec![[0, 20]]), vec!["by_recency".to_string()]);
        let b = cfg(Some(vec![[0, 50]]), vec!["by_recency".to_string()]);
        assert_ne!(list_shape_fingerprint(&a), list_shape_fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_when_sort_changes() {
        let a = cfg(Some(vec![[0, 20]]), vec!["by_recency".to_string()]);
        let b = cfg(Some(vec![[0, 20]]), vec!["by_name".to_string()]);
        assert_ne!(list_shape_fingerprint(&a), list_shape_fingerprint(&b));
    }

    #[test]
    fn cache_returns_same_handle_within_ttl() {
        let cache = SlidingSyncCache::new();
        let a = cache.get_or_init(42, "conn-A");
        // Touch last_used so it's non-stale.
        a.lock().unwrap().last_used = Some(Instant::now());
        let b = cache.get_or_init(42, "conn-A");
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn cache_isolates_by_conn_id() {
        let cache = SlidingSyncCache::new();
        let a = cache.get_or_init(42, "conn-A");
        let b = cache.get_or_init(42, "conn-B");
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn cache_concurrent_get_or_init_returns_same_arc() {
        // Regression: previous version raced — two threads could
        // create two different Arcs for the same key.
        let cache = Arc::new(SlidingSyncCache::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = cache.clone();
            handles.push(std::thread::spawn(move || c.get_or_init(99, "shared")));
        }
        let arcs: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for a in &arcs[1..] {
            assert!(Arc::ptr_eq(&arcs[0], a));
        }
    }
}
