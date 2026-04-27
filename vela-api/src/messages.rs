use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct MessagesQuery {
    pub from: Option<String>,
    pub to: Option<String>,
    pub dir: Option<String>, // "f" or "b"
    pub limit: Option<usize>,
    /// Inline JSON filter; `lazy_load_members: true` here makes
    /// /messages also return the senders' `m.room.member` state events
    /// in a top-level `state` array, so clients can avoid a separate
    /// /state request.
    pub filter: Option<String>,
}

/// Pagination cursor.
///
/// `s{n}` — stream-position based, used for live forward timeline. Backwards
/// scan from `from = s{n}` returns events with `stream_pos < n`.
///
/// `e{event_id}` — DAG-walk based. Returned when backwards scan exhausts the
/// `room_timeline` CF; subsequent backwards request walks `prev_events` from
/// this event. See SPRINT3C7_HISTORICAL_TIMELINE_PLAN.md.
enum Cursor {
    Stream(u64),
    DagFromEvent(String),
}

impl Cursor {
    fn parse(s: &str) -> Option<Self> {
        if let Some(rest) = s.strip_prefix('s') {
            rest.parse::<u64>().ok().map(Cursor::Stream)
        } else if let Some(rest) = s.strip_prefix('e') {
            if rest.is_empty() {
                None
            } else {
                Some(Cursor::DagFromEvent(rest.to_string()))
            }
        } else {
            None
        }
    }
}

/// GET /_matrix/client/v3/rooms/{roomId}/messages
pub async fn get_messages(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Query(query): Query<MessagesQuery>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    // Check membership
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let limit = query.limit.unwrap_or(10).min(100);
    let dir = query.dir.as_deref().unwrap_or("b");

    // Parse the from cursor. Default for backwards = "from end of timeline".
    let cursor = query.from.as_deref().and_then(Cursor::parse);

    // --- Branch 1: DAG-walk mode (backwards continuation past timeline) ---
    if dir == "b"
        && let Some(Cursor::DagFromEvent(eid)) = &cursor
    {
        return paginate_dag(&state, &room_id_str, room_nid, eid, limit).await;
    }

    // --- Branch 2: Forward / backwards via the stream-position timeline ---
    let from: u64 = match (dir, &cursor) {
        ("b", Some(Cursor::Stream(n))) => *n,
        ("b", _) => u64::MAX,
        ("f", Some(Cursor::Stream(n))) => *n,
        ("f", _) => 0,
        _ => u64::MAX,
    };

    let events = if dir == "b" {
        state
            .db
            .get_timeline_before(room_nid, from, limit)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    } else {
        let to = query
            .to
            .as_deref()
            .and_then(|s| s.strip_prefix('s'))
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::MAX);
        state
            .db
            .get_timeline_range(room_nid, from, to, limit)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    };

    let mut chunk = Vec::new();
    let mut start_token = String::new();
    let mut end_token = String::new();

    for (i, (stream_pos, event_nid)) in events.iter().enumerate() {
        if i == 0 {
            start_token = format!("s{stream_pos}");
        }
        end_token = format!("s{stream_pos}");

        if let Some(client_event) =
            load_client_event_with_relations(&state, *event_nid, &room_id_str, Some(user.user_nid))?
        {
            chunk.push(client_event);
        }
    }

    // Backwards transition: switch the `end` token to a DAG cursor pointing
    // at the earliest event we have for this user so the next backwards
    // request continues via `paginate_dag` (which knows how to backfill).
    //
    // Two cases:
    // - Timeline returned some events but less than `limit`: use the earliest.
    // - Timeline empty (e.g. freshly federated-joined room): use the user's
    //   current `m.room.member` event as an entry point. Without this the
    //   client would see `end == start == ""` and have no way to continue.
    if dir == "b" {
        if events.len() < limit && !events.is_empty() {
            if let Some((_, earliest_nid)) = events.last()
                && let Ok(Some(earliest_eid)) = state.db.get_event_id_by_nid(*earliest_nid)
            {
                end_token = format!("e{earliest_eid}");
            }
        } else if events.is_empty()
            && let Some(entry_eid) = user_member_event_id(&state, room_nid, user.user_nid)?
        {
            end_token = format!("e{entry_eid}");
            if start_token.is_empty() {
                start_token = end_token.clone();
            }
        }
    }

    let mut response = json!({
        "chunk": chunk,
        "start": start_token,
        "end": end_token,
    });

    // `lazy_load_members`: if the filter requests it, surface the
    // m.room.member state events for every distinct sender in the
    // chunk so clients can render display names + avatars without a
    // round-trip to /state. Per c2s spec on lazy-loading.
    if filter_lazy_load_members(query.filter.as_deref()) {
        let state_events =
            collect_lazy_loaded_member_events(&state, room_nid, &room_id_str, &chunk)?;
        response
            .as_object_mut()
            .unwrap()
            .insert("state".into(), Value::Array(state_events));
    }

    Ok(Json(response))
}

/// Returns true if the inline JSON filter requests lazy loading of
/// member events. Spec shape: `{"lazy_load_members": true}` either at
/// the top level or under `room.timeline`.
fn filter_lazy_load_members(filter_str: Option<&str>) -> bool {
    let Some(s) = filter_str else { return false };
    let Ok(v) = serde_json::from_str::<Value>(s) else {
        return false;
    };
    let direct = v
        .get("lazy_load_members")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let nested = v
        .pointer("/room/timeline/lazy_load_members")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    direct || nested
}

/// Collect the m.room.member state event for every distinct sender
/// appearing in `chunk`. Used by the /messages lazy-load path.
fn collect_lazy_loaded_member_events(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    chunk: &[Value],
) -> Result<Vec<Value>, ApiError> {
    use std::collections::HashSet;

    let senders: HashSet<&str> = chunk
        .iter()
        .filter_map(|ev| ev.get("sender").and_then(|s| s.as_str()))
        .collect();
    if senders.is_empty() {
        return Ok(Vec::new());
    }

    let type_nid = match state
        .db
        .get_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(Vec::new()),
    };

    let mut out = Vec::with_capacity(senders.len());
    for sender in senders {
        let Some(sender_nid) = state
            .db
            .get_nid(sender)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        let Some(event_nid) = state
            .db
            .get_state_event_nid(room_nid, type_nid, sender_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        if let Some(client_event) = load_client_event(state, event_nid, room_id)? {
            out.push(client_event);
        }
    }
    Ok(out)
}

/// Find the caller's current `m.room.member` event id in this room. Used
/// as a fallback DAG-walk entry point when the user's timeline is empty —
/// typically right after joining a remote room where no local events
/// exist but the room's history is available via federation backfill.
fn user_member_event_id(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
) -> Result<Option<String>, ApiError> {
    let type_nid = match state
        .db
        .get_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let event_nid = match state
        .db
        .get_state_event_nid(room_nid, type_nid, user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    state
        .db
        .get_event_id_by_nid(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))
}

/// Continue backwards pagination via DAG walk.
///
/// `from_event_id` is the last event the client received; this call returns
/// events strictly before it (its prev_events and their ancestors), in
/// depth-descending order.
async fn paginate_dag(
    state: &AppState,
    room_id: &str,
    room_nid: u64,
    from_event_id: &str,
    limit: usize,
) -> Result<Json<Value>, ApiError> {
    let from_nid = match state
        .db
        .get_event_nid_by_id(from_event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => {
            // Cursor points at an event we don't have. Possible if the client
            // shared a token across server resets, or if a prior backfill
            // dropped the event. Return empty rather than 404.
            return Ok(Json(json!({
                "chunk": [],
                "start": format!("e{from_event_id}"),
                "end": format!("e{from_event_id}"),
            })));
        }
    };

    // Walk the DAG backwards. If the walk runs short and there's reason to
    // believe federation has more (room has remote members), opportunistically
    // backfill on the cursor's prev_events.
    let nids = state
        .db
        .walk_dag_backwards(from_nid, limit)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if nids.len() < limit
        && let Ok(Some(prev_eids)) = collect_prev_event_ids(state, from_nid)
        && !prev_eids.is_empty()
    {
        let _ = crate::federation_backfill::attempt_backfill(
            state,
            room_nid,
            room_id,
            &prev_eids,
            crate::federation_backfill::BACKFILL_LIMIT,
        )
        .await;
    }

    // Re-walk to pick up any newly-backfilled events.
    let nids = state
        .db
        .walk_dag_backwards(from_nid, limit)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut chunk = Vec::new();
    let mut last_event_id: Option<String> = None;

    for nid in &nids {
        if let Some(client_event) = load_client_event(state, *nid, room_id)? {
            chunk.push(client_event);
        }
        if let Ok(Some(eid)) = state.db.get_event_id_by_nid(*nid) {
            last_event_id = Some(eid);
        }
    }

    // The start token reflects where this page begins (the cursor we received).
    // The end token reflects the last event of this page, suitable for the
    // next backwards request. Empty chunk → both equal the cursor.
    let start_token = format!("e{from_event_id}");
    let end_token = match last_event_id {
        Some(eid) => format!("e{eid}"),
        None => format!("e{from_event_id}"),
    };

    Ok(Json(json!({
        "chunk": chunk,
        "start": start_token,
        "end": end_token,
    })))
}

/// Look up an event's prev_events and resolve them to event_id strings.
/// Returns Ok(Some(ids)) on success, Ok(None) on missing event_nid, Err on DB error.
fn collect_prev_event_ids(
    state: &AppState,
    event_nid: u64,
) -> Result<Option<Vec<String>>, rocksdb::Error> {
    let prevs = state.db.get_prev_events(event_nid)?;
    if prevs.is_empty() {
        return Ok(None);
    }
    let mut out = Vec::with_capacity(prevs.len());
    for p in prevs {
        if let Some(eid) = state.db.get_event_id_by_nid(p)? {
            out.push(eid);
        }
    }
    Ok(Some(out))
}

/// Load an event from storage and format it for client consumption.
/// Adds event_id, room_id, and unsigned.age. If the event has been
/// redacted (per the `event_redactions` table), applies the v11 redact
/// algorithm and injects `unsigned.redacted_because`.
pub fn load_client_event(
    state: &AppState,
    event_nid: u64,
    room_id: &str,
) -> Result<Option<Value>, ApiError> {
    let (header, json_bytes) = match state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(v) => v,
        None => return Ok(None),
    };

    let mut event: serde_json::Map<String, Value> = serde_json::from_slice(&json_bytes)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let event_id = state
        .db
        .get_event_id_by_nid(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_default();

    // Check for a redaction marker. Do this before age/unsigned work because
    // redaction overwrites `content` and drops `unsigned`.
    let redactor_nid = state
        .db
        .get_redacted_by(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let Some(rnid) = redactor_nid {
        event = vela_core::events::redact::redact_event(&event);
        let redactor = load_redactor_client_event(state, rnid, room_id)?;
        let mut unsigned = serde_json::Map::new();
        if let Some(r) = redactor {
            unsigned.insert("redacted_because".to_string(), r);
        }
        event.insert("unsigned".to_string(), Value::Object(unsigned));
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let age = now.saturating_sub(header.origin_server_ts);
        event.insert("unsigned".to_string(), json!({"age": age}));
    }

    event.insert("event_id".to_string(), json!(event_id));
    if !event.contains_key("room_id") {
        event.insert("room_id".to_string(), json!(room_id));
    }

    event.remove("hashes");
    event.remove("signatures");
    event.remove("prev_events");
    event.remove("auth_events");
    event.remove("depth");

    Ok(Some(Value::Object(event)))
}

/// Render an event for client consumption, then attach
/// `unsigned.m.relations.m.thread` aggregation if it is a thread root.
/// Pass `Some(user_nid)` to populate `current_user_participated`; pass
/// `None` (sync timeline doesn't always carry caller context) to omit it.
pub fn load_client_event_with_relations(
    state: &AppState,
    event_nid: u64,
    room_id: &str,
    user_nid: Option<u64>,
) -> Result<Option<Value>, ApiError> {
    let mut ev = match load_client_event(state, event_nid, room_id)? {
        Some(v) => v,
        None => return Ok(None),
    };
    if let Some(agg) = compute_thread_aggregation(state, event_nid, room_id, user_nid)? {
        let unsigned = ev
            .as_object_mut()
            .unwrap()
            .entry("unsigned".to_string())
            .or_insert_with(|| json!({}));
        let relations = unsigned
            .as_object_mut()
            .unwrap()
            .entry("m.relations".to_string())
            .or_insert_with(|| json!({}));
        relations
            .as_object_mut()
            .unwrap()
            .insert("m.thread".to_string(), agg);
    }
    Ok(Some(ev))
}

/// Build the `m.thread` aggregation object per spec §Threading. Returns
/// `None` when the event has no thread children (the common case).
fn compute_thread_aggregation(
    state: &AppState,
    event_nid: u64,
    room_id: &str,
    user_nid: Option<u64>,
) -> Result<Option<Value>, ApiError> {
    let thread_nid = match state
        .db
        .get_nid("m.thread")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    // Pull a generous window — we only need a count and the latest entry, so
    // the window can be large enough to make the count meaningful for typical
    // threads. Heavy threads are paginated separately via /relations.
    let entries = state
        .db
        .list_relations(event_nid, Some(thread_nid), None, u64::MAX, true, 1000)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if entries.is_empty() {
        return Ok(None);
    }

    let count = entries.len() as u64;
    let (_latest_sp, latest_nid, _, _) = entries[0];
    let latest = load_client_event(state, latest_nid, room_id)?;

    let participated = match user_nid {
        Some(uid) => {
            // Cheap check: was the root sender uid? If so, true.
            let root_sender_is_user = state
                .db
                .get_event(event_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .map(|(h, _)| h.sender_nid == uid)
                .unwrap_or(false);
            root_sender_is_user
                || entries.iter().any(|(_, child_nid, _, _)| {
                    state
                        .db
                        .get_event(*child_nid)
                        .ok()
                        .flatten()
                        .map(|(h, _)| h.sender_nid == uid)
                        .unwrap_or(false)
                })
        }
        None => false,
    };

    let mut agg = serde_json::Map::new();
    if let Some(l) = latest {
        agg.insert("latest_event".to_string(), l);
    }
    agg.insert("count".to_string(), json!(count));
    if user_nid.is_some() {
        agg.insert("current_user_participated".to_string(), json!(participated));
    }
    Ok(Some(Value::Object(agg)))
}

/// Render the redactor event for inclusion in `unsigned.redacted_because`.
/// Deliberately avoids recursion into `load_client_event` — a redaction
/// event is never itself presented-as-redacted via this field (the spec
/// does not require it, and cycling would complicate the contract).
fn load_redactor_client_event(
    state: &AppState,
    event_nid: u64,
    room_id: &str,
) -> Result<Option<Value>, ApiError> {
    let (header, json_bytes) = match state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(v) => v,
        None => return Ok(None),
    };
    let mut event: serde_json::Map<String, Value> = serde_json::from_slice(&json_bytes)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let event_id = state
        .db
        .get_event_id_by_nid(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_default();
    event.insert("event_id".to_string(), json!(event_id));
    if !event.contains_key("room_id") {
        event.insert("room_id".to_string(), json!(room_id));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let age = now.saturating_sub(header.origin_server_ts);
    event.insert("unsigned".to_string(), json!({"age": age}));
    event.remove("hashes");
    event.remove("signatures");
    event.remove("prev_events");
    event.remove("auth_events");
    event.remove("depth");
    Ok(Some(Value::Object(event)))
}

/// GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}
pub async fn get_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, event_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership.is_none() || membership == Some(0) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let event_nid = state
        .db
        .get_event_nid_by_id(&event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;

    let event =
        load_client_event_with_relations(&state, event_nid, &room_id_str, Some(user.user_nid))?
            .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;

    Ok(Json(event))
}
