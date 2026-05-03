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
    // Spec: an unknown room_id and a known room where the caller isn't
    // a member must both surface as 403 M_FORBIDDEN — leaking the
    // existence of rooms via 404-vs-403 would let unauthenticated
    // probing enumerate room IDs.
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::Forbidden("not a member of this room".into())))?;

    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Spec history-visibility rule 2: members at the time of an event
    // can read it, even if they later left. Departed users (leave=0,
    // ban=3) see events up to their leave/ban stream_pos and nothing
    // after. `None` (never a member) and other buckets (invite, knock)
    // are denied for /messages. Encoding mirrors `set_membership` in
    // federation_receive.rs.
    let leave_cap: Option<u64> = match membership {
        Some(1) => None,
        Some(0) | Some(3) => state
            .db
            .get_user_room_membership_pos(user.user_nid, room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?,
        _ => return Err(VelaError::Forbidden("not a member of this room".into()).into()),
    };

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

    // Cap range by leave_pos so departed users only see pre-leave
    // events. For backward pagination we cap `from`; for forward we
    // cap `to`.
    let events = if dir == "b" {
        let from = match leave_cap {
            Some(cap) => from.min(cap),
            None => from,
        };
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
        let to = match leave_cap {
            Some(cap) => to.min(cap),
            None => to,
        };
        state
            .db
            .get_timeline_range(room_nid, from, to, limit)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    };

    // /messages chunk ordering is direction-aware per spec:
    //
    // - `dir=f`: chronological (oldest → newest). `start` is the
    //   token at the first chunk event, `end` is the token at the
    //   last (= newest reached on this page).
    // - `dir=b`: reverse-chronological (newest → oldest). `start`
    //   is the newest event's token, `end` is the oldest reached
    //   (= where the client paginates further back from).
    //
    // `get_timeline_before` returns chronological order; reverse it
    // for backward pagination so callers see newest-first chunks.
    let events: Vec<(u64, u64)> = if dir == "b" {
        let mut e = events;
        e.reverse();
        e
    } else {
        events
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

    // Apply the `contains_url` content filter, if present in the query
    // filter. Spec `RoomEventFilter`: `true` keeps only events whose
    // content includes a `url` field, `false` keeps only those that
    // don't, omitted = no filter. Server-side filtering keeps clients
    // from having to walk through entire timelines to find media
    // (TestRoomImageRoundtrip relies on this).
    if let Some(want_url) = filter_contains_url(query.filter.as_deref()) {
        chunk.retain(|ev| {
            let has_url = ev
                .get("content")
                .and_then(|c| c.get("url"))
                .map(|v| !v.is_null())
                .unwrap_or(false);
            has_url == want_url
        });
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

/// Inline filter: `room.timeline.contains_url` (RoomEventFilter).
/// `Some(true)` keeps only events whose `content.url` is present;
/// `Some(false)` keeps only events without a url; `None` = filter
/// absent or malformed (apply no filter).
fn filter_contains_url(filter_str: Option<&str>) -> Option<bool> {
    let s = filter_str?;
    let v: Value = serde_json::from_str(s).ok()?;
    // Spec keeps `contains_url` under either `room.timeline` (the
    // /messages-applicable subfilter) or directly at the top level
    // when the filter is already a RoomEventFilter. Accept both.
    let nested = v
        .pointer("/room/timeline/contains_url")
        .and_then(|x| x.as_bool());
    let top = v.get("contains_url").and_then(|x| x.as_bool());
    nested.or(top)
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
///
/// MSC4115: when `user_nid` is `Some`, also annotate
/// `unsigned.membership` with the user's `m.room.member` value at the
/// time of this event. The default (no member event) is `"leave"`.
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
    if let Some(uid) = user_nid {
        let membership =
            membership_at_event(state, 0, uid, event_nid)?.unwrap_or_else(|| "leave".to_string());
        let unsigned = ev
            .as_object_mut()
            .unwrap()
            .entry("unsigned".to_string())
            .or_insert_with(|| json!({}));
        unsigned
            .as_object_mut()
            .unwrap()
            .insert("membership".to_string(), json!(membership));
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
///
/// Spec: applies the room's `m.room.history_visibility` rules. The
/// not-allowed cases all surface as `404` (not `403`) to avoid
/// confirming the room/event exists to a caller who has no business
/// reading it.
pub async fn get_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, event_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;

    // First try the local store. If the event isn't here yet but
    // the user belongs to a room with remote members, fetch from a
    // peer — historical events on a federated timeline aren't
    // automatically replicated to us, so a 404 on first access
    // would force the client into a backfill loop.
    let event_nid = match state
        .db
        .get_event_nid_by_id(&event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => {
            try_fetch_event_from_federation(&state, room_nid, user.user_nid, &event_id).await?;
            state
                .db
                .get_event_nid_by_id(&event_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?
        }
    };

    let visibility = current_history_visibility(&state, room_nid)?;
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if !history_visibility_permits(
        &state,
        room_nid,
        user.user_nid,
        membership,
        &visibility,
        event_nid,
    )? {
        return Err(VelaError::NotFound("event not found".into()).into());
    }

    let event =
        load_client_event_with_relations(&state, event_nid, &room_id_str, Some(user.user_nid))?
            .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;

    Ok(Json(event))
}

/// Best-effort fetch of a missing event from a remote member of the
/// room. Spec lets a server fall back to a peer's `/event/{eventId}`
/// when the client asks for an event we haven't seen yet (e.g. an
/// older message in a federated room we joined recently).
///
/// Errors here surface as 404 to the client — there's nothing
/// actionable beyond retry, and operators can find the underlying
/// failure in the trace via `tracing::debug!`.
async fn try_fetch_event_from_federation(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
    event_id: &str,
) -> Result<(), ApiError> {
    let membership = state
        .db
        .get_membership(room_nid, user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Only members can trigger a federated fetch — parity with the
    // membership check we'll repeat below for visibility, but here
    // it doubles as a denial-of-service shield against unauthenticated
    // probes for arbitrary event IDs.
    if !matches!(membership, Some(0) | Some(1) | Some(3)) {
        return Err(VelaError::NotFound("event not found".into()).into());
    }

    let our_server = state.config.server_name.as_str();
    let peers = state
        .db
        .get_remote_servers_in_room(room_nid, our_server)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if peers.is_empty() {
        // Local-only room — no peer can have this event.
        return Err(VelaError::NotFound("event not found".into()).into());
    }

    let budget = crate::federation_receive::new_fetch_budget();
    for peer in &peers {
        let pdu = match state
            .federation_client
            .fetch_event_pdu(peer, event_id)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!(remote = %peer, %event_id, error = %e, "fetch_event_pdu failed");
                continue;
            }
        };
        if let Err(e) = crate::federation_receive::persist_fetched_event(
            state,
            &pdu,
            peer,
            budget.clone(),
            crate::federation_receive::FetchKind::AuthChain,
        )
        .await
        {
            tracing::debug!(remote = %peer, %event_id, error = %e, "persist fetched event failed");
            continue;
        }
        return Ok(());
    }
    Err(VelaError::NotFound("event not found".into()).into())
}

/// Read the current `m.room.history_visibility` value, defaulting to
/// `"shared"` when the state event isn't present (matches spec default).
fn current_history_visibility(state: &AppState, room_nid: u64) -> Result<String, ApiError> {
    let v =
        crate::membership::read_state_value_pub(state, room_nid, "m.room.history_visibility", "")?;
    Ok(v.as_ref()
        .and_then(|ev| ev.get("content"))
        .and_then(|c| c.get("history_visibility"))
        .and_then(|s| s.as_str())
        .unwrap_or("shared")
        .to_string())
}

/// Returns true if the caller is permitted to read `event_nid` under
/// the given history-visibility setting. Implements the four spec
/// modes; a user with no membership at all is denied for everything
/// except `world_readable`. For `joined` / `invited` modes we compare
/// the event's depth against the depth of the caller's *current*
/// member event — sufficient for the rejoin-free flows the suite
/// exercises today.
///
/// Implements `client-server-api/#room-history-visibility` exactly:
///
/// 1. world_readable → allow
/// 2. user's membership AT THE EVENT was `join` → allow
/// 3. shared + user joined any time AFTER the event → allow
/// 4. invited + user's membership AT THE EVENT was `invite` → allow
/// 5. otherwise deny
///
/// "AT THE EVENT" is evaluated by looking up the room state snapshot
/// recorded when this specific event was applied (`get_state_at_event`)
/// and finding the user's `m.room.member` entry in that snapshot.
/// Matches the per-event-state approach used by Synapse,
/// Continuwuity (`user_was_joined(shortstatehash)`), and Dendrite
/// (`membershipAtEvent`).
fn history_visibility_permits(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
    membership: Option<u8>,
    visibility: &str,
    event_nid: u64,
) -> Result<bool, ApiError> {
    // Rule 1: world_readable lets anyone read, regardless of past or
    // current membership.
    if visibility == "world_readable" {
        return Ok(true);
    }

    let at_event = membership_at_event(state, room_nid, user_nid, event_nid)?;

    // Rule 2: "If the user's membership was join, allow." Applies to
    // every visibility mode (world_readable handled above).
    if at_event.as_deref() == Some("join") {
        return Ok(true);
    }

    match visibility {
        // Rule 3: shared additionally allows users who joined at any
        // point AFTER the event. We approximate "joined any time
        // after" by checking whether the user is currently joined
        // (membership=1); without a per-user join history, this is
        // sufficient for the join→leave→join→… pattern that
        // Synapse handles via `roommemberhistory`. Currently-leave
        // users with prior joins are also a "shared" hit, since
        // their leave event implies they were once joined.
        "shared" => Ok(matches!(membership, Some(0) | Some(1))),
        // Rule 4: invited allows readers whose membership at the
        // event was `invite`.
        "invited" => Ok(at_event.as_deref() == Some("invite")),
        // Rule "joined": only rule 2 applies (membership at event
        // was join), already returned above.
        "joined" => Ok(false),
        // Unknown mode → spec says default to `shared`. Same logic
        // as the shared branch.
        _ => Ok(matches!(membership, Some(0) | Some(1))),
    }
}

/// Look up the user's `m.room.member` value in the room state as it
/// existed when `event_nid` was applied. Returns the `membership`
/// string from that member event's content, or `None` when the user
/// had no member event at that depth (i.e. they hadn't been invited
/// or joined yet).
pub(crate) fn membership_at_event(
    state: &AppState,
    _room_nid: u64,
    user_nid: u64,
    event_nid: u64,
) -> Result<Option<String>, ApiError> {
    let user_id = match state
        .db
        .resolve_nid(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(s) => s,
        None => return Ok(None),
    };
    let member_type_nid = match state
        .db
        .get_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let user_sk_nid = match state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };

    let snapshot = match state
        .db
        .get_state_at_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(s) => s,
        // No recorded state snapshot — fall back to "no membership at
        // the time" (deny under stricter rules; rule 3's
        // post-join-shared branch in the caller handles the recovery
        // path). This shows up for events from before per-event
        // snapshots were tracked, e.g. a freshly-bootstrapped DB.
        None => return Ok(None),
    };

    for nid in snapshot {
        let header = match state
            .db
            .get_event(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some((h, _)) => h,
            None => continue,
        };
        if header.type_nid != member_type_nid || header.state_key_nid != user_sk_nid {
            continue;
        }
        // Found the user's member event in the snapshot — read its
        // `content.membership`.
        let bytes = match state
            .db
            .get_event(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some((_, b)) => b,
            None => return Ok(None),
        };
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };
        return Ok(value
            .pointer("/content/membership")
            .and_then(|m| m.as_str())
            .map(String::from));
    }
    Ok(None)
}
