//! `POST /_matrix/client/v3/search` — event search across the caller's rooms.
//!
//! Spec: `client-server-api/#post_matrixclientv3search`.
//!
//! Index-backed: matches against the `search_index` inverted index (see
//! `vela_store::search`), which is jieba-tokenized so Chinese/CJK text is
//! searched word-by-word. The query is tokenized the same way, then postings
//! are AND-intersected per room. Searches every room the caller has been in —
//! joined and left (a left room is capped to events visible before leaving).
//! Supports `keys`, `filter.rooms`, `filter.senders`, `filter.limit`,
//! `order_by` (`rank` by term frequency, or `recent`), `event_context`
//! (before/after), `groupings.group_by` (room_id / sender), `include_state`,
//! `next_batch` pagination, and predecessor-chain search. Redacted events are
//! filtered, and every hit and its context is checked against per-event
//! history-visibility.
//!
//! E2EE rooms are skipped: we hold only ciphertext for them, so the server
//! can't usefully match. Clients index E2EE rooms locally.

use crate::middleware::json::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

use vela_core::error::VelaError;
use vela_store::search::{FIELD_BODY, FIELD_NAME, FIELD_TOPIC};

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::messages::{TimelineReadGate, load_client_event};
use crate::router::AppState;

/// Per-token, per-room postings we consider. Bounds memory and pagination
/// depth: for a very common token in a huge room we look at the newest
/// `CANDIDATE_CAP` occurrences. Rare tokens (the usual case) are unaffected.
///
/// Caveat for a *left* room that stayed very active: the newest
/// `CANDIDATE_CAP` postings can all be post-leave, so the leave-cap drops
/// them and pre-leave matches beyond the window are missed — left-room search
/// of a busy room may under-return. Fine for quiet/small left rooms (the
/// common case) and still ahead of Synapse, which doesn't search left rooms
/// at all. A leave-cap-relative scan bound is a possible follow-up.
const CANDIDATE_CAP: usize = 1000;
/// Default `filter.limit` when the caller doesn't supply one.
const DEFAULT_LIMIT: usize = 10;
/// Hard ceiling so a malicious `limit` can't make us serialize 10⁶ events.
const MAX_LIMIT: usize = 100;

#[derive(Debug, Deserialize, Default)]
pub struct SearchQuery {
    #[serde(default)]
    pub next_batch: Option<String>,
}

pub async fn post_search(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<SearchQuery>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let room_events = body
        .pointer("/search_categories/room_events")
        .cloned()
        .unwrap_or_else(|| json!({}));

    // Tokenize the query exactly as the index did (jieba, CJK-aware). An
    // empty tokenization (blank / punctuation-only term) yields no results.
    let raw_term = room_events
        .get("search_term")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let q_tokens = vela_store::search::query_tokens(raw_term);
    if q_tokens.is_empty() {
        return Ok(Json(empty_response()));
    }

    let order_by = room_events
        .get("order_by")
        .and_then(|v| v.as_str())
        .unwrap_or("rank")
        .to_string();
    // Which of the searchable keys to match (spec `keys`; defaults to all).
    let keys_mask = parse_keys_mask(&room_events);
    let filter = room_events.get("filter").cloned().unwrap_or(json!({}));
    let limit: usize = filter
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, MAX_LIMIT);
    let filter_rooms: Option<Vec<String>> =
        filter.get("rooms").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    let filter_senders: Option<HashSet<String>> =
        filter.get("senders").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
    let context = room_events.get("event_context").cloned();
    let context_before = context
        .as_ref()
        .and_then(|c| c.get("before_limit"))
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(0);
    let context_after = context
        .as_ref()
        .and_then(|c| c.get("after_limit"))
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(0);

    // Determine which rooms to scan. The spec searches every room the user
    // has been in — joined AND left (the per-event gate caps a left room to
    // what the user could see before leaving). If `filter.rooms` is set, use
    // those (restricted to rooms the caller has access to). Expand with each
    // room's predecessor chain so an upgrade history is searchable from the
    // new room id.
    let joined: Vec<u64> = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let left: Vec<u64> = state
        .db
        .get_user_left_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let accessible_ids: HashSet<String> = joined
        .iter()
        .chain(left.iter())
        .filter_map(|nid| state.db.resolve_nid(*nid).ok().flatten())
        .collect();

    let mut rooms_to_scan: Vec<(u64, String)> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let seed_rooms: Vec<String> = match filter_rooms {
        Some(ids) => ids
            .into_iter()
            .filter(|rid| accessible_ids.contains(rid))
            .collect(),
        None => accessible_ids.iter().cloned().collect(),
    };
    for room_id in seed_rooms {
        let _ = collect_room_and_predecessors(&state, &room_id, &mut rooms_to_scan, &mut visited);
    }

    // Collect every visible match across all rooms (we need the full count
    // for the response and pagination). Per room, pull each query token's
    // postings from the index and AND-intersect by event: an event matches
    // iff every token appears in it (in an allowed key). `rank` is the summed
    // term frequency.
    struct Hit {
        room_nid: u64,
        room_id: String,
        event: Value,
        stream_pos: u64,
        origin_server_ts: u64,
        rank: u32,
    }
    struct Cand {
        stream_pos: u64,
        tf: u32,
        matched: usize,
    }
    let mut all_hits: Vec<Hit> = Vec::new();
    for (room_nid, room_id) in rooms_to_scan {
        if is_room_encrypted(&state, room_nid) {
            continue;
        }
        // Per-event visibility gate for this caller (leave-cap + history
        // visibility). Reflects membership; never 403s here.
        let gate = TimelineReadGate::resolve_reader(&state, room_nid, user.user_nid)?;

        // A searchable event carries exactly one field, so a token appears at
        // most once per event → one posting per (token, event). `matched`
        // therefore counts distinct query tokens present.
        let mut cand: HashMap<u64, Cand> = HashMap::new();
        for tok in &q_tokens {
            for p in state.db.search_room_token(room_nid, tok, CANDIDATE_CAP) {
                if (keys_mask & (1u8 << p.field)) == 0 {
                    continue;
                }
                let c = cand.entry(p.event_nid).or_insert(Cand {
                    stream_pos: p.stream_pos,
                    tf: 0,
                    matched: 0,
                });
                c.tf += u32::from(p.tf);
                c.matched += 1;
            }
        }

        for (enid, c) in cand {
            if c.matched != q_tokens.len() {
                continue; // AND: every query token must be present
            }
            // Redacted events must never surface.
            if matches!(state.db.get_redacted_by(enid), Ok(Some(_))) {
                continue;
            }
            // History-visibility + leave-cap for this specific event.
            if !gate.permits(&state, room_nid, user.user_nid, enid, Some(c.stream_pos))? {
                continue;
            }
            let Some(ev) = load_client_event(&state, enid, &room_id)? else {
                continue;
            };
            if let Some(senders) = &filter_senders {
                let sender = ev.get("sender").and_then(|v| v.as_str()).unwrap_or("");
                if !senders.contains(sender) {
                    continue;
                }
            }
            let ts = ev
                .get("origin_server_ts")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            all_hits.push(Hit {
                room_nid,
                room_id: room_id.clone(),
                event: ev,
                stream_pos: c.stream_pos,
                origin_server_ts: ts,
                rank: c.tf,
            });
        }
    }

    // Order: `recent` = newest first; `rank` (default) = most term matches
    // first, ties broken by recency.
    if order_by == "recent" {
        all_hits.sort_by(|a, b| {
            b.origin_server_ts
                .cmp(&a.origin_server_ts)
                .then(b.stream_pos.cmp(&a.stream_pos))
        });
    } else {
        all_hits.sort_by(|a, b| b.rank.cmp(&a.rank).then(b.stream_pos.cmp(&a.stream_pos)));
    }

    let count = all_hits.len();

    // Paginate: `next_batch` is "skip N hits, return the next page".
    let offset: usize = query
        .next_batch
        .as_deref()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let page_start = offset.min(count);
    let page_end = (page_start + limit).min(count);
    let page = &all_hits[page_start..page_end];

    let mut results: Vec<Value> = Vec::with_capacity(page.len());
    for hit in page {
        let mut entry = json!({
            "rank": f64::from(hit.rank),
            "result": hit.event.clone(),
        });
        if context.is_some() {
            // The flanking context events must pass the SAME per-event
            // visibility gate as the hit — otherwise a `joined`-visibility
            // room leaks pre-join events (or a departed member leaks
            // post-leave events) as "context". Re-resolve the gate for this
            // hit's room (page is bounded by `limit`).
            let gate = TimelineReadGate::resolve_reader(&state, hit.room_nid, user.user_nid)?;
            let ctx = build_event_context(
                &state,
                &gate,
                user.user_nid,
                hit.room_nid,
                &hit.room_id,
                hit.stream_pos,
                context_before,
                context_after,
            )?;
            entry
                .as_object_mut()
                .unwrap()
                .insert("context".to_string(), ctx);
        }
        results.push(entry);
    }

    let mut room_events_resp = serde_json::Map::new();
    room_events_resp.insert("count".to_string(), json!(count));
    room_events_resp.insert("results".to_string(), Value::Array(results));
    // Highlights: the query tokens clients should emphasize — the actual
    // (jieba-segmented) tokens we matched on, so CJK words highlight too.
    room_events_resp.insert("highlights".to_string(), json!(q_tokens));

    // Groupings (`groupings.group_by`): partition the returned results by
    // room_id and/or sender. Each group lists its result event ids and an
    // `order` clients can sort groups by (we use the best member rank).
    let group_by = parse_group_by(&room_events);
    if group_by.room_id || group_by.sender {
        let mut groups = serde_json::Map::new();
        if group_by.room_id {
            let members: Vec<(String, String, u32)> = page
                .iter()
                .map(|h| (h.room_id.clone(), event_id_of(&h.event), h.rank))
                .collect();
            groups.insert("room_id".to_string(), build_group(&members));
        }
        if group_by.sender {
            let members: Vec<(String, String, u32)> = page
                .iter()
                .map(|h| (sender_of(&h.event), event_id_of(&h.event), h.rank))
                .collect();
            groups.insert("sender".to_string(), build_group(&members));
        }
        room_events_resp.insert("groups".to_string(), Value::Object(groups));
    }

    // `include_state`: the current state of every room appearing in results.
    if room_events
        .get("include_state")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        let mut state_map = serde_json::Map::new();
        let mut seen: HashSet<u64> = HashSet::new();
        for hit in page {
            if !seen.insert(hit.room_nid) {
                continue;
            }
            // Only expose *current* state for rooms the caller is still
            // joined to. A departed member must not learn how the room's
            // state (members, topic, …) changed after they left — that's why
            // this is gated even though the hit itself is a left-room event
            // the leave-cap allowed.
            if state
                .db
                .get_membership(hit.room_nid, user.user_nid)
                .ok()
                .flatten()
                != Some(1)
            {
                continue;
            }
            let events = current_room_state_events(&state, hit.room_nid, &hit.room_id)?;
            state_map.insert(hit.room_id.clone(), Value::Array(events));
        }
        room_events_resp.insert("state".to_string(), Value::Object(state_map));
    }

    // Spec-loose semantic: include `next_batch` whenever we returned
    // any results, so the client paginates one more call to confirm
    // "no more". Drop it on the first empty page — matches the
    // Synapse-derived behaviour the Complement back-paginate test
    // expects: keep going while results come back, stop when an
    // empty page arrives without a next_batch.
    if !page.is_empty() {
        room_events_resp.insert("next_batch".to_string(), json!(page_end.to_string()));
    }

    Ok(Json(json!({
        "search_categories": {
            "room_events": Value::Object(room_events_resp),
        }
    })))
}

/// Walk the predecessor chain from `room_id` so a search over an
/// upgraded room transparently includes its history. Idempotent
/// against `visited` so we never iterate the same room twice (which
/// also breaks any accidental upgrade cycle).
fn collect_room_and_predecessors(
    state: &AppState,
    room_id: &str,
    out: &mut Vec<(u64, String)>,
    visited: &mut HashSet<String>,
) -> Result<(), ApiError> {
    let mut cursor: Option<String> = Some(room_id.to_string());
    while let Some(rid) = cursor.take() {
        if !visited.insert(rid.clone()) {
            return Ok(());
        }
        let Some(room_nid) = state
            .db
            .get_nid(&rid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            return Ok(());
        };
        out.push((room_nid, rid.clone()));
        // Walk into the predecessor if any.
        let type_nid = state
            .db
            .get_nid("m.room.create")
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let skey_nid = state
            .db
            .get_nid("")
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let (Some(tn), Some(sn)) = (type_nid, skey_nid) else {
            return Ok(());
        };
        let Some(create_nid) = state
            .db
            .get_state_event_nid(room_nid, tn, sn)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            return Ok(());
        };
        let Some((_, bytes)) = state
            .db
            .get_event(create_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            return Ok(());
        };
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else {
            return Ok(());
        };
        cursor = json
            .pointer("/content/predecessor/room_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
    }
    Ok(())
}

/// Build the spec's `context` block for a hit: timeline events
/// immediately before and after the match (no further filtering). The
/// page is small (test caps at 2 each side) so a linear walk is fine.
#[allow(clippy::too_many_arguments)]
fn build_event_context(
    state: &AppState,
    gate: &TimelineReadGate,
    user_nid: u64,
    room_nid: u64,
    room_id: &str,
    pivot_pos: u64,
    before: usize,
    after: usize,
) -> Result<Value, ApiError> {
    let mut before_events: Vec<Value> = Vec::with_capacity(before);
    let mut after_events: Vec<Value> = Vec::with_capacity(after);
    if before > 0 {
        let entries = state
            .db
            .get_timeline_before(room_nid, pivot_pos, before)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        // get_timeline_before returns chronological order; we want
        // newest-first per spec. Each event is visibility-gated so context
        // can't leak events the caller may not see.
        for (pos, enid) in entries.iter().rev() {
            if !gate.permits(state, room_nid, user_nid, *enid, Some(*pos))? {
                continue;
            }
            if let Some(ev) = load_client_event(state, *enid, room_id)? {
                before_events.push(ev);
            }
        }
    }
    if after > 0 {
        let entries = state
            .db
            .get_timeline_range(room_nid, pivot_pos + 1, u64::MAX, after)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        for (pos, enid) in entries.iter() {
            if !gate.permits(state, room_nid, user_nid, *enid, Some(*pos))? {
                continue;
            }
            if let Some(ev) = load_client_event(state, *enid, room_id)? {
                after_events.push(ev);
            }
        }
    }
    Ok(json!({
        "events_before": before_events,
        "events_after": after_events,
        "start": pivot_pos.to_string(),
        "end": pivot_pos.to_string(),
    }))
}

/// Parse the spec `keys` array into a field bitmask (one bit per `FIELD_*`).
/// An absent, empty, or all-unrecognized `keys` means "all keys" — the spec
/// default. A hit is kept only if it matched in one of these keys.
fn parse_keys_mask(room_events: &Value) -> u8 {
    let all = (1u8 << FIELD_BODY) | (1u8 << FIELD_NAME) | (1u8 << FIELD_TOPIC);
    let Some(arr) = room_events.get("keys").and_then(|v| v.as_array()) else {
        return all;
    };
    let mut mask = 0u8;
    for k in arr {
        match k.as_str() {
            Some("content.body") => mask |= 1u8 << FIELD_BODY,
            Some("content.name") => mask |= 1u8 << FIELD_NAME,
            Some("content.topic") => mask |= 1u8 << FIELD_TOPIC,
            _ => {}
        }
    }
    if mask == 0 { all } else { mask }
}

/// Which groupings the client asked for (`groupings.group_by`).
struct GroupBy {
    room_id: bool,
    sender: bool,
}

fn parse_group_by(room_events: &Value) -> GroupBy {
    let mut g = GroupBy {
        room_id: false,
        sender: false,
    };
    if let Some(arr) = room_events
        .pointer("/groupings/group_by")
        .and_then(|v| v.as_array())
    {
        for item in arr {
            match item.get("key").and_then(|v| v.as_str()) {
                Some("room_id") => g.room_id = true,
                Some("sender") => g.sender = true,
                _ => {}
            }
        }
    }
    g
}

/// Build the spec group object `{<group_value>: {results: [event_id], order}}`
/// from `(group_value, event_id, rank)` members. `order` is the best (max)
/// rank in the group, so more-relevant groups sort higher. No per-group
/// `next_batch` — we don't paginate within a group (spec allows omitting it).
fn build_group(members: &[(String, String, u32)]) -> Value {
    let mut groups: HashMap<String, (Vec<String>, u32)> = HashMap::new();
    for (gval, eid, rank) in members {
        if gval.is_empty() {
            continue;
        }
        let e = groups.entry(gval.clone()).or_insert((Vec::new(), 0));
        e.0.push(eid.clone());
        e.1 = e.1.max(*rank);
    }
    let obj: serde_json::Map<String, Value> = groups
        .into_iter()
        .map(|(gid, (results, order))| (gid, json!({ "results": results, "order": order })))
        .collect();
    Value::Object(obj)
}

fn event_id_of(ev: &Value) -> String {
    ev.get("event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn sender_of(ev: &Value) -> String {
    ev.get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

/// The current state of a room as client events — for `include_state`.
fn current_room_state_events(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
) -> Result<Vec<Value>, ApiError> {
    let nids = state
        .db
        .get_all_state_event_nids(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut out = Vec::with_capacity(nids.len());
    for enid in nids {
        if let Some(ev) = load_client_event(state, enid, room_id)? {
            out.push(ev);
        }
    }
    Ok(out)
}

/// True iff the room currently has an `m.room.encryption` state event.
fn is_room_encrypted(state: &AppState, room_nid: u64) -> bool {
    let Ok(Some(type_nid)) = state.db.get_nid("m.room.encryption") else {
        return false;
    };
    let Ok(Some(skey_nid)) = state.db.get_nid("") else {
        return false;
    };
    matches!(
        state.db.get_state_event_nid(room_nid, type_nid, skey_nid),
        Ok(Some(_))
    )
}

fn empty_response() -> Value {
    json!({
        "search_categories": {
            "room_events": {
                "count": 0,
                "results": [],
                "highlights": [],
            }
        }
    })
}
