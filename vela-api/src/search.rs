//! `POST /_matrix/client/v3/search` — event search across joined rooms.
//!
//! Spec: `client-server-api/#post_matrixclientv3search`.
//!
//! MVP: linear case-insensitive substring scan over the timelines of
//! each of the caller's joined rooms. No inverted index — `SCAN_PER_ROOM`
//! bounds the per-room work. Supports `filter.rooms`, `filter.limit`,
//! `order_by` (`rank` or `recent`), `event_context` (before/after),
//! `next_batch` pagination, redaction filtering, and predecessor-chain
//! search.
//!
//! E2EE rooms are skipped: we hold only ciphertext for them, so the
//! server can't usefully match against the encrypted body. Clients are
//! expected to do their own local index for E2EE rooms.

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashSet;

use vela_core::error::VelaError;

use crate::messages::load_client_event;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Per-room events we scan before giving up. Large enough that recent
/// chat history is covered; small enough that we don't burn cycles on
/// pathological rooms.
const SCAN_PER_ROOM: usize = 1000;
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

    let search_term = room_events
        .get("search_term")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase());
    let Some(term) = search_term else {
        return Ok(Json(empty_response()));
    };
    if term.is_empty() {
        return Ok(Json(empty_response()));
    }

    let order_by = room_events
        .get("order_by")
        .and_then(|v| v.as_str())
        .unwrap_or("rank")
        .to_string();
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

    // Determine which rooms to scan. If `filter.rooms` is set, use those
    // (after checking the caller is joined). Otherwise scan every joined
    // room. Expand the set with each room's predecessor chain so an
    // upgrade history is searchable from the new room id.
    let joined: Vec<u64> = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let joined_ids: HashSet<String> = joined
        .iter()
        .filter_map(|nid| state.db.resolve_nid(*nid).ok().flatten())
        .collect();

    let mut rooms_to_scan: Vec<(u64, String)> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let seed_rooms: Vec<String> = match filter_rooms {
        Some(ids) => ids
            .into_iter()
            .filter(|rid| joined_ids.contains(rid))
            .collect(),
        None => joined
            .iter()
            .filter_map(|nid| state.db.resolve_nid(*nid).ok().flatten())
            .collect(),
    };
    for room_id in seed_rooms {
        let _ = collect_room_and_predecessors(&state, &room_id, &mut rooms_to_scan, &mut visited);
    }

    // Collect every match across all rooms (we need the full count
    // anyway for the response and for pagination). For each hit
    // remember its stream_pos in its room so we can stitch
    // before/after context.
    struct Hit {
        room_nid: u64,
        room_id: String,
        event: Value,
        stream_pos: u64,
        origin_server_ts: u64,
    }
    let mut all_hits: Vec<Hit> = Vec::new();
    for (room_nid, room_id) in rooms_to_scan {
        if is_room_encrypted(&state, room_nid) {
            continue;
        }
        let entries = state
            .db
            .get_timeline_latest(room_nid, SCAN_PER_ROOM)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let redacted = redacted_event_ids(&state, &entries);
        for (pos, enid) in entries.iter().rev() {
            let Some(ev) = load_client_event(&state, *enid, &room_id)? else {
                continue;
            };
            let event_id = ev
                .get("event_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if redacted.contains(&event_id) {
                continue;
            }
            let body = ev
                .pointer("/content/body")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let body_lc = body.to_lowercase();
            // Token AND match: every whitespace-separated token in the
            // search term must appear as a substring of the body.
            // Synapse uses Postgres FTS (tsvector) which is closer to
            // word-boundary matching; substring is a simpler MVP that
            // still handles `"Message 4"` against `"Message number 4"`
            // (token "4" is present even though "Message 4" verbatim
            // isn't a substring).
            let all_present = term
                .split_whitespace()
                .all(|t| !t.is_empty() && body_lc.contains(t));
            if !all_present {
                continue;
            }
            let ts = ev
                .get("origin_server_ts")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            all_hits.push(Hit {
                room_nid,
                room_id: room_id.clone(),
                event: ev,
                stream_pos: *pos,
                origin_server_ts: ts,
            });
        }
    }

    // Order: spec defines `rank` (relevance-weighted; we have no
    // relevance signal, so fall back to recent) and `recent`. Both
    // sort newest first.
    all_hits.sort_by(|a, b| {
        b.origin_server_ts
            .cmp(&a.origin_server_ts)
            .then(b.stream_pos.cmp(&a.stream_pos))
    });
    let _ = order_by; // future: actually weight by token frequency for "rank".

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

    let mut term_tokens: HashSet<String> = HashSet::new();
    for t in term.split_whitespace() {
        term_tokens.insert(t.to_string());
    }

    let mut results: Vec<Value> = Vec::with_capacity(page.len());
    for hit in page {
        let mut entry = json!({
            "rank": 1.0,
            "result": hit.event.clone(),
        });
        if context.is_some() {
            let ctx = build_event_context(
                &state,
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
    room_events_resp.insert(
        "highlights".to_string(),
        json!(term_tokens.into_iter().collect::<Vec<_>>()),
    );
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
fn build_event_context(
    state: &AppState,
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
        // newest-first per spec.
        for (_pos, enid) in entries.iter().rev() {
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
        for (_pos, enid) in entries.iter() {
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

/// Collect the set of event_ids that have been redacted in the given
/// timeline window. We look at `m.room.redaction` events and capture
/// their `redacts` field (or `content.redacts` for newer rooms).
fn redacted_event_ids(state: &AppState, entries: &[(u64, u64)]) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    let Ok(Some(redaction_type_nid)) = state.db.get_nid("m.room.redaction") else {
        return out;
    };
    for (_pos, enid) in entries {
        let Ok(Some((header, bytes))) = state.db.get_event(*enid) else {
            continue;
        };
        if header.type_nid != redaction_type_nid {
            continue;
        }
        let Ok(json) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Some(target) = json
            .pointer("/content/redacts")
            .and_then(|v| v.as_str())
            .or_else(|| json.get("redacts").and_then(|v| v.as_str()))
        {
            out.insert(target.to_string());
        }
    }
    out
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
