//! `POST /_matrix/client/v3/search` — event search across joined rooms.
//!
//! Spec: `client-server-api/#post_matrixclientv3search`.
//!
//! MVP implementation: linear substring scan (case-insensitive) over recent
//! timeline events in each of the caller's joined rooms. No index — we're
//! bounded by a scan-window per room. Good enough that Element's search
//! dialog actually returns results; replacing with tantivy is a follow-up.

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::messages::load_client_event;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Per-room events we scan before giving up. Small enough to keep latency
/// sane on a naive impl; large enough that recent chat history is covered.
const SCAN_PER_ROOM: usize = 500;
/// Max results we return.
const MAX_HITS: usize = 50;

pub async fn post_search(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let search_term = body
        .pointer("/search_categories/room_events/search_term")
        .and_then(|v| v.as_str())
        .map(|s| s.to_lowercase());

    let Some(term) = search_term else {
        // No search term → empty results (spec-compliant shape).
        return Ok(Json(empty_response()));
    };
    if term.is_empty() {
        return Ok(Json(empty_response()));
    }

    let joined = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut hits: Vec<Value> = Vec::new();
    let mut highlights: std::collections::HashSet<String> = std::collections::HashSet::new();
    let term_tokens: Vec<&str> = term.split_whitespace().collect();

    'rooms: for room_nid in joined {
        let room_id = match state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(r) => r,
            None => continue,
        };
        // E2EE rooms: the server holds only ciphertext, so substring
        // search would never match anything useful — skip them rather
        // than burn cycles iterating their encrypted timeline. Search
        // for E2EE rooms is the client's responsibility.
        if is_room_encrypted(&state, room_nid) {
            continue;
        }
        let entries = state
            .db
            .get_timeline_latest(room_nid, SCAN_PER_ROOM)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        for (_pos, enid) in entries.iter().rev() {
            let Some(ev) = load_client_event(&state, *enid, &room_id)? else {
                continue;
            };
            let body = ev
                .pointer("/content/body")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if body.to_lowercase().contains(&term) {
                for t in &term_tokens {
                    highlights.insert(t.to_string());
                }
                hits.push(json!({
                    "rank": 1.0,
                    "result": ev,
                }));
                if hits.len() >= MAX_HITS {
                    break 'rooms;
                }
            }
        }
    }

    let count = hits.len();
    Ok(Json(json!({
        "search_categories": {
            "room_events": {
                "count": count,
                "results": hits,
                "highlights": highlights.into_iter().collect::<Vec<_>>(),
            }
        }
    })))
}

/// True iff the room currently has an `m.room.encryption` state event.
/// Used by `/search` to skip rooms whose timeline is ciphertext.
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
