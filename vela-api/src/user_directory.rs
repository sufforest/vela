//! `POST /_matrix/client/v3/user_directory/search`.
//!
//! Spec: `client-server-api/#user-directory`.
//!
//! Two search strategies:
//! - **Privacy default** (`search_all_users=false`): resolve the caller's
//!   room-mates, then point-lookup each peer by nid. Cost is `O(peers)`
//!   — a few dozen point reads per query regardless of how many accounts
//!   the server has. This is the common path.
//! - **Open directory** (`search_all_users=true`): full CF scan. Cost is
//!   `O(total_users)`. Operators who opt in accept this.
//!
//! Deactivated users are omitted. The caller themself is always in the
//! peer set so self-search works.

use std::collections::HashSet;

use axum::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Hard cap so a pathological request can't walk the entire user table
/// back to the client. Spec says servers may choose; 50 is the
/// commonly-used cap.
const DEFAULT_LIMIT: usize = 10;
const MAX_LIMIT: usize = 50;

#[derive(Debug, Deserialize)]
pub struct SearchBody {
    pub search_term: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// POST /_matrix/client/v3/user_directory/search
pub async fn search(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<SearchBody>,
) -> Result<Json<Value>, ApiError> {
    let term = body.search_term.trim().to_lowercase();
    let limit = body.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

    if term.is_empty() {
        return Ok(Json(json!({"results": [], "limited": false})));
    }

    let mut matches: Vec<Value> = Vec::new();
    let mut truncated = false;

    if state.config.search_all_users {
        // Open-directory path: linear scan over the whole user table.
        let all = state
            .db
            .scan_all_users()
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        for (_nid, record) in all {
            if try_push(&record, &term, limit, &mut matches) {
                truncated = true;
                break;
            }
        }
    } else {
        // Privacy-default path: iterate peers and point-lookup each. Cost
        // scales with the caller's social graph, not total server users.
        let peers = resolve_shared_room_peers(&state, user.user_nid)?;
        for peer_nid in peers {
            let Some(record) = state
                .db
                .get_user(peer_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            else {
                continue;
            };
            if try_push(&record, &term, limit, &mut matches) {
                truncated = true;
                break;
            }
        }
    }

    Ok(Json(json!({
        "results": matches,
        "limited": truncated,
    })))
}

/// Inspect a user record; if it's active and matches `term`, append it
/// to `matches`. Returns `true` if the limit would be exceeded (caller
/// should break and mark `limited=true`).
fn try_push(record: &Value, term_lc: &str, limit: usize, matches: &mut Vec<Value>) -> bool {
    let user_id = record.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    if user_id.is_empty() {
        return false;
    }
    if record
        .get("deactivated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return false;
    }
    let displayname = record
        .get("displayname")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let avatar_url = record
        .get("avatar_url")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if !matches_substring(user_id, displayname, term_lc) {
        return false;
    }
    if matches.len() >= limit {
        return true;
    }
    let mut entry = serde_json::Map::new();
    entry.insert("user_id".into(), json!(user_id));
    if !displayname.is_empty() {
        entry.insert("display_name".into(), json!(displayname));
    }
    if !avatar_url.is_empty() {
        entry.insert("avatar_url".into(), json!(avatar_url));
    }
    matches.push(Value::Object(entry));
    false
}

/// Case-insensitive substring hit on either user id or display name.
fn matches_substring(user_id: &str, displayname: &str, term_lc: &str) -> bool {
    user_id.to_lowercase().contains(term_lc) || displayname.to_lowercase().contains(term_lc)
}

/// Collect every user_nid that co-occupies at least one room with `caller`.
/// Includes the caller themself (Element renders self results specially,
/// but users expect to find their own profile when searching). Used to
/// filter user-directory search under the privacy-preserving default.
fn resolve_shared_room_peers(state: &AppState, caller_nid: u64) -> Result<HashSet<u64>, ApiError> {
    let mut peers = HashSet::new();
    peers.insert(caller_nid);
    let rooms = state
        .db
        .get_user_joined_rooms(caller_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for room_nid in rooms {
        let members = state
            .db
            .get_room_members(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        for m in members {
            peers.insert(m);
        }
    }
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substring_hits_user_id_and_display_name() {
        assert!(matches_substring("@alice:example.com", "Alice", "alic"));
        assert!(matches_substring("@bob:example.com", "Bob Smith", "smith"));
        assert!(matches_substring("@bob:example.com", "Bob", "bob"));
        assert!(!matches_substring("@carol:example.com", "Carol", "dave"));
    }

    #[test]
    fn substring_is_case_insensitive() {
        // The helper expects a pre-lowercased `term_lc`; the caller
        // lowercases before invoking it.
        assert!(matches_substring("@Alice:example.com", "Alice", "alice"));
        assert!(matches_substring("@alice:example.com", "ALICE", "alice"));
    }
}
