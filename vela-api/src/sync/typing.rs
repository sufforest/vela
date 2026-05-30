use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct TypingRequest {
    pub typing: bool,
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    30_000
}

/// PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
pub async fn set_typing(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, _user_id)): Path<(String, String)>,
    Json(body): Json<TypingRequest>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let was_typing;
    {
        let mut entry = state.typing_state.entry(room_nid).or_default();
        let typers = entry.value_mut();
        // Was the user already in the typing set (and unexpired)?
        was_typing = typers
            .iter()
            .any(|(uid, exp)| *uid == user.user_nid && *exp > now_ms);

        // Remove this user's existing entry; re-insert if still typing.
        typers.retain(|(uid, _)| *uid != user.user_nid);
        if body.typing {
            let expires_at = now_ms + body.timeout;
            typers.push((user.user_nid, expires_at));
        }
        // Lazy prune expired entries.
        typers.retain(|(_, expires)| *expires > now_ms);
    }

    // Federate only on STATE TRANSITION (started typing, stopped
    // typing). Clients re-PUT every 20–30s while still typing per
    // c2s spec — federating those would be pure noise on the wire.
    if was_typing != body.typing {
        // Bump the "typing changed" stream pos so /sync knows this
        // room has a fresh typing transition. We must allocate a
        // FRESH position (not just read current_stream_position),
        // otherwise the value can equal a previously-returned
        // `next_batch` and the `>` comparison in /sync drops the
        // EDU. Burning a pos per transition is fine — typing is
        // rare relative to PDUs.
        let pos = state.db.next_stream_position().as_u64();
        // Typing doesn't persist to RocksDB (in-memory only), but we still
        // must mark the position applied so safe_stream_position advances.
        let _stream_guard = vela_store::db::StreamApplyOnDrop::new(&state.db, pos);
        state.typing_change_pos.insert(room_nid, pos);

        // Wake local /sync long-polls in the room so the typing EDU
        // is delivered immediately, not after the long-poll timeout.
        if let Some(sender) = state
            .room_senders
            .get(&vela_core::identifiers::Nid(room_nid))
        {
            let _ = sender.send(pos);
        }

        state
            .typing_stream
            .enqueue(&room_id_str, &user.user_id, room_nid, body.typing);
        state.federation_sender.notify_room(room_nid);

        // AS ephemeral push: every AS with `receive_ephemeral` +
        // interest in this room gets an `m.typing` EDU with the full
        // current typing set. Mirrors the shape /sync emits.
        let typer_nids = get_typing_users(&state, room_nid);
        let typer_mxids: Vec<String> = typer_nids
            .into_iter()
            .filter_map(|nid| state.db.resolve_nid(nid).ok().flatten())
            .collect();
        crate::appservice::ephemeral::dispatch_ephemeral_to_room(
            &state,
            &room_id_str,
            room_nid,
            &user.user_id,
            crate::appservice::ephemeral::typing_edu(typer_mxids),
        );
    }

    Ok(Json(json!({})))
}

/// Get current typing users for a room (with lazy expiry pruning).
pub fn get_typing_users(state: &AppState, room_nid: u64) -> Vec<u64> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let mut entry = match state.typing_state.get_mut(&room_nid) {
        Some(e) => e,
        None => return vec![],
    };

    let typers = entry.value_mut();
    typers.retain(|(_, expires)| *expires > now_ms);
    typers.iter().map(|(uid, _)| *uid).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    /// A room with no typing entries returns an empty list — not None
    /// or panic. This is the no-op fast path /sync hits for every
    /// quiet room.
    #[test]
    fn get_typing_users_returns_empty_when_no_entry() {
        let (state, _tmp) = build_test_state();
        let users = get_typing_users(&state, 999);
        assert!(users.is_empty());
    }

    /// Active (non-expired) typers come back in arbitrary order.
    /// Pin the contract that the set is what got inserted, ignoring
    /// order.
    #[test]
    fn get_typing_users_returns_active_typers() {
        let (state, _tmp) = build_test_state();
        let room_nid = 1u64;
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 60_000;
        state
            .typing_state
            .insert(room_nid, vec![(10, future), (20, future), (30, future)]);
        let mut users = get_typing_users(&state, room_nid);
        users.sort();
        assert_eq!(users, vec![10, 20, 30]);
    }

    /// Lazy expiry pruning: typers whose `expires` is in the past
    /// must be filtered out on the next read. The state DashMap also
    /// retains the pruned-down entry so subsequent reads are O(active).
    #[test]
    fn get_typing_users_prunes_expired_entries() {
        let (state, _tmp) = build_test_state();
        let room_nid = 2u64;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // Two typers: one active, one expired 60s ago.
        state.typing_state.insert(
            room_nid,
            vec![(11, now_ms + 60_000), (22, now_ms.saturating_sub(60_000))],
        );
        let users = get_typing_users(&state, room_nid);
        assert_eq!(users, vec![11]);

        // The in-place prune persists.
        let entry = state.typing_state.get(&room_nid).unwrap();
        let stored: Vec<u64> = entry.value().iter().map(|(u, _)| *u).collect();
        assert_eq!(stored, vec![11]);
    }

    /// All-expired returns empty AND the room's entry is pruned to an
    /// empty vec rather than removed entirely. Subsequent inserts
    /// reuse the slot.
    #[test]
    fn get_typing_users_returns_empty_when_all_expired() {
        let (state, _tmp) = build_test_state();
        let room_nid = 3u64;
        let past = 1u64; // long expired
        state
            .typing_state
            .insert(room_nid, vec![(1, past), (2, past)]);
        let users = get_typing_users(&state, room_nid);
        assert!(users.is_empty());
    }
}
