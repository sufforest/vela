use axum::Json;
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
        state
            .typing_stream
            .enqueue(&room_id_str, &user.user_id, room_nid, body.typing);
        state.federation_sender.notify_room(room_nid);
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
