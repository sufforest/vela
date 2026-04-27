use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::messages::load_client_event;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// `?format=` controls whether `state/.../{eventType}/{stateKey}` returns
/// just the event content (default `content`, omitted) or the full client
/// event (when `event`).
#[derive(Debug, Default, Deserialize)]
pub struct StateFormatQuery {
    pub format: Option<String>,
}

/// GET /_matrix/client/v3/rooms/{roomId}/state
pub async fn get_all_state(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    check_membership(&state, room_nid, user.user_nid)?;

    let state_nids = state
        .db
        .get_all_state_event_nids(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut events = Vec::new();
    for nid in state_nids {
        if let Some(ev) = load_client_event(&state, nid, &room_id)? {
            events.push(ev);
        }
    }

    Ok(Json(Value::Array(events)))
}

/// GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
pub async fn get_state_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(params): Path<(String, String, String)>,
    Query(q): Query<StateFormatQuery>,
) -> Result<Json<Value>, ApiError> {
    let (room_id, event_type, state_key) = params;

    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    check_membership(&state, room_nid, user.user_nid)?;

    let type_nid = state
        .db
        .get_nid(&event_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    let skey_nid = state
        .db
        .get_nid(&state_key)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    let event_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    let event = load_client_event(&state, event_nid, &room_id)?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    // ?format=event returns the full client event; default returns content only.
    if matches!(q.format.as_deref(), Some("event")) {
        Ok(Json(event))
    } else {
        let content = event.get("content").cloned().unwrap_or(json!({}));
        Ok(Json(content))
    }
}

/// GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}
/// (state_key defaults to empty string)
pub async fn get_state_event_no_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, event_type)): Path<(String, String)>,
    Query(q): Query<StateFormatQuery>,
) -> Result<Json<Value>, ApiError> {
    get_state_event(
        State(state),
        user,
        Path((room_id, event_type, String::new())),
        Query(q),
    )
    .await
}

fn check_membership(state: &AppState, room_nid: u64, user_nid: u64) -> Result<(), ApiError> {
    let membership = state
        .db
        .get_membership(room_nid, user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }
    Ok(())
}
