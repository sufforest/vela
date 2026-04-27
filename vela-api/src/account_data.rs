use axum::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// GET /_matrix/client/v3/user/{userId}/account_data/{type}
pub async fn get_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, data_type)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only access own account data".into()).into());
    }

    let value = state
        .db
        .get_account_data(user.user_nid, &data_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("account data not found".into())))?;

    Ok(Json(value))
}

/// PUT /_matrix/client/v3/user/{userId}/account_data/{type}
pub async fn set_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, data_type)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own account data".into()).into());
    }

    state
        .db
        .set_account_data(user.user_nid, &data_type, &body)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Wake any pending /sync so the writer sees their own change on the
    // next poll without waiting for the long-poll timeout. Element's
    // cross-signing setup writes m.cross_signing.* and waits for them
    // to stream back before continuing; without this wake, the whole
    // flow stalls for up to 30s per write.
    crate::router::notify_user(&state, user.user_nid);

    Ok(Json(json!({})))
}

/// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
pub async fn get_room_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only access own account data".into()).into());
    }

    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let value = state
        .db
        .get_room_account_data(user.user_nid, room_nid, &data_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("account data not found".into())))?;

    Ok(Json(value))
}

/// PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}
pub async fn set_room_account_data(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, data_type)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own account data".into()).into());
    }

    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    state
        .db
        .set_room_account_data(user.user_nid, room_nid, &data_type, &body)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    crate::router::notify_user(&state, user.user_nid);
    Ok(Json(json!({})))
}

// ----- Room tags (m.tag account data) -----

/// GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags
pub async fn list_tags(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only access own tags".into()).into());
    }
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    let tags = state
        .db
        .get_room_account_data(user.user_nid, room_nid, "m.tag")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .and_then(|v| v.get("tags").cloned())
        .unwrap_or_else(|| json!({}));
    Ok(Json(json!({"tags": tags})))
}

/// PUT /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}
///
/// Body is the tag content blob (typically `{order: <float>}`); we store
/// it under `m.tag.tags.{tag}` in room account data, preserving any other
/// tags already set.
pub async fn put_tag(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own tags".into()).into());
    }
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let mut current = state
        .db
        .get_room_account_data(user.user_nid, room_nid, "m.tag")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_else(|| json!({"tags": {}}));
    let tags = current
        .as_object_mut()
        .unwrap()
        .entry("tags".to_string())
        .or_insert_with(|| json!({}));
    tags.as_object_mut().unwrap().insert(tag, body);

    state
        .db
        .set_room_account_data(user.user_nid, room_nid, "m.tag", &current)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(&state, user.user_nid);
    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/v3/user/{userId}/rooms/{roomId}/tags/{tag}
pub async fn delete_tag(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, room_id, tag)): Path<(String, String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only delete own tags".into()).into());
    }
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let mut current = match state
        .db
        .get_room_account_data(user.user_nid, room_nid, "m.tag")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(v) => v,
        None => return Ok(Json(json!({}))),
    };
    if let Some(tags) = current.get_mut("tags").and_then(|v| v.as_object_mut()) {
        tags.remove(&tag);
    }
    state
        .db
        .set_room_account_data(user.user_nid, room_nid, "m.tag", &current)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(&state, user.user_nid);
    Ok(Json(json!({})))
}
