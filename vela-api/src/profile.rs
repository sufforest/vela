use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// GET /_matrix/client/v3/profile/{userId}
pub async fn get_profile(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user not found".into())))?;

    let record = state
        .db
        .get_user(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or(json!({}));

    let mut response = json!({});
    let obj = response.as_object_mut().unwrap();
    if let Some(name) = record.get("displayname") {
        obj.insert("displayname".into(), name.clone());
    }
    if let Some(avatar) = record.get("avatar_url") {
        obj.insert("avatar_url".into(), avatar.clone());
    }

    Ok(Json(response))
}

/// GET /_matrix/client/v3/profile/{userId}/displayname
pub async fn get_displayname(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user not found".into())))?;

    let record = state
        .db
        .get_user(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or(json!({}));

    Ok(Json(json!({
        "displayname": record.get("displayname").cloned().unwrap_or(Value::Null)
    })))
}

#[derive(Deserialize)]
pub struct SetDisplaynameRequest {
    pub displayname: Option<String>,
}

/// PUT /_matrix/client/v3/profile/{userId}/displayname
pub async fn set_displayname(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(body): Json<SetDisplaynameRequest>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own profile".into()).into());
    }

    state
        .db
        .update_user_profile(user.user_nid, body.displayname.as_deref(), None)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Merge the stored avatar_url into the propagation so we don't wipe
    // the avatar by emitting a member event with avatar_url missing.
    let avatar = read_avatar(&state, user.user_nid);
    crate::membership::propagate_profile_update(
        &state,
        &user,
        body.displayname.as_deref(),
        avatar.as_deref(),
    )
    .await;

    Ok(Json(json!({})))
}

fn read_avatar(state: &AppState, user_nid: u64) -> Option<String> {
    state.db.get_user(user_nid).ok().flatten().and_then(|u| {
        u.get("avatar_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    })
}

fn read_displayname(state: &AppState, user_nid: u64) -> Option<String> {
    state.db.get_user(user_nid).ok().flatten().and_then(|u| {
        u.get("displayname")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    })
}

/// GET /_matrix/client/v3/profile/{userId}/avatar_url
pub async fn get_avatar_url(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let user_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user not found".into())))?;

    let record = state
        .db
        .get_user(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or(json!({}));

    Ok(Json(json!({
        "avatar_url": record.get("avatar_url").cloned().unwrap_or(Value::Null)
    })))
}

#[derive(Deserialize)]
pub struct SetAvatarUrlRequest {
    pub avatar_url: Option<String>,
}

/// PUT /_matrix/client/v3/profile/{userId}/avatar_url
pub async fn set_avatar_url(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(body): Json<SetAvatarUrlRequest>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own profile".into()).into());
    }

    state
        .db
        .update_user_profile(user.user_nid, None, body.avatar_url.as_deref())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let displayname = read_displayname(&state, user.user_nid);
    crate::membership::propagate_profile_update(
        &state,
        &user,
        displayname.as_deref(),
        body.avatar_url.as_deref(),
    )
    .await;

    Ok(Json(json!({})))
}
