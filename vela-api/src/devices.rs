//! `/devices` CRUD — list, fetch, rename, delete.
//!
//! Spec: `references/matrix-spec/data/api/client-server/device_management.yaml`.

use axum::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;
use crate::uia;

pub async fn list_devices(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let devices = state
        .db
        .list_devices(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({"devices": devices})))
}

/// `GET /_matrix/client/v3/devices/{deviceId}`
///
/// Always includes `display_name` in the response (null when unset);
/// some clients reject responses missing the field even though spec
/// says it's optional.
pub async fn get_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let device = state
        .db
        .get_device(user.user_nid, &device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("device not found".into())))?;
    Ok(Json(json!({
        "device_id": device.get("device_id").cloned().unwrap_or_else(|| Value::String(device_id.clone())),
        "display_name": device.get("display_name").cloned().unwrap_or(Value::Null),
        "last_seen_ip": device.get("last_seen_ip").cloned().unwrap_or(Value::Null),
        "last_seen_ts": device.get("last_seen_ts").cloned().unwrap_or(Value::Null),
    })))
}

/// `PUT /_matrix/client/v3/devices/{deviceId}`
///
/// Returns 404 if the device doesn't exist for the caller — without this
/// guard, PUT on an unknown id would silently succeed (creating an
/// orphaned record).
pub async fn rename_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if state
        .db
        .get_device(user.user_nid, &device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .is_none()
    {
        return Err(ApiError(VelaError::NotFound("device not found".into())));
    }
    if let Some(name) = body.get("display_name").and_then(|v| v.as_str()) {
        state
            .db
            .update_device_display_name(user.user_nid, &device_id, name)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/devices/{deviceId}`
///
/// Spec requires UIA. First call (no auth in body) returns 401 with a
/// challenge; subsequent call with valid `m.login.password` proceeds.
/// After UIA, the target device must belong to the caller — otherwise
/// 403, regardless of whether the UIA-supplied password was correct.
pub async fn delete_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    uia::require_password_auth(&state, &body)?;

    if state
        .db
        .get_device(user.user_nid, &device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .is_none()
    {
        return Err(ApiError(VelaError::Forbidden(
            "cannot delete another user's device".into(),
        )));
    }

    state
        .db
        .delete_device_tokens(user.user_nid, &device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let _ = state.db.delete_device(user.user_nid, &device_id);
    Ok(Json(json!({})))
}
