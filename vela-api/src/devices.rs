//! `/devices` CRUD — list, fetch, rename, delete.
//!
//! Spec: `references/matrix-spec/data/api/client-server/device_management.yaml`.

use axum::Json;
use axum::body::Bytes;
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

        // Surface the change to /sync's device_lists.changed for local
        // observers and over federation as m.device_list_update so
        // peers know to re-fetch the device's metadata. Without this,
        // a remote client showing alice's device-name list never
        // updates after she renames a device.
        let _ = state.db.record_device_key_change(user.user_nid);
        crate::router::notify_user(&state, user.user_nid);

        let mut keys_value = state
            .db
            .get_device_keys(user.user_nid, &device_id)
            .ok()
            .flatten()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        keys_value.insert("device_display_name".into(), json!(name));
        crate::keys::federate_device_list_update_for(
            &state,
            user.user_nid,
            &user.user_id,
            &device_id,
            Value::Object(keys_value),
            false,
        );
    }
    Ok(Json(json!({})))
}

/// `DELETE /_matrix/client/v3/devices/{deviceId}`
///
/// Spec requires UIA. First call (no body or no `auth`) returns 401
/// with a challenge; subsequent call with valid `m.login.password`
/// proceeds. After UIA, the auth-supplied identifier must match the
/// caller AND the target device must belong to the caller — otherwise
/// 403. (If we only checked device ownership, alice could supply
/// bob's password to delete alice's device, which the spec forbids:
/// "the user must complete UIA *as themselves*".)
pub async fn delete_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<String>,
    body_bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
    // Empty body → kick UIA. Json<Value> on empty bytes returns 400
    // M_BAD_JSON before we ever see it; the spec says the bare delete
    // request gets a 401 challenge.
    let body: Value = if body_bytes.is_empty() {
        Value::Object(serde_json::Map::new())
    } else {
        serde_json::from_slice(&body_bytes).map_err(|e| {
            ApiError(VelaError::NotJson(format!(
                "request body is not valid JSON: {e}"
            )))
        })?
    };

    uia::require_password_auth(&state, &body)?;

    let auth_user = body
        .pointer("/auth/identifier/user")
        .and_then(|v| v.as_str())
        .or_else(|| body.pointer("/auth/user").and_then(|v| v.as_str()))
        .unwrap_or("");
    let auth_user_id = if auth_user.starts_with('@') {
        auth_user.to_lowercase()
    } else {
        format!("@{}:{}", auth_user.to_lowercase(), state.config.server_name)
    };
    if auth_user_id != user.user_id {
        return Err(ApiError(VelaError::Forbidden(
            "UIA identifier does not match the caller".into(),
        )));
    }

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
