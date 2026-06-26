//! `/devices` CRUD — list, fetch, rename, delete.
//!
//! Spec: `references/matrix-spec/data/api/client-server/device_management.yaml`.

use crate::middleware::json::Json;
use axum::body::Bytes;
use axum::extract::{Path, State};
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::auth::uia;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

pub async fn list_devices(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let raw = state
        .db
        .list_devices(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut devices = Vec::with_capacity(raw.len());
    for d in &raw {
        let device_id = d
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let (ts, ip) = state
            .db
            .get_device_last_seen(user.user_nid, device_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        devices.push(json!({
            "device_id": device_id,
            "display_name": d.get("display_name").cloned().unwrap_or(Value::Null),
            "last_seen_ts": ts.map(Value::from).unwrap_or(Value::Null),
            "last_seen_ip": ip.map(Value::String).unwrap_or(Value::Null),
        }));
    }
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
    let (ts, ip) = state
        .db
        .get_device_last_seen(user.user_nid, &device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({
        "device_id": device.get("device_id").cloned().unwrap_or_else(|| Value::String(device_id.clone())),
        "display_name": device.get("display_name").cloned().unwrap_or(Value::Null),
        "last_seen_ip": ip.map(Value::String).unwrap_or(Value::Null),
        "last_seen_ts": ts.map(Value::from).unwrap_or(Value::Null),
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
        crate::e2ee::keys::federate_device_list_update_for(
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

    purge_device(&state, user.user_nid, &device_id)?;
    Ok(Json(json!({})))
}

/// Delete one device's tokens, record, and MSC3890 device-local
/// notification settings. Shared by the single and batch delete paths.
///
/// MSC3890: device-local notification settings live in account_data
/// keyed by the device_id and stop being useful once the device is
/// gone, so tombstone the entry as part of the device deletion.
pub(crate) fn purge_device(
    state: &AppState,
    user_nid: u64,
    device_id: &str,
) -> Result<(), ApiError> {
    state
        .db
        .delete_device_tokens(user_nid, device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let _ = state.db.delete_device(user_nid, device_id);
    crate::auth::logout::purge_msc3890_local_notification_settings_pub(state, user_nid, device_id);
    // Federate the removal so remote servers drop this device from their
    // `/keys/query` view — an `m.device_list_update` with `deleted: true`.
    // Matches the local key reclaim in `Database::delete_device`.
    if let Ok(Some(user_id)) = state.db.resolve_nid(user_nid) {
        crate::e2ee::keys::federate_device_list_update_for(
            state,
            user_nid,
            &user_id,
            device_id,
            json!({}),
            /* deleted = */ true,
        );
    }
    Ok(())
}

/// `POST /_matrix/client/v3/delete_devices`
///
/// Batch device deletion. Same UIA discipline as the single-device
/// delete: a bare request (or one without `auth`) gets a 401 challenge,
/// and the completed UIA identifier must match the caller. Devices in
/// the list that don't belong to the caller are silently skipped
/// (Synapse parity) rather than failing the whole batch — the caller
/// can only ever target their own devices, so an unknown id is a no-op.
pub async fn delete_devices(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    body_bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
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

    let devices = body
        .get("devices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| ApiError(VelaError::BadJson("missing 'devices' array".into())))?;

    for device in devices {
        let Some(device_id) = device.as_str() else {
            continue;
        };
        // Only act on devices the caller actually owns; skip anything
        // else so a stray id can't fail the whole batch.
        if state
            .db
            .get_device(user.user_nid, device_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .is_some()
        {
            purge_device(&state, user.user_nid, device_id)?;
        }
    }

    Ok(Json(json!({})))
}
