//! `/devices` CRUD — list, fetch, rename, delete.
//!
//! Spec: `references/matrix-spec/data/api/client-server/device_management.yaml`.
//!
//! Delete here uses simple access-token gating; spec says it MUST run UIA.
//! That's a follow-up — current behaviour matches what register/login do
//! (no UIA enforcement).

use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

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
    Ok(Json(device))
}

#[derive(Deserialize)]
pub struct RenameBody {
    pub display_name: Option<String>,
}

/// PUT /_matrix/client/v3/devices/{deviceId}
pub async fn rename_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<String>,
    Json(body): Json<RenameBody>,
) -> Result<Json<Value>, ApiError> {
    if let Some(name) = body.display_name {
        state
            .db
            .update_device_display_name(user.user_nid, &device_id, &name)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/v3/devices/{deviceId}
///
/// Spec requires UIA. We don't enforce it yet (consistent with register).
/// Removes the device record + all tokens issued to it; the next request
/// from that device sees `M_UNKNOWN_TOKEN`.
pub async fn delete_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    state
        .db
        .delete_device_tokens(user.user_nid, &device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let _ = state.db.delete_device(user.user_nid, &device_id);
    Ok(Json(json!({})))
}
