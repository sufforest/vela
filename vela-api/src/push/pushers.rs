//! `/pushers` — register HTTP pushers for mobile / web push delivery.
//!
//! Spec: `client-server-api/#push-notifications`.
//!
//! Storage-only for now: we round-trip pusher records so Element's
//! settings UI works, but we don't actually dispatch HTTP notifications
//! to the configured URLs yet. That's Sprint 8 Block 3 follow-up —
//! requires a background worker that reads push rules + matches events
//! + POSTs to `{pusher.data.url}/_matrix/push/v1/notify`.

use crate::middleware::json::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Upper bound on registered pushers per user. Each push dispatch fans out
/// over every recipient's pushers, so an unbounded set is a delivery-cost
/// amplifier (and storage). Far above any real client's needs.
const MAX_PUSHERS_PER_USER: usize = 100;

/// GET /_matrix/client/v3/pushers
pub async fn get_pushers(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let pushers = state
        .db
        .list_pushers(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({ "pushers": pushers })))
}

#[derive(Debug, Deserialize)]
pub struct SetPusherBody {
    pub app_id: String,
    pub pushkey: String,
    /// When `"remove"`, delete this pusher (no other fields required).
    pub kind: Option<String>,
    #[serde(default)]
    pub app_display_name: Option<String>,
    #[serde(default)]
    pub device_display_name: Option<String>,
    #[serde(default)]
    pub profile_tag: Option<String>,
    #[serde(default)]
    pub lang: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
    /// Spec: when true, other pushers with the same (app_id, pushkey)
    /// registered by other users should be removed. We don't track
    /// cross-user pushers, so this is a no-op.
    #[serde(default)]
    #[allow(dead_code)]
    pub append: Option<bool>,
}

/// POST /_matrix/client/v3/pushers/set
pub async fn set_pusher(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<SetPusherBody>,
) -> Result<Json<Value>, ApiError> {
    // `kind: null` is the spec's way to say "remove this pusher".
    if body.kind.is_none() {
        state
            .db
            .delete_pusher(user.user_nid, &body.app_id, &body.pushkey)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        return Ok(Json(json!({})));
    }

    // Cap the number of pushers per user. A re-set of an existing
    // (app_id, pushkey) is an update (same storage key) and is always
    // allowed; only a genuinely new pusher beyond the cap is refused.
    let existing = state
        .db
        .list_pushers(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let is_update = existing.iter().any(|p| {
        p.get("app_id").and_then(|v| v.as_str()) == Some(body.app_id.as_str())
            && p.get("pushkey").and_then(|v| v.as_str()) == Some(body.pushkey.as_str())
    });
    if !is_update && existing.len() >= MAX_PUSHERS_PER_USER {
        return Err(VelaError::InvalidParam(format!(
            "too many pushers (max {MAX_PUSHERS_PER_USER})"
        ))
        .into());
    }

    // Record the device_id of the access token that registered this
    // pusher. /account/password (logout_devices=true) deletes tokens
    // for every device except the caller's; the spec also requires
    // those devices' pushers to disappear, so we need a back-pointer.
    let mut record = json!({
        "app_id": body.app_id,
        "pushkey": body.pushkey,
        "kind": body.kind,
        "device_id": user.device_id,
    });
    let obj = record.as_object_mut().unwrap();
    if let Some(v) = body.app_display_name {
        obj.insert("app_display_name".into(), json!(v));
    }
    if let Some(v) = body.device_display_name {
        obj.insert("device_display_name".into(), json!(v));
    }
    if let Some(v) = body.profile_tag {
        obj.insert("profile_tag".into(), json!(v));
    }
    if let Some(v) = body.lang {
        obj.insert("lang".into(), json!(v));
    }
    if let Some(v) = body.data {
        obj.insert("data".into(), v);
    }

    state
        .db
        .set_pusher(user.user_nid, &body.app_id, &body.pushkey, &record)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({})))
}
