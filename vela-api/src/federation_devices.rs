//! `GET /_matrix/federation/v1/user/devices/{userId}`
//!
//! Used by remote servers when they need a complete snapshot of
//! one of our local user's devices — e.g. to populate their device
//! cache after a fresh room join, or to refresh after losing track
//! of `m.device_list_update` EDUs.
//!
//! Behind the existing `federation_auth` middleware so only signed
//! requests reach this handler. We serve only for users on our
//! own server; queries for users on other domains return 404 to
//! avoid implying we're authoritative for someone else.

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::middleware::federation_auth::XMatrixOrigin;
use crate::router::AppState;

/// GET /_matrix/federation/v1/user/devices/{userId}
pub async fn get_user_devices(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    axum::extract::Extension(_origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    let our_server = state.config.server_name.as_str();
    let user_server = user_id
        .strip_prefix('@')
        .and_then(|s| s.split_once(':'))
        .map(|(_, s)| s);
    if user_server != Some(our_server) {
        return Err(StatusCode::NOT_FOUND);
    }

    let user_nid = match state
        .db
        .get_nid(&user_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(n) => n,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let stream_id = state
        .db
        .current_user_device_list_stream(user_nid)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Devices: list every (device_id, optional keys, optional name)
    // we've recorded for this user. Devices without uploaded keys
    // still appear in the response with just `device_id` so the
    // peer can still track presence.
    let device_records = state
        .db
        .list_devices(user_nid)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut devices = Vec::with_capacity(device_records.len());
    for record in device_records {
        let Some(device_id) = record.get("device_id").and_then(|v| v.as_str()) else {
            continue;
        };
        let keys = state.db.get_device_keys(user_nid, device_id).ok().flatten();
        let display_name = record
            .get("display_name")
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| {
                keys.as_ref()
                    .and_then(|k| k.get("device_display_name"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        let mut entry = serde_json::Map::new();
        entry.insert("device_id".into(), json!(device_id));
        if let Some(k) = keys {
            entry.insert("keys".into(), k);
        }
        if let Some(name) = display_name {
            entry.insert("device_display_name".into(), json!(name));
        }
        devices.push(Value::Object(entry));
    }

    let cs = state
        .db
        .get_cross_signing_keys(user_nid)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut out = serde_json::Map::new();
    out.insert("user_id".into(), json!(user_id));
    out.insert("stream_id".into(), json!(stream_id));
    out.insert("devices".into(), Value::Array(devices));
    if let Some(master) = cs.get("master_key") {
        out.insert("master_key".into(), master.clone());
    }
    if let Some(ssk) = cs.get("self_signing_key") {
        out.insert("self_signing_key".into(), ssk.clone());
    }
    // user_signing_key is intentionally omitted — it's private to
    // the user and never federated.

    Ok(Json(Value::Object(out)))
}
