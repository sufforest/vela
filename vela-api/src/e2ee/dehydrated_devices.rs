//! MSC3814 — dehydrated devices.
//!
//! A dehydrated device is a real device whose private state is stored,
//! encrypted, on the server (`device_data`) so a returning client can
//! "rehydrate" it and decrypt to-device messages (room keys) that arrived
//! while it was offline. Because it's registered like any other device,
//! `/keys/query`, `/keys/claim`, and to-device routing all work unchanged;
//! the only extra surface is storing the opaque `device_data` and draining
//! the device's to-device queue on rehydration.
//!
//! Endpoints (unstable prefix `org.matrix.msc3814.v1`, the form Element
//! and the MSC use):
//!   - `PUT    .../dehydrated_device`              upload/replace
//!   - `GET    .../dehydrated_device`              fetch device_data
//!   - `DELETE .../dehydrated_device`              remove
//!   - `POST   .../dehydrated_device/{id}/events`  drain to-device queue
//!
//! `fallback_keys` are accepted but not persisted — vela's `/keys/upload`
//! doesn't implement fallback keys either, so this keeps parity rather than
//! growing that surface here.

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vela_core::error::VelaError;

use crate::auth::devices::purge_device;
use crate::e2ee::keys::federate_device_list_update_for;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::{AppState, notify_user};

/// The opaque pickle a real olm dehydration produces is well under a KB;
/// 64 KiB (matching the profile-value / event caps) is generous headroom
/// while keeping a single client from parking arbitrary blobs on the server.
const MAX_DEVICE_DATA_BYTES: usize = 64 * 1024;

/// Upper bound on one-time keys accepted in a single dehydrated PUT, so a
/// client can't grow the OTK store without bound by looping uploads.
const MAX_DEHYDRATED_OTKS: usize = 100;

/// Tear down a superseded or deleted dehydrated device: tell remote servers
/// to drop it from their `/keys/query` view, reclaim its queued to-device
/// messages (it never runs `/sync` to drain them itself), then remove the
/// device record + tokens. Best-effort — a failure here leaves an orphan but
/// must not fail the request that triggered the replacement/deletion.
fn purge_dehydrated_device(state: &AppState, user_nid: u64, user_id: &str, device_id: &str) {
    federate_device_list_update_for(state, user_nid, user_id, device_id, json!({}), true);
    match state.db.get_to_device_messages(user_nid, device_id) {
        Ok(msgs) if !msgs.is_empty() => {
            let keys: Vec<Vec<u8>> = msgs.into_iter().map(|(k, _)| k).collect();
            if let Err(e) = state.db.delete_to_device_messages(&keys) {
                tracing::warn!(%device_id, error = %e, "dehydrated purge: to-device cleanup failed");
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(%device_id, error = %e, "dehydrated purge: to-device scan failed"),
    }
    if let Err(e) = purge_device(state, user_nid, device_id) {
        tracing::warn!(%device_id, error = ?e.0, "dehydrated purge: device removal failed");
    }
}

#[derive(Deserialize)]
pub struct PutDehydratedDeviceRequest {
    pub device_id: String,
    pub device_data: Value,
    #[serde(default)]
    pub device_keys: Option<Value>,
    #[serde(default)]
    pub one_time_keys: Option<Map<String, Value>>,
    #[serde(default)]
    pub fallback_keys: Option<Map<String, Value>>,
}

/// `PUT /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device`
///
/// Registers `device_id` as a live device, stores its identity keys +
/// one-time keys, and records the opaque `device_data`. Replaces any prior
/// dehydrated device, purging the old one so a user only ever has one.
pub async fn put_dehydrated_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<PutDehydratedDeviceRequest>,
) -> Result<Json<Value>, ApiError> {
    let device_id = body.device_id.trim();
    if device_id.is_empty() {
        return Err(VelaError::BadJson("device_id must be non-empty".into()).into());
    }

    // Bound the opaque blob — it's stored verbatim and never interpreted.
    if body.device_data.to_string().len() > MAX_DEVICE_DATA_BYTES {
        return Err(VelaError::BadJson("device_data too large".into()).into());
    }
    if let Some(otks) = &body.one_time_keys
        && otks.len() > MAX_DEHYDRATED_OTKS
    {
        return Err(VelaError::BadJson("too many one_time_keys".into()).into());
    }

    // A dehydrated device must never alias one of the user's real devices:
    // create_device + set_device_keys are blind upserts, so reusing an active
    // device id would overwrite that session's E2EE identity keys and, on the
    // next replace, purge its tokens (logging the user out). Re-PUTting the
    // *current* dehydrated id is fine (it just refreshes data/keys).
    let current = state
        .db
        .get_dehydrated_device(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .map(|(id, _)| id);
    if current.as_deref() != Some(device_id)
        && state
            .db
            .get_device(user.user_nid, device_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .is_some()
    {
        return Err(
            VelaError::Forbidden("device_id already belongs to an existing device".into()).into(),
        );
    }

    // Identity keys are how other users encrypt to this device; without
    // them a dehydrated device can't receive anything. Validate they're
    // bound to the caller and to this device_id, mirroring /keys/upload.
    let device_keys = body
        .device_keys
        .as_ref()
        .ok_or_else(|| ApiError(VelaError::BadJson("device_keys is required".into())))?;
    let obj = device_keys
        .as_object()
        .ok_or_else(|| ApiError(VelaError::BadJson("device_keys must be an object".into())))?;
    if let Some(uid) = obj.get("user_id").and_then(|v| v.as_str())
        && uid != user.user_id
    {
        return Err(VelaError::BadJson(format!(
            "device_keys.user_id {uid} does not match caller {}",
            user.user_id
        ))
        .into());
    }
    if let Some(did) = obj.get("device_id").and_then(|v| v.as_str())
        && did != device_id
    {
        return Err(VelaError::BadJson(format!(
            "device_keys.device_id {did} does not match dehydrated device {device_id}"
        ))
        .into());
    }
    for required in ["algorithms", "keys", "signatures"] {
        if !obj.contains_key(required) {
            return Err(VelaError::BadJson(format!(
                "device_keys missing required field {required}"
            ))
            .into());
        }
    }

    // Register the device first so OTK claims / to-device sends targeting
    // it land somewhere, then attach keys.
    state
        .db
        .create_device(user.user_nid, device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    state
        .db
        .set_device_keys(user.user_nid, device_id, device_keys)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if let Some(otks) = &body.one_time_keys
        && !otks.is_empty()
    {
        state
            .db
            .add_one_time_keys(user.user_nid, device_id, otks)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    let prior = state
        .db
        .store_dehydrated_device(user.user_nid, device_id, &body.device_data)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Drop the device a previous dehydration left behind (different id).
    if let Some(old) = prior
        && old != device_id
    {
        purge_dehydrated_device(&state, user.user_nid, &user.user_id, &old);
    }

    // The new device's keys are now queryable. Tell local observers to
    // re-query, and federate the device-list update so remote users in
    // shared rooms learn to encrypt to it — without this it never receives
    // the room keys it exists to hold.
    let _ = state.db.record_device_key_change(user.user_nid);
    notify_user(&state, user.user_nid);
    federate_device_list_update_for(
        &state,
        user.user_nid,
        &user.user_id,
        device_id,
        device_keys.clone(),
        false,
    );

    Ok(Json(json!({ "device_id": device_id })))
}

/// `GET /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device`
pub async fn get_dehydrated_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    match state
        .db
        .get_dehydrated_device(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some((device_id, device_data)) => Ok(Json(json!({
            "device_id": device_id,
            "device_data": device_data,
        }))),
        None => Err(VelaError::NotFound("no dehydrated device".into()).into()),
    }
}

/// `DELETE /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device`
pub async fn delete_dehydrated_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let removed = state
        .db
        .remove_dehydrated_device(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    match removed {
        Some(device_id) => {
            purge_dehydrated_device(&state, user.user_nid, &user.user_id, &device_id);
            Ok(Json(json!({ "device_id": device_id })))
        }
        None => Err(VelaError::NotFound("no dehydrated device".into()).into()),
    }
}

#[derive(Deserialize)]
pub struct DehydratedEventsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Deserialize, Default)]
pub struct DehydratedEventsRequest {
    #[serde(default)]
    pub next_batch: Option<String>,
}

/// `POST /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{device_id}/events`
///
/// Pages through to-device messages queued for the dehydrated device. The
/// `next_batch` cursor is the last-seen to-device stream id; messages are
/// not consumed (read-ahead), so a client can resume or re-fetch. Only the
/// caller's own current dehydrated device may be drained.
pub async fn dehydrated_device_events(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(device_id): Path<String>,
    Query(query): Query<DehydratedEventsQuery>,
    Json(body): Json<DehydratedEventsRequest>,
) -> Result<Json<Value>, ApiError> {
    // Bind the request to the caller's actual dehydrated device — a client
    // can't drain an arbitrary device id.
    let current = state
        .db
        .get_dehydrated_device(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    match current {
        Some((id, _)) if id == device_id => {}
        _ => return Err(VelaError::Forbidden("not your dehydrated device".into()).into()),
    }

    let since = body.next_batch.as_deref().map(parse_cursor).unwrap_or(0);
    let limit = query.limit.clamp(1, 1000);

    let (events, cursor) = state
        .db
        .get_to_device_messages_since(user.user_nid, &device_id, since, limit)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    Ok(Json(json!({
        "events": events,
        // `d`-prefixed to match the form clients round-trip (Synapse parity);
        // parse_cursor tolerates the prefix on the way back in.
        "next_batch": format!("d{cursor}"),
    })))
}

/// Cursor is a plain decimal stream id; tolerate an optional `d` prefix in
/// case a client echoes a sync-style token. Unparseable → start from 0.
fn parse_cursor(s: &str) -> u64 {
    let trimmed = s.strip_prefix('d').unwrap_or(s);
    trimmed.parse().unwrap_or(0)
}
