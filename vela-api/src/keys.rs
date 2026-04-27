use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

// --- Keys Upload ---

#[derive(Deserialize)]
pub struct KeysUploadRequest {
    pub device_keys: Option<Value>,
    pub one_time_keys: Option<Map<String, Value>>,
}

/// POST /_matrix/client/v3/keys/upload
pub async fn upload_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<KeysUploadRequest>,
) -> Result<Json<Value>, ApiError> {
    if let Some(device_keys) = &body.device_keys {
        state
            .db
            .set_device_keys(user.user_nid, &user.device_id, device_keys)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        // Tell our observers (self + joined room-mates) to re-query.
        let _ = state.db.record_device_key_change(user.user_nid);
        crate::router::notify_user(&state, user.user_nid);
        // Federate the change to remote servers sharing a room with
        // this user. Spec: m.device_list_update EDU per destination
        // with a per-user monotonic stream_id.
        federate_device_list_update(&state, &user, device_keys.clone(), /* deleted */ false);
    }

    if let Some(otks) = &body.one_time_keys
        && !otks.is_empty()
    {
        state
            .db
            .add_one_time_keys(user.user_nid, &user.device_id, otks)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    let counts = state
        .db
        .count_one_time_keys(user.user_nid, &user.device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    Ok(Json(json!({"one_time_key_counts": counts})))
}

// --- Keys Query ---

#[derive(Deserialize)]
pub struct KeysQueryRequest {
    pub device_keys: HashMap<String, Vec<String>>,
}

/// POST /_matrix/client/v3/keys/query
pub async fn query_keys(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Json(body): Json<KeysQueryRequest>,
) -> Result<Json<Value>, ApiError> {
    let mut device_keys_response: Map<String, Value> = Map::new();

    for (user_id, device_ids) in &body.device_keys {
        let user_nid = match state
            .db
            .get_nid(user_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(nid) => nid,
            None => continue,
        };

        let mut user_devices: Map<String, Value> = Map::new();

        if device_ids.is_empty() {
            // Empty list = return all devices
            let all_keys = state
                .db
                .get_all_device_keys(user_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            for (device_id, keys) in all_keys {
                user_devices.insert(device_id, keys);
            }
        } else {
            for device_id in device_ids {
                if let Some(keys) = state
                    .db
                    .get_device_keys(user_nid, device_id)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                {
                    user_devices.insert(device_id.clone(), keys);
                }
            }
        }

        device_keys_response.insert(user_id.clone(), Value::Object(user_devices));
    }

    // Include cross-signing keys
    let mut master_keys: Map<String, Value> = Map::new();
    let mut self_signing_keys: Map<String, Value> = Map::new();
    let mut user_signing_keys: Map<String, Value> = Map::new();

    for user_id in body.device_keys.keys() {
        if let Some(user_nid) = state
            .db
            .get_nid(user_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            let cs_keys = state
                .db
                .get_cross_signing_keys(user_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            if let Some(k) = cs_keys.get("master_key") {
                master_keys.insert(user_id.clone(), k.clone());
            }
            if let Some(k) = cs_keys.get("self_signing_key") {
                self_signing_keys.insert(user_id.clone(), k.clone());
            }
            if let Some(k) = cs_keys.get("user_signing_key") {
                user_signing_keys.insert(user_id.clone(), k.clone());
            }
        }
    }

    Ok(Json(json!({
        "device_keys": device_keys_response,
        "master_keys": master_keys,
        "self_signing_keys": self_signing_keys,
        "user_signing_keys": user_signing_keys,
    })))
}

// --- Keys Claim ---

#[derive(Deserialize)]
pub struct KeysClaimRequest {
    pub one_time_keys: HashMap<String, HashMap<String, String>>,
}

/// POST /_matrix/client/v3/keys/claim
pub async fn claim_keys(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Json(body): Json<KeysClaimRequest>,
) -> Result<Json<Value>, ApiError> {
    let mut result: Map<String, Value> = Map::new();

    for (user_id, devices) in &body.one_time_keys {
        let user_nid = match state
            .db
            .get_nid(user_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(nid) => nid,
            None => continue,
        };

        // Per-user lock prevents two concurrent claims from reading the same OTK
        let lock = state
            .user_locks
            .entry(user_nid)
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        let mut user_keys: Map<String, Value> = Map::new();

        for (device_id, algorithm) in devices {
            if let Some((key_id, key_data)) = state
                .db
                .claim_one_time_key(user_nid, device_id, algorithm)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                let mut device_map = Map::new();
                device_map.insert(key_id, key_data);
                user_keys.insert(device_id.clone(), Value::Object(device_map));
            }
        }

        result.insert(user_id.clone(), Value::Object(user_keys));
    }

    Ok(Json(json!({"one_time_keys": result})))
}

// --- Key Changes ---

#[derive(Deserialize)]
pub struct KeyChangesQuery {
    pub from: String,
    pub to: String,
}

/// GET /_matrix/client/v3/keys/changes
pub async fn key_changes(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<KeyChangesQuery>,
) -> Result<Json<Value>, ApiError> {
    let from: u64 = query.from.parse().unwrap_or(0);
    let to: u64 = query.to.parse().unwrap_or(u64::MAX);

    let changed_nids = state
        .db
        .get_device_key_changes(user.user_nid, from, to)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut changed = Vec::new();
    for nid in changed_nids {
        if let Some(user_id) = state
            .db
            .resolve_nid(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            changed.push(Value::String(user_id));
        }
    }

    Ok(Json(json!({
        "changed": changed,
        "left": [],
    })))
}

// --- Cross-signing key upload ---

/// POST /_matrix/client/v3/keys/device_signing/upload
///
/// UIA gate per MSC3967 (folded into current CS-API): UIA is required
/// only when the user already has cross-signing keys on file (i.e. this
/// upload would *replace* them). First-time uploads — the "Set up secure
/// backup" / "Reset cryptographic identity" flow on a fresh account —
/// skip UIA so the bootstrap isn't blocked on an extra password prompt.
pub async fn upload_signing_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    // Decide whether UIA is required based on whether the user already
    // has ANY cross-signing key stored. Missing = first-time setup.
    let existing = state
        .db
        .get_cross_signing_keys(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if !existing.is_empty() {
        crate::uia::require_password_auth(&state, &body)?;
    }

    // Pull the three optional key fields from the JSON body.
    let master_key = body.get("master_key").filter(|v| !v.is_null()).cloned();
    let self_signing_key = body
        .get("self_signing_key")
        .filter(|v| !v.is_null())
        .cloned();
    let user_signing_key = body
        .get("user_signing_key")
        .filter(|v| !v.is_null())
        .cloned();

    if let Some(key) = master_key {
        state
            .db
            .set_cross_signing_keys(user.user_nid, "master_key", &key)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    if let Some(key) = self_signing_key {
        state
            .db
            .set_cross_signing_keys(user.user_nid, "self_signing_key", &key)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    if let Some(key) = user_signing_key {
        state
            .db
            .set_cross_signing_keys(user.user_nid, "user_signing_key", &key)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    // Notify observers (self + joined room-mates) that cross-signing keys
    // changed so /sync surfaces device_lists.changed and clients re-query.
    let _ = state.db.record_device_key_change(user.user_nid);
    crate::router::notify_user(&state, user.user_nid);

    Ok(Json(json!({})))
}

// --- Signatures Upload ---
//
// `POST /_matrix/client/v3/keys/signatures/upload` — merge signatures a
// user has produced into the persisted device/cross-signing key records.
// Body shape: `{ <user_id>: { <key_id_or_device>: { signatures: {...}, ... } } }`.
// For every entry we find the matching stored key and fold the new
// signatures in, preserving any we already had.

/// POST /_matrix/client/v3/keys/signatures/upload
pub async fn upload_signatures(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let Some(users) = body.as_object() else {
        return Ok(Json(json!({"failures": {}})));
    };
    let mut changed_users: Vec<u64> = Vec::new();
    for (user_id, devs) in users {
        let Some(dev_map) = devs.as_object() else {
            continue;
        };
        let Some(user_nid) = state
            .db
            .get_nid(user_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        if !changed_users.contains(&user_nid) {
            changed_users.push(user_nid);
        }
        for (dev_or_key_id, new_body) in dev_map {
            // Try device keys first (typical case for self-signatures),
            // fall back to cross-signing keys (e.g. master key signed by
            // user-signing key).
            if let Some(mut existing) = state
                .db
                .get_device_keys(user_nid, dev_or_key_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                merge_signatures(&mut existing, new_body);
                state
                    .db
                    .set_device_keys(user_nid, dev_or_key_id, &existing)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                continue;
            }
            // Cross-signing keys are addressed in the input by their
            // public key id (not a device id), so we scan all stored
            // cross-signing records for this user and fold signatures
            // into whichever one owns the supplied key id.
            let all_xs = state
                .db
                .get_cross_signing_keys(user_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            for (xs_type, mut existing) in all_xs {
                let matches = existing
                    .get("keys")
                    .and_then(|k| k.as_object())
                    .map(|m| {
                        m.keys()
                            .any(|k| k == dev_or_key_id || k.ends_with(dev_or_key_id))
                    })
                    .unwrap_or(false);
                if matches {
                    merge_signatures(&mut existing, new_body);
                    state
                        .db
                        .set_cross_signing_keys(user_nid, &xs_type, &existing)
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                    break;
                }
            }
        }
    }
    // Record changes for each affected user so their next /sync carries
    // device_lists.changed and clients re-query.
    for nid in changed_users {
        let _ = state.db.record_device_key_change(nid);
        crate::router::notify_user(&state, nid);
    }
    Ok(Json(json!({"failures": {}})))
}

/// Fold `new_body.signatures.*` into `existing.signatures.*`. Preserves
/// all other fields in the existing record.
fn merge_signatures(existing: &mut Value, new_body: &Value) {
    let Some(new_sigs) = new_body.get("signatures").and_then(|v| v.as_object()) else {
        return;
    };
    let obj = match existing.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    let sigs = obj
        .entry("signatures".to_string())
        .or_insert_with(|| json!({}));
    let sig_map = match sigs.as_object_mut() {
        Some(s) => s,
        None => return,
    };
    for (user_id, key_map) in new_sigs {
        let Some(new_keys) = key_map.as_object() else {
            continue;
        };
        let entry = sig_map.entry(user_id.clone()).or_insert_with(|| json!({}));
        let Some(entry_obj) = entry.as_object_mut() else {
            continue;
        };
        for (key_id, sig) in new_keys {
            entry_obj.insert(key_id.clone(), sig.clone());
        }
    }
}

/// Enqueue an `m.device_list_update` EDU for every remote server that
/// shares any joined room with `user`. Wakes the affected senders so
/// the EDU rides out promptly. No-op for users with no remote
/// audience.
fn federate_device_list_update(
    state: &AppState,
    user: &AuthenticatedUser,
    device_keys: Value,
    deleted: bool,
) {
    use std::collections::HashSet;

    // Resolve the audience: union of remote servers across all rooms
    // the user is joined to.
    let rooms = match state.db.get_user_joined_rooms(user.user_nid) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "device_list federate: get_user_joined_rooms failed");
            return;
        }
    };
    let mut destinations: HashSet<String> = HashSet::new();
    for room_nid in rooms {
        match state
            .db
            .get_remote_servers_in_room(room_nid, &state.config.server_name)
        {
            Ok(servers) => destinations.extend(servers),
            Err(e) => tracing::warn!(error = %e, "device_list federate: room scan failed"),
        }
    }
    if destinations.is_empty() {
        return;
    }

    let stream_id = match state.db.bump_user_device_list_stream(user.user_nid) {
        Ok(n) => n,
        Err(e) => {
            tracing::warn!(error = %e, "device_list federate: stream bump failed");
            return;
        }
    };

    let display_name = device_keys
        .get("device_display_name")
        .and_then(|v| v.as_str())
        .map(String::from);

    let mut content = serde_json::Map::new();
    content.insert("user_id".into(), json!(user.user_id));
    content.insert("device_id".into(), json!(user.device_id));
    content.insert("stream_id".into(), json!(stream_id));
    content.insert("deleted".into(), json!(deleted));
    if let Some(name) = display_name {
        content.insert("device_display_name".into(), json!(name));
    }
    if !deleted {
        content.insert("keys".into(), device_keys);
    }
    let content_value = Value::Object(content);

    for dest in destinations {
        if let Err(e) = state.db.enqueue_device_list_outbound(&dest, &content_value) {
            tracing::warn!(target = %dest, error = %e, "device_list enqueue failed");
            continue;
        }
        state.federation_sender.notify_destination(&dest);
    }
}
