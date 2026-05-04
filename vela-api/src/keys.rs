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
        // Spec: device_keys MUST carry the caller's user_id +
        // device_id when present, and MUST include the
        // `algorithms`, `keys`, and `signatures` required fields.
        // Bob can't upload keys claiming to be Alice; nor can a
        // client elide the cryptographic payload.
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
            && did != user.device_id
        {
            return Err(VelaError::BadJson(format!(
                "device_keys.device_id {did} does not match caller device {}",
                user.device_id
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
///
/// Spec: clients call this on their own server to discover device +
/// cross-signing keys for any user, local OR remote. We split the
/// request into local users (DB lookup) and remote users (one
/// federation `/user/keys/query` per destination server, batched per
/// remote), then merge the four top-level keys
/// (device_keys/master_keys/self_signing_keys/user_signing_keys)
/// from each branch.
pub async fn query_keys(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    body: axum::body::Bytes,
) -> Result<Json<Value>, ApiError> {
    // Manual parse so deserialize errors surface as 400 M_BAD_JSON
    // rather than axum's default 422 — Complement's
    // `TestKeysQueryWithDeviceIDAsObjectFails` asserts on 400 when
    // a client sends `device_keys.<user>: {}` (object) where a
    // sequence is required.
    let body: KeysQueryRequest = serde_json::from_slice(&body)
        .map_err(|e| ApiError(VelaError::BadJson(format!("/keys/query body: {e}"))))?;
    let mut device_keys_response: Map<String, Value> = Map::new();
    let mut master_keys: Map<String, Value> = Map::new();
    let mut self_signing_keys: Map<String, Value> = Map::new();
    let mut user_signing_keys: Map<String, Value> = Map::new();

    // Partition users by home server.
    let our_server = &state.config.server_name;
    let mut by_remote: HashMap<String, HashMap<String, Vec<String>>> = HashMap::new();
    for (user_id, device_ids) in &body.device_keys {
        match user_server(user_id) {
            Some(server) if server == our_server => {
                fold_local_user_keys(
                    &state,
                    user_id,
                    device_ids,
                    &mut device_keys_response,
                    &mut master_keys,
                    &mut self_signing_keys,
                    &mut user_signing_keys,
                )?;
            }
            Some(server) => {
                by_remote
                    .entry(server.to_string())
                    .or_default()
                    .insert(user_id.clone(), device_ids.clone());
            }
            None => {} // malformed user_id — skip silently
        }
    }

    // One federation call per remote server, fan out concurrently.
    if !by_remote.is_empty() {
        let mut futures = Vec::with_capacity(by_remote.len());
        for (server, device_keys_for_server) in by_remote {
            let body = json!({"device_keys": device_keys_for_server});
            let client = state.federation_client.clone();
            futures.push(async move {
                let resp = client.query_user_keys(&server, body).await;
                (server, resp)
            });
        }
        for (server, resp) in futures::future::join_all(futures).await {
            match resp {
                Ok(v) => merge_remote_keys_response(
                    v,
                    &mut device_keys_response,
                    &mut master_keys,
                    &mut self_signing_keys,
                    &mut user_signing_keys,
                ),
                Err(e) => {
                    tracing::debug!(remote = %server, error = %e, "remote /keys/query failed");
                }
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

/// Resolve `user_id`'s server portion (`@local:server` → `server`).
/// Returns `None` for malformed IDs so callers can skip them.
fn user_server(user_id: &str) -> Option<&str> {
    user_id.strip_prefix('@')?.split_once(':').map(|(_, s)| s)
}

/// Read a local user's device + cross-signing keys into the four
/// per-user maps that build up the /keys/query response.
pub(crate) fn fold_local_user_keys(
    state: &AppState,
    user_id: &str,
    device_ids: &[String],
    device_keys_response: &mut Map<String, Value>,
    master_keys: &mut Map<String, Value>,
    self_signing_keys: &mut Map<String, Value>,
    user_signing_keys: &mut Map<String, Value>,
) -> Result<(), ApiError> {
    let Some(user_nid) = state
        .db
        .get_nid(user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(());
    };
    let mut user_devices: Map<String, Value> = Map::new();
    let collected: Vec<(String, Value)> = if device_ids.is_empty() {
        state
            .db
            .get_all_device_keys(user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    } else {
        let mut out = Vec::with_capacity(device_ids.len());
        for device_id in device_ids {
            if let Some(keys) = state
                .db
                .get_device_keys(user_nid, device_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                out.push((device_id.clone(), keys));
            }
        }
        out
    };
    for (device_id, mut keys) in collected {
        // Spec: /keys/query carries the display name (if any) under
        // `unsigned.device_display_name`. Stored separately from the
        // crypto material in the `devices` CF — pulled in here so a
        // PUT /devices rename surfaces in the next /keys/query.
        let display_name = state
            .db
            .get_device(user_nid, &device_id)
            .ok()
            .flatten()
            .and_then(|rec| {
                rec.get("display_name")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });
        if let Some(name) = display_name
            && let Some(obj) = keys.as_object_mut()
        {
            let unsigned = obj
                .entry("unsigned".to_string())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(u) = unsigned.as_object_mut() {
                u.insert("device_display_name".to_string(), Value::String(name));
            }
        }
        user_devices.insert(device_id, keys);
    }
    device_keys_response.insert(user_id.to_string(), Value::Object(user_devices));

    let cs_keys = state
        .db
        .get_cross_signing_keys(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if let Some(k) = cs_keys.get("master_key") {
        master_keys.insert(user_id.to_string(), k.clone());
    }
    if let Some(k) = cs_keys.get("self_signing_key") {
        self_signing_keys.insert(user_id.to_string(), k.clone());
    }
    if let Some(k) = cs_keys.get("user_signing_key") {
        user_signing_keys.insert(user_id.to_string(), k.clone());
    }
    Ok(())
}

/// Fold a remote `/user/keys/query` response into the per-user maps
/// that make up our C2S /keys/query response.
fn merge_remote_keys_response(
    response: Value,
    device_keys_response: &mut Map<String, Value>,
    master_keys: &mut Map<String, Value>,
    self_signing_keys: &mut Map<String, Value>,
    user_signing_keys: &mut Map<String, Value>,
) {
    let Some(obj) = response.as_object() else {
        return;
    };
    if let Some(remote_devs) = obj.get("device_keys").and_then(|v| v.as_object()) {
        for (uid, keys) in remote_devs {
            device_keys_response.insert(uid.clone(), keys.clone());
        }
    }
    if let Some(mk) = obj.get("master_keys").and_then(|v| v.as_object()) {
        for (uid, k) in mk {
            master_keys.insert(uid.clone(), k.clone());
        }
    }
    if let Some(sk) = obj.get("self_signing_keys").and_then(|v| v.as_object()) {
        for (uid, k) in sk {
            self_signing_keys.insert(uid.clone(), k.clone());
        }
    }
    if let Some(uk) = obj.get("user_signing_keys").and_then(|v| v.as_object()) {
        for (uid, k) in uk {
            user_signing_keys.insert(uid.clone(), k.clone());
        }
    }
}

// --- Keys Claim ---

#[derive(Deserialize)]
pub struct KeysClaimRequest {
    pub one_time_keys: HashMap<String, HashMap<String, String>>,
}

/// POST /_matrix/client/v3/keys/claim
///
/// Spec: clients call this on their own server; the server is
/// responsible for federating to each owning home server. We split
/// the request into local users (DB claim under the per-user lock)
/// and remote users (one federation `/user/keys/claim` per
/// destination), then merge the per-user maps into a single response.
pub async fn claim_keys(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Json(body): Json<KeysClaimRequest>,
) -> Result<Json<Value>, ApiError> {
    let mut result: Map<String, Value> = Map::new();

    // Partition users by home server.
    let our_server = &state.config.server_name;
    let mut by_remote: HashMap<String, HashMap<String, HashMap<String, String>>> = HashMap::new();
    for (user_id, devices) in &body.one_time_keys {
        match user_server(user_id) {
            Some(server) if server == our_server => {
                claim_local_user_otks(&state, user_id, devices, &mut result).await?;
            }
            Some(server) => {
                by_remote
                    .entry(server.to_string())
                    .or_default()
                    .insert(user_id.clone(), devices.clone());
            }
            None => {} // malformed user_id — skip silently
        }
    }

    // One federation call per remote server, fan out concurrently.
    if !by_remote.is_empty() {
        let mut futures = Vec::with_capacity(by_remote.len());
        for (server, otks_for_server) in by_remote {
            let body = json!({"one_time_keys": otks_for_server});
            let client = state.federation_client.clone();
            futures.push(async move {
                let resp = client.claim_user_keys(&server, body).await;
                (server, resp)
            });
        }
        for (server, resp) in futures::future::join_all(futures).await {
            match resp {
                Ok(v) => merge_remote_claim_response(v, &mut result),
                Err(e) => {
                    tracing::debug!(remote = %server, error = %e, "remote /keys/claim failed");
                }
            }
        }
    }

    Ok(Json(json!({"one_time_keys": result})))
}

/// Claim one-time keys for a local user under the per-user lock and
/// fold the result into the per-user response map.
pub(crate) async fn claim_local_user_otks(
    state: &AppState,
    user_id: &str,
    devices: &HashMap<String, String>,
    result: &mut Map<String, Value>,
) -> Result<(), ApiError> {
    let Some(user_nid) = state
        .db
        .get_nid(user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(());
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
    // Spec: omit users for whom no keys could be claimed. The test
    // `TestFederationKeyUploadQuery/Can_claim_remote_one_time_key_using_POST`
    // pings /keys/claim a second time after exhausting the OTK and
    // asserts the user_id is *missing* from the response — an
    // empty-but-present map fails that match.
    if !user_keys.is_empty() {
        result.insert(user_id.to_string(), Value::Object(user_keys));
    }
    Ok(())
}

/// Fold a remote `/user/keys/claim` response into the per-user map
/// that makes up our C2S /keys/claim response.
fn merge_remote_claim_response(response: Value, result: &mut Map<String, Value>) {
    let Some(obj) = response.as_object() else {
        return;
    };
    let Some(remote) = obj.get("one_time_keys").and_then(|v| v.as_object()) else {
        return;
    };
    for (uid, devices) in remote {
        result.insert(uid.clone(), devices.clone());
    }
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

    // Federate the change. We send BOTH:
    //   * `m.device_list_update` — peers without `m.signing_key_update`
    //     support fall through to a `/keys/query` re-fetch and pick up
    //     the new master/self-signing keys via our federated
    //     `/keys/query` handler.
    //   * `m.signing_key_update` (proper EDU) — peers with the spec
    //     handler persist the new keys directly without the round-trip.
    // Belt-and-suspenders for compatibility with any peer in the
    // federation.
    let device_keys = state
        .db
        .get_device_keys(user.user_nid, &user.device_id)
        .ok()
        .flatten()
        .unwrap_or_else(|| Value::Object(Map::new()));
    federate_device_list_update(&state, &user, device_keys, /* deleted */ false);

    let stored = state
        .db
        .get_cross_signing_keys(user.user_nid)
        .unwrap_or_default();
    federate_signing_key_update(&state, &user, &stored);

    Ok(Json(json!({})))
}

/// Enqueue an `m.signing_key_update` EDU for every remote server
/// that shares a room with the user. Content carries the user's
/// current `master_key` and `self_signing_key`; `user_signing_key`
/// is intentionally NOT federated (it's the user's private key for
/// signing trust assertions about other users — only the local
/// server needs it).
fn federate_signing_key_update(
    state: &AppState,
    user: &AuthenticatedUser,
    cross_signing: &std::collections::HashMap<String, Value>,
) {
    use std::collections::HashSet;

    let rooms = match state.db.get_user_joined_rooms(user.user_nid) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "signing_key federate: get_user_joined_rooms failed");
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
            Err(e) => tracing::warn!(error = %e, "signing_key federate: room scan failed"),
        }
    }
    if destinations.is_empty() {
        return;
    }

    let mut content = serde_json::Map::new();
    content.insert("user_id".into(), json!(user.user_id));
    if let Some(master) = cross_signing.get("master_key") {
        content.insert("master_key".into(), master.clone());
    }
    if let Some(ssk) = cross_signing.get("self_signing_key") {
        content.insert("self_signing_key".into(), ssk.clone());
    }
    // No keys to share → nothing for peers to act on; skip the EDU.
    if !content.contains_key("master_key") && !content.contains_key("self_signing_key") {
        return;
    }
    let content_value = Value::Object(content);

    for dest in destinations {
        if let Err(e) = state
            .db
            .enqueue_signing_key_update_outbound(&dest, &content_value)
        {
            tracing::warn!(target = %dest, error = %e, "signing_key_update enqueue failed");
            continue;
        }
        state.federation_sender.notify_destination(&dest);
    }
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
/// shares any joined room with the user. Wakes the affected senders
/// so the EDU rides out promptly. No-op for users with no remote
/// audience.
///
/// `device_keys` is the device-keys object for the affected device
/// (with optional `device_display_name`). For changes that don't
/// touch crypto material — a rename, say — pass a value containing
/// just `{"device_display_name": "..."}`; receivers will re-query
/// `/keys/query` to pick up the canonical key set.
pub(crate) fn federate_device_list_update_for(
    state: &AppState,
    user_nid: u64,
    user_id: &str,
    device_id: &str,
    device_keys: Value,
    deleted: bool,
) {
    use std::collections::HashSet;

    let rooms = match state.db.get_user_joined_rooms(user_nid) {
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

    let stream_id = match state.db.bump_user_device_list_stream(user_nid) {
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
    content.insert("user_id".into(), json!(user_id));
    content.insert("device_id".into(), json!(device_id));
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

fn federate_device_list_update(
    state: &AppState,
    user: &AuthenticatedUser,
    device_keys: Value,
    deleted: bool,
) {
    federate_device_list_update_for(
        state,
        user.user_nid,
        &user.user_id,
        &user.device_id,
        device_keys,
        deleted,
    );
}

/// Bookkeeping run when a local user joins (or is joined to) a room.
/// Two effects, both required for `device_lists.changed` to behave
/// correctly per spec:
///
/// 1. Record `record_device_key_change(joiner)` so all observers — the
///    joiner's other devices and existing room-mates across all rooms —
///    see the joiner in their next `/sync` `device_lists.changed`.
///    Existing room-mates' clients re-`/keys/query` and discover any
///    new device.
/// 2. Record `notify_device_key_change(member, [joiner], pos)` for
///    every other current member of the new room, so the joiner's own
///    next `/sync` surfaces those members in `device_lists.changed`.
///    The joiner is a "fresh" observer of those users — their device
///    state is new information from the joiner's perspective.
///
/// Federation: the outbound `m.device_list_update` EDUs are emitted
/// by `federate_device_lists_on_join`; this helper is local-only.
pub fn record_device_changes_on_join(state: &AppState, user_nid: u64, room_nid: u64) {
    if let Err(e) = state.db.record_device_key_change(user_nid) {
        tracing::warn!(error = %e, "record_device_key_change on join failed");
    }
    let stream_pos = state.db.next_stream_position().as_u64();
    if let Ok(members) = state.db.get_room_members(room_nid) {
        for member_nid in members {
            if member_nid == user_nid {
                continue;
            }
            if let Err(e) = state
                .db
                .notify_device_key_change(member_nid, &[user_nid], stream_pos)
            {
                tracing::warn!(error = %e, "notify_device_key_change on join failed");
            }
        }
    }
    crate::router::notify_user(state, user_nid);
}

/// Bookkeeping run when a member is about to leave (or be banned/
/// kicked from) `room_nid`. The "no longer shared" relation is
/// symmetric: every remaining member loses the leaver from their
/// shared-room set, AND the leaver themselves loses every remaining
/// member. We write `device_list_left` entries in both directions so
/// /sync's `device_lists.left` is correct from either side.
///
/// Must be called BEFORE updating memberships so `get_room_members`
/// still returns the full member list including the departing user.
/// The post-filter in /sync deals with the case where two users
/// still share another room.
pub fn record_device_changes_on_leave(state: &AppState, departing_nid: u64, room_nid: u64) {
    let members = match state.db.get_room_members(room_nid) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "device_list_left: get_room_members failed");
            return;
        }
    };
    if members.is_empty() {
        return;
    }
    let stream_pos = state.db.next_stream_position().as_u64();

    // Direction 1: from each remaining member's perspective, the
    // departing user has left.
    if let Err(e) = state
        .db
        .record_peer_departure(departing_nid, &members, stream_pos)
    {
        tracing::warn!(error = %e, "record_peer_departure (forward) failed");
    }

    // Direction 2: from the departing user's perspective, each
    // remaining member has dropped out of their shared set. Skip
    // remote-domain peers because their server publishes its own
    // membership transitions independently.
    let our_server = state.config.server_name.as_str();
    let leaver_is_local = state
        .db
        .resolve_nid(departing_nid)
        .ok()
        .flatten()
        .and_then(|s| s.split_once(':').map(|(_, d)| d.to_string()))
        .map(|d| d == our_server)
        .unwrap_or(false);
    if leaver_is_local {
        for &peer in &members {
            if peer == departing_nid {
                continue;
            }
            if let Err(e) = state
                .db
                .record_peer_departure(peer, &[departing_nid], stream_pos)
            {
                tracing::warn!(error = %e, "record_peer_departure (reverse) failed");
            }
        }
    }

    for &obs in &members {
        if obs == departing_nid {
            continue;
        }
        crate::router::notify_user(state, obs);
    }
    if leaver_is_local {
        crate::router::notify_user(state, departing_nid);
    }
}

/// Push `m.device_list_update` EDUs for every device the local user
/// owns to every remote server in the room they just joined. Spec:
///
/// > Servers must send m.device_list_update EDUs to all the servers
/// > who share a room with a given local user … when that user joins
/// > a room which contains servers which are not already receiving
/// > updates for that user's device list.
///
/// Without this, a remote server has no record of the joiner's
/// devices until the user uploads keys again — clients on the remote
/// won't see the joiner appear in `device_lists.changed` after a
/// federation join.
pub fn federate_device_lists_on_join(
    state: &AppState,
    user_nid: u64,
    user_id: &str,
    room_nid: u64,
) {
    let destinations = match state
        .db
        .get_remote_servers_in_room(room_nid, &state.config.server_name)
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "device_list join-federate: room scan failed");
            return;
        }
    };
    if destinations.is_empty() {
        return;
    }

    let devices = match state.db.list_devices(user_nid) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, "device_list join-federate: list_devices failed");
            return;
        }
    };
    if devices.is_empty() {
        return;
    }

    for device in &devices {
        let Some(device_id) = device.get("device_id").and_then(|v| v.as_str()) else {
            continue;
        };

        let device_keys = state.db.get_device_keys(user_nid, device_id).ok().flatten();

        let stream_id = match state.db.bump_user_device_list_stream(user_nid) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "device_list join-federate: stream bump failed");
                return;
            }
        };

        let display_name = device_keys
            .as_ref()
            .and_then(|v| v.get("device_display_name"))
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| {
                device
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            });

        let mut content = serde_json::Map::new();
        content.insert("user_id".into(), json!(user_id));
        content.insert("device_id".into(), json!(device_id));
        content.insert("stream_id".into(), json!(stream_id));
        content.insert("deleted".into(), json!(false));
        if let Some(name) = display_name {
            content.insert("device_display_name".into(), json!(name));
        }
        if let Some(keys) = device_keys {
            content.insert("keys".into(), keys);
        }
        let content_value = Value::Object(content);

        for dest in &destinations {
            if let Err(e) = state.db.enqueue_device_list_outbound(dest, &content_value) {
                tracing::warn!(target = %dest, error = %e, "device_list enqueue (join) failed");
                continue;
            }
            state.federation_sender.notify_destination(dest);
        }
    }
}

// --- Federation key endpoints ---

/// POST /_matrix/federation/v1/user/keys/query
///
/// Federation companion to the C2S `/keys/query`. Same body shape:
/// `{device_keys: {user_id: [device_id, ...]}}`. We respond ONLY
/// for users on our own server — peers serve their own users.
///
/// Spec response omits `user_signing_keys` (private to the user's
/// home server); we discard the map populated by
/// `fold_local_user_keys` rather than maintain a separate
/// federation-only helper.
pub async fn federation_query_keys(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Extension(_origin): axum::extract::Extension<
        crate::middleware::federation_auth::XMatrixOrigin,
    >,
    axum::extract::Extension(crate::middleware::federation_auth::VerifiedBody(body)): axum::extract::Extension<crate::middleware::federation_auth::VerifiedBody>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    let body = body.ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    let req: KeysQueryRequest =
        serde_json::from_value(body).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    let mut device_keys_response: Map<String, Value> = Map::new();
    let mut master_keys: Map<String, Value> = Map::new();
    let mut self_signing_keys: Map<String, Value> = Map::new();
    let mut user_signing_keys_discard: Map<String, Value> = Map::new();

    let our_server = state.config.server_name.as_str();
    for (user_id, device_ids) in &req.device_keys {
        if user_server(user_id) != Some(our_server) {
            continue;
        }
        fold_local_user_keys(
            &state,
            user_id,
            device_ids,
            &mut device_keys_response,
            &mut master_keys,
            &mut self_signing_keys,
            &mut user_signing_keys_discard,
        )
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(json!({
        "device_keys": device_keys_response,
        "master_keys": master_keys,
        "self_signing_keys": self_signing_keys,
    })))
}

/// POST /_matrix/federation/v1/user/keys/claim
///
/// Federation companion to the C2S `/keys/claim`. Body:
/// `{one_time_keys: {user_id: {device_id: algorithm}}}`. Claims
/// happen under the per-user lock so two concurrent peers don't
/// both win the same one-time key.
pub async fn federation_claim_keys(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Extension(_origin): axum::extract::Extension<
        crate::middleware::federation_auth::XMatrixOrigin,
    >,
    axum::extract::Extension(crate::middleware::federation_auth::VerifiedBody(body)): axum::extract::Extension<crate::middleware::federation_auth::VerifiedBody>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    let body = body.ok_or(axum::http::StatusCode::BAD_REQUEST)?;
    let req: KeysClaimRequest =
        serde_json::from_value(body).map_err(|_| axum::http::StatusCode::BAD_REQUEST)?;

    let mut result: Map<String, Value> = Map::new();
    let our_server = state.config.server_name.as_str();
    for (user_id, devices) in &req.one_time_keys {
        if user_server(user_id) != Some(our_server) {
            continue;
        }
        claim_local_user_otks(&state, user_id, devices, &mut result)
            .await
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    }

    Ok(Json(json!({ "one_time_keys": result })))
}
