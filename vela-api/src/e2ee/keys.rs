use std::collections::HashMap;

use crate::middleware::json::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vela_core::error::VelaError;
use vela_core::federation::keys::{decode_public_key, verify_json_signature};

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

// --- Keys Upload ---

#[derive(Deserialize)]
pub struct KeysUploadRequest {
    pub device_keys: Option<Value>,
    pub one_time_keys: Option<Map<String, Value>>,
    /// MSC2732 fallback keys. Accept both the stable `fallback_keys` field and
    /// the unstable `org.matrix.msc2732:fallback_keys` name older clients send.
    #[serde(default, alias = "org.matrix.msc2732:fallback_keys")]
    pub fallback_keys: Option<Map<String, Value>>,
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

        // Preserve cross-signing signatures a re-upload would otherwise
        // drop. The device only ever signs itself; the self_signing-key
        // signature that marks it verified was added separately via
        // /keys/signatures/upload and lives only in the stored copy.
        let mut device_keys = device_keys.clone();
        let existing = state
            .db
            .get_device_keys(user.user_nid, &user.device_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        preserve_existing_signatures(existing.as_ref(), &mut device_keys);

        state
            .db
            .set_device_keys(user.user_nid, &user.device_id, &device_keys)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        // Tell our observers (self + joined room-mates) to re-query.
        let _ = state.db.record_device_key_change(user.user_nid);
        crate::router::notify_user(&state, user.user_nid);
        // Federate the change to remote servers sharing a room with
        // this user. Spec: m.device_list_update EDU per destination
        // with a per-user monotonic stream_id. Moves the merged keys —
        // this is their last use.
        federate_device_list_update(&state, &user, device_keys, /* deleted */ false);
    }

    if let Some(otks) = &body.one_time_keys
        && !otks.is_empty()
    {
        state
            .db
            .add_one_time_keys(user.user_nid, &user.device_id, otks)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    // MSC2732 fallback keys: stored one-per-algorithm, kept after claim, and
    // handed out when the device's one-time keys are exhausted.
    if let Some(fallback) = &body.fallback_keys
        && !fallback.is_empty()
    {
        // Serialize against /keys/claim, which read-modify-writes the `used`
        // flag under this same per-user lock. Without it, a claim landing
        // between this upload's read and write could mark a freshly-uploaded
        // fallback key used and keep serving the old one.
        let lock = state
            .user_locks
            .entry(user.user_nid)
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;
        state
            .db
            .set_fallback_keys(user.user_nid, &user.device_id, fallback)
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
    user: AuthenticatedUser,
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

    // Partition users by home server. For remote users, consult the
    // per-user cache first — a cache hit means the last
    // `/user/keys/query` response is still fresh (no
    // m.device_list_update EDU or full-room-leave has invalidated it).
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
                // Pre-existing members of a partial-state room don't
                // exist in our `memberships` index yet — the bundle
                // omits them and we won't learn about them until the
                // filler completes. For those users we must federate
                // every /keys/query (no caching) because we don't
                // even know they're tracking us yet. New joiners
                // (delivered via /send → process_pdu → set_membership)
                // ARE in memberships and cache normally.
                if let Ok(Some(user_nid)) = state.db.get_nid(user_id) {
                    let known_member = state
                        .db
                        .get_user_joined_rooms(user_nid)
                        .map(|r| !r.is_empty())
                        .unwrap_or(false);
                    if known_member
                        && let Ok(Some(cached)) = state.db.get_remote_user_keys_cache(user_nid)
                    {
                        fold_cached_remote_user(
                            &cached,
                            user_id,
                            device_ids,
                            &mut device_keys_response,
                            &mut master_keys,
                            &mut self_signing_keys,
                            &mut user_signing_keys,
                        );
                        continue;
                    }
                }
                by_remote
                    .entry(server.to_string())
                    .or_default()
                    .insert(user_id.clone(), device_ids.clone());
            }
            None => {} // malformed user_id — skip silently
        }
    }

    // One federation call per remote server, fan out concurrently.
    // Persist the per-user pieces of each response into the cache so
    // the next /keys/query for the same user short-circuits above.
    if !by_remote.is_empty() {
        use futures::StreamExt;
        // Bound the outbound fan-out. A single client request can name users
        // on arbitrarily many remote servers; firing one federation call per
        // server concurrently turns one request into a connection/DNS
        // amplifier. Cap how many run at once.
        const MAX_CONCURRENT_REMOTE_KEY_QUERIES: usize = 16;
        let results = futures::stream::iter(by_remote.into_iter().map(
            |(server, device_keys_for_server)| {
                let body = json!({ "device_keys": device_keys_for_server });
                let client = state.federation_client.clone();
                async move {
                    let resp = client.query_user_keys(&server, body).await;
                    (server, resp)
                }
            },
        ))
        .buffer_unordered(MAX_CONCURRENT_REMOTE_KEY_QUERIES)
        .collect::<Vec<_>>()
        .await;
        for (server, resp) in results {
            match resp {
                Ok(v) => {
                    persist_remote_keys_response_to_cache(&state, &v);
                    merge_remote_keys_response(
                        v,
                        &mut device_keys_response,
                        &mut master_keys,
                        &mut self_signing_keys,
                        &mut user_signing_keys,
                    );
                }
                Err(e) => {
                    tracing::debug!(remote = %server, error = %e, "remote /keys/query failed");
                }
            }
        }
    }

    // Spec: `user_signing_keys` is returned ONLY for the requesting user,
    // and only when they queried their own keys. Master + self_signing are
    // public (returned for every queried user); the user-signing key is
    // not. Leaking another user's user-signing key also breaks clients:
    // matrix-rust-sdk builds OTHER users' identities with master +
    // self_signing only, so an unexpected user-signing key corrupts that
    // identity's processing and a verified user is shown as untrusted.
    user_signing_keys.retain(|uid, _| uid == &user.user_id);

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

/// Project a single remote user's cached `/user/keys/query` payload
/// into the C2S response maps. The cache value is shaped per-user (see
/// `cache_remote_user_keys` in `vela-store`); we filter the `devices`
/// map to the requested `device_ids` (empty = all) and forward the
/// cross-signing keys verbatim.
fn fold_cached_remote_user(
    cached: &Value,
    user_id: &str,
    device_ids: &[String],
    device_keys_response: &mut Map<String, Value>,
    master_keys: &mut Map<String, Value>,
    self_signing_keys: &mut Map<String, Value>,
    user_signing_keys: &mut Map<String, Value>,
) {
    let Some(obj) = cached.as_object() else {
        return;
    };
    if let Some(devices) = obj.get("devices").and_then(|v| v.as_object()) {
        if device_ids.is_empty() {
            device_keys_response.insert(user_id.to_string(), Value::Object(devices.clone()));
        } else {
            let mut filtered = Map::new();
            for did in device_ids {
                if let Some(k) = devices.get(did) {
                    filtered.insert(did.clone(), k.clone());
                }
            }
            if !filtered.is_empty() {
                device_keys_response.insert(user_id.to_string(), Value::Object(filtered));
            }
        }
    }
    if let Some(mk) = obj.get("master_key") {
        master_keys.insert(user_id.to_string(), mk.clone());
    }
    if let Some(sk) = obj.get("self_signing_key") {
        self_signing_keys.insert(user_id.to_string(), sk.clone());
    }
    if let Some(uk) = obj.get("user_signing_key") {
        user_signing_keys.insert(user_id.to_string(), uk.clone());
    }
}

/// Split a federation `/user/keys/query` response into its per-user
/// pieces and write each piece into the remote-device cache. Each
/// piece is the shape `fold_cached_remote_user` expects to read back.
fn persist_remote_keys_response_to_cache(state: &AppState, response: &Value) {
    let Some(obj) = response.as_object() else {
        return;
    };
    let mut per_user: HashMap<String, Map<String, Value>> = HashMap::new();
    if let Some(devs) = obj.get("device_keys").and_then(|v| v.as_object()) {
        for (uid, devices) in devs {
            per_user
                .entry(uid.clone())
                .or_default()
                .insert("devices".into(), devices.clone());
        }
    }
    for (response_key, target_key) in [
        ("master_keys", "master_key"),
        ("self_signing_keys", "self_signing_key"),
        ("user_signing_keys", "user_signing_key"),
    ] {
        if let Some(map) = obj.get(response_key).and_then(|v| v.as_object()) {
            for (uid, k) in map {
                per_user
                    .entry(uid.clone())
                    .or_default()
                    .insert(target_key.into(), k.clone());
            }
        }
    }
    for (uid, payload) in per_user {
        let Ok(user_nid) = state.db.get_or_create_nid(&uid) else {
            continue;
        };
        // Symmetric with the read path: only cache users whose local
        // membership tells us they belong to a room with a local
        // observer. Caching a pre-existing partial-state member's
        // response here would leak across the filler-clear boundary —
        // the first /keys/query after clear must refetch so the
        // observer learns whatever the resident peer surfaced about
        // the user during the partial-state window.
        let known_member = state
            .db
            .get_user_joined_rooms(user_nid)
            .map(|r| !r.is_empty())
            .unwrap_or(false);
        if !known_member {
            continue;
        }
        let value = Value::Object(payload);
        if let Err(e) = state.db.cache_remote_user_keys(user_nid, &value) {
            tracing::debug!(%uid, error = %e, "cache_remote_user_keys failed");
        }
    }
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

    // One federation call per remote server. Bound the concurrency for the
    // same reason as /keys/query: a client request can name users on many
    // servers, and unbounded fan-out is a connection/DNS amplifier.
    if !by_remote.is_empty() {
        use futures::StreamExt;
        const MAX_CONCURRENT_REMOTE_KEY_CLAIMS: usize = 16;
        let results =
            futures::stream::iter(by_remote.into_iter().map(|(server, otks_for_server)| {
                let body = json!({ "one_time_keys": otks_for_server });
                let client = state.federation_client.clone();
                async move {
                    let resp = client.claim_user_keys(&server, body).await;
                    (server, resp)
                }
            }))
            .buffer_unordered(MAX_CONCURRENT_REMOTE_KEY_CLAIMS)
            .collect::<Vec<_>>()
            .await;
        for (server, resp) in results {
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
        // Prefer a one-time key; fall back to the device's MSC2732 fallback key
        // when the OTKs are exhausted (kept, not consumed) so the sender can
        // still establish an Olm session instead of getting nothing.
        let claimed = match state
            .db
            .claim_one_time_key(user_nid, device_id, algorithm)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(otk) => Some(otk),
            None => state
                .db
                .claim_fallback_key(user_nid, device_id, algorithm)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?,
        };
        if let Some((key_id, key_data)) = claimed {
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

/// Device-list `changed` user-nids for an incremental window `[from, to)`,
/// with the fall-behind guard shared by `/sync` and `/keys/changes`.
///
/// If `from` predates the device-list prune horizon, the retained change
/// entries for that window are incomplete (the retention pruner removed
/// them), so we over-report every user the caller shares a room with —
/// forcing a full `/keys/query`. Over-reporting is safe (an extra
/// refetch); under-reporting would silently leave stale device keys after
/// a long absence. `from == 0` (initial sync / no prior token) is never
/// guarded: the spec only populates `device_lists` for incremental syncs.
pub(crate) fn device_list_changed_nids(
    state: &AppState,
    user_nid: u64,
    from: u64,
    to: u64,
) -> Result<Vec<u64>, ApiError> {
    // Read the precise list FIRST, then the horizon. The pruner commits its
    // deletes and the new horizon in one atomic batch, so a horizon read
    // that happens-after the change read is guaranteed to reflect any prune
    // that could have dropped an entry from the window we just read. Reading
    // the horizon first would leave a race where a concurrent prune slips a
    // gap past the guard and the client permanently misses a change.
    let precise = state
        .db
        .get_device_key_changes(user_nid, from, to)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if from > 0 && from <= state.db.device_list_prune_horizon() {
        // Fell behind the retained window → over-report. The precise path
        // always reports the caller's OWN changes too (the user is always
        // their own observer), so self must be in the over-report set or a
        // client whose own device list changed wouldn't re-query itself.
        let mut nids = state
            .db
            .users_sharing_room_with(user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        nids.push(user_nid);
        return Ok(nids);
    }
    Ok(precise)
}

/// GET /_matrix/client/v3/keys/changes
pub async fn key_changes(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<KeyChangesQuery>,
) -> Result<Json<Value>, ApiError> {
    let from: u64 = query.from.parse().unwrap_or(0);
    let to: u64 = query.to.parse().unwrap_or(u64::MAX);

    let changed_nids = device_list_changed_nids(&state, user.user_nid, from, to)?;

    // `left`: users with whom the caller no longer shares ANY room
    // within the [from, to) window. Mirrors /sync's device_lists.left
    // computation: take the raw "departed-from-shared-room" events,
    // post-filter against current shared-room membership so a user
    // who left one room but still shares another isn't reported.
    let raw_left = state
        .db
        .get_device_list_left(user.user_nid, from, to)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let our_rooms = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .unwrap_or_default();
    let mut left = Vec::new();
    for nid in raw_left {
        let still_sharing = our_rooms
            .iter()
            .any(|&room_nid| state.db.get_membership(room_nid, nid).ok().flatten() == Some(1));
        if still_sharing {
            continue;
        }
        if let Some(uid) = state
            .db
            .resolve_nid(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            left.push(Value::String(uid));
        }
    }

    // Spec: a user appearing in both `changed` and `left` should only
    // appear in `left` (the stronger signal). Sync follows the same rule.
    let left_set: std::collections::HashSet<String> = left
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    let mut changed = Vec::new();
    for nid in changed_nids {
        if let Some(user_id) = state
            .db
            .resolve_nid(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && !left_set.contains(&user_id)
        {
            changed.push(Value::String(user_id));
        }
    }

    Ok(Json(json!({
        "changed": changed,
        "left": left,
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
    // Decide whether UIA is required. Per MSC3967:
    //   * No keys on file yet → first-time setup, skip UIA.
    //   * Existing keys but the new body matches them exactly (no slot
    //     differs, no new slot introduced) → idempotent re-upload, skip
    //     UIA.
    //   * Any slot in the new body that's either changing an existing
    //     value OR populating a previously-empty slot → require UIA.
    //     "Adding a self_signing_key when only master_key was on file"
    //     is itself a key-material change clients must re-authenticate
    //     to authorise.
    let existing = state
        .db
        .get_cross_signing_keys(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let any_change = ["master_key", "self_signing_key", "user_signing_key"]
        .iter()
        .any(|slot| {
            let new = body.get(*slot).filter(|v| !v.is_null());
            let old = existing.get(*slot);
            match (new, old) {
                // Compare SIGNED CONTENT, not the whole object: a stored key
                // accumulates device signatures (via /keys/signatures/upload)
                // that a bare re-upload doesn't carry, and a signature-only
                // difference is not a key-material change — gating it behind
                // UIA spuriously prompts for a password on an idempotent
                // re-upload. UIA still fires when the key material changes.
                (Some(n), Some(o)) => signed_content(n) != signed_content(o),
                (Some(_), None) => true,
                _ => false,
            }
        });
    if !existing.is_empty() && any_change {
        crate::auth::uia::require_uia_identifier_matches(&state, &body, &user.user_id)?;
        crate::auth::uia::require_password_auth(&state, &body).await?;
    }

    // Pull the three optional key fields from the JSON body.
    let mut master_key = body.get("master_key").filter(|v| !v.is_null()).cloned();
    let mut self_signing_key = body
        .get("self_signing_key")
        .filter(|v| !v.is_null())
        .cloned();
    let mut user_signing_key = body
        .get("user_signing_key")
        .filter(|v| !v.is_null())
        .cloned();

    // The master key that anchors this upload's cross-signing links: the one
    // in the request, else the most-recently-stored master. Spec: a
    // self/user-signing key "must be signed by the accompanying master
    // signing key, or by the user's most recently uploaded master signing
    // key if no master signing key is included in the request." Its public
    // key lives in `keys`, which signature preservation below never touches,
    // so cloning the pre-preserve value is fine.
    let effective_master = master_key
        .clone()
        .or_else(|| existing.get("master_key").cloned());

    // Preserve signatures across an idempotent re-upload (same key
    // material): a device's signature on the master key, or the
    // self_signing signature, was added via /keys/signatures/upload and
    // lives only in the stored copy — re-uploading the bare key would drop
    // it and break verification. `existing` was fetched above for the UIA
    // gate. Fold those back in FIRST, then verify the cross-signing links
    // over the merged key so a bare idempotent re-upload (master signature
    // restored from storage) still verifies, while a genuinely new/changed
    // key must carry a valid master signature of its own.
    if let Some(key) = master_key.as_mut() {
        preserve_existing_signatures(existing.get("master_key"), key);
    }
    if let Some(key) = self_signing_key.as_mut() {
        preserve_existing_signatures(existing.get("self_signing_key"), key);
        verify_signed_by_master(key, &user.user_id, effective_master.as_ref())?;
    }
    if let Some(key) = user_signing_key.as_mut() {
        preserve_existing_signatures(existing.get("user_signing_key"), key);
        verify_signed_by_master(key, &user.user_id, effective_master.as_ref())?;
    }

    // Persist only after every cross-signing link verified, so a mis-signed
    // key is rejected atomically with no partial write.
    if let Some(key) = &master_key {
        state
            .db
            .set_cross_signing_keys(user.user_nid, "master_key", key)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    if let Some(key) = &self_signing_key {
        state
            .db
            .set_cross_signing_keys(user.user_nid, "self_signing_key", key)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    if let Some(key) = &user_signing_key {
        state
            .db
            .set_cross_signing_keys(user.user_nid, "user_signing_key", key)
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
    user: AuthenticatedUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let Some(users) = body.as_object() else {
        return Ok(Json(json!({"failures": {}})));
    };
    // The caller may only contribute signatures made by keys they've
    // published; anything else is dropped before it's folded into a target's
    // key record (see retain_published_signatures).
    let allowed = caller_published_key_ids(&state, user.user_nid)?;
    let mut changed_users: Vec<u64> = Vec::new();
    for (target_user_id, devs) in users {
        let Some(dev_map) = devs.as_object() else {
            continue;
        };
        let Some(target_nid) = state
            .db
            .get_nid(target_user_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        // A user may only upload signatures THEY produced: self-signatures on
        // their own devices and master key, or their user_signing-key
        // signature on ANOTHER user's master key. So cross-user uploads are
        // limited to the target's master key; signing another user's device
        // is never allowed.
        let is_self = target_user_id == &user.user_id;
        let mut touched = false;
        for (dev_or_key_id, new_body) in dev_map {
            // Accept only the signatures attributed to the caller — a client
            // can't forge a signature in another user's name.
            let Some(filtered) = caller_signatures_only(new_body, &user.user_id) else {
                continue;
            };
            // Keep only signatures from the caller's own published keys.
            let Some(filtered) = retain_published_signatures(filtered, &user.user_id, &allowed)
            else {
                continue;
            };
            // Own device keys (typical self-signature). Cross-user device
            // signing is refused by gating on `is_self`.
            if is_self
                && let Some(mut existing) = state
                    .db
                    .get_device_keys(target_nid, dev_or_key_id)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                merge_signatures(&mut existing, &filtered);
                state
                    .db
                    .set_device_keys(target_nid, dev_or_key_id, &existing)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                touched = true;
                continue;
            }
            // Cross-signing keys are addressed by their public key id, so we
            // scan the target's stored cross-signing records and fold into
            // whichever one owns the supplied key id. For a cross-user upload
            // only the master key is eligible.
            let all_xs = state
                .db
                .get_cross_signing_keys(target_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            for (xs_type, mut existing) in all_xs {
                if !is_self && xs_type != "master_key" {
                    continue;
                }
                let matches = existing
                    .get("keys")
                    .and_then(|k| k.as_object())
                    .map(|m| {
                        // Match the stored key id exactly, or by bare-pubkey
                        // suffix when the client omitted the `ed25519:` prefix.
                        // Guard the empty id: `"".ends_with("")` is true, which
                        // would otherwise match the master key unconditionally.
                        m.keys().any(|k| {
                            k == dev_or_key_id
                                || (!dev_or_key_id.is_empty() && k.ends_with(dev_or_key_id))
                        })
                    })
                    .unwrap_or(false);
                if matches {
                    merge_signatures(&mut existing, &filtered);
                    state
                        .db
                        .set_cross_signing_keys(target_nid, &xs_type, &existing)
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                    touched = true;
                    break;
                }
            }
        }
        if touched && !changed_users.contains(&target_nid) {
            changed_users.push(target_nid);
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

/// Reduce an uploaded `{…, signatures}` object to ONLY the signatures the
/// authenticated caller produced (`signatures[caller]`). Returns `None` when
/// the caller contributed nothing — a client may upload only its own
/// signatures (self-signing its devices/master, or user-signing another
/// user's master), never one attributed to a different user.
fn caller_signatures_only(new_body: &Value, caller: &str) -> Option<Value> {
    let mine = new_body
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|sigs| sigs.get(caller))?;
    let mut signer = Map::new();
    signer.insert(caller.to_string(), mine.clone());
    Some(json!({ "signatures": Value::Object(signer) }))
}

/// The set of ed25519 signing key ids the user has PUBLISHED: their device
/// keys plus their cross-signing (master / self_signing / user_signing)
/// public keys. A client only ever signs with a key it has published, so
/// this is exactly the set of key ids a legitimate `signatures/upload` can
/// carry.
fn caller_published_key_ids(
    state: &AppState,
    caller_nid: u64,
) -> Result<std::collections::HashSet<String>, ApiError> {
    let mut ids = std::collections::HashSet::new();
    for (_device, dk) in state
        .db
        .get_all_device_keys(caller_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        if let Some(keys) = dk.get("keys").and_then(|k| k.as_object()) {
            ids.extend(keys.keys().filter(|k| k.starts_with("ed25519:")).cloned());
        }
    }
    for (_ty, xs) in state
        .db
        .get_cross_signing_keys(caller_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        if let Some(keys) = xs.get("keys").and_then(|k| k.as_object()) {
            ids.extend(keys.keys().filter(|k| k.starts_with("ed25519:")).cloned());
        }
    }
    Ok(ids)
}

/// Drop any signature whose signing key id is NOT one of the caller's
/// published keys. A client signs only with keys it has published, so this
/// never drops a legitimate signature — but it stops a caller from folding
/// arbitrary, unbounded `(key_id -> blob)` entries under fake key ids into
/// ANOTHER user's published key record (a cross-user write / storage
/// amplification). Returns `None` when nothing the caller is entitled to
/// remains. (Cryptographic verification of the signature bytes is left to
/// clients, which already reject invalid signatures.)
fn retain_published_signatures(
    filtered: Value,
    caller: &str,
    allowed: &std::collections::HashSet<String>,
) -> Option<Value> {
    let mine = filtered
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(caller))
        .and_then(|v| v.as_object())?;
    let kept: Map<String, Value> = mine
        .iter()
        .filter(|(kid, _)| allowed.contains(kid.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if kept.is_empty() {
        return None;
    }
    let mut signer = Map::new();
    signer.insert(caller.to_string(), Value::Object(kept));
    Some(json!({ "signatures": Value::Object(signer) }))
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

/// A key object reduced to exactly the bytes its signatures cover: the
/// whole object minus `signatures` and `unsigned`. Two keys with equal
/// `signed_content` are signed over identical material (`user_id`,
/// `device_id`, `algorithms`, `keys`, `usage`, …); a stored signature is
/// valid against one iff it's valid against the other.
fn signed_content(key: &Value) -> Value {
    let mut c = key.clone();
    if let Some(obj) = c.as_object_mut() {
        obj.remove("signatures");
        obj.remove("unsigned");
    }
    c
}

/// Verify a self-signing or user-signing key is signed by the user's master
/// cross-signing key, per the `/keys/device_signing/upload` contract: the
/// SSK/USK "must be signed by the accompanying master signing key, or by the
/// user's most recently uploaded master signing key if no master signing key
/// is included in the request." A key whose master signature is absent,
/// malformed, or invalid is rejected with `M_INVALID_SIGNATURE` (400) so we
/// never persist — nor serve to `/keys/query` — a cross-signing identity that
/// every other client would reject.
fn verify_signed_by_master(
    key: &Value,
    user_id: &str,
    master: Option<&Value>,
) -> Result<(), ApiError> {
    let invalid = |msg: &str| {
        ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_INVALID_SIGNATURE",
            msg: msg.to_string(),
        })
    };

    // A signing key with no master to anchor it can never be validated.
    let master = master.ok_or_else(|| invalid("no master key to sign the cross-signing key"))?;

    // The master key object is `{keys: {"ed25519:<pub>": "<pub>"}, ...}`; its
    // single entry gives both the signature key_id and the public key. Cross-
    // signing key_ids embed the unpadded-base64 public key, so `keys` carries
    // everything needed to verify without a separate lookup.
    let (master_key_id, master_pub_b64) = master
        .get("keys")
        .and_then(|k| k.as_object())
        .and_then(|m| m.iter().next())
        .ok_or_else(|| invalid("master key has no key material"))?;
    let master_pub_b64 = master_pub_b64
        .as_str()
        .ok_or_else(|| invalid("master public key is not a string"))?;
    let master_pub = decode_public_key(master_pub_b64)
        .map_err(|_| invalid("master public key is not ed25519"))?;

    let key_obj = key
        .as_object()
        .ok_or_else(|| invalid("cross-signing key is not an object"))?;

    verify_json_signature(key_obj, user_id, master_key_id, &master_pub)
        .map_err(|_| invalid("cross-signing key is not signed by the master key"))
}

/// Fold the signatures from a previously stored key into a fresh upload of
/// the SAME key. A client re-uploading a device key or cross-signing key
/// carries only its own signature(s); signatures added by other signers —
/// the self_signing key cross-signing a device, or a device signing the
/// master key, via `/keys/signatures/upload` — live only in the stored
/// copy. Without folding them back in, a re-upload silently drops them and
/// the key reverts to "unverified" across every client.
///
/// Preserved ONLY when the full SIGNED CONTENT is byte-identical: a stored
/// signature is valid over exactly the bytes it signed, so any change to a
/// signed field (not just `keys` — also `algorithms`/`usage`) invalidates
/// it, and a stale signature carried onto changed content would just fail
/// client verification (still "unverified"). The fresh upload's OWN
/// signatures always win; stored signatures are folded in only for
/// `(signer, key_id)` pairs the upload doesn't already carry — so a
/// re-signed self-signature is never clobbered by the stored one.
fn preserve_existing_signatures(existing: Option<&Value>, new_key: &mut Value) {
    let Some(old) = existing else {
        return;
    };
    if signed_content(old) != signed_content(new_key) {
        return;
    }
    let Some(old_sigs) = old.get("signatures").and_then(|v| v.as_object()) else {
        return;
    };
    let Some(new_obj) = new_key.as_object_mut() else {
        return;
    };
    let new_sigs = new_obj
        .entry("signatures".to_string())
        .or_insert_with(|| json!({}));
    let Some(new_sigs) = new_sigs.as_object_mut() else {
        return;
    };
    for (signer, key_map) in old_sigs {
        let Some(old_keys) = key_map.as_object() else {
            continue;
        };
        let entry = new_sigs.entry(signer.clone()).or_insert_with(|| json!({}));
        let Some(entry_obj) = entry.as_object_mut() else {
            continue;
        };
        for (key_id, sig) in old_keys {
            // new-wins: only fill in signatures the fresh upload lacks.
            entry_obj
                .entry(key_id.clone())
                .or_insert_with(|| sig.clone());
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
    // Rooms where we pruned a partial-state hint server because the
    // local view contradicted it — queued for replay if the filler
    // clear later proves the hint was right after all.
    let mut partial_state_rooms_with_pruning: Vec<u64> = Vec::new();
    for room_nid in rooms {
        match state
            .db
            .get_remote_servers_in_room(room_nid, &state.config.server_name)
        {
            Ok(servers) => destinations.extend(servers),
            Err(e) => tracing::warn!(error = %e, "device_list federate: room scan failed"),
        }
        // MSC3902: for partial-state rooms the local memberships index
        // doesn't list every peer the resident server already knows
        // about. Union in `servers_in_room` from the partial-state
        // record so device-list updates reach every server the
        // resident server tells us is in the room. The replay queue
        // below ALSO records every send during partial state so the
        // filler's clear-time sweep can re-fan to any server the
        // full state proves should also have received the update.
        if let Ok((true, hint_servers)) = state.db.get_partial_state_info(room_nid) {
            let mut hint_unioned = false;
            for s in hint_servers {
                if s != state.config.server_name && destinations.insert(s) {
                    hint_unioned = true;
                }
            }
            // Track every partial-state room so the replay queue
            // captures this update — `incorrectly_kicked/absent`
            // tests want updates that vela's view DID send to reach
            // peers we may have incorrectly excluded. Belt-and-braces:
            // the hint already covers the easy case; the queue
            // covers the case where local belief diverged.
            if hint_unioned || partial_state_rooms_with_pruning.last() != Some(&room_nid) {
                partial_state_rooms_with_pruning.push(room_nid);
            }
        }
    }
    if destinations.is_empty() && partial_state_rooms_with_pruning.is_empty() {
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

    let sent_destinations: Vec<String> = destinations.iter().cloned().collect();
    for dest in destinations {
        if let Err(e) = state.db.enqueue_device_list_outbound(&dest, &content_value) {
            tracing::warn!(target = %dest, error = %e, "device_list enqueue failed");
            continue;
        }
        state.federation_sender.notify_destination(&dest);
    }

    // MSC3902 replay queue. For each partial-state room where we
    // pruned a hint server based on local view, persist the content
    // payload so the filler's clear-time sweep can re-fan it to
    // whichever servers the full state now proves we should have
    // reached. Records the live destinations so the replay skips
    // duplicate delivery to peers that already received this stream_id.
    // Keyed by (room_nid, user_nid, stream_id) → {content, sent_to}.
    for room_nid in partial_state_rooms_with_pruning {
        if let Err(e) = state.db.mark_partial_state_pending_dlu(
            room_nid,
            user_nid,
            stream_id,
            &content_value,
            &sent_destinations,
        ) {
            tracing::warn!(error = %e, "mark_partial_state_pending_dlu failed");
        }
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
/// Per spec:
///
/// - Every other current member of the new room gets the joiner
///   added to their next /sync `device_lists.changed`.
/// - The joiner gets every other member added to its own /sync
///   `device_lists.changed` (now-share-a-room semantics).
/// - The joiner ALSO gets itself added — Synapse/Conduit do this
///   so the joiner's other devices see the joiner. But ONLY when
///   the room had members other than the joiner: a solo-create
///   has no "share with anyone new" signal, and the spurious
///   self-entry on every room creation races with later
///   legitimate self-changes (alice2 logging in) and breaks
///   `TestDeviceListsUpdateOverFederation/good_connectivity`.
///
/// Federation: the outbound `m.device_list_update` EDUs are emitted
/// by `federate_device_lists_on_join`; this helper is local-only.
pub fn record_device_changes_on_join(state: &AppState, user_nid: u64, room_nid: u64) {
    let members = state.db.get_room_members(room_nid).unwrap_or_default();
    let other_members: Vec<u64> = members.iter().copied().filter(|&m| m != user_nid).collect();
    if other_members.is_empty() {
        // Solo room create: no shared-room peer, no spurious
        // self-entry. (Skipping this was the fix for
        // TestDeviceListsUpdateOverFederation/good_connectivity —
        // the previous self-entry on every solo create raced with
        // later legitimate self-changes like alice2 logging in.)
        crate::router::notify_user(state, user_nid);
        return;
    }
    // Each notify_device_key_change call writes one entry per
    // observer at the given (observer, pos) key. We need separate
    // positions per call so writes to the same observer key don't
    // overwrite each other (joiner is the observer in two of the
    // three writes below).
    for &member_nid in &other_members {
        let pos = state.db.next_stream_position().as_u64();
        let _g = vela_store::db::StreamApplyOnDrop::new(&state.db, pos);
        if let Err(e) = state
            .db
            .notify_device_key_change(member_nid, &[user_nid], pos)
        {
            tracing::warn!(error = %e, "notify_device_key_change on join (member) failed");
        }
        drop(_g);
        let pos = state.db.next_stream_position().as_u64();
        let _g = vela_store::db::StreamApplyOnDrop::new(&state.db, pos);
        if let Err(e) = state
            .db
            .notify_device_key_change(user_nid, &[member_nid], pos)
        {
            tracing::warn!(error = %e, "notify_device_key_change on join (joiner-knows-member) failed");
        }
    }
    let pos = state.db.next_stream_position().as_u64();
    let _g = vela_store::db::StreamApplyOnDrop::new(&state.db, pos);
    if let Err(e) = state
        .db
        .notify_device_key_change(user_nid, &[user_nid], pos)
    {
        tracing::warn!(error = %e, "notify_device_key_change on join (self) failed");
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
    let _stream_guard = vela_store::db::StreamApplyOnDrop::new(&state.db, stream_pos);

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

    // Drop any cached `/user/keys/query` response for a remote peer
    // whose last shared room with us just collapsed — either because
    // the peer themself left (REMOTE leaver direction) or because the
    // last local user in their room is leaving (LOCAL leaver
    // direction). In both shapes the peer's home server is now under
    // no obligation to send us m.device_list_update EDUs for them, so
    // anything we hold is permanently stale. Spec tests:
    // Device_list_no_longer_tracked_when_new_member_leaves_partial_state_room,
    // TestDeviceListUpdates/when_leaving_a_room_with_a_remote_user.
    let mut candidates: Vec<u64> = Vec::new();
    if leaver_is_local {
        // Local user is leaving — check every remote peer they shared
        // this room with.
        for &peer in &members {
            if peer == departing_nid {
                continue;
            }
            let Ok(Some(uid)) = state.db.resolve_nid(peer) else {
                continue;
            };
            if uid
                .split_once(':')
                .map(|(_, d)| d != our_server)
                .unwrap_or(false)
            {
                candidates.push(peer);
            }
        }
    } else {
        // Remote user is leaving — check only that peer.
        candidates.push(departing_nid);
    }
    for peer_nid in candidates {
        let still_shared = state
            .db
            .get_user_joined_rooms(peer_nid)
            .map(|rooms| {
                rooms
                    .iter()
                    .any(|&r| r != room_nid && room_has_local_member(state, r))
            })
            .unwrap_or(false);
        if !still_shared && let Err(e) = state.db.invalidate_remote_user_keys_cache(peer_nid) {
            tracing::debug!(error = %e, "invalidate_remote_user_keys_cache on leave failed");
        }
    }
}

/// True if `room_nid` has at least one currently-joined member on our
/// server. Used by `record_device_changes_on_leave` to decide whether
/// a departing remote user still shares any room with us — if not,
/// their device-key cache is dropped because we stop "tracking" them.
fn room_has_local_member(state: &AppState, room_nid: u64) -> bool {
    let Ok(members) = state.db.get_room_members(room_nid) else {
        return false;
    };
    let our_server = state.config.server_name.as_str();
    for m in members {
        if let Ok(Some(uid)) = state.db.resolve_nid(m)
            && uid
                .split_once(':')
                .map(|(_, d)| d == our_server)
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
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
        // Partial-state rooms intentionally fall through here: the
        // joiner doesn't yet know who the resident considers "in the
        // room," and the partial_state_filler's
        // reconcile_device_lists pass will fan out once the filler
        // clears (using the pending-EDU buffer). Forcing an EDU out
        // now via the hint surfaces unexpected device_list_update
        // EDUs on the resident mock side and breaks the broader
        // TestPartialStateJoin/CanSend… family.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    fn device_key(keys: Value, sigs: Value) -> Value {
        json!({
            "user_id": "@alice:example.com",
            "device_id": "DEV",
            "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
            "keys": keys,
            "signatures": sigs,
        })
    }

    /// Fall-behind guard: a caller whose device-list token predates the
    /// prune horizon over-reports all shared-room users (forcing a full
    /// resync), a caller within the window gets the precise pruned-aware
    /// list, and an initial sync (from == 0) is never over-reported.
    #[test]
    fn device_list_changed_nids_over_reports_below_horizon() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room = db.get_or_create_nid("!r:local").unwrap();
        let a = db.get_or_create_nid("@a:local").unwrap();
        let b = db.get_or_create_nid("@b:local").unwrap();
        db.set_membership(room, a, 1).unwrap();
        db.set_membership(room, b, 1).unwrap();

        // B's keys change; A (a room-mate) observes it precisely.
        db.record_device_key_change(b).unwrap();
        assert_eq!(
            device_list_changed_nids(&state, a, 1, u64::MAX).unwrap(),
            vec![b],
            "within window: precise change list"
        );

        // Prune everything → the horizon advances past the change.
        let (_removed, horizon) = db.prune_device_lists(u64::MAX).unwrap();
        assert!(horizon > 0);

        // A's token predates the horizon → over-report all shared-room
        // users, even though the precise entry was pruned. Self (A) MUST be
        // included: the precise path always reports the caller's own
        // changes, so the over-report must too or A wouldn't re-query its
        // own devices after falling behind.
        let mut behind = device_list_changed_nids(&state, a, 1, u64::MAX).unwrap();
        behind.sort_unstable();
        assert_eq!(
            behind,
            vec![a, b],
            "fell behind → full-resync over-report incl. self"
        );

        // A token after the horizon trusts the (now empty) precise list.
        assert!(
            device_list_changed_nids(&state, a, horizon + 1, u64::MAX)
                .unwrap()
                .is_empty(),
            "within window after prune: nothing changed"
        );

        // Initial sync (from == 0) is never over-reported.
        assert!(
            device_list_changed_nids(&state, a, 0, u64::MAX)
                .unwrap()
                .is_empty(),
            "initial sync must not trigger the over-report"
        );
    }

    /// Same key material → existing signatures from other signers are
    /// folded into the fresh upload (so a verified device stays verified).
    #[test]
    fn preserve_keeps_cross_signing_sig_when_keys_unchanged() {
        let keys = json!({"curve25519:DEV": "C", "ed25519:DEV": "E"});
        let stored = device_key(
            keys.clone(),
            json!({"@alice:example.com": {"ed25519:DEV": "self", "ed25519:SSK": "cross"}}),
        );
        // A re-upload carries only the device's own self-signature.
        let mut fresh = device_key(keys, json!({"@alice:example.com": {"ed25519:DEV": "self"}}));
        preserve_existing_signatures(Some(&stored), &mut fresh);
        let sigs = &fresh["signatures"]["@alice:example.com"];
        assert_eq!(sigs["ed25519:DEV"], "self");
        assert_eq!(
            sigs["ed25519:SSK"], "cross",
            "cross-signing sig must survive"
        );
    }

    /// Different key material → prior signatures are over a different key
    /// and MUST NOT be carried onto the new one.
    #[test]
    fn preserve_drops_sigs_when_key_material_changes() {
        let stored = device_key(
            json!({"ed25519:DEV": "OLD"}),
            json!({"@alice:example.com": {"ed25519:SSK": "cross"}}),
        );
        let mut fresh = device_key(
            json!({"ed25519:DEV": "NEW"}),
            json!({"@alice:example.com": {"ed25519:DEV": "self"}}),
        );
        preserve_existing_signatures(Some(&stored), &mut fresh);
        let sigs = &fresh["signatures"]["@alice:example.com"];
        assert!(
            sigs.get("ed25519:SSK").is_none(),
            "stale sig must be dropped"
        );
        assert_eq!(sigs["ed25519:DEV"], "self");
    }

    /// Same `keys` but a different signed field (`algorithms`) → the stored
    /// signatures are over different bytes and would fail client
    /// verification, so they MUST be dropped, not carried over.
    #[test]
    fn preserve_drops_sigs_when_algorithms_change() {
        let keys = json!({"ed25519:DEV": "E"});
        let mut stored = device_key(
            keys.clone(),
            json!({"@alice:example.com": {"ed25519:SSK": "cross"}}),
        );
        stored["algorithms"] = json!(["m.megolm.v1.aes-sha2"]); // differs from device_key default
        let mut fresh = device_key(keys, json!({"@alice:example.com": {"ed25519:DEV": "self"}}));
        preserve_existing_signatures(Some(&stored), &mut fresh);
        let sigs = &fresh["signatures"]["@alice:example.com"];
        assert!(
            sigs.get("ed25519:SSK").is_none(),
            "sig over different algorithms must be dropped"
        );
    }

    /// On a `(signer, key_id)` collision the fresh upload's signature wins —
    /// a freshly re-signed self-signature is never clobbered by the stored
    /// one; only foreign signatures the upload lacks are folded in.
    #[test]
    fn preserve_new_signature_wins_on_collision() {
        let keys = json!({"ed25519:DEV": "E"});
        let stored = device_key(
            keys.clone(),
            json!({"@alice:example.com": {"ed25519:DEV": "OLD", "ed25519:SSK": "cross"}}),
        );
        let mut fresh = device_key(keys, json!({"@alice:example.com": {"ed25519:DEV": "NEW"}}));
        preserve_existing_signatures(Some(&stored), &mut fresh);
        let sigs = &fresh["signatures"]["@alice:example.com"];
        assert_eq!(sigs["ed25519:DEV"], "NEW", "fresh self-sig must win");
        assert_eq!(sigs["ed25519:SSK"], "cross", "foreign sig folded in");
    }

    /// No stored key (first upload) → nothing to merge, left as-is.
    #[test]
    fn preserve_noop_when_nothing_stored() {
        let mut fresh = device_key(
            json!({"ed25519:DEV": "E"}),
            json!({"@alice:example.com": {"ed25519:DEV": "self"}}),
        );
        let before = fresh.clone();
        preserve_existing_signatures(None, &mut fresh);
        assert_eq!(fresh, before);
    }

    /// End to end through the handler: a device re-uploading its keys (the
    /// bare self-signed object a client regenerates) must not strip the
    /// self_signing-key signature that marked it verified.
    #[tokio::test]
    async fn reupload_via_handler_preserves_verification_signature() {
        let (state, _tmp) = build_test_state();
        let user_nid = state.db.get_or_create_nid("@alice:example.com").unwrap();
        let user = AuthenticatedUser {
            user_nid,
            user_id: "@alice:example.com".to_string(),
            device_id: "DEV".to_string(),
            appservice_nid: None,
        };
        let keys = json!({"curve25519:DEV": "C", "ed25519:DEV": "E"});

        // Verified state: device key carries both its self-sig and the
        // self_signing-key cross-signature (as /keys/signatures/upload left it).
        state
            .db
            .set_device_keys(
                user_nid,
                "DEV",
                &device_key(
                    keys.clone(),
                    json!({"@alice:example.com": {"ed25519:DEV": "self", "ed25519:SSK": "cross"}}),
                ),
            )
            .unwrap();

        // Client re-uploads the bare, self-signed key.
        let body = KeysUploadRequest {
            device_keys: Some(device_key(
                keys,
                json!({"@alice:example.com": {"ed25519:DEV": "self"}}),
            )),
            one_time_keys: None,
            fallback_keys: None,
        };
        upload_keys(State(state.clone()), user, Json(body))
            .await
            .expect("upload ok");

        let stored = state.db.get_device_keys(user_nid, "DEV").unwrap().unwrap();
        assert_eq!(
            stored["signatures"]["@alice:example.com"]["ed25519:SSK"], "cross",
            "re-upload must not strip the cross-signing signature"
        );
    }

    fn auth_user(state: &AppState, user_id: &str) -> AuthenticatedUser {
        AuthenticatedUser {
            user_nid: state.db.get_or_create_nid(user_id).unwrap(),
            user_id: user_id.to_string(),
            device_id: "DEV".to_string(),
            appservice_nid: None,
        }
    }

    /// `caller_signatures_only` keeps only the caller's signatures and drops
    /// any attributed to another user (forgery guard).
    #[test]
    fn caller_signatures_only_drops_foreign_signers() {
        let body = json!({"signatures": {
            "@alice:example.com": {"ed25519:SSK": "alice"},
            "@mallory:example.com": {"ed25519:EVIL": "forged"},
        }});
        let f = caller_signatures_only(&body, "@alice:example.com").unwrap();
        assert_eq!(
            f["signatures"]["@alice:example.com"]["ed25519:SSK"],
            "alice"
        );
        assert!(f["signatures"].get("@mallory:example.com").is_none());
        // Caller contributed nothing → None.
        assert!(caller_signatures_only(&body, "@bob:example.com").is_none());
    }

    /// `/keys/signatures/upload` must (a) drop a signature forged in another
    /// user's name and (b) refuse to sign another user's DEVICE.
    #[tokio::test]
    async fn upload_signatures_rejects_forged_and_cross_user_device() {
        let (state, _tmp) = build_test_state();
        let alice = state.db.get_or_create_nid("@alice:example.com").unwrap();
        let bob = state.db.get_or_create_nid("@bob:example.com").unwrap();
        state
            .db
            .set_device_keys(
                alice,
                "ADEV",
                &json!({"signatures": {"@alice:example.com": {"ed25519:ADEV": "self"}}}),
            )
            .unwrap();
        state
            .db
            .set_device_keys(
                bob,
                "BDEV",
                &json!({"signatures": {"@bob:example.com": {"ed25519:BDEV": "self"}}}),
            )
            .unwrap();
        // Alice publishes her self-signing key, so signing her device with
        // `ed25519:ASSK` is from a key she actually owns.
        state
            .db
            .set_cross_signing_keys(
                alice,
                "self_signing",
                &json!({"user_id": "@alice:example.com", "usage": ["self_signing"], "keys": {"ed25519:ASSK": "ASSK"}}),
            )
            .unwrap();

        let body = json!({
            "@alice:example.com": {"ADEV": {"signatures": {
                "@alice:example.com": {"ed25519:ASSK": "ok"},
                "@bob:example.com": {"ed25519:FORGE": "forged"},
            }}},
            "@bob:example.com": {"BDEV": {"signatures": {
                "@alice:example.com": {"ed25519:ASSK": "should-not-land"},
            }}},
        });
        upload_signatures(
            State(state.clone()),
            auth_user(&state, "@alice:example.com"),
            Json(body),
        )
        .await
        .unwrap();

        let adev = state.db.get_device_keys(alice, "ADEV").unwrap().unwrap();
        assert_eq!(
            adev["signatures"]["@alice:example.com"]["ed25519:ASSK"],
            "ok"
        );
        assert!(
            adev["signatures"].get("@bob:example.com").is_none(),
            "forged foreign-signer signature must be dropped"
        );
        let bdev = state.db.get_device_keys(bob, "BDEV").unwrap().unwrap();
        assert!(
            bdev["signatures"]["@alice:example.com"]
                .get("ed25519:ASSK")
                .is_none(),
            "signing another user's device must be refused"
        );
    }

    /// Cross-user signing of another user's MASTER key (the legitimate
    /// user_signing flow) is allowed.
    #[tokio::test]
    async fn upload_signatures_allows_cross_user_master() {
        let (state, _tmp) = build_test_state();
        let alice = state.db.get_or_create_nid("@alice:example.com").unwrap();
        let bob = state.db.get_or_create_nid("@bob:example.com").unwrap();
        state
            .db
            .set_cross_signing_keys(
                bob,
                "master_key",
                &json!({"user_id": "@bob:example.com", "usage": ["master"], "keys": {"ed25519:BMASTER": "BMASTER"}, "signatures": {}}),
            )
            .unwrap();
        // Alice publishes her user-signing key — the key the user_signing
        // flow uses to sign another user's master.
        state
            .db
            .set_cross_signing_keys(
                alice,
                "user_signing",
                &json!({"user_id": "@alice:example.com", "usage": ["user_signing"], "keys": {"ed25519:AUSK": "AUSK"}}),
            )
            .unwrap();

        let body = json!({"@bob:example.com": {"ed25519:BMASTER": {"signatures": {
            "@alice:example.com": {"ed25519:AUSK": "alice-usk-sig"},
        }}}});
        upload_signatures(
            State(state.clone()),
            auth_user(&state, "@alice:example.com"),
            Json(body),
        )
        .await
        .unwrap();

        let master = state.db.get_cross_signing_keys(bob).unwrap();
        assert_eq!(
            master["master_key"]["signatures"]["@alice:example.com"]["ed25519:AUSK"],
            "alice-usk-sig",
            "cross-user master signature must be stored"
        );
    }

    /// A caller can only fold signatures made by keys they've PUBLISHED. A
    /// signature attributed to an unpublished (fake) key id must be dropped,
    /// not written into another user's master key — this bounds a cross-user
    /// write / storage-amplification abuse.
    #[tokio::test]
    async fn upload_signatures_drops_unpublished_key_ids() {
        let (state, _tmp) = build_test_state();
        let _alice = state.db.get_or_create_nid("@alice:example.com").unwrap();
        let bob = state.db.get_or_create_nid("@bob:example.com").unwrap();
        state
            .db
            .set_cross_signing_keys(
                bob,
                "master_key",
                &json!({"user_id": "@bob:example.com", "usage": ["master"], "keys": {"ed25519:BMASTER": "BMASTER"}, "signatures": {}}),
            )
            .unwrap();

        // Alice has published NO keys, so `ed25519:FAKE` is not hers.
        let body = json!({"@bob:example.com": {"ed25519:BMASTER": {"signatures": {
            "@alice:example.com": {"ed25519:FAKE": "garbage-blob"},
        }}}});
        upload_signatures(
            State(state.clone()),
            auth_user(&state, "@alice:example.com"),
            Json(body),
        )
        .await
        .unwrap();

        let master = state.db.get_cross_signing_keys(bob).unwrap();
        assert!(
            master["master_key"]["signatures"]
                .get("@alice:example.com")
                .is_none(),
            "a signature from an unpublished key id must not land on another user's master key"
        );
    }

    /// Item 1: an idempotent cross-signing re-upload (same key material, but
    /// the stored copy has since gained a device signature) must NOT demand
    /// UIA — the gate keys off signed content, not signatures.
    #[tokio::test]
    async fn idempotent_cross_signing_reupload_skips_uia() {
        let (state, _tmp) = build_test_state();
        let alice = state.db.get_or_create_nid("@alice:example.com").unwrap();
        // Stored master carries a device signature, as /keys/signatures/upload
        // would have left it after the user verified.
        state
            .db
            .set_cross_signing_keys(
                alice,
                "master_key",
                &json!({"user_id": "@alice:example.com", "usage": ["master"], "keys": {"ed25519:M": "M"}, "signatures": {"@alice:example.com": {"ed25519:DEV": "sig"}}}),
            )
            .unwrap();

        // Client re-uploads the bare master (same material, no signatures, no
        // `auth`). Old gate compared whole objects → UIA challenge (Err);
        // new gate compares signed content → no change → Ok.
        let bare = json!({"master_key": {"user_id": "@alice:example.com", "usage": ["master"], "keys": {"ed25519:M": "M"}, "signatures": {}}});
        let res = upload_signing_keys(
            State(state.clone()),
            auth_user(&state, "@alice:example.com"),
            Json(bare),
        )
        .await;
        assert!(
            res.is_ok(),
            "idempotent re-upload of unchanged key material must not require UIA: {:?}",
            res.err().map(|e| e.0)
        );
    }

    /// Item 1 (bound-fire): swapping in DIFFERENT key material still requires
    /// UIA — the gate must reject the change when no `auth` is supplied.
    #[tokio::test]
    async fn cross_signing_material_change_requires_uia() {
        let (state, _tmp) = build_test_state();
        let alice = state.db.get_or_create_nid("@alice:example.com").unwrap();
        state
            .db
            .set_cross_signing_keys(
                alice,
                "master_key",
                &json!({"user_id": "@alice:example.com", "usage": ["master"], "keys": {"ed25519:OLD": "OLD"}, "signatures": {}}),
            )
            .unwrap();

        // Replace the master key material, no `auth` in the body.
        let changed = json!({"master_key": {"user_id": "@alice:example.com", "usage": ["master"], "keys": {"ed25519:NEW": "NEW"}, "signatures": {}}});
        let res = upload_signing_keys(
            State(state.clone()),
            auth_user(&state, "@alice:example.com"),
            Json(changed),
        )
        .await;
        assert!(
            res.is_err(),
            "changing master key material without auth must still require UIA"
        );
    }

    /// Build a cross-signing signer whose `key_id` is the full
    /// `ed25519:<pubkey>` form, matching how a master key advertises itself in
    /// its `keys` map (so its signatures land under the looked-up key_id).
    fn xsigner() -> vela_core::events::sign::ServerSigningKey {
        use vela_core::events::sign::ServerSigningKey;
        let k = ServerSigningKey::generate();
        let pb = k.public_key_base64();
        ServerSigningKey::from_bytes(format!("ed25519:{pb}"), k.secret_bytes())
    }

    fn xsign_key(user: &str, usage: &str, pub_b64: &str) -> Map<String, Value> {
        let mut keys = Map::new();
        keys.insert(format!("ed25519:{pub_b64}"), json!(pub_b64));
        let mut m = Map::new();
        m.insert("user_id".into(), json!(user));
        m.insert("usage".into(), json!([usage]));
        m.insert("keys".into(), Value::Object(keys));
        m
    }

    /// The linkage check accepts a self-signing key signed by a master passed
    /// explicitly — the branch the handler takes when the request omits the
    /// master and falls back to the stored one (legit SSK rotation, UIA-gated
    /// end to end, so exercised here directly), and rejects when there is no
    /// master anywhere to anchor trust.
    #[test]
    fn verify_signed_by_master_uses_the_supplied_master() {
        let user = "@alice:example.com";
        let master = xsigner();
        let master_key = Value::Object(xsign_key(user, "master", &master.public_key_base64()));

        let mut ssk = xsign_key(user, "self_signing", &xsigner().public_key_base64());
        master.sign_json(&mut ssk, user);
        let ssk = Value::Object(ssk);

        assert!(verify_signed_by_master(&ssk, user, Some(&master_key)).is_ok());
        assert!(
            verify_signed_by_master(&ssk, user, None).is_err(),
            "no master anywhere → cannot validate"
        );
    }

    /// The guard behind bare re-uploads: signature preservation folds stored
    /// signatures ONLY when the signed content is byte-identical, so a
    /// DIFFERENT self-signing key uploaded bare is not rescued by the stored
    /// master signature and fails verification.
    #[test]
    fn fold_does_not_rescue_a_changed_signing_key() {
        let user = "@alice:example.com";
        let master = xsigner();
        let master_key = Value::Object(xsign_key(user, "master", &master.public_key_base64()));

        // A stored SSK properly signed by the master.
        let mut stored = xsign_key(user, "self_signing", &xsigner().public_key_base64());
        master.sign_json(&mut stored, user);
        let stored = Value::Object(stored);

        // A different SSK (new pubkey), uploaded bare (no signature).
        let mut fresh = Value::Object(xsign_key(
            user,
            "self_signing",
            &xsigner().public_key_base64(),
        ));
        preserve_existing_signatures(Some(&stored), &mut fresh);

        assert!(
            fresh
                .get("signatures")
                .and_then(|s| s.as_object())
                .is_none_or(|s| s.is_empty()),
            "changed material must not inherit the stored signature"
        );
        assert!(
            verify_signed_by_master(&fresh, user, Some(&master_key)).is_err(),
            "an unsigned, changed SSK must fail verification"
        );
    }
}
