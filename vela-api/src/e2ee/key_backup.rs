//! Key backup — `GET/PUT/DELETE /room_keys/...`.
//!
//! Spec: `client-server-api/#server-side-key-backups`.
//!
//! Storage layout (the `key_backup` CF in vela-store):
//!
//!   - Versions metadata: one JSON blob per user, written via
//!     `Database::key_backup_versions_set` / `_get`. Holds the map of
//!     version_id → {algorithm, auth_data, latest, ver_counter}. Few,
//!     small; blob writes are fine here.
//!
//!   - Sessions: ONE ROW PER session, keyed by
//!     `(user_nid, version, room_id, session_id)`. Replaces the
//!     previous load-mutate-save-an-account_data-blob design, which
//!     had a real lost-write race when Element parallel-uploaded
//!     sessions during initial Secure Backup setup.
//!
//!   - Stats: one row per (user_nid, version) holding packed
//!     `(count, etag)` u64s. Updated on each session put/delete
//!     under a per-user lock so concurrent uploads can't drift the
//!     count.
//!
//! Migration: on first read of a user's versions, if the legacy
//! `m.vela.key_backup` account_data entry exists, we drain it into
//! the new CF and clear the account_data row so future syncs no
//! longer ship the entire backup blob to the user's other devices.

use std::sync::Arc;

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::sync::Mutex;

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

const LEGACY_BACKUP_STORE: &str = "m.vela.key_backup";

// --- Versions ---

#[derive(Deserialize)]
pub struct CreateBackupBody {
    pub algorithm: String,
    pub auth_data: Value,
}

/// POST /_matrix/client/v3/room_keys/version
///
/// Create a new backup version. Increments `ver_counter` so version
/// strings stay monotonic even after deletions.
pub async fn post_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<CreateBackupBody>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;

    let mut store = load_versions(&state, user.user_nid)?;
    let next = next_version(&store);
    let version = next.to_string();
    let meta = json!({
        "version": version,
        "algorithm": body.algorithm,
        "auth_data": body.auth_data,
        "etag": "0",
        "count": 0,
    });
    let versions = store
        .as_object_mut()
        .unwrap()
        .entry("versions")
        .or_insert_with(|| json!({}));
    versions
        .as_object_mut()
        .unwrap()
        .insert(version.clone(), meta);
    let store_obj = store.as_object_mut().unwrap();
    store_obj.insert("latest".to_string(), json!(version));
    // Bump ver_counter so a subsequent POST gets a fresh number even
    // if no keys were uploaded against this version.
    store_obj.insert("ver_counter".to_string(), json!(next));
    save_versions(&state, user.user_nid, &store)?;

    // Seed stats so subsequent ?version=N queries hit a real row.
    state
        .db
        .key_backup_stats_set(user.user_nid, &version, 0, 0)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({ "version": version })))
}

#[allow(dead_code)]
#[derive(Debug, Default, Deserialize)]
pub struct VersionQuery {
    pub version: Option<String>,
}

/// GET /_matrix/client/v3/room_keys/version
pub async fn get_latest_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let store = load_versions(&state, user.user_nid)?;
    let latest = store
        .get("latest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError(VelaError::NotFound("no backup version found".into())))?;
    let meta = read_version_meta(&state, &store, user.user_nid, latest)?;
    Ok(Json(meta))
}

/// GET /_matrix/client/v3/room_keys/version/{version}
pub async fn get_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(version): Path<String>,
) -> Result<Json<Value>, ApiError> {
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let store = load_versions(&state, user.user_nid)?;
    let meta = read_version_meta(&state, &store, user.user_nid, &version)?;
    Ok(Json(meta))
}

/// PUT /_matrix/client/v3/room_keys/version/{version}
///
/// Clients call this to update `auth_data` for an existing version.
pub async fn put_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(version): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let mut store = load_versions(&state, user.user_nid)?;
    let meta = store
        .pointer_mut(&format!("/versions/{version}"))
        .ok_or_else(|| ApiError(VelaError::NotFound("version not found".into())))?;
    if let Some(new_auth) = body.get("auth_data") {
        meta.as_object_mut()
            .unwrap()
            .insert("auth_data".to_string(), new_auth.clone());
    }
    if let Some(new_algo) = body.get("algorithm") {
        meta.as_object_mut()
            .unwrap()
            .insert("algorithm".to_string(), new_algo.clone());
    }
    save_versions(&state, user.user_nid, &store)?;
    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/v3/room_keys/version/{version}
pub async fn delete_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(version): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let mut store = load_versions(&state, user.user_nid)?;
    if let Some(versions) = store.get_mut("versions").and_then(|v| v.as_object_mut()) {
        versions.remove(&version);
    }
    if store
        .get("latest")
        .and_then(|v| v.as_str())
        .is_some_and(|l| l == version)
    {
        store
            .as_object_mut()
            .unwrap()
            .insert("latest".to_string(), Value::Null);
    }
    save_versions(&state, user.user_nid, &store)?;
    state
        .db
        .key_backup_delete_version(user.user_nid, &version)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({})))
}

// --- Keys ---

#[derive(Debug, Default, Deserialize)]
pub struct KeysVersionQuery {
    pub version: Option<String>,
}

/// PUT /_matrix/client/v3/room_keys/keys
pub async fn put_all_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<KeysVersionQuery>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    require_current_version(&state, user.user_nid, &version)?;
    let rooms = body
        .get("rooms")
        .and_then(|v| v.as_object())
        .ok_or_else(|| ApiError(VelaError::BadJson("missing rooms".into())))?;
    let mut count_added = 0u64;
    for (room_id, room_body) in rooms {
        let sessions = room_body
            .get("sessions")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        for (session_id, sess) in sessions {
            if write_session(&state, user.user_nid, &version, room_id, &session_id, sess)? {
                count_added += 1;
            }
        }
    }
    let (etag, total) = bump_stats(&state, user.user_nid, &version, count_added)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// PUT /_matrix/client/v3/room_keys/keys/{roomId}
pub async fn put_room_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(q): Query<KeysVersionQuery>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    require_current_version(&state, user.user_nid, &version)?;
    let sessions = body
        .get("sessions")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut count_added = 0u64;
    for (session_id, sess) in sessions {
        if write_session(&state, user.user_nid, &version, &room_id, &session_id, sess)? {
            count_added += 1;
        }
    }
    let (etag, total) = bump_stats(&state, user.user_nid, &version, count_added)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// PUT /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}
pub async fn put_session(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<KeysVersionQuery>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    require_current_version(&state, user.user_nid, &version)?;
    let written = write_session(&state, user.user_nid, &version, &room_id, &session_id, body)?;
    let delta = if written { 1 } else { 0 };
    let (etag, total) = bump_stats(&state, user.user_nid, &version, delta)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// GET /_matrix/client/v3/room_keys/keys
pub async fn get_all_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let entries = state
        .db
        .key_backup_iter_version(user.user_nid, &version)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut rooms_out: Map<String, Value> = Map::new();
    for (room_id, session_id, sess) in entries {
        let entry = rooms_out
            .entry(room_id)
            .or_insert_with(|| json!({"sessions": {}}));
        entry
            .as_object_mut()
            .unwrap()
            .get_mut("sessions")
            .and_then(|v| v.as_object_mut())
            .unwrap()
            .insert(session_id, sess);
    }
    Ok(Json(json!({"rooms": rooms_out})))
}

/// GET /_matrix/client/v3/room_keys/keys/{roomId}
pub async fn get_room_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let entries = state
        .db
        .key_backup_iter_room(user.user_nid, &version, &room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut sessions: Map<String, Value> = Map::new();
    for (sid, sess) in entries {
        sessions.insert(sid, sess);
    }
    Ok(Json(json!({"sessions": sessions})))
}

/// GET /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}
pub async fn get_session(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let sess = state
        .db
        .key_backup_session_get(user.user_nid, &version, &room_id, &session_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("session not found".into())))?;
    Ok(Json(sess))
}

/// DELETE /_matrix/client/v3/room_keys/keys
pub async fn delete_all_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let removed = state
        .db
        .key_backup_delete_version(user.user_nid, &version)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (etag, total) = decrement_stats(&state, user.user_nid, &version, removed)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// DELETE /_matrix/client/v3/room_keys/keys/{roomId}
pub async fn delete_room_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let removed = state
        .db
        .key_backup_delete_room(user.user_nid, &version, &room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (etag, total) = decrement_stats(&state, user.user_nid, &version, removed)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// DELETE /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}
pub async fn delete_session(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let _guard = backup_lock(&state, user.user_nid).lock_owned().await;
    migrate_legacy_if_needed(&state, user.user_nid)?;
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let removed = state
        .db
        .key_backup_session_delete(user.user_nid, &version, &room_id, &session_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let delta = if removed { 1 } else { 0 };
    let (etag, total) = decrement_stats(&state, user.user_nid, &version, delta)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

// --- Helpers --------------------------------------------------------------

/// Per-user lock guarding mutating handlers. Sessions go to distinct
/// CF rows so cross-row session writes are race-free at the storage
/// layer; the lock protects the (read, modify, write) cycles on
/// version metadata + stats, which DO touch shared rows.
fn backup_lock(state: &AppState, user_nid: u64) -> Arc<Mutex<()>> {
    state
        .key_backup_user_locks
        .entry(user_nid)
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

fn load_versions(state: &AppState, user_nid: u64) -> Result<Value, ApiError> {
    let v = state
        .db
        .key_backup_versions_get(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(v.unwrap_or_else(|| json!({"versions": {}, "latest": null, "ver_counter": 0})))
}

/// A `/room_keys` PUT MUST target the current backup version (spec). A version
/// that isn't the latest (superseded, or deleted) → 403
/// `M_WRONG_ROOM_KEYS_VERSION` carrying the current version; no backup at all →
/// 404. Without this a client silently writes keys to a backup nobody restores
/// from, losing them on recovery.
fn require_current_version(state: &AppState, user_nid: u64, version: &str) -> Result<(), ApiError> {
    let store = load_versions(state, user_nid)?;
    match store.get("latest").and_then(|v| v.as_str()) {
        None => Err(ApiError(VelaError::NotFound(
            "no current key backup version".into(),
        ))),
        Some(latest) if latest != version => Err(ApiError(VelaError::WrongRoomKeysVersion {
            current_version: latest.to_string(),
        })),
        Some(_) => Ok(()),
    }
}

fn save_versions(state: &AppState, user_nid: u64, v: &Value) -> Result<(), ApiError> {
    state
        .db
        .key_backup_versions_set(user_nid, v)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))
}

fn next_version(store: &Value) -> u64 {
    store
        .get("ver_counter")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        + 1
}

/// Compose the version-meta response shape, merging the live
/// (count, etag) from the stats row so clients see freshly-uploaded
/// keys reflected immediately.
fn read_version_meta(
    state: &AppState,
    store: &Value,
    user_nid: u64,
    version: &str,
) -> Result<Value, ApiError> {
    let mut meta = store
        .pointer(&format!("/versions/{version}"))
        .cloned()
        .ok_or_else(|| ApiError(VelaError::NotFound("version not found".into())))?;
    let (count, etag) = state
        .db
        .key_backup_stats_get(user_nid, version)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if let Some(obj) = meta.as_object_mut() {
        obj.insert("etag".to_string(), json!(etag.to_string()));
        obj.insert("count".to_string(), json!(count));
    }
    Ok(meta)
}

/// Conditional session put applying the spec's replacement rule.
/// Returns true iff the row was inserted or replaced, false iff the
/// existing row is preferred and was kept untouched.
fn write_session(
    state: &AppState,
    user_nid: u64,
    version: &str,
    room_id: &str,
    session_id: &str,
    body: Value,
) -> Result<bool, ApiError> {
    let existing = state
        .db
        .key_backup_session_get(user_nid, version, room_id, session_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let is_new = existing.is_none();
    if let Some(existing_val) = existing
        && !should_replace(&existing_val, &body)
    {
        return Ok(false);
    }
    state
        .db
        .key_backup_session_put(user_nid, version, room_id, session_id, &body)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(is_new)
}

/// Spec rule for whether `incoming` should replace `existing`:
/// 1. is_verified=true beats is_verified=false
/// 2. else lower first_message_index wins
/// 3. else lower forwarded_count wins
/// 4. else keep existing.
fn should_replace(existing: &Value, incoming: &Value) -> bool {
    let ev = existing
        .get("is_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let nv = incoming
        .get("is_verified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if nv != ev {
        return nv;
    }
    let efmi = existing
        .get("first_message_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let nfmi = incoming
        .get("first_message_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    if nfmi != efmi {
        return nfmi < efmi;
    }
    let efc = existing
        .get("forwarded_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let nfc = incoming
        .get("forwarded_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    nfc < efc
}

/// Bump stats after a successful write. `delta` is the count change
/// (replacements give 0). Etag bumps only when something changed.
fn bump_stats(
    state: &AppState,
    user_nid: u64,
    version: &str,
    delta: u64,
) -> Result<(String, u64), ApiError> {
    let (count, etag) = state
        .db
        .key_backup_stats_get(user_nid, version)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let new_etag = if delta == 0 { etag } else { etag + 1 };
    let new_count = count + delta;
    state
        .db
        .key_backup_stats_set(user_nid, version, new_count, new_etag)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok((new_etag.to_string(), new_count))
}

/// Decrement stats after deletions. Symmetric to `bump_stats`.
fn decrement_stats(
    state: &AppState,
    user_nid: u64,
    version: &str,
    removed: u64,
) -> Result<(String, u64), ApiError> {
    let (count, etag) = state
        .db
        .key_backup_stats_get(user_nid, version)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let new_etag = if removed == 0 { etag } else { etag + 1 };
    let new_count = count.saturating_sub(removed);
    state
        .db
        .key_backup_stats_set(user_nid, version, new_count, new_etag)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok((new_etag.to_string(), new_count))
}

/// Migration: drain the legacy `m.vela.key_backup` account_data blob
/// into the new CF on first read after upgrade. Idempotent (the
/// account_data row is deleted after drain so subsequent calls see
/// nothing to do). Without this, existing deployments lose their
/// backups on upgrade.
fn migrate_legacy_if_needed(state: &AppState, user_nid: u64) -> Result<(), ApiError> {
    let Some(legacy) = state
        .db
        .get_account_data(user_nid, LEGACY_BACKUP_STORE)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(());
    };

    // Versions metadata: keep the legacy shape minus the per-version
    // `keys` blob (we move that into the CF below).
    let mut new_versions = json!({
        "versions": legacy.get("versions").cloned().unwrap_or_else(|| json!({})),
        "latest": legacy.get("latest").cloned().unwrap_or(Value::Null),
        "ver_counter": legacy.get("ver_counter").cloned().unwrap_or_else(|| json!(0)),
    });
    // Strip any stale stats from the per-version metadata — stats now
    // live in their own row and we recompute count below.
    if let Some(versions_obj) = new_versions
        .get_mut("versions")
        .and_then(|v| v.as_object_mut())
    {
        for (_vid, meta) in versions_obj.iter_mut() {
            if let Some(meta_obj) = meta.as_object_mut() {
                meta_obj.remove("etag");
                meta_obj.remove("count");
            }
        }
    }
    save_versions(state, user_nid, &new_versions)?;

    // Sessions: walk `keys.<version>.<room_id>.sessions.<session_id>`
    // and re-insert each as a per-row CF entry. Maintain stats per
    // version.
    if let Some(keys) = legacy.get("keys").and_then(|v| v.as_object()) {
        for (version, rooms) in keys {
            let mut count = 0u64;
            if let Some(rooms_obj) = rooms.as_object() {
                for (room_id, room_blob) in rooms_obj {
                    let sessions = room_blob
                        .get("sessions")
                        .and_then(|v| v.as_object())
                        .cloned()
                        .unwrap_or_default();
                    for (sid, sess) in sessions {
                        state
                            .db
                            .key_backup_session_put(user_nid, version, room_id, &sid, &sess)
                            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                        count += 1;
                    }
                }
            }
            // Etag starts at the post-migration count so clients see
            // a fresh value and re-fetch the bucket — that's the
            // signal that something on the server changed.
            state
                .db
                .key_backup_stats_set(user_nid, version, count, count)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        }
    }

    // Clear the legacy account_data so it stops leaking via /sync.
    // Writing `null` is enough — /sync filters null account_data
    // bodies. We DON'T delete the row (no helper for that today);
    // the value is harmless once null.
    state
        .db
        .set_account_data(user_nid, LEGACY_BACKUP_STORE, &Value::Null)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(is_verified: bool, fmi: u64, fc: u64) -> Value {
        json!({
            "first_message_index": fmi,
            "forwarded_count": fc,
            "is_verified": is_verified,
            "session_data": {"a": "b"},
        })
    }

    #[test]
    fn should_replace_verified_beats_unverified() {
        assert!(should_replace(&key(false, 0, 0), &key(true, 999, 999)));
        assert!(!should_replace(&key(true, 999, 999), &key(false, 0, 0)));
    }

    #[test]
    fn should_replace_lower_first_message_index_wins() {
        assert!(should_replace(&key(false, 10, 5), &key(false, 9, 999)));
        assert!(!should_replace(&key(false, 10, 5), &key(false, 11, 0)));
    }

    #[test]
    fn should_replace_lower_forwarded_count_wins_on_tie() {
        assert!(should_replace(&key(false, 10, 5), &key(false, 10, 4)));
        assert!(!should_replace(&key(false, 10, 5), &key(false, 10, 6)));
    }

    #[test]
    fn should_replace_full_tie_keeps_existing() {
        assert!(!should_replace(&key(false, 10, 5), &key(false, 10, 5)));
    }
}
