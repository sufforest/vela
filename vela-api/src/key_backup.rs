//! Key backup — `GET/PUT /room_keys/...`.
//!
//! Spec: `client-server-api/#server-side-key-backups`.
//!
//! Clients use key backup so newly-logged-in devices can recover room
//! keys without needing every device to be online. Backup data is
//! opaque to us: the client encrypts a Megolm session per room with an
//! SSSS-derived key and stores it here.
//!
//! Vela's MVP: sessions keyed by `(user, version, room_id, session_id)`.
//! Etag is the string version of the server's internal counter. No
//! global deletion GC.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

const BACKUP_STORE: &str = "m.vela.key_backup";

// --- Versions ---

#[derive(Deserialize)]
pub struct CreateBackupBody {
    pub algorithm: String,
    pub auth_data: Value,
}

/// POST /_matrix/client/v3/room_keys/version
///
/// Create a new backup version. We store the version metadata in the
/// user's account data under a private type and increment the version
/// string so it's monotonic.
pub async fn post_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<CreateBackupBody>,
) -> Result<Json<Value>, ApiError> {
    let mut store = load_store(&state, user.user_nid)?;
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
    // Bump ver_counter so the next POST gets a fresh number even if no
    // keys were uploaded against this version.
    store_obj.insert("ver_counter".to_string(), json!(next));
    save_store(&state, user.user_nid, &store)?;
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
    let store = load_store(&state, user.user_nid)?;
    let latest = store
        .get("latest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError(VelaError::NotFound("no backup version found".into())))?;
    let meta = store
        .pointer(&format!("/versions/{latest}"))
        .cloned()
        .ok_or_else(|| ApiError(VelaError::NotFound("version metadata missing".into())))?;
    Ok(Json(meta))
}

/// GET /_matrix/client/v3/room_keys/version/{version}
pub async fn get_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(version): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let store = load_store(&state, user.user_nid)?;
    let meta = store
        .pointer(&format!("/versions/{version}"))
        .cloned()
        .ok_or_else(|| ApiError(VelaError::NotFound("version not found".into())))?;
    Ok(Json(meta))
}

/// PUT /_matrix/client/v3/room_keys/version/{version}
///
/// Clients call this to update `auth_data` for an existing version
/// (e.g. after re-wrapping the backup key).
pub async fn put_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(version): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let mut store = load_store(&state, user.user_nid)?;
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
    save_store(&state, user.user_nid, &store)?;
    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/v3/room_keys/version/{version}
pub async fn delete_version(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(version): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut store = load_store(&state, user.user_nid)?;
    if let Some(versions) = store.get_mut("versions").and_then(|v| v.as_object_mut()) {
        versions.remove(&version);
    }
    // Clear keys for this version too.
    if let Some(keys) = store.get_mut("keys").and_then(|v| v.as_object_mut()) {
        keys.remove(&version);
    }
    save_store(&state, user.user_nid, &store)?;
    Ok(Json(json!({})))
}

// --- Keys ---

#[derive(Debug, Default, Deserialize)]
pub struct KeysVersionQuery {
    pub version: Option<String>,
}

/// PUT /_matrix/client/v3/room_keys/keys
///
/// Body shape: `{rooms: {<roomId>: {sessions: {<sessionId>: <body>}}}}`.
pub async fn put_all_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<KeysVersionQuery>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let rooms = body
        .get("rooms")
        .and_then(|v| v.as_object())
        .ok_or_else(|| ApiError(VelaError::BadJson("missing rooms".into())))?;
    let mut store = load_store(&state, user.user_nid)?;
    let mut count_added = 0u64;
    for (room_id, room_body) in rooms {
        let sessions = room_body
            .get("sessions")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        for (session_id, sess) in sessions {
            if write_session(&mut store, &version, room_id, &session_id, sess) {
                count_added += 1;
            }
        }
    }
    let (etag, total) = bump_version_stats(&mut store, &version, count_added);
    save_store(&state, user.user_nid, &store)?;
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
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let sessions = body
        .get("sessions")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let mut store = load_store(&state, user.user_nid)?;
    let mut count_added = 0u64;
    for (session_id, sess) in sessions {
        if write_session(&mut store, &version, &room_id, &session_id, sess) {
            count_added += 1;
        }
    }
    let (etag, total) = bump_version_stats(&mut store, &version, count_added);
    save_store(&state, user.user_nid, &store)?;
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
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let mut store = load_store(&state, user.user_nid)?;
    let written = write_session(&mut store, &version, &room_id, &session_id, body);
    let (etag, total) = bump_version_stats(&mut store, &version, if written { 1 } else { 0 });
    save_store(&state, user.user_nid, &store)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// GET /_matrix/client/v3/room_keys/keys
pub async fn get_all_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let store = load_store(&state, user.user_nid)?;
    let rooms = store
        .pointer(&format!("/keys/{version}"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(Json(json!({"rooms": rooms})))
}

/// GET /_matrix/client/v3/room_keys/keys/{roomId}
pub async fn get_room_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let store = load_store(&state, user.user_nid)?;
    let sessions = store
        .pointer(&format!("/keys/{version}/{room_id}/sessions"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    Ok(Json(json!({"sessions": sessions})))
}

/// GET /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}
pub async fn get_session(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let store = load_store(&state, user.user_nid)?;
    let sess = store
        .pointer(&format!("/keys/{version}/{room_id}/sessions/{session_id}"))
        .cloned()
        .ok_or_else(|| ApiError(VelaError::NotFound("session not found".into())))?;
    Ok(Json(sess))
}

/// DELETE /_matrix/client/v3/room_keys/keys
pub async fn delete_all_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let mut store = load_store(&state, user.user_nid)?;
    let removed = count_keys_in_version(&store, &version);
    if let Some(keys) = store.get_mut("keys").and_then(|v| v.as_object_mut()) {
        keys.insert(version.clone(), json!({}));
    }
    let (etag, total) = clear_count_after_delete(&mut store, &version, removed);
    save_store(&state, user.user_nid, &store)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// DELETE /_matrix/client/v3/room_keys/keys/{roomId}
pub async fn delete_room_keys(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let mut store = load_store(&state, user.user_nid)?;
    let removed = count_keys_in_room(&store, &version, &room_id);
    if let Some(rooms) = store
        .pointer_mut(&format!("/keys/{version}"))
        .and_then(|v| v.as_object_mut())
    {
        rooms.remove(&room_id);
    }
    let (etag, total) = clear_count_after_delete(&mut store, &version, removed);
    save_store(&state, user.user_nid, &store)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

/// DELETE /_matrix/client/v3/room_keys/keys/{roomId}/{sessionId}
pub async fn delete_session(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, session_id)): Path<(String, String)>,
    Query(q): Query<KeysVersionQuery>,
) -> Result<Json<Value>, ApiError> {
    let version = q
        .version
        .ok_or_else(|| ApiError(VelaError::BadJson("version query param required".into())))?;
    let mut store = load_store(&state, user.user_nid)?;
    let mut removed = 0u64;
    if let Some(sessions) = store
        .pointer_mut(&format!("/keys/{version}/{room_id}/sessions"))
        .and_then(|v| v.as_object_mut())
        && sessions.remove(&session_id).is_some()
    {
        removed = 1;
    }
    let (etag, total) = clear_count_after_delete(&mut store, &version, removed);
    save_store(&state, user.user_nid, &store)?;
    Ok(Json(json!({"etag": etag, "count": total})))
}

// --- helpers ---

fn load_store(state: &AppState, user_nid: u64) -> Result<Value, ApiError> {
    let v = state
        .db
        .get_account_data(user_nid, BACKUP_STORE)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(v.unwrap_or_else(|| json!({"versions": {}, "keys": {}, "latest": null, "ver_counter": 0})))
}

fn save_store(state: &AppState, user_nid: u64, v: &Value) -> Result<(), ApiError> {
    state
        .db
        .set_account_data(user_nid, BACKUP_STORE, v)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(())
}

fn next_version(store: &Value) -> u64 {
    store
        .get("ver_counter")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        + 1
}

/// Insert a session, applying the spec's replacement rule. Returns true
/// if the new key replaced an existing one (or was newly stored), false
/// if the existing key is preferred and was kept.
///
/// Replacement order: prefer is_verified=true, then lower
/// first_message_index, then lower forwarded_count. Ties keep the
/// existing key (idempotent, no-op).
fn write_session(
    store: &mut Value,
    version: &str,
    room_id: &str,
    session_id: &str,
    body: Value,
) -> bool {
    let keys = store
        .as_object_mut()
        .unwrap()
        .entry("keys")
        .or_insert_with(|| json!({}));
    let ver = keys
        .as_object_mut()
        .unwrap()
        .entry(version.to_string())
        .or_insert_with(|| json!({}));
    let room = ver
        .as_object_mut()
        .unwrap()
        .entry(room_id.to_string())
        .or_insert_with(|| json!({"sessions": {}}));
    let sessions = room
        .as_object_mut()
        .unwrap()
        .entry("sessions".to_string())
        .or_insert_with(|| json!({}));
    let sessions_obj = sessions.as_object_mut().unwrap();
    if let Some(existing) = sessions_obj.get(session_id)
        && !should_replace(existing, &body)
    {
        return false;
    }
    sessions_obj.insert(session_id.to_string(), body);
    true
}

/// Spec rule for whether `incoming` should replace `existing`:
/// 1. is_verified=true beats is_verified=false
/// 2. else lower first_message_index wins
/// 3. else lower forwarded_count wins
/// 4. else keep existing (no replacement).
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

/// Bump this version's etag + count, also remember the counter we used
/// so the next POST /version picks a fresh number. When `count_delta`
/// is 0 (PUT had no effect — replacement rule kept the existing key),
/// etag is NOT bumped: spec says it represents stored-keys state, and
/// nothing changed.
fn bump_version_stats(store: &mut Value, version: &str, count_delta: u64) -> (String, u64) {
    // ver_counter: max(counter, version as u64).
    if let Ok(n) = version.parse::<u64>() {
        let cur = store
            .get("ver_counter")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        store
            .as_object_mut()
            .unwrap()
            .insert("ver_counter".to_string(), json!(cur.max(n)));
    }

    let Some(meta) = store.pointer_mut(&format!("/versions/{version}")) else {
        return ("0".to_string(), 0);
    };
    let obj = meta.as_object_mut().unwrap();
    let cur_etag = obj
        .get("etag")
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .parse::<u64>()
        .unwrap_or(0);
    let etag = if count_delta == 0 {
        cur_etag
    } else {
        cur_etag + 1
    };
    obj.insert("etag".to_string(), json!(etag.to_string()));
    let count = obj.get("count").and_then(|v| v.as_u64()).unwrap_or(0) + count_delta;
    obj.insert("count".to_string(), json!(count));
    (etag.to_string(), count)
}

/// Bump etag and decrement count after a delete. `removed` is how many
/// keys actually disappeared. Etag bumps iff at least one key was removed.
fn clear_count_after_delete(store: &mut Value, version: &str, removed: u64) -> (String, u64) {
    let Some(meta) = store.pointer_mut(&format!("/versions/{version}")) else {
        return ("0".to_string(), 0);
    };
    let obj = meta.as_object_mut().unwrap();
    let cur_etag = obj
        .get("etag")
        .and_then(|v| v.as_str())
        .unwrap_or("0")
        .parse::<u64>()
        .unwrap_or(0);
    let etag = if removed == 0 { cur_etag } else { cur_etag + 1 };
    obj.insert("etag".to_string(), json!(etag.to_string()));
    let cur_count = obj.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
    let count = cur_count.saturating_sub(removed);
    obj.insert("count".to_string(), json!(count));
    (etag.to_string(), count)
}

fn count_keys_in_version(store: &Value, version: &str) -> u64 {
    let Some(rooms) = store
        .pointer(&format!("/keys/{version}"))
        .and_then(|v| v.as_object())
    else {
        return 0;
    };
    let mut total = 0u64;
    for (_, room) in rooms {
        if let Some(sessions) = room.get("sessions").and_then(|v| v.as_object()) {
            total += sessions.len() as u64;
        }
    }
    total
}

fn count_keys_in_room(store: &Value, version: &str, room_id: &str) -> u64 {
    store
        .pointer(&format!("/keys/{version}/{room_id}/sessions"))
        .and_then(|v| v.as_object())
        .map(|o| o.len() as u64)
        .unwrap_or(0)
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
        // is_verified=true beats is_verified=false regardless of other fields.
        assert!(should_replace(&key(false, 0, 0), &key(true, 999, 999)));
        assert!(!should_replace(&key(true, 999, 999), &key(false, 0, 0)));
    }

    #[test]
    fn should_replace_lower_first_message_index_wins() {
        assert!(should_replace(&key(false, 10, 5), &key(false, 9, 999)));
        assert!(!should_replace(&key(false, 10, 5), &key(false, 11, 0)));
        assert!(should_replace(&key(true, 10, 5), &key(true, 9, 999)));
        assert!(!should_replace(&key(true, 10, 5), &key(true, 11, 0)));
    }

    #[test]
    fn should_replace_lower_forwarded_count_wins_on_tie() {
        assert!(should_replace(&key(false, 10, 5), &key(false, 10, 4)));
        assert!(!should_replace(&key(false, 10, 5), &key(false, 10, 6)));
    }

    #[test]
    fn should_replace_full_tie_keeps_existing() {
        assert!(!should_replace(&key(false, 10, 5), &key(false, 10, 5)));
        assert!(!should_replace(&key(true, 10, 5), &key(true, 10, 5)));
    }

    /// Mirrors TestE2EKeyBackupReplaceRoomKeyRules sessionId="a" case:
    /// after writing the canonical key, no key with worse fields displaces it.
    #[test]
    fn complement_unverified_input_no_displacement() {
        let mut store = json!({});
        let initial = key(false, 10, 5);
        assert!(write_session(&mut store, "1", "!r", "a", initial.clone()));

        let candidates = [key(false, 11, 5), key(false, 10, 6), key(false, 11, 6)];
        for c in &candidates {
            assert!(
                !write_session(&mut store, "1", "!r", "a", c.clone()),
                "expected no replacement for {c}"
            );
        }
        let stored = store.pointer("/keys/1/!r/sessions/a").unwrap();
        assert_eq!(stored, &initial);
    }

    /// Mirrors TestE2EKeyBackupReplaceRoomKeyRules sessionId="b" case:
    /// canonical is verified — no unverified key wins, no higher-fmi or
    /// higher-fc verified key wins.
    #[test]
    fn complement_verified_input_no_displacement() {
        let mut store = json!({});
        let initial = key(true, 10, 5);
        assert!(write_session(&mut store, "1", "!r", "b", initial.clone()));

        let candidates = [
            key(false, 11, 5),
            key(false, 10, 6),
            key(false, 11, 6),
            key(true, 11, 5),
            key(true, 10, 6),
            key(true, 11, 6),
        ];
        for c in &candidates {
            assert!(
                !write_session(&mut store, "1", "!r", "b", c.clone()),
                "expected no replacement for {c}"
            );
        }
        let stored = store.pointer("/keys/1/!r/sessions/b").unwrap();
        assert_eq!(stored, &initial);
    }

    #[test]
    fn delete_session_drops_one_and_decrements_count() {
        let mut store = json!({"versions": {"1": {"etag": "5", "count": 3}}});
        write_session(&mut store, "1", "!r", "a", key(false, 1, 1));
        write_session(&mut store, "1", "!r", "b", key(false, 2, 2));

        let removed = if let Some(sessions) = store
            .pointer_mut("/keys/1/!r/sessions")
            .and_then(|v| v.as_object_mut())
        {
            if sessions.remove("a").is_some() { 1 } else { 0 }
        } else {
            0
        };
        let (etag, count) = clear_count_after_delete(&mut store, "1", removed);

        assert_eq!(etag, "6", "etag bumps when key removed");
        // We never set count to 2 in this contrived test (we just
        // pre-populated count=3); the delete path subtracts removed.
        assert_eq!(count, 2);
        assert!(store.pointer("/keys/1/!r/sessions/a").is_none());
        assert!(store.pointer("/keys/1/!r/sessions/b").is_some());
    }

    #[test]
    fn count_helpers_walk_the_store() {
        let mut store = json!({});
        write_session(&mut store, "1", "!r1", "s1", key(false, 1, 1));
        write_session(&mut store, "1", "!r1", "s2", key(false, 2, 1));
        write_session(&mut store, "1", "!r2", "s3", key(false, 3, 1));
        assert_eq!(count_keys_in_version(&store, "1"), 3);
        assert_eq!(count_keys_in_room(&store, "1", "!r1"), 2);
        assert_eq!(count_keys_in_room(&store, "1", "!r2"), 1);
        assert_eq!(count_keys_in_room(&store, "1", "!unknown"), 0);
    }

    #[test]
    fn etag_does_not_bump_when_replacement_is_rejected() {
        let mut store = json!({"versions": {"1": {"etag": "0", "count": 0}}});
        write_session(&mut store, "1", "!r", "a", key(false, 10, 5));
        let (etag1, _) = bump_version_stats(&mut store, "1", 1);
        assert_eq!(etag1, "1");

        // Worse key — rejected, count_delta=0, etag must not bump.
        let written = write_session(&mut store, "1", "!r", "a", key(false, 11, 5));
        assert!(!written);
        let (etag2, _) = bump_version_stats(&mut store, "1", 0);
        assert_eq!(etag2, "1", "etag must stay constant when nothing changed");
    }
}
