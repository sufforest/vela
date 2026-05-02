use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Extract the server name from a Matrix user ID (`@local:server`).
/// Returns `None` for malformed IDs (no `:` or no `@` prefix).
fn user_server(user_id: &str) -> Option<&str> {
    user_id.strip_prefix('@')?.split_once(':').map(|(_, s)| s)
}

/// True if the given user_id's server-portion matches our configured
/// `server_name`. Treats malformed IDs as local (let the storage
/// lookup fail with a clean 404 rather than mis-routing them).
fn is_local_user(user_id: &str, server_name: &str) -> bool {
    user_server(user_id)
        .map(|s| s == server_name)
        .unwrap_or(true)
}

/// Translate a federation `query_profile` failure into a client-API
/// `ApiError`. We surface the remote's own 404 as `M_NOT_FOUND`;
/// every other transport/JSON failure becomes `M_NOT_FOUND` too,
/// since spec says profile lookups MUST surface as not-found rather
/// than leaking remote-server health.
fn federation_profile_err(e: crate::federation_client::FederationClientError) -> ApiError {
    ApiError(VelaError::NotFound(format!(
        "remote profile lookup failed: {e}"
    )))
}

/// GET /_matrix/client/v3/profile/{userId}
pub async fn get_profile(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !is_local_user(&user_id, &state.config.server_name) {
        // Federate to the user's home server. Spec: clients can call
        // /profile/{remote_user_id} on their own server and we MUST
        // forward the lookup over /_matrix/federation/v1/query/profile.
        let server = user_server(&user_id)
            .ok_or_else(|| ApiError(VelaError::NotFound("malformed user id".into())))?;
        let resp = state
            .federation_client
            .query_profile(server, &user_id, None)
            .await
            .map_err(federation_profile_err)?;
        return Ok(Json(resp));
    }

    let user_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user not found".into())))?;

    let record = state
        .db
        .get_user(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or(json!({}));

    let mut response = json!({});
    let obj = response.as_object_mut().unwrap();
    if let Some(name) = record.get("displayname") {
        obj.insert("displayname".into(), name.clone());
    }
    if let Some(avatar) = record.get("avatar_url") {
        obj.insert("avatar_url".into(), avatar.clone());
    }

    Ok(Json(response))
}

/// GET /_matrix/client/v3/profile/{userId}/displayname
pub async fn get_displayname(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !is_local_user(&user_id, &state.config.server_name) {
        let server = user_server(&user_id)
            .ok_or_else(|| ApiError(VelaError::NotFound("malformed user id".into())))?;
        let resp = state
            .federation_client
            .query_profile(server, &user_id, Some("displayname"))
            .await
            .map_err(federation_profile_err)?;
        return Ok(Json(resp));
    }

    let user_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user not found".into())))?;

    let record = state
        .db
        .get_user(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or(json!({}));

    Ok(Json(json!({
        "displayname": record.get("displayname").cloned().unwrap_or(Value::Null)
    })))
}

#[derive(Deserialize)]
pub struct SetDisplaynameRequest {
    pub displayname: Option<String>,
}

/// PUT /_matrix/client/v3/profile/{userId}/displayname
pub async fn set_displayname(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(body): Json<SetDisplaynameRequest>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own profile".into()).into());
    }

    state
        .db
        .update_user_profile(user.user_nid, body.displayname.as_deref(), None)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Merge the stored avatar_url into the propagation so we don't wipe
    // the avatar by emitting a member event with avatar_url missing.
    let avatar = read_avatar(&state, user.user_nid);
    crate::membership::propagate_profile_update(
        &state,
        &user,
        body.displayname.as_deref(),
        avatar.as_deref(),
    )
    .await;

    Ok(Json(json!({})))
}

fn read_avatar(state: &AppState, user_nid: u64) -> Option<String> {
    state.db.get_user(user_nid).ok().flatten().and_then(|u| {
        u.get("avatar_url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    })
}

fn read_displayname(state: &AppState, user_nid: u64) -> Option<String> {
    state.db.get_user(user_nid).ok().flatten().and_then(|u| {
        u.get("displayname")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    })
}

/// GET /_matrix/client/v3/profile/{userId}/avatar_url
pub async fn get_avatar_url(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if !is_local_user(&user_id, &state.config.server_name) {
        let server = user_server(&user_id)
            .ok_or_else(|| ApiError(VelaError::NotFound("malformed user id".into())))?;
        let resp = state
            .federation_client
            .query_profile(server, &user_id, Some("avatar_url"))
            .await
            .map_err(federation_profile_err)?;
        return Ok(Json(resp));
    }

    let user_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user not found".into())))?;

    let record = state
        .db
        .get_user(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or(json!({}));

    Ok(Json(json!({
        "avatar_url": record.get("avatar_url").cloned().unwrap_or(Value::Null)
    })))
}

#[derive(Deserialize)]
pub struct SetAvatarUrlRequest {
    pub avatar_url: Option<String>,
}

/// PUT /_matrix/client/v3/profile/{userId}/avatar_url
pub async fn set_avatar_url(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(body): Json<SetAvatarUrlRequest>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own profile".into()).into());
    }

    state
        .db
        .update_user_profile(user.user_nid, None, body.avatar_url.as_deref())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let displayname = read_displayname(&state, user.user_nid);
    crate::membership::propagate_profile_update(
        &state,
        &user,
        displayname.as_deref(),
        body.avatar_url.as_deref(),
    )
    .await;

    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_server_extracts_domain() {
        assert_eq!(user_server("@alice:hs1"), Some("hs1"));
        assert_eq!(
            user_server("@bob:host.docker.internal:53647"),
            Some("host.docker.internal:53647"),
            "server portion includes any port suffix"
        );
        assert_eq!(user_server("@unicode-名:server"), Some("server"));
    }

    #[test]
    fn user_server_rejects_malformed_ids() {
        assert_eq!(user_server(""), None);
        assert_eq!(user_server("alice:hs1"), None, "missing leading @");
        assert_eq!(user_server("@alice"), None, "missing colon separator");
    }

    #[test]
    fn is_local_user_matches_configured_server() {
        assert!(is_local_user("@alice:hs1", "hs1"));
        assert!(!is_local_user("@alice:hs2", "hs1"));
        assert!(!is_local_user("@bob:host.docker.internal:53647", "hs1"));
        // Malformed → treated as local (storage layer surfaces the
        // clean 404 rather than mis-routing).
        assert!(is_local_user("not-a-user-id", "hs1"));
    }
}
