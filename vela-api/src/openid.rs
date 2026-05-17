//! OpenID Connect single-sign-on plumbing for Matrix.
//!
//! - `POST /_matrix/client/v3/user/{userId}/openid/request_token`
//!   issues a short-lived bearer token for the caller. Used by
//!   widgets and integrations to prove identity to a third-party
//!   service that talks Matrix federation.
//! - `GET /_matrix/federation/v1/openid/userinfo?access_token=...`
//!   is hit by that third-party service to verify the token and
//!   resolve it to a user_id. Spec marks this endpoint as
//!   unauthenticated — the access_token IS the auth, so the
//!   request bypasses the X-Matrix federation auth middleware.

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// 1 hour, per spec recommendation. Long enough for typical SSO
/// handoff round-trips, short enough that token theft has a
/// bounded window of usefulness.
const OPENID_TOKEN_TTL_MS: u64 = 60 * 60 * 1000;

/// POST /_matrix/client/v3/user/{userId}/openid/request_token
///
/// Issues a fresh OpenID token for the authenticated caller. Body
/// is empty per spec; we ignore any body that's sent. The path
/// `userId` MUST match the caller — clients can't request tokens
/// for other users.
pub async fn request_token(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(target_user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if target_user_id != user.user_id {
        return Err(VelaError::Forbidden(
            "openid token can only be requested for the caller".into(),
        )
        .into());
    }

    // Random 32-byte token, URL-safe base64. Plenty of entropy for
    // the spec's "implementation chooses an opaque token" contract.
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let expires_at_ms = now_ms + OPENID_TOKEN_TTL_MS;

    state
        .db
        .store_openid_token(&token, &user.user_id, expires_at_ms)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    Ok(Json(json!({
        "access_token": token,
        "token_type": "Bearer",
        "matrix_server_name": state.config.server_name,
        "expires_in": OPENID_TOKEN_TTL_MS / 1000,
    })))
}

#[derive(Deserialize)]
pub struct UserinfoQuery {
    pub access_token: String,
}

/// GET /_matrix/federation/v1/openid/userinfo?access_token=...
///
/// Spec-mandated unauthenticated endpoint. Verifies the token and
/// returns `{ "sub": "@user:server" }` on success, 401 otherwise.
/// "Unauthenticated" here means no X-Matrix federation signature —
/// the access_token in the query string is the bearer.
pub async fn federation_userinfo(
    State(state): State<AppState>,
    Query(q): Query<UserinfoQuery>,
) -> Result<Json<Value>, StatusCode> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let user_id = state
        .db
        .lookup_openid_token(&q.access_token, now_ms)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(Json(json!({ "sub": user_id })))
}
