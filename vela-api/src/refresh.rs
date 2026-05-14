use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use vela_core::error::VelaError;

use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Default access-token lifetime when a refresh-token flow is in use.
/// One hour is well inside what the spec recommends ("substantially
/// less than the lifetime of the refresh token").
pub const ACCESS_TOKEN_LIFETIME_MS: u64 = 60 * 60 * 1000;

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: Option<String>,
}

/// POST /_matrix/client/v3/refresh
///
/// Consumes the supplied refresh token, invalidates the previously paired
/// access token, and returns a freshly-issued (access, refresh) pair plus
/// the new access token's lifetime. On unknown/consumed token, returns
/// 401 `M_UNKNOWN_TOKEN` with `soft_logout: false` — the session is gone
/// and the client must discard any persisted state.
pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Response, ApiError> {
    let refresh_token = body
        .refresh_token
        .as_deref()
        .ok_or_else(|| ApiError(VelaError::BadJson("refresh_token required".into())))?;

    let pair = state
        .db
        .refresh_access_token(refresh_token, ACCESS_TOKEN_LIFETIME_MS)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let (access, refresh, user_nid, _device_id) = match pair {
        Some(p) => p,
        None => return Ok(unknown_token()),
    };

    // Deactivated users must never get a fresh access token. In normal
    // flow `deactivate` already deleted every refresh token, so we'd
    // never reach here — this is the belt-and-braces check for any
    // racing refresh that snuck through during deactivation.
    if state
        .db
        .user_is_deactivated(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        return Err(VelaError::UserDeactivated.into());
    }

    Ok(Json(json!({
        "access_token": access,
        "refresh_token": refresh,
        "expires_in_ms": ACCESS_TOKEN_LIFETIME_MS,
    }))
    .into_response())
}

/// Build a 401 `M_UNKNOWN_TOKEN` body for an unknown or already-consumed
/// refresh token. `soft_logout: false` (the spec default) is the correct
/// signal here: the refresh token has no paired session left, so the
/// client must discard persisted state and re-log in.
fn unknown_token() -> Response {
    let body = json!({
        "errcode": "M_UNKNOWN_TOKEN",
        "error": "Unknown refresh token",
        "soft_logout": false,
    });
    (StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use axum::extract::State;
    use axum::http::StatusCode;

    /// In normal flow `deactivate` revokes refresh tokens, so a
    /// post-deactivation refresh hits the unknown-token 401 path. This
    /// test covers the *racing-refresh* branch: the refresh token
    /// survived somehow, but the user is flagged deactivated. We must
    /// not mint a new access token in that case.
    #[tokio::test]
    async fn refresh_rejects_deactivated_user() {
        let (state, _tmp) = build_test_state();
        let user_nid = state.db.create_user("@alice:example.com", "hash").unwrap();
        state.db.create_device(user_nid, "DEV").unwrap();
        let (_access, refresh_tok) = state.db.create_token_pair(user_nid, "DEV", 60_000).unwrap();

        // Race: user gets flagged deactivated AFTER the refresh token
        // landed but BEFORE the refresh request is processed.
        state.db.deactivate_user(user_nid).unwrap();

        let err = refresh(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: Some(refresh_tok),
            }),
        )
        .await
        .expect_err("deactivated user must not get a fresh token");

        assert!(matches!(err.0, VelaError::UserDeactivated));
    }

    /// After a real `deactivate` call the refresh CF entry is gone, so
    /// the request short-circuits via the unknown-token 401 before the
    /// deactivation check is even reached. Sanity-check that path too.
    #[tokio::test]
    async fn refresh_with_unknown_token_returns_401() {
        let (state, _tmp) = build_test_state();
        let resp = refresh(
            State(state.clone()),
            Json(RefreshRequest {
                refresh_token: Some("nonexistent".into()),
            }),
        )
        .await
        .expect("ok-but-401 response shape");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
