use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use vela_core::error::VelaError;

use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Authenticated user extractor. Use this in handler signatures
/// to require authentication:
///
/// ```ignore
/// async fn handler(user: AuthenticatedUser, ...) { ... }
/// ```
pub struct AuthenticatedUser {
    pub user_nid: u64,
    pub user_id: String,
    pub device_id: String,
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract token from Authorization header or query param
        let token = extract_token(parts).ok_or(ApiError(VelaError::MissingToken))?;

        // Validate token
        let (user_nid, device_id) = state
            .db
            .validate_token(&token)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .ok_or(ApiError(VelaError::UnknownToken))?;

        // Resolve user_id from NID
        let user_id = state
            .db
            .resolve_nid(user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .ok_or(ApiError(VelaError::UnknownToken))?;

        Ok(AuthenticatedUser {
            user_nid,
            user_id,
            device_id,
        })
    }
}

fn extract_token(parts: &Parts) -> Option<String> {
    // Try Authorization: Bearer <token>
    if let Some(auth) = parts.headers.get("authorization")
        && let Ok(auth_str) = auth.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        return Some(token.to_string());
    }

    // Try ?access_token=<token> query param
    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("access_token=") {
                return Some(token.to_string());
            }
        }
    }

    None
}
