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

        // First try as a regular user access token.
        if let Some((user_nid, device_id)) = state
            .db
            .validate_token(&token)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            let user_id = state
                .db
                .resolve_nid(user_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .ok_or(ApiError(VelaError::UnknownToken))?;
            return Ok(AuthenticatedUser {
                user_nid,
                user_id,
                device_id,
            });
        }

        // Fall through to AS masquerading: maybe this is an
        // `Authorization: Bearer <as_token>` from a registered AS.
        // Look up the as_token's hash in the registry; if it matches,
        // honour `?user_id=` (or fall back to sender_localpart).
        if let Some(live) =
            crate::appservice::auth::lookup_appservice(&state.appservice_registry, &token)
        {
            let query_user_id = extract_query_param(parts, "user_id");
            let device_id =
                extract_query_param(parts, "device_id").unwrap_or_else(|| "AS".to_string());
            let (user_id, user_nid) = crate::appservice::auth::resolve_masquerade(
                &state.db,
                &state.config.server_name,
                &live,
                query_user_id.as_deref(),
            )
            .map_err(|e| ApiError(VelaError::Forbidden(e.to_string())))?;
            return Ok(AuthenticatedUser {
                user_nid,
                user_id,
                device_id,
            });
        }

        Err(ApiError(VelaError::UnknownToken))
    }
}

/// Read one query string parameter by name. Returns the first match
/// found; ignores duplicates. Percent decoding is not applied —
/// callers handle that if needed (today's only caller is AS
/// masquerading, where `user_id` is an MXID with predictable shape).
fn extract_query_param(parts: &Parts, name: &str) -> Option<String> {
    let query = parts.uri.query()?;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix(&format!("{name}=")) {
            return Some(v.to_string());
        }
    }
    None
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
