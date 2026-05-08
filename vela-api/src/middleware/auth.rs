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
    /// True when the bearer token came from an `[[appservice]]`
    /// registration rather than a session login. AS callers can
    /// `act-as` any user in the registration's namespaces and may
    /// supply `?ts=` overrides on outbound events.
    pub is_appservice: bool,
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Extract token from Authorization header or query param
        let token = extract_token(parts).ok_or(ApiError(VelaError::MissingToken))?;

        // Application-service path: bearer matches a registered
        // `as_token`. Resolve the acting user from the `?user_id=`
        // query parameter (default: the registration's
        // sender_localpart). We auto-create the user nid if it isn't
        // known yet — bridges typically appear before their virtual
        // users have ever been seen.
        if let Some(reg) = state.appservices.iter().find(|r| r.as_token == token) {
            let user_id = pick_appservice_user(parts, reg, &state.config.server_name);
            if !reg.covers_user(&user_id) {
                return Err(VelaError::Forbidden(format!(
                    "appservice {} not authorised to act as {}",
                    reg.id, user_id
                ))
                .into());
            }
            let user_nid = state
                .db
                .get_or_create_nid(&user_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            return Ok(AuthenticatedUser {
                user_nid,
                user_id,
                // Synthetic device — AS callers don't have a real
                // device, but downstream code (txn idempotency, sync)
                // keys on (user_nid, device_id), so we need a stable
                // string. Reusing the AS id keeps two appservices
                // from colliding.
                device_id: format!("AS_{}", reg.id),
                is_appservice: true,
            });
        }

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
            is_appservice: false,
        })
    }
}

fn pick_appservice_user(
    parts: &Parts,
    reg: &vela_core::appservice::AppserviceRegistration,
    server_name: &str,
) -> String {
    if let Some(query) = parts.uri.query() {
        for pair in query.split('&') {
            if let Some(v) = pair.strip_prefix("user_id=") {
                return percent_decode(v);
            }
        }
    }
    format!("@{}:{}", reg.sender_localpart, server_name)
}

/// Tiny percent-decoder for the `user_id` and `ts` query params. Just
/// enough to handle Go's net/url encoding of `@` and `:` (the only
/// chars Matrix user IDs ever contain that need escaping). Non-UTF8
/// bytes are passed through; bad %-sequences are left literal.
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(h) = hex
                && let Ok(b) = u8::from_str_radix(h, 16)
            {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
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
