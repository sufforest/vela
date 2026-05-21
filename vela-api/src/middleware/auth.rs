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
    /// `Some(nid)` when the request was authenticated via an
    /// Application Service's `as_token` (with optional `?user_id=`
    /// masquerade). Lets downstream handlers apply AS-specific
    /// behaviour: skip UIA on device-mgmt endpoints, honour `?ts=`
    /// timestamp override, allow names inside the AS's exclusive
    /// namespaces.
    pub appservice_nid: Option<u64>,
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
                appservice_nid: None,
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
            let appservice_nid = live.appservice.nid;
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
                appservice_nid: Some(appservice_nid),
            });
        }

        Err(ApiError(VelaError::UnknownToken))
    }
}

/// Read one query string parameter by name. Returns the first match
/// found; ignores duplicates. Applies percent-decoding so AS
/// masquerade with a URL-encoded `?user_id=%40_irc_alice%3Aexample.com`
/// (the shape matrix-appservice-bridge emits) round-trips to the
/// expected `@_irc_alice:example.com` MXID. `+` is intentionally
/// NOT treated as a space — that's `application/x-www-form-urlencoded`
/// body decoding, not URL path/query decoding.
fn extract_query_param(parts: &Parts, name: &str) -> Option<String> {
    let query = parts.uri.query()?;
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix(&format!("{name}=")) {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex(bytes[i + 1]);
            let lo = hex(bytes[i + 2]);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // Decoded query params SHOULD be valid UTF-8 for MXIDs; fall back
    // to lossy decoding rather than refusing the request — callers
    // surface a real auth error downstream when the resulting string
    // doesn't match a namespace.
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_colon_and_at() {
        assert_eq!(
            percent_decode("%40_irc_alice%3Aexample.com"),
            "@_irc_alice:example.com",
        );
    }

    #[test]
    fn percent_decode_preserves_unencoded_input() {
        assert_eq!(
            percent_decode("@_irc_alice:example.com"),
            "@_irc_alice:example.com",
        );
    }

    #[test]
    fn percent_decode_lowercase_and_uppercase_hex() {
        assert_eq!(percent_decode("%2f%2F"), "//");
    }

    #[test]
    fn percent_decode_leaves_malformed_percent_alone() {
        // Trailing `%` with no two hex digits.
        assert_eq!(percent_decode("foo%"), "foo%");
        assert_eq!(percent_decode("foo%2"), "foo%2");
        // Non-hex sequence — emit the literal bytes.
        assert_eq!(percent_decode("foo%zz"), "foo%zz");
    }
}
