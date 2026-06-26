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
#[derive(Debug, Clone)]
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
            // Best-effort: record this device's activity for GET /devices.
            // Throttled in the store (one write/device/minute), so the cost
            // on the hot path is a small point lookup + parse of the
            // last-seen row, with an actual write only past the throttle.
            // Never fatal — a failure here must not block an otherwise-
            // authenticated request.
            let ip = crate::auth::client_ip::client_ip_from_headers(&parts.headers);
            let _ = state
                .db
                .touch_device_seen(user_nid, &device_id, now_unix_ms(), ip.as_deref());
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

        // Final fallthrough: MSC3861 Phase 2 delegated auth. Only
        // attempted when the operator configured an introspection
        // endpoint; otherwise this is identical to the previous
        // two-path extractor.
        if let Some(oidc) = state.oidc_introspection.as_ref() {
            return resolve_oidc_token(state, oidc, &token).await;
        }

        Err(ApiError(VelaError::UnknownToken))
    }
}

/// Optional authentication: `Option<AuthenticatedUser>` in a handler
/// signature yields `None` when no token is presented at all, but still
/// rejects (401) a token that is present but invalid. Used by endpoints
/// the spec allows unauthenticated for world-readable rooms (e.g.
/// MSC3266 room summary) while keeping bad-token requests honest.
impl axum::extract::OptionalFromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Option<Self>, Self::Rejection> {
        if extract_token(parts).is_none() {
            return Ok(None);
        }
        <AuthenticatedUser as FromRequestParts<AppState>>::from_request_parts(parts, state)
            .await
            .map(Some)
    }
}

/// Validate `token` against the IdP, provision the user+device on
/// first touch, and return an `AuthenticatedUser`. Each failure mode
/// maps to a distinct ApiError so clients see the right status:
///   - IdP unreachable / 5xx → 503 (caller should retry)
///   - inactive / wrong scope / missing device_id → 401 M_UNKNOWN_TOKEN
///   - storage error during provisioning → 500
async fn resolve_oidc_token(
    state: &AppState,
    oidc: &std::sync::Arc<crate::auth::oidc::IntrospectionState>,
    token: &str,
) -> Result<AuthenticatedUser, ApiError> {
    use crate::auth::oidc::{IntrospectionOutcome, REQUIRED_SCOPES, mapping};

    // Cache hit short-circuits the IdP round-trip.
    let outcome = if let Some(cached) = oidc.cache.get(token) {
        cached
    } else {
        let fresh = oidc.client.introspect(token).await.map_err(|e| {
            // IdP unreachable / 5xx: surface 503 so the client can retry.
            // We deliberately do NOT cache failures — a flaky IdP would
            // otherwise lock the token out for the cache TTL.
            ApiError(VelaError::Custom {
                status: 503,
                errcode: "M_UNKNOWN",
                msg: format!("delegated auth: IdP error: {e}"),
            })
        })?;
        oidc.cache.put(token.to_string(), fresh.clone());
        fresh
    };

    let introspection = match outcome {
        IntrospectionOutcome::Active(r) => r,
        IntrospectionOutcome::Inactive => return Err(ApiError(VelaError::UnknownToken)),
    };

    // Scope gate: client must hold at least one of the MSC2967 scopes
    // granting CS-API access. Failing this is "this token is for some
    // other API," surface as M_UNKNOWN_TOKEN to keep the client error
    // shape identical to "no scope at all."
    let has_scope = introspection
        .scope
        .iter()
        .any(|s| REQUIRED_SCOPES.contains(&s.as_str()));
    if !has_scope {
        return Err(ApiError(VelaError::UnknownToken));
    }

    let identity = mapping::lookup_or_provision(
        &state.db,
        crate::auth::oidc::PROVIDER,
        &state.config.server_name,
        &introspection,
    )
    .map_err(|e| match e {
        mapping::MappingError::MissingDeviceId | mapping::MappingError::InvalidLocalpart(_) => {
            ApiError(VelaError::UnknownToken)
        }
        mapping::MappingError::Storage(msg) => ApiError(VelaError::Store(msg)),
    })?;

    Ok(AuthenticatedUser {
        user_nid: identity.user_nid,
        user_id: identity.user_id,
        device_id: identity.device_id,
        appservice_nid: None,
    })
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

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

#[cfg(test)]
mod oidc_extractor_tests {
    use std::sync::Arc;

    use axum::extract::FromRequestParts;
    use axum::http::Request;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::auth::oidc::{
        DEFAULT_CACHE_TTL, IntrospectionCache, IntrospectionClient, IntrospectionState,
    };
    use crate::router::IntrospectionAuthMethod;
    use crate::test_helpers::build_test_state;

    /// Build an AppState whose OIDC client points at the given mock
    /// server. Cache TTL is the production default; tests that need
    /// to exercise expiry override individual entries.
    async fn state_with_idp(server: &MockServer) -> (AppState, tempfile::TempDir) {
        let (mut state, tmp) = build_test_state();
        let client = IntrospectionClient::with_http(
            reqwest::Client::new(),
            format!("{}/oauth2/introspect", server.uri()),
            "vela-client".into(),
            "s3cret".into(),
            IntrospectionAuthMethod::ClientSecretBasic,
        );
        let cache = IntrospectionCache::new(DEFAULT_CACHE_TTL);
        state.oidc_introspection = Some(Arc::new(IntrospectionState { client, cache }));
        (state, tmp)
    }

    fn bearer_request(token: &str) -> Request<()> {
        Request::builder()
            .uri("/_matrix/client/v3/sync")
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .unwrap()
    }

    async fn extract(state: &AppState, token: &str) -> Result<AuthenticatedUser, ApiError> {
        let req = bearer_request(token);
        let (mut parts, _) = req.into_parts();
        AuthenticatedUser::from_request_parts(&mut parts, state).await
    }

    /// Happy path: IdP confirms an active token with the required
    /// scope and a device_id; the extractor provisions the user +
    /// device on first touch.
    #[tokio::test]
    async fn first_touch_provisions_user_and_device() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "idp-sub-alice",
                "username": "alice",
                "scope": "urn:matrix:client:api:*",
                "device_id": "DEV-1",
            })))
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let user = extract(&state, "tok-alice").await.expect("auth ok");
        assert_eq!(user.user_id, "@alice:example.com");
        assert_eq!(user.device_id, "DEV-1");
        assert!(user.appservice_nid.is_none());
        // Mapping persisted in store.
        assert_eq!(
            state
                .db
                .get_external_id_mapping(crate::auth::oidc::PROVIDER, "idp-sub-alice")
                .unwrap(),
            Some(user.user_nid)
        );
    }

    /// Second request with the same token must hit the cache (IdP
    /// receives exactly one introspection call).
    #[tokio::test]
    async fn second_call_hits_cache() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "idp-sub-bob",
                "username": "bob",
                "scope": "urn:matrix:client:api:*",
                "device_id": "DEV-1",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let _ = extract(&state, "tok-bob").await.expect("first call");
        let _ = extract(&state, "tok-bob").await.expect("second call");
        // wiremock's drop will assert expect(1).
        drop(server);
    }

    /// Inactive tokens are rejected with M_UNKNOWN_TOKEN — the same
    /// error shape the password-auth path returns for a bad token,
    /// so clients don't need to special-case delegated auth.
    #[tokio::test]
    async fn inactive_token_returns_unknown_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let err = extract(&state, "expired-token").await.unwrap_err();
        assert!(matches!(err.0, VelaError::UnknownToken));
    }

    /// Active token without the required CS-API scope is refused.
    /// Synapse parity: clients see the same M_UNKNOWN_TOKEN shape.
    #[tokio::test]
    async fn missing_required_scope_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "idp-sub-carol",
                "username": "carol",
                "scope": "urn:custom:other-api",
                "device_id": "DEV-1",
            })))
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let err = extract(&state, "wrong-scope").await.unwrap_err();
        assert!(matches!(err.0, VelaError::UnknownToken));
    }

    /// Active token without a device_id claim (top-level OR scope-
    /// derived) is refused — we can't anchor session state to a
    /// device that doesn't exist.
    #[tokio::test]
    async fn missing_device_id_is_rejected() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "idp-sub-dave",
                "username": "dave",
                "scope": "urn:matrix:client:api:*",
            })))
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let err = extract(&state, "no-device").await.unwrap_err();
        assert!(matches!(err.0, VelaError::UnknownToken));
    }

    /// IdP unreachable → 503, NOT M_UNKNOWN_TOKEN. Client retries
    /// rather than treating the token as bad.
    #[tokio::test]
    async fn idp_5xx_returns_503() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let err = extract(&state, "any-token").await.unwrap_err();
        match err.0 {
            VelaError::Custom { status, .. } => assert_eq!(status, 503),
            other => panic!("expected 503, got {other:?}"),
        }
    }

    /// Returning user (existing external_ids mapping) goes through
    /// the fast path: no second user_create, just device check.
    #[tokio::test]
    async fn returning_user_uses_fast_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "idp-sub-eve",
                "username": "eve",
                "scope": "urn:matrix:client:api:*",
                "device_id": "DEV-2",
            })))
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let first = extract(&state, "tok-eve-1").await.expect("first auth");
        // Invalidate cache so the second request re-hits the IdP path
        // (without this, we'd test the cache hit, not the mapping).
        state
            .oidc_introspection
            .as_ref()
            .unwrap()
            .cache
            .invalidate("tok-eve-1");
        let second = extract(&state, "tok-eve-1").await.expect("second auth");
        assert_eq!(first.user_nid, second.user_nid);
        assert_eq!(first.user_id, second.user_id);
    }

    /// When oidc_introspection is None (Phase 2 not configured), a
    /// random Bearer token falls through to UnknownToken — the
    /// pre-MSC3861-Phase-2 behaviour is preserved exactly.
    #[tokio::test]
    async fn extractor_skips_oidc_when_phase2_not_configured() {
        let (state, _tmp) = build_test_state();
        assert!(state.oidc_introspection.is_none());
        let err = extract(&state, "unknown-token").await.unwrap_err();
        assert!(matches!(err.0, VelaError::UnknownToken));
    }

    /// Unstable scope variant is also accepted for compatibility with
    /// older IdPs that haven't switched to the stable URN.
    #[tokio::test]
    async fn unstable_scope_variant_is_accepted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "idp-sub-frank",
                "username": "frank",
                "scope": "urn:matrix:org.matrix.msc2967.client:api:*",
                "device_id": "DEV-1",
            })))
            .mount(&server)
            .await;
        let (state, _tmp) = state_with_idp(&server).await;
        let user = extract(&state, "unstable-scope").await.expect("auth ok");
        assert_eq!(user.user_id, "@frank:example.com");
    }
}
