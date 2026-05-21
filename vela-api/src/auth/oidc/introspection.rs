//! RFC 7662 token introspection client. Wraps a single POST to the
//! IdP's introspection endpoint and parses the response into a
//! structured `IntrospectionResult`.
//!
//! Client authentication on the wire is RFC 6749 §2.3:
//!   - `ClientSecretBasic`: HTTP `Authorization: Basic base64(id:secret)`.
//!   - `ClientSecretPost`: credentials in the form body next to `token`.
//!
//! Both methods are functionally equivalent — the IdP picks based on
//! how vela's client was registered. We support either, switched by
//! `IntrospectionAuthMethod` in `OidcConfig`.
//!
//! Spec citations and synapse parity reference are in the
//! checkpoint doc; this module is intentionally narrow — no caching,
//! no provisioning, just one round-trip.

use std::time::Duration;

use serde::Deserialize;
use thiserror::Error;

use crate::router::IntrospectionAuthMethod;

/// Outcome of a single introspection round-trip. Three branches so
/// the caller can distinguish "IdP said no" (cacheable) from "IdP
/// is sick" (don't cache; retry next request) cleanly.
#[derive(Debug, Clone)]
pub enum IntrospectionOutcome {
    /// IdP returned 200 with `active = true`. Token is valid.
    Active(IntrospectionResult),
    /// IdP returned 200 with `active = false`. Token is expired,
    /// revoked, or otherwise no longer usable. Permanent for this
    /// token; cache to avoid hammering the IdP on every retry.
    Inactive,
}

/// Parsed RFC 7662 introspection response for an active token.
/// Field set is what MSC3861 + MSC2967 expect; unknown fields are
/// ignored so newer IdP additions don't break parsing.
#[derive(Debug, Clone)]
pub struct IntrospectionResult {
    /// IdP-issued stable subject id. The vela ↔ IdP mapping table is
    /// keyed by this.
    pub sub: String,
    /// Matrix localpart the IdP wants this user to have. MAS sets
    /// this; generic IdPs may leave it out, in which case vela
    /// derives the localpart from `sub` (in `mapping.rs`).
    pub username: Option<String>,
    /// Space-separated scope claim, split into tokens. MSC2967
    /// requires `urn:matrix:client:api:*` (or unstable variant) to
    /// be present; the validator in `middleware/auth.rs` checks it.
    pub scope: Vec<String>,
    /// Matrix device id this token is bound to. Either a top-level
    /// `device_id` field (MAS extension) or parsed from a
    /// `urn:matrix:client:device:<id>` scope token (spec form).
    pub device_id: Option<String>,
    /// Unix-seconds expiry from the IdP. Used to bound cache TTL so
    /// we never serve a token past its IdP-declared lifetime.
    pub expires_at: Option<u64>,
}

#[derive(Debug, Error)]
pub enum IntrospectionError {
    /// IdP unreachable, TLS error, or another network-layer issue.
    /// Don't cache; retry on next request.
    #[error("IdP unreachable: {0}")]
    Unreachable(String),
    /// IdP returned 4xx/5xx, or a 200 with an unparseable body.
    /// Don't cache; same retry behaviour as `Unreachable`.
    #[error("IdP rejected request: {0}")]
    Permanent(String),
}

/// Stateless introspection HTTP client. One per `AppState`; reuses
/// its inner `reqwest::Client` connection pool across calls.
#[derive(Clone)]
pub struct IntrospectionClient {
    http: reqwest::Client,
    endpoint: String,
    client_id: String,
    client_secret: String,
    auth_method: IntrospectionAuthMethod,
    timeout: Duration,
}

impl IntrospectionClient {
    /// Build a client around the validated OidcConfig fields. Caller
    /// guarantees endpoint + client_id + client_secret are present
    /// (`validate_config` enforces this at boot).
    pub fn new(
        endpoint: String,
        client_id: String,
        client_secret: String,
        auth_method: IntrospectionAuthMethod,
    ) -> Self {
        // 35s ceiling matches the AS-outbox http client; introspection
        // is short-poll so it'll virtually never get near it, but a
        // hung IdP shouldn't be able to pin a vela worker thread
        // forever either.
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .expect("reqwest client");
        Self {
            http,
            endpoint,
            client_id,
            client_secret,
            auth_method,
            timeout: Duration::from_secs(10),
        }
    }

    /// Test-only constructor that lets us inject a pre-built reqwest
    /// client (for wiremock fixtures) and a short per-call timeout.
    #[cfg(test)]
    pub fn with_http(
        http: reqwest::Client,
        endpoint: String,
        client_id: String,
        client_secret: String,
        auth_method: IntrospectionAuthMethod,
    ) -> Self {
        Self {
            http,
            endpoint,
            client_id,
            client_secret,
            auth_method,
            timeout: Duration::from_secs(5),
        }
    }

    /// POST one introspection request. Returns `Ok(Active(...))` /
    /// `Ok(Inactive)` for an IdP-acknowledged response; `Err(...)`
    /// when the IdP is unreachable or returns something we can't
    /// interpret.
    pub async fn introspect(
        &self,
        token: &str,
    ) -> Result<IntrospectionOutcome, IntrospectionError> {
        let mut form: Vec<(&str, &str)> = vec![("token", token)];

        let mut req = self.http.post(&self.endpoint).timeout(self.timeout);
        match self.auth_method {
            IntrospectionAuthMethod::ClientSecretBasic => {
                req = req.basic_auth(&self.client_id, Some(&self.client_secret));
            }
            IntrospectionAuthMethod::ClientSecretPost => {
                form.push(("client_id", &self.client_id));
                form.push(("client_secret", &self.client_secret));
            }
        }
        let resp = req
            .form(&form)
            .send()
            .await
            .map_err(|e| IntrospectionError::Unreachable(format!("{e}")))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(IntrospectionError::Permanent(format!(
                "status {}",
                status.as_u16()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| IntrospectionError::Unreachable(format!("body: {e}")))?;
        parse_response(&bytes)
    }
}

/// Parse the IdP's JSON body into an `IntrospectionOutcome`. Public
/// so unit tests can exercise odd shapes without spinning up a mock
/// HTTP server.
pub fn parse_response(bytes: &[u8]) -> Result<IntrospectionOutcome, IntrospectionError> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        active: bool,
        sub: Option<String>,
        username: Option<String>,
        scope: Option<String>,
        device_id: Option<String>,
        exp: Option<u64>,
    }
    let raw: Raw = serde_json::from_slice(bytes)
        .map_err(|e| IntrospectionError::Permanent(format!("malformed body: {e}")))?;
    if !raw.active {
        return Ok(IntrospectionOutcome::Inactive);
    }
    let Some(sub) = raw.sub else {
        // `active: true` with no `sub` is the IdP misbehaving — there's
        // no identity to anchor a user to. Treat as permanent.
        return Err(IntrospectionError::Permanent(
            "active token without `sub` claim".into(),
        ));
    };
    let scope: Vec<String> = raw
        .scope
        .as_deref()
        .unwrap_or("")
        .split_ascii_whitespace()
        .map(|s| s.to_string())
        .collect();
    // Device id: prefer top-level `device_id` (MAS shape); otherwise
    // parse from a `urn:matrix:client:device:<id>` scope token (spec
    // shape).
    let device_id = raw.device_id.clone().or_else(|| {
        for s in &scope {
            for prefix in [
                "urn:matrix:client:device:",
                "urn:matrix:org.matrix.msc2967.client:device:",
            ] {
                if let Some(rest) = s.strip_prefix(prefix)
                    && !rest.is_empty()
                {
                    return Some(rest.to_string());
                }
            }
        }
        None
    });
    Ok(IntrospectionOutcome::Active(IntrospectionResult {
        sub,
        username: raw.username,
        scope,
        device_id,
        expires_at: raw.exp,
    }))
}

/// Decode a Basic-Auth header value into `(username, password)` for
/// assertions in wiremock tests. Internal helper — not part of the
/// public surface.
#[cfg(test)]
pub fn decode_basic_auth(header: &str) -> Option<(String, String)> {
    use base64::Engine;
    let b64 = header.strip_prefix("Basic ")?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    let s = String::from_utf8(bytes).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client_for(
        server: &MockServer,
        auth_method: IntrospectionAuthMethod,
    ) -> IntrospectionClient {
        IntrospectionClient::with_http(
            reqwest::Client::new(),
            format!("{}/oauth2/introspect", server.uri()),
            "vela-client".into(),
            "s3cret".into(),
            auth_method,
        )
    }

    #[tokio::test]
    async fn active_token_parsed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "user-1",
                "username": "alice",
                "scope": "urn:matrix:client:api:* urn:matrix:client:device:DEV-X",
                "exp": 9_999_999_999u64,
            })))
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretBasic);
        let out = client.introspect("opaque-token").await.unwrap();
        let result = match out {
            IntrospectionOutcome::Active(r) => r,
            other => panic!("expected Active, got {other:?}"),
        };
        assert_eq!(result.sub, "user-1");
        assert_eq!(result.username.as_deref(), Some("alice"));
        // Device id picked up from the scope token even though there
        // was no top-level device_id field.
        assert_eq!(result.device_id.as_deref(), Some("DEV-X"));
        assert!(
            result
                .scope
                .contains(&"urn:matrix:client:api:*".to_string())
        );
        assert_eq!(result.expires_at, Some(9_999_999_999));
    }

    #[tokio::test]
    async fn top_level_device_id_takes_precedence_over_scope() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true,
                "sub": "user-1",
                "device_id": "TOP_LEVEL_DEV",
                "scope": "urn:matrix:client:api:* urn:matrix:client:device:SCOPE_DEV",
            })))
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretBasic);
        let out = client.introspect("opaque-token").await.unwrap();
        let result = match out {
            IntrospectionOutcome::Active(r) => r,
            other => panic!("expected Active, got {other:?}"),
        };
        assert_eq!(result.device_id.as_deref(), Some("TOP_LEVEL_DEV"));
    }

    #[tokio::test]
    async fn inactive_token_returns_inactive_outcome() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretBasic);
        let out = client.introspect("opaque-token").await.unwrap();
        assert!(matches!(out, IntrospectionOutcome::Inactive));
    }

    /// IdP-side bug: returns `active: true` but no sub. We refuse to
    /// invent an identity; surface as Permanent.
    #[tokio::test]
    async fn active_without_sub_is_permanent_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"active": true, "username": "alice"})),
            )
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretBasic);
        let err = client.introspect("opaque-token").await.unwrap_err();
        assert!(matches!(err, IntrospectionError::Permanent(_)));
    }

    #[tokio::test]
    async fn idp_503_is_permanent_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretBasic);
        let err = client.introspect("opaque-token").await.unwrap_err();
        // 5xx surfaces as Permanent because we can't tell if a retry
        // would succeed — the caller (cache+middleware layer) re-tries
        // on next request anyway.
        assert!(matches!(err, IntrospectionError::Permanent(_)));
    }

    #[tokio::test]
    async fn malformed_body_is_permanent_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<not-json>"))
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretBasic);
        let err = client.introspect("opaque-token").await.unwrap_err();
        assert!(matches!(err, IntrospectionError::Permanent(_)));
    }

    /// `client_secret_basic`: credentials in the Authorization header,
    /// not in the form body. The form body carries `token=...` only.
    #[tokio::test]
    async fn client_secret_basic_uses_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .and(header(
                "authorization",
                // base64("vela-client:s3cret") = "dmVsYS1jbGllbnQ6czNjcmV0"
                "Basic dmVsYS1jbGllbnQ6czNjcmV0",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true, "sub": "u", "device_id": "D",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretBasic);
        let out = client.introspect("opaque").await.unwrap();
        assert!(matches!(out, IntrospectionOutcome::Active(_)));
    }

    /// `client_secret_post`: credentials in the form body, no
    /// Authorization header.
    #[tokio::test]
    async fn client_secret_post_uses_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/introspect"))
            .and(body_string_contains("client_id=vela-client"))
            .and(body_string_contains("client_secret=s3cret"))
            .and(body_string_contains("token=opaque"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "active": true, "sub": "u", "device_id": "D",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let client = client_for(&server, IntrospectionAuthMethod::ClientSecretPost);
        let out = client.introspect("opaque").await.unwrap();
        assert!(matches!(out, IntrospectionOutcome::Active(_)));
    }

    #[test]
    fn decode_basic_auth_roundtrip() {
        // sanity for the test helper itself.
        assert_eq!(
            decode_basic_auth("Basic dmVsYS1jbGllbnQ6czNjcmV0"),
            Some(("vela-client".into(), "s3cret".into()))
        );
        assert!(decode_basic_auth("Bearer foo").is_none());
    }
}
