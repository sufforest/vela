//! `GET /_matrix/client/v1/auth_metadata` (MSC2965): relays the IdP's
//! RFC 8414 metadata, falls back to issuer-only, 404 when OIDC is off.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{ConfigOverrides, Harness, read_json};

fn oidc(issuer: &str) -> vela_api::router::OidcConfig {
    vela_api::router::OidcConfig {
        enabled: true,
        issuer: issuer.to_string(),
        account_management_url: Some("https://account.example".to_string()),
        ..Default::default()
    }
}

async fn auth_metadata(harness: &Harness) -> (StatusCode, serde_json::Value) {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v1/auth_metadata")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let s = resp.status();
    (s, read_json(resp).await)
}

#[tokio::test]
async fn auth_metadata_404_when_oidc_disabled() {
    let harness = Harness::new();
    let (status, body) = auth_metadata(&harness).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Spec (CS-API v1.15): not-supported → M_UNRECOGNIZED. Element keys
    // on this errcode to fall back to legacy login; a different 404
    // errcode here surfaces as "your Element is misconfigured".
    assert_eq!(body["errcode"], "M_UNRECOGNIZED");
}

#[tokio::test]
async fn auth_metadata_relays_idp_document() {
    let idp = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": idp.uri(),
            "authorization_endpoint": format!("{}/authorize", idp.uri()),
            "token_endpoint": format!("{}/token", idp.uri()),
            "response_types_supported": ["code"],
        })))
        .mount(&idp)
        .await;

    let harness = Harness::with_overrides(
        "example.com",
        ConfigOverrides {
            oidc: oidc(&idp.uri()),
            ..Default::default()
        },
    );

    let (status, body) = auth_metadata(&harness).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_endpoint"], format!("{}/token", idp.uri()));
    assert_eq!(body["response_types_supported"][0], "code");
    // Account management URL folded in from config.
    assert_eq!(body["account_management_uri"], "https://account.example");
}

#[tokio::test]
async fn auth_metadata_falls_back_when_idp_unreachable() {
    // Port 1 refuses immediately → fetch fails → minimal fallback doc.
    let harness = Harness::with_overrides(
        "example.com",
        ConfigOverrides {
            oidc: oidc("http://127.0.0.1:1"),
            ..Default::default()
        },
    );

    let (status, body) = auth_metadata(&harness).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["issuer"], "http://127.0.0.1:1");
    assert_eq!(body["account_management_uri"], "https://account.example");
}
