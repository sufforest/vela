//! MSC3861 phase 1: OIDC discovery + capability advertisement.
//!
//! Locks in:
//! - `/auth_issuer` is gated entirely by `[auth.oidc] enabled` — when
//!   off (default), the route 404s with `M_NOT_FOUND` (the spec's
//!   "we don't delegate" signal). When on, it returns 200 with the
//!   configured issuer URL and (optional) account-management URL.
//! - `/_matrix/client/versions` advertises `org.matrix.msc3861 = true`
//!   in `unstable_features` ONLY when delegation is on. A bare `true`
//!   would mislead clients into attempting an OAuth flow against a
//!   server that hasn't been configured for it.
//! - `/.well-known/matrix/client` mirrors the same posture in its
//!   `org.matrix.msc3861` block.
//!
//! Token validation against the IdP is phase 2 and explicitly NOT
//! exercised here.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use common::{ConfigOverrides, Harness, read_json};

// --- disabled (default) ---------------------------------------------------

#[tokio::test]
async fn auth_issuer_disabled_returns_404_m_not_found() {
    let harness = Harness::new(); // default: oidc.enabled = false
    let resp = harness
        .request(
            Request::get("/_matrix/client/v1/auth_issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = read_json(resp).await;
    assert_eq!(body["errcode"], "M_NOT_FOUND");
}

#[tokio::test]
async fn versions_disabled_does_not_advertise_msc3861() {
    let harness = Harness::new();
    let resp = harness
        .request(
            Request::get("/_matrix/client/versions")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    // Absent OR explicit false would both be acceptable; assert
    // absent to match the implementation and rule out future drift
    // where someone adds it with `false`.
    assert!(
        body["unstable_features"]
            .get("org.matrix.msc3861")
            .is_none(),
        "msc3861 must NOT appear in unstable_features when disabled: {body:?}"
    );
}

#[tokio::test]
async fn well_known_disabled_does_not_include_msc3861_block() {
    let harness = Harness::new();
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert!(
        body.get("org.matrix.msc3861").is_none(),
        ".well-known must not advertise MSC3861 when disabled: {body:?}"
    );
}

// --- enabled --------------------------------------------------------------

fn oidc_overrides() -> ConfigOverrides {
    ConfigOverrides {
        oidc: vela_api::router::OidcConfig {
            enabled: true,
            issuer: "https://idp.example.com".to_string(),
            client_id: Some("vela-client-id".to_string()),
            account_management_url: Some("https://idp.example.com/account".to_string()),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[tokio::test]
async fn auth_issuer_enabled_returns_configured_issuer() {
    let harness = Harness::with_config(oidc_overrides());
    let resp = harness
        .request(
            Request::get("/_matrix/client/v1/auth_issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["issuer"], "https://idp.example.com");
    assert_eq!(body["account"], "https://idp.example.com/account");
}

#[tokio::test]
async fn auth_issuer_enabled_omits_account_when_unset() {
    let harness = Harness::with_config(ConfigOverrides {
        oidc: vela_api::router::OidcConfig {
            enabled: true,
            issuer: "https://idp.example.com".to_string(),
            client_id: None,
            account_management_url: None,
            ..Default::default()
        },
        ..Default::default()
    });
    let resp = harness
        .request(
            Request::get("/_matrix/client/v1/auth_issuer")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["issuer"], "https://idp.example.com");
    assert!(
        body.get("account").is_none(),
        "account must be omitted when not configured: {body:?}"
    );
}

#[tokio::test]
async fn versions_enabled_advertises_msc3861() {
    let harness = Harness::with_config(oidc_overrides());
    let resp = harness
        .request(
            Request::get("/_matrix/client/versions")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["unstable_features"]["org.matrix.msc3861"], true);
}

#[tokio::test]
async fn well_known_enabled_includes_msc3861_block() {
    let harness = Harness::with_config(oidc_overrides());
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let block = &body["org.matrix.msc3861"];
    assert_eq!(block["issuer"], "https://idp.example.com");
    assert_eq!(block["account"], "https://idp.example.com/account");
}
