//! `GET /.well-known/matrix/support` (MSC1929 / spec v1.10).
//!
//! 404 when unconfigured (don't advertise an empty doc); otherwise the
//! configured contacts + support_page round-trip verbatim.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use common::{ConfigOverrides, Harness, read_json};

#[tokio::test]
async fn support_unconfigured_returns_404() {
    let harness = Harness::new();
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/support")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn support_returns_configured_contacts_and_page() {
    let harness = Harness::with_overrides(
        "example.com",
        ConfigOverrides {
            support: vela_api::router::SupportConfig {
                contacts: vec![vela_api::router::SupportContact {
                    matrix_id: Some("@admin:example.com".into()),
                    email_address: Some("admin@example.com".into()),
                    role: Some("m.role.admin".into()),
                }],
                support_page: Some("https://example.com/support".into()),
            },
            ..Default::default()
        },
    );
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/support")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["support_page"], "https://example.com/support");
    assert_eq!(body["contacts"][0]["matrix_id"], "@admin:example.com");
    assert_eq!(body["contacts"][0]["email_address"], "admin@example.com");
    assert_eq!(body["contacts"][0]["role"], "m.role.admin");
}

#[tokio::test]
async fn support_page_only_is_enough() {
    // At least one of contacts / support_page present → 200 (not 404).
    let harness = Harness::with_overrides(
        "example.com",
        ConfigOverrides {
            support: vela_api::router::SupportConfig {
                contacts: vec![],
                support_page: Some("https://help.example.com".into()),
            },
            ..Default::default()
        },
    );
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/support")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["support_page"], "https://help.example.com");
    // No contacts key when none configured.
    assert!(body.get("contacts").is_none());
}
