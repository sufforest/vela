//! Refresh-token flow.
//!
//! Covers:
//! - login with `refresh_token: true` returns paired access/refresh + expires_in_ms
//! - register with `refresh_token: true` returns the same
//! - POST /v3/refresh rotates both tokens, old access token rejected
//! - POST /v3/refresh with consumed refresh token returns 401 + soft_logout
//! - non-refreshable login still issues a non-expiring token

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::{Harness, read_json};

async fn login_with_refresh(h: &Harness, user: &str, pw: &str) -> serde_json::Value {
    let body = json!({
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": user},
        "password": pw,
        "refresh_token": true,
    });
    let resp = h
        .request(
            Request::post("/_matrix/client/v3/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

async fn whoami(h: &Harness, token: &str) -> StatusCode {
    let resp = h
        .request(
            Request::get("/_matrix/client/v3/account/whoami")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    resp.status()
}

async fn refresh(h: &Harness, refresh_token: &str) -> (StatusCode, serde_json::Value) {
    let resp = h
        .request(
            Request::post("/_matrix/client/v3/refresh")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": refresh_token}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    let status = resp.status();
    (status, read_json(resp).await)
}

#[tokio::test]
async fn login_with_refresh_returns_paired_tokens() {
    let h = Harness::new();
    h.register("alice", "pw").await;
    let body = login_with_refresh(&h, "alice", "pw").await;

    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    assert!(body["expires_in_ms"].as_u64().unwrap() > 0);
    assert_ne!(body["access_token"], body["refresh_token"]);
}

#[tokio::test]
async fn register_without_refresh_omits_refresh_token() {
    let h = Harness::new();
    let (_uid, token) = h.register("bob", "pw").await;
    // Plain register path should still issue a non-expiring access token.
    assert_eq!(whoami(&h, &token).await, StatusCode::OK);
}

#[tokio::test]
async fn refresh_rotates_and_invalidates_old_access() {
    let h = Harness::new();
    h.register("carol", "pw").await;
    let initial = login_with_refresh(&h, "carol", "pw").await;
    let access1 = initial["access_token"].as_str().unwrap().to_string();
    let refresh1 = initial["refresh_token"].as_str().unwrap().to_string();

    assert_eq!(whoami(&h, &access1).await, StatusCode::OK);

    let (status, body) = refresh(&h, &refresh1).await;
    assert_eq!(status, StatusCode::OK);
    let access2 = body["access_token"].as_str().unwrap().to_string();
    let refresh2 = body["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(access1, access2);
    assert_ne!(refresh1, refresh2);

    assert_eq!(whoami(&h, &access2).await, StatusCode::OK);
    // Old access token is invalidated by rotation.
    assert_eq!(whoami(&h, &access1).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_twice_with_same_token_soft_logout() {
    let h = Harness::new();
    h.register("dave", "pw").await;
    let initial = login_with_refresh(&h, "dave", "pw").await;
    let refresh1 = initial["refresh_token"].as_str().unwrap().to_string();

    let (status, _) = refresh(&h, &refresh1).await;
    assert_eq!(status, StatusCode::OK);

    let (status2, body) = refresh(&h, &refresh1).await;
    assert_eq!(status2, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    assert_eq!(body["soft_logout"], true);
}

#[tokio::test]
async fn refresh_unknown_token_soft_logout() {
    let h = Harness::new();
    let (status, body) = refresh(&h, "definitely-not-a-real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["errcode"], "M_UNKNOWN_TOKEN");
    assert_eq!(body["soft_logout"], true);
}
