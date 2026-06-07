//! `POST /_matrix/client/v3/delete_devices` — batch device delete + UIA.
//!
//! Negative space: a bare request must challenge (not silently no-op),
//! a UIA identifier that isn't the caller must 403, and a foreign /
//! unknown device id in the list must be skipped rather than failing
//! the whole batch.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

/// Mint a second device for an already-registered user via password login.
async fn login(harness: &Harness, user: &str, password: &str, device_id: &str) -> (String, String) {
    let body = json!({
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": user},
        "password": password,
        "device_id": device_id,
    });
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/login")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "login failed: {resp:?}");
    let v = read_json(resp).await;
    (
        v["access_token"].as_str().unwrap().to_string(),
        v["device_id"].as_str().unwrap().to_string(),
    )
}

async fn list_device_ids(harness: &Harness, token: &str) -> Vec<String> {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/devices")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = read_json(resp).await;
    v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["device_id"].as_str().map(|s| s.to_string()))
        .collect()
}

async fn delete_devices(harness: &Harness, token: &str, body: Value) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/delete_devices")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    let status = resp.status();
    (status, read_json(resp).await)
}

#[tokio::test]
async fn bare_request_challenges_uia() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;
    let (status, body) = delete_devices(&harness, &tok, json!({"devices": []})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // UIA challenge carries flows + a session.
    assert!(body.get("flows").is_some(), "expected UIA flows: {body}");
    assert!(body.get("session").is_some());
}

#[tokio::test]
async fn wrong_uia_identifier_is_forbidden() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;
    let (_bob, _bobtok) = harness.register("bob", "pw").await;
    // Alice's token, but UIA completed as bob → 403 even with bob's
    // correct password.
    let (status, _) = delete_devices(
        &harness,
        &tok,
        json!({
            "devices": [],
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "bob"},
                "password": "pw",
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deletes_listed_devices_and_skips_unknown() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;
    let (_tok2, dev2) = login(&harness, "alice", "pw", "DEVTWO").await;
    let (_tok3, dev3) = login(&harness, "alice", "pw", "DEVTHREE").await;

    let before = list_device_ids(&harness, &tok).await;
    assert!(before.contains(&dev2) && before.contains(&dev3));

    // Delete dev2 + an id alice doesn't own; the unknown id must not
    // fail the batch, and dev3 must survive.
    let (status, _) = delete_devices(
        &harness,
        &tok,
        json!({
            "devices": [dev2, "NOPE_DOES_NOT_EXIST"],
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "alice"},
                "password": "pw",
            }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let after = list_device_ids(&harness, &tok).await;
    assert!(!after.contains(&dev2), "dev2 should be deleted");
    assert!(after.contains(&dev3), "dev3 should survive");
}
