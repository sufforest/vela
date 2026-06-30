//! MSC2732 fallback keys end-to-end: when a device's one-time keys are
//! exhausted, `/keys/claim` must hand out the device's fallback key (kept, not
//! consumed) so a sender can still establish an Olm session, and `/sync` must
//! advertise the unused fallback algorithm in `device_unused_fallback_key_types`.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn whoami_device(harness: &Harness, token: &str) -> String {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/account/whoami")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let v = read_json(resp).await;
    v["device_id"].as_str().unwrap().to_string()
}

async fn unused_fallback_types(harness: &Harness, token: &str) -> Vec<String> {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/sync")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = read_json(resp).await;
    v["device_unused_fallback_key_types"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

async fn claim(harness: &Harness, token: &str, user: &str, device: &str) -> Value {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/keys/claim")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"one_time_keys": {user: {device: "signed_curve25519"}}}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

#[tokio::test]
async fn fallback_key_served_when_one_time_keys_exhausted() {
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let device = whoami_device(&harness, &alice_tok).await;

    // Upload identity keys + a single OTK + a fallback key.
    let upload = json!({
        "device_keys": {
            "user_id": alice,
            "device_id": device,
            "algorithms": ["m.olm.v1.curve25519-aes-sha2"],
            "keys": {format!("curve25519:{device}"): "curve_pub"},
            "signatures": {},
        },
        "one_time_keys": {"signed_curve25519:otk1": {"key": "OTK"}},
        "fallback_keys": {"signed_curve25519:fb1": {"key": "FB", "fallback": true}},
    });
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/keys/upload")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(upload.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // /sync advertises the unused fallback algorithm.
    assert_eq!(
        unused_fallback_types(&harness, &alice_tok).await,
        vec!["signed_curve25519".to_string()]
    );

    // First claim consumes the one-time key.
    let first = claim(&harness, &alice_tok, &alice, &device).await;
    assert_eq!(
        first["one_time_keys"][&alice][&device]
            .as_object()
            .and_then(|m| m.keys().next())
            .map(String::as_str),
        Some("signed_curve25519:otk1"),
        "first claim returns the one-time key: {first}"
    );

    // OTKs now exhausted → the next claim returns the fallback key.
    let second = claim(&harness, &alice_tok, &alice, &device).await;
    assert_eq!(
        second["one_time_keys"][&alice][&device]
            .as_object()
            .and_then(|m| m.keys().next())
            .map(String::as_str),
        Some("signed_curve25519:fb1"),
        "claim falls back to the fallback key once OTKs run out: {second}"
    );

    // The fallback is now used → no longer advertised, but still claimable
    // (kept) so a later sender can also reach the device.
    assert!(
        unused_fallback_types(&harness, &alice_tok).await.is_empty(),
        "a claimed fallback key is no longer advertised as unused"
    );
    let third = claim(&harness, &alice_tok, &alice, &device).await;
    assert_eq!(
        third["one_time_keys"][&alice][&device]
            .as_object()
            .and_then(|m| m.keys().next())
            .map(String::as_str),
        Some("signed_curve25519:fb1"),
        "fallback key is kept and served again: {third}"
    );
}
