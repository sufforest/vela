//! MSC3814 dehydrated devices — `.../org.matrix.msc3814.v1/dehydrated_device`.
//!
//! Negative space: PUT must require valid, self-bound `device_keys`; a
//! device_id mismatch must 400; GET/events on an absent or non-matching
//! device must 404; replacing a dehydrated device must purge the old one;
//! the events drain must paginate by cursor and never double-deliver.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

fn device_keys(user: &str, device: &str) -> Value {
    json!({
        "user_id": user,
        "device_id": device,
        "algorithms": ["m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"],
        "keys": { format!("curve25519:{device}"): "key", format!("ed25519:{device}"): "key" },
        "signatures": { user: { format!("ed25519:{device}"): "sig" } },
    })
}

async fn put(harness: &Harness, token: &str, body: Value) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::put("/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    let s = resp.status();
    (s, read_json(resp).await)
}

async fn get(harness: &Harness, token: &str) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::get("/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let s = resp.status();
    (s, read_json(resp).await)
}

async fn events(
    harness: &Harness,
    token: &str,
    device: &str,
    next_batch: Option<&str>,
) -> (StatusCode, Value) {
    let body = match next_batch {
        Some(nb) => json!({ "next_batch": nb }),
        None => json!({}),
    };
    let resp = harness
        .request(
            Request::post(format!(
                "/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{device}/events"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await;
    let s = resp.status();
    (s, read_json(resp).await)
}

#[tokio::test]
async fn put_requires_self_bound_device_keys() {
    let harness = Harness::new();
    let (user, token) = harness.register("alice", "secret").await;

    // Missing device_keys entirely → 400.
    let (s, _) = put(
        &harness,
        &token,
        json!({"device_id": "DEHYD", "device_data": {"a": 1}}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // device_keys.device_id disagreeing with the dehydrated device_id → 400.
    let (s, _) = put(
        &harness,
        &token,
        json!({
            "device_id": "DEHYD",
            "device_data": {"a": 1},
            "device_keys": device_keys(&user, "OTHER"),
        }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // device_keys for a different user → 400.
    let (s, _) = put(
        &harness,
        &token,
        json!({
            "device_id": "DEHYD",
            "device_data": {"a": 1},
            "device_keys": device_keys("@mallory:example.com", "DEHYD"),
        }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_get_roundtrip_and_404_when_absent() {
    let harness = Harness::new();
    let (user, token) = harness.register("alice", "secret").await;

    // Absent → 404.
    let (s, _) = get(&harness, &token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let data = json!({"algorithm": "m.dehydration.v1.olm", "device_pickle": "blob"});
    let (s, body) = put(
        &harness,
        &token,
        json!({
            "device_id": "DEHYD1",
            "device_data": data,
            "device_keys": device_keys(&user, "DEHYD1"),
            "one_time_keys": {"signed_curve25519:AAAA": {"key": "k", "signatures": {}}},
        }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["device_id"], "DEHYD1");

    let (s, body) = get(&harness, &token).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["device_id"], "DEHYD1");
    assert_eq!(
        body["device_data"], data,
        "device_data must round-trip verbatim"
    );
}

#[tokio::test]
async fn put_replaces_and_purges_old_device() {
    let harness = Harness::new();
    let (user, token) = harness.register("alice", "secret").await;

    put(
        &harness,
        &token,
        json!({"device_id": "DEHYD_A", "device_data": {"v": 1}, "device_keys": device_keys(&user, "DEHYD_A")}),
    )
    .await;
    put(
        &harness,
        &token,
        json!({"device_id": "DEHYD_B", "device_data": {"v": 2}, "device_keys": device_keys(&user, "DEHYD_B")}),
    )
    .await;

    // GET reflects the latest; only one dehydrated device per user.
    let (_, body) = get(&harness, &token).await;
    assert_eq!(body["device_id"], "DEHYD_B");

    // The superseded device must be purged from the device list.
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/devices")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let v = read_json(resp).await;
    let ids: Vec<&str> = v["devices"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|d| d["device_id"].as_str())
        .collect();
    assert!(
        !ids.contains(&"DEHYD_A"),
        "old dehydrated device should be purged: {ids:?}"
    );
    assert!(
        ids.contains(&"DEHYD_B"),
        "new dehydrated device should be registered: {ids:?}"
    );
}

#[tokio::test]
async fn delete_then_get_404() {
    let harness = Harness::new();
    let (user, token) = harness.register("alice", "secret").await;
    put(
        &harness,
        &token,
        json!({"device_id": "DEHYD", "device_data": {}, "device_keys": device_keys(&user, "DEHYD")}),
    )
    .await;

    let resp = harness
        .request(
            Request::delete("/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let (s, _) = get(&harness, &token).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // Deleting again → 404 (nothing to remove).
    let resp = harness
        .request(
            Request::delete("/_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn events_paginate_by_cursor_without_double_delivery() {
    let harness = Harness::new();
    let (user, token) = harness.register("alice", "secret").await;
    put(
        &harness,
        &token,
        json!({"device_id": "DEHYD", "device_data": {}, "device_keys": device_keys(&user, "DEHYD")}),
    )
    .await;

    // Queue two to-device messages straight to the dehydrated device.
    let user_nid = harness.state.db.get_nid(&user).unwrap().unwrap();
    for i in 0..2 {
        harness
            .state
            .db
            .queue_to_device(
                user_nid,
                "DEHYD",
                "m.room_key",
                "@bob:example.com",
                &json!({"n": i}),
            )
            .unwrap();
    }

    // Drain one at a time; the cursor must advance and never repeat.
    let (s, page1) = events(&harness, &token, "DEHYD", None).await;
    assert_eq!(s, StatusCode::OK);
    // With the default limit both come in one page; assert we got them and a cursor.
    assert_eq!(page1["events"].as_array().unwrap().len(), 2, "{page1}");
    let cursor = page1["next_batch"].as_str().unwrap().to_string();

    // Re-draining from the cursor yields nothing (no double-delivery), but
    // messages are NOT consumed — the cursor is read-ahead.
    let (_, page2) = events(&harness, &token, "DEHYD", Some(&cursor)).await;
    assert_eq!(page2["events"].as_array().unwrap().len(), 0, "{page2}");

    // From the start again, both reappear (read-ahead, not destructive).
    let (_, replay) = events(&harness, &token, "DEHYD", None).await;
    assert_eq!(replay["events"].as_array().unwrap().len(), 2);

    // A device id that isn't the caller's dehydrated device → 403.
    let (s, _) = events(&harness, &token, "NOTMINE", None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_rejects_aliasing_an_active_device() {
    let harness = Harness::new();
    let (user, token) = harness.register("alice", "secret").await;

    // The login created a live device; aliasing it as a dehydrated device
    // would clobber its keys / log it out, so it must be refused.
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/devices")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let v = read_json(resp).await;
    let active = v["devices"][0]["device_id"].as_str().unwrap().to_string();

    let (s, _) = put(
        &harness,
        &token,
        json!({"device_id": active, "device_data": {}, "device_keys": device_keys(&user, &active)}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "must not alias an active device");

    // Re-PUTting the *current* dehydrated id is still allowed (refresh).
    put(
        &harness,
        &token,
        json!({"device_id": "DEHYD", "device_data": {"v": 1}, "device_keys": device_keys(&user, "DEHYD")}),
    )
    .await;
    let (s, _) = put(
        &harness,
        &token,
        json!({"device_id": "DEHYD", "device_data": {"v": 2}, "device_keys": device_keys(&user, "DEHYD")}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "refreshing the current dehydrated device is allowed"
    );
}

#[tokio::test]
async fn put_bounds_blob_and_otk_count() {
    let harness = Harness::new();
    let (user, token) = harness.register("alice", "secret").await;

    // Oversize device_data → 400.
    let big = "x".repeat(64 * 1024 + 1);
    let (s, _) = put(
        &harness,
        &token,
        json!({"device_id": "D", "device_data": {"blob": big}, "device_keys": device_keys(&user, "D")}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "oversize device_data must be rejected"
    );

    // Too many one_time_keys → 400.
    let mut otks = serde_json::Map::new();
    for i in 0..101 {
        otks.insert(
            format!("signed_curve25519:K{i}"),
            json!({"key": "k", "signatures": {}}),
        );
    }
    let (s, _) = put(
        &harness,
        &token,
        json!({"device_id": "D", "device_data": {}, "device_keys": device_keys(&user, "D"), "one_time_keys": otks}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "over-cap one_time_keys must be rejected"
    );
}
