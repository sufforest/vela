//! Regression tests for event redaction visibility.
//!
//! After Alice redacts her own message, /sync, /messages, and the
//! single-event endpoint must all hide the original `body` and surface
//! a `redacted_because` link to the redaction event.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync(harness: &Harness, token: &str) -> Value {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/sync?timeout=0")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    read_json(resp).await
}

async fn redact(harness: &Harness, token: &str, room: &str, event_id: &str) -> StatusCode {
    let txn = format!("redact-{}", rand_suffix());
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room}/redact/{event_id}/{txn}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"reason": "oops"}).to_string()))
            .unwrap(),
        )
        .await;
    resp.status()
}

async fn get_event(harness: &Harness, token: &str, room: &str, event_id: &str) -> Value {
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

#[tokio::test]
async fn redacted_message_loses_body_in_sync_and_event_endpoints() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;

    let room = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    let event_id = harness.send_message(&alice_tok, &room, "secret data").await;

    // Pre-redaction: body is visible.
    let pre = get_event(&harness, &alice_tok, &room, &event_id).await;
    assert_eq!(pre["content"]["body"], "secret data");

    let status = redact(&harness, &alice_tok, &room, &event_id).await;
    assert_eq!(status, StatusCode::OK, "alice can redact own message");

    // Post-redaction: body gone, redacted_because populated.
    let post = get_event(&harness, &alice_tok, &room, &event_id).await;
    assert!(
        post["content"].get("body").is_none(),
        "body must be stripped after redaction: {post}"
    );
    assert_eq!(
        post.pointer("/unsigned/redacted_because/type")
            .and_then(|v| v.as_str()),
        Some("m.room.redaction"),
        "redacted_because should reference the redaction event: {post}"
    );

    // Same invariant via /sync — the redacted event in the timeline must
    // not leak the body.
    let synced = sync(&harness, &alice_tok).await;
    let events = synced
        .pointer(&format!("/rooms/join/{room}/timeline/events"))
        .and_then(|v| v.as_array())
        .expect("timeline events");
    let redacted_event = events
        .iter()
        .find(|e| e["event_id"] == event_id)
        .expect("redacted event in timeline");
    assert!(
        redacted_event["content"].get("body").is_none(),
        "sync must hide body of redacted event: {redacted_event}"
    );
}

#[tokio::test]
async fn redacted_message_disappears_from_messages_endpoint() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    let event_id = harness
        .send_message(&alice_tok, &room, "before redaction")
        .await;
    let status = redact(&harness, &alice_tok, &room, &event_id).await;
    assert_eq!(status, StatusCode::OK);

    // /messages should serve the redacted form too.
    let resp = harness
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=20"
            ))
            .header("authorization", format!("Bearer {alice_tok}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let chunks = body["chunk"].as_array().expect("chunk");
    let target = chunks
        .iter()
        .find(|e| e["event_id"] == event_id)
        .expect("target in chunk");
    assert!(
        target["content"].get("body").is_none(),
        "/messages must hide redacted body: {target}"
    );
}

fn rand_suffix() -> String {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos}")
}
