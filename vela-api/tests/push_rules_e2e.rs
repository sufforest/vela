//! End-to-end tests that push rules actually gate push dispatch.
//!
//! The unit tests in `vela_core::push_rules::tests` cover the matcher in
//! isolation. These tests wire the full register → set pusher → mute-room
//! / suppress-notice → send message → assert gateway received (or didn't)
//! flow, so we catch regressions in the integration points — the wrong
//! rule set being loaded, display name not read, etc.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::Request;
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::Harness;

async fn put_room_mute_rule(harness: &Harness, token: &str, room_id: &str) {
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/pushrules/global/room/{room_id}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"actions": ["dont_notify"]}).to_string()))
            .unwrap(),
        )
        .await;
    assert!(resp.status().is_success(), "mute rule PUT failed: {resp:?}");
}

async fn send_notice(harness: &Harness, token: &str, room_id: &str, body: &str) {
    let txn = format!("notice-{}", body.len());
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"msgtype": "m.notice", "body": body}).to_string(),
            ))
            .unwrap(),
        )
        .await;
    assert!(resp.status().is_success());
}

#[tokio::test]
async fn muted_room_suppresses_push() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());
    // Bob's gateway MUST NOT be called after mute.
    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&gateway)
        .await;

    harness
        .set_pusher(&bob_tok, "com.example.app", "pk-bob", &notify_url)
        .await;

    let room = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob_id]}),
        )
        .await;
    harness.join(&bob_tok, &room).await;

    // Bob mutes the room by setting a per-room `dont_notify` rule.
    put_room_mute_rule(&harness, &bob_tok, &room).await;

    // Alice posts — normally this pushes; with the mute rule it must not.
    harness.send_message(&alice_tok, &room, "hello").await;

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        gateway.received_requests().await.unwrap().is_empty(),
        "muted room should not dispatch push"
    );
}

#[tokio::test]
async fn m_notice_does_not_push_by_default() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());
    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&gateway)
        .await;

    harness
        .set_pusher(&bob_tok, "com.example.app", "pk-bob", &notify_url)
        .await;

    let room = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob_id]}),
        )
        .await;
    harness.join(&bob_tok, &room).await;

    send_notice(&harness, &alice_tok, &room, "auto announcement").await;

    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        gateway.received_requests().await.unwrap().is_empty(),
        "m.notice should be suppressed by default rule"
    );
}

#[tokio::test]
async fn plain_message_still_notifies_with_default_rules() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());
    // Regular text should fire exactly one notification via the default
    // `.m.rule.message` underride rule.
    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&gateway)
        .await;

    harness
        .set_pusher(&bob_tok, "com.example.app", "pk-bob", &notify_url)
        .await;

    let room = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob_id]}),
        )
        .await;
    harness.join(&bob_tok, &room).await;

    harness.send_message(&alice_tok, &room, "plain text").await;

    tokio::time::sleep(Duration::from_millis(250)).await;
    let received = gateway.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        1,
        "default rules should notify on plain message"
    );

    // Verify the tweak for sound rode along.
    let body: serde_json::Value = serde_json::from_slice(&received[0].body).expect("json");
    let tweaks = body
        .pointer("/notification/devices/0/tweaks")
        .and_then(|v| v.as_object())
        .expect("tweaks present");
    assert_eq!(
        tweaks.get("sound").and_then(|v| v.as_str()),
        Some("default")
    );
}
