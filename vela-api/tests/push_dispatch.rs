//! End-to-end test for push notification dispatch.
//!
//! Registers two users, has one invite the other into a room, registers
//! a pusher against a wiremock-backed HTTP gateway for the recipient,
//! sends a message, and asserts the gateway received a well-formed
//! `/_matrix/push/v1/notify` POST.

mod common;

use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::Harness;

#[tokio::test]
async fn message_triggers_push_to_recipient_gateway() {
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob, bob_tok) = harness.register("bob", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());

    // Bob registers a pusher pointing at the mock gateway BEFORE being
    // invited — simulates a real mobile client that sets up push once at
    // login and expects to receive notifications for all subsequent
    // messages.
    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rejected": []})))
        .expect(1)
        .mount(&gateway)
        .await;

    harness
        .set_pusher(&bob_tok, "com.example.app", "pk-bob-1", &notify_url)
        .await;

    // Alice creates a room and invites Bob; Bob joins.
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    // Alice sends a message — should fan out to bob's pusher.
    let event_id = harness
        .send_message(&alice_tok, &room_id, "hello bob")
        .await;

    // Dispatch is fire-and-forget inside a tokio::spawn; allow a brief
    // window for the gateway to observe the POST. The Mock's `.expect(1)`
    // assertion is checked on drop — if we exit too early wiremock will
    // fail the test with a clear message.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let received = gateway.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "expected one POST to the push gateway");

    let body: Value = serde_json::from_slice(&received[0].body).expect("json body");
    let notif = &body["notification"];
    assert_eq!(notif["event_id"], event_id);
    assert_eq!(notif["room_id"], room_id);
    assert_eq!(notif["sender"], alice);
    assert_eq!(notif["type"], "m.room.message");
    let devices = notif["devices"].as_array().expect("devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["pushkey"], "pk-bob-1");
    assert_eq!(devices[0]["app_id"], "com.example.app");
}

#[tokio::test]
async fn sender_does_not_receive_push_for_own_message() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());

    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&gateway)
        .await;

    // Alice pushes to her own pusher (unusual, but tests the sender-skip path).
    harness
        .set_pusher(&alice_tok, "com.example.app", "pk-alice-1", &notify_url)
        .await;

    let room_id = harness.create_room(&alice_tok, json!({})).await;
    harness
        .send_message(&alice_tok, &room_id, "talking to myself")
        .await;

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        gateway.received_requests().await.unwrap().is_empty(),
        "sender should not receive push for own message"
    );
}
