//! End-to-end test for push notification dispatch.
//!
//! Registers two users, has one invite the other into a room, registers
//! a pusher against a wiremock-backed HTTP gateway for the recipient,
//! sends a message, and asserts the gateway received a well-formed
//! `/_matrix/push/v1/notify` POST.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
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
async fn room_mention_from_powered_sender_highlights_in_push() {
    // End-to-end MSC3952 @room: alice is the room creator (v12 → infinite
    // power), so her `m.mentions.room` clears the notifications.room gate and
    // the push carries a highlight tweak. Exercises the push/mod.rs wiring
    // that reads the sender's power level + notifications.room from state.
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob, bob_tok) = harness.register("bob", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());
    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rejected": []})))
        .mount(&gateway)
        .await;
    harness
        .set_pusher(&bob_tok, "com.example.app", "pk-bob-1", &notify_url)
        .await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room_id}/send/m.room.message/mention-txn-1"
            ))
            .header("authorization", format!("Bearer {alice_tok}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "msgtype": "m.text",
                    "body": "@room standup in 5",
                    "m.mentions": {"room": true},
                })
                .to_string(),
            ))
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    tokio::time::sleep(Duration::from_millis(250)).await;

    let received = gateway.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "expected one push for the @room mention");
    let body: Value = serde_json::from_slice(&received[0].body).unwrap();
    let tweaks = &body["notification"]["devices"][0]["tweaks"];
    assert_eq!(
        tweaks["highlight"], true,
        "@room from the room creator should highlight: {body}"
    );
    let _ = alice;
}

/// Two recipients whose pushers point at the SAME gateway URL must each
/// receive their own notification from a single message. Guards the
/// dispatch-time dedup: clients are now shared per unique URL, so a bug there
/// could collapse same-gateway recipients into one delivery (or drop one).
#[tokio::test]
async fn two_recipients_on_same_gateway_each_get_pushed() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob, bob_tok) = harness.register("bob", "pw").await;
    let (carol, carol_tok) = harness.register("carol", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());
    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rejected": []})))
        .expect(2)
        .mount(&gateway)
        .await;

    // Distinct pushkeys, same gateway URL — the shared-client case.
    harness
        .set_pusher(&bob_tok, "com.example.app", "pk-bob", &notify_url)
        .await;
    harness
        .set_pusher(&carol_tok, "com.example.app", "pk-carol", &notify_url)
        .await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob, carol]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;
    harness.join(&carol_tok, &room_id).await;

    harness.send_message(&alice_tok, &room_id, "hi both").await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let received = gateway.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        2,
        "both recipients on the shared gateway push"
    );
    let pushkeys: Vec<String> = received
        .iter()
        .map(|r| {
            let body: Value = serde_json::from_slice(&r.body).unwrap();
            body["notification"]["devices"][0]["pushkey"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(pushkeys.contains(&"pk-bob".to_string()), "bob pushed");
    assert!(pushkeys.contains(&"pk-carol".to_string()), "carol pushed");
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

/// A pusher registered with `format: "event_id_only"` (Push Gateway API)
/// must receive only routing fields — never the event `type`, `sender`, or
/// message `content`. Privacy: the plaintext never reaches the gateway.
#[tokio::test]
async fn event_id_only_pusher_omits_event_content() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob, bob_tok) = harness.register("bob", "pw").await;

    let gateway = MockServer::start().await;
    let notify_url = format!("{}/_matrix/push/v1/notify", gateway.uri());
    Mock::given(method("POST"))
        .and(path("/_matrix/push/v1/notify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"rejected": []})))
        .mount(&gateway)
        .await;

    // Bob registers an event_id_only pusher.
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/pushers/set")
                .header("authorization", format!("Bearer {bob_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "app_id": "com.example.app",
                        "pushkey": "pk-bob-1",
                        "kind": "http",
                        "app_display_name": "App",
                        "device_display_name": "Dev",
                        "lang": "en",
                        "data": {"url": notify_url, "format": "event_id_only"},
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;
    let event_id = harness
        .send_message(&alice_tok, &room_id, "secret-plaintext")
        .await;

    tokio::time::sleep(Duration::from_millis(250)).await;

    let received = gateway.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "expected one POST to the gateway");
    let raw = &received[0].body;
    let body: Value = serde_json::from_slice(raw).expect("json body");
    let notif = &body["notification"];

    // Routing fields present.
    assert_eq!(notif["event_id"], event_id);
    assert_eq!(notif["room_id"], room_id);
    assert!(
        notif["devices"]
            .as_array()
            .is_some_and(|d| d.iter().any(|x| x["pushkey"] == "pk-bob-1")),
        "the recipient's device must be present"
    );

    // Privacy: no event content / type / sender.
    assert!(notif.get("content").is_none(), "must not send content");
    assert!(notif.get("type").is_none(), "must not send type");
    assert!(notif.get("sender").is_none(), "must not send sender");
    assert!(
        !String::from_utf8_lossy(raw).contains("secret-plaintext"),
        "the message plaintext must not reach the gateway"
    );
}
