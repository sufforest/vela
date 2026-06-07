//! `GET /_matrix/client/v3/notifications` — history, read flag, highlight filter.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn notifications(harness: &Harness, token: &str, query: &str) -> Value {
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v3/notifications{query}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "notifications call failed");
    read_json(resp).await
}

async fn send_read_receipt(harness: &Harness, token: &str, room: &str, event_id: &str) {
    let resp = harness
        .request(
            Request::post(format!(
                "/_matrix/client/v3/rooms/{room}/receipt/m.read/{event_id}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("{}".to_string()))
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "receipt failed");
}

#[tokio::test]
async fn message_creates_notification_with_read_tracking() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;
    let (bob, btok) = harness.register("bob", "pw").await;

    let room = harness
        .create_room(
            &atok,
            json!({"preset": "trusted_private_chat", "invite": [bob]}),
        )
        .await;
    harness.join(&btok, &room).await;
    let event_id = harness.send_message(&atok, &room, "ping bob").await;

    // dispatch is fire-and-forget; give it a moment to persist.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let body = notifications(&harness, &btok, "").await;
    let notifs = body["notifications"].as_array().unwrap();
    assert_eq!(notifs.len(), 1, "expected one notification: {body}");
    assert_eq!(notifs[0]["room_id"], room);
    assert_eq!(notifs[0]["event"]["event_id"], event_id);
    assert_eq!(notifs[0]["read"], false, "unread before receipt");
    assert!(
        notifs[0]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "notify"),
        "actions should contain notify: {body}"
    );

    // After bob reads up to the event, the notification reads as read.
    send_read_receipt(&harness, &btok, &room, &event_id).await;
    let body = notifications(&harness, &btok, "").await;
    assert_eq!(body["notifications"][0]["read"], true, "read after receipt");

    // The sender (alice) gets no notification for her own message.
    let alice_body = notifications(&harness, &atok, "").await;
    assert_eq!(
        alice_body["notifications"].as_array().unwrap().len(),
        0,
        "sender should not be notified of own message"
    );
}

#[tokio::test]
async fn only_highlight_filters_to_mentions() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;
    let (bob, btok) = harness.register("bob", "pw").await;

    let room = harness
        .create_room(
            &atok,
            json!({"preset": "trusted_private_chat", "invite": [bob]}),
        )
        .await;
    harness.join(&btok, &room).await;

    // A plain message (notify, no highlight) and an @room mention (highlight).
    harness.send_message(&atok, &room, "just chatting").await;
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room}/send/m.room.message/hl-1"
            ))
            .header("authorization", format!("Bearer {atok}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"msgtype": "m.text", "body": "@room!", "m.mentions": {"room": true}})
                    .to_string(),
            ))
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let all = notifications(&harness, &btok, "").await;
    assert_eq!(all["notifications"].as_array().unwrap().len(), 2, "{all}");

    let hl = notifications(&harness, &btok, "?only=highlight").await;
    let hl_notifs = hl["notifications"].as_array().unwrap();
    assert_eq!(
        hl_notifs.len(),
        1,
        "only the @room mention highlights: {hl}"
    );
    assert_eq!(hl_notifs[0]["event"]["content"]["body"], "@room!");
}
