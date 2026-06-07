//! `/messages` must not leak pre-join history in `joined`/`invited`
//! history-visibility rooms (and must still show it in `shared`).
//!
//! Regression test for the per-event history-visibility gate in
//! `room/messages.rs` — previously `/messages` applied only the coarse
//! `leave_cap` (bounding the recent end), so a member could page back into
//! events from before they joined.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::{Harness, read_json};

async fn message_bodies(harness: &Harness, token: &str, room: &str) -> Vec<String> {
    let resp = harness
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "messages call failed");
    let v = read_json(resp).await;
    v["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| {
            e.get("content")
                .and_then(|c| c.get("body"))
                .and_then(|b| b.as_str())
                .map(String::from)
        })
        .collect()
}

async fn room_with_visibility(harness: &Harness, token: &str, visibility: &str) -> String {
    harness
        .create_room(
            token,
            json!({
                "preset": "public_chat",
                "initial_state": [{
                    "type": "m.room.history_visibility",
                    "state_key": "",
                    "content": {"history_visibility": visibility}
                }]
            }),
        )
        .await
}

#[tokio::test]
async fn joined_visibility_hides_pre_join_history() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;
    let (_bob, btok) = harness.register("bob", "pw").await;

    let room = room_with_visibility(&harness, &atok, "joined").await;
    harness
        .send_message(&atok, &room, "secret-before-bob")
        .await;
    harness.join(&btok, &room).await;
    harness.send_message(&atok, &room, "after-bob-joined").await;

    let bodies = message_bodies(&harness, &btok, &room).await;
    assert!(
        bodies.iter().any(|b| b == "after-bob-joined"),
        "bob should see post-join messages: {bodies:?}"
    );
    assert!(
        !bodies.iter().any(|b| b == "secret-before-bob"),
        "LEAK: bob saw pre-join history in a joined-visibility room: {bodies:?}"
    );
}

#[tokio::test]
async fn shared_visibility_shows_pre_join_history() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;
    let (_bob, btok) = harness.register("bob", "pw").await;

    let room = room_with_visibility(&harness, &atok, "shared").await;
    harness
        .send_message(&atok, &room, "shared-before-bob")
        .await;
    harness.join(&btok, &room).await;
    harness.send_message(&atok, &room, "shared-after-bob").await;

    let bodies = message_bodies(&harness, &btok, &room).await;
    // shared explicitly permits members to read pre-join history.
    assert!(
        bodies.iter().any(|b| b == "shared-before-bob"),
        "{bodies:?}"
    );
    assert!(bodies.iter().any(|b| b == "shared-after-bob"), "{bodies:?}");
}

#[tokio::test]
async fn invited_visibility_shows_from_invite_not_before() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;
    let (bob, btok) = harness.register("bob", "pw").await;

    // invite-capable room with invited visibility.
    let room = harness
        .create_room(
            &atok,
            json!({
                "preset": "private_chat",
                "initial_state": [{
                    "type": "m.room.history_visibility",
                    "state_key": "",
                    "content": {"history_visibility": "invited"}
                }]
            }),
        )
        .await;

    harness.send_message(&atok, &room, "before-invite").await;
    // Invite bob, then post while he's invited, then he joins.
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room}/invite"))
                .header("authorization", format!("Bearer {atok}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_id": bob}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "invite failed");
    harness.send_message(&atok, &room, "during-invite").await;
    harness.join(&btok, &room).await;
    harness.send_message(&atok, &room, "after-join").await;

    let bodies = message_bodies(&harness, &btok, &room).await;
    assert!(bodies.iter().any(|b| b == "after-join"), "{bodies:?}");
    assert!(bodies.iter().any(|b| b == "during-invite"), "{bodies:?}");
    assert!(
        !bodies.iter().any(|b| b == "before-invite"),
        "LEAK: bob saw pre-invite history in an invited-visibility room: {bodies:?}"
    );
}
