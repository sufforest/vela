//! Setting the user's display name must emit a refreshed m.room.member
//! in every room they're joined to. Without this, name changes look like
//! a silent no-op in Element.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn current_member_event(
    harness: &Harness,
    token: &str,
    room_id: &str,
    user_id: &str,
) -> Value {
    let resp = harness
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{room_id}/state/m.room.member/{user_id}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "state fetch failed");
    read_json(resp).await
}

#[tokio::test]
async fn displayname_change_updates_member_event_in_all_rooms() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    // Two rooms where Alice is a joined member.
    let room_a = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    let room_b = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    // Before: member content has no displayname.
    let before = current_member_event(&harness, &alice_tok, &room_a, &alice_id).await;
    assert!(
        before.get("displayname").is_none() && before.get("avatar_url").is_none(),
        "pre-change member should not carry profile fields: {before}"
    );

    // Set displayname.
    let resp = harness
        .request(
            Request::put(format!("/_matrix/client/v3/profile/{alice_id}/displayname"))
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"displayname": "Ziggy"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // After: every joined room's member event carries displayname=Ziggy.
    for room in &[&room_a, &room_b] {
        let after = current_member_event(&harness, &alice_tok, room, &alice_id).await;
        assert_eq!(
            after.get("displayname").and_then(|v| v.as_str()),
            Some("Ziggy"),
            "room {room} member event did not update: {after}"
        );
    }
}

#[tokio::test]
async fn avatar_change_preserves_existing_displayname() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    let room = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    // Set a display name first.
    let resp = harness
        .request(
            Request::put(format!("/_matrix/client/v3/profile/{alice_id}/displayname"))
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"displayname": "Ziggy"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Now set an avatar — displayname must survive.
    let resp = harness
        .request(
            Request::put(format!("/_matrix/client/v3/profile/{alice_id}/avatar_url"))
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"avatar_url": "mxc://example/pic"}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let member = current_member_event(&harness, &alice_tok, &room, &alice_id).await;
    assert_eq!(
        member.get("displayname").and_then(|v| v.as_str()),
        Some("Ziggy")
    );
    assert_eq!(
        member.get("avatar_url").and_then(|v| v.as_str()),
        Some("mxc://example/pic")
    );
}
