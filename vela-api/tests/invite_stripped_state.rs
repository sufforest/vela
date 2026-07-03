//! An invite's stripped state (`rooms.invite.{id}.invite_state`) must include
//! `m.room.topic` and `m.room.encryption` (CS-API recommended set), so an
//! invitee sees the room topic and the "encrypted" badge before joining.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn put_state(h: &Harness, token: &str, room: &str, etype: &str, body: Value) -> StatusCode {
    h.request(
        Request::put(format!("/_matrix/client/v3/rooms/{room}/state/{etype}/"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .status()
}

async fn invite(h: &Harness, token: &str, room: &str, user: &str) -> StatusCode {
    h.request(
        Request::post(format!("/_matrix/client/v3/rooms/{room}/invite"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "user_id": user }).to_string()))
            .unwrap(),
    )
    .await
    .status()
}

async fn sync(h: &Harness, token: &str) -> Value {
    let resp = h
        .request(
            Request::get("/_matrix/client/v3/sync?timeout=0")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

#[tokio::test]
async fn invite_state_includes_topic_and_encryption() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "pw").await;
    let (bob, bob_tok) = h.register("bob", "pw").await;

    let room = h.create_room(&alice_tok, json!({})).await;
    assert_eq!(
        put_state(
            &h,
            &alice_tok,
            &room,
            "m.room.topic",
            json!({"topic": "hi there"})
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        put_state(
            &h,
            &alice_tok,
            &room,
            "m.room.encryption",
            json!({"algorithm": "m.megolm.v1.aes-sha2"}),
        )
        .await,
        StatusCode::OK
    );

    assert_eq!(invite(&h, &alice_tok, &room, &bob).await, StatusCode::OK);

    let s = sync(&h, &bob_tok).await;
    let events = s["rooms"]["invite"][&room]["invite_state"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("no invite_state for {room}: {s}"));
    let types: Vec<&str> = events.iter().filter_map(|e| e["type"].as_str()).collect();
    assert!(
        types.contains(&"m.room.topic"),
        "invite_state must include m.room.topic: {types:?}"
    );
    assert!(
        types.contains(&"m.room.encryption"),
        "invite_state must include m.room.encryption: {types:?}"
    );
}
