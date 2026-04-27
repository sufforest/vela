//! GET /rooms/{roomId}/hierarchy (MSC2946 spaces).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn add_space_child(harness: &Harness, token: &str, space: &str, child_id: &str) {
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{space}/state/m.space.child/{child_id}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"via": ["localhost:8008"]}).to_string()))
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "m.space.child PUT failed");
}

async fn hierarchy(harness: &Harness, token: &str, room: &str) -> Value {
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v1/rooms/{room}/hierarchy"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "hierarchy call failed: {resp:?}"
    );
    read_json(resp).await
}

#[tokio::test]
async fn hierarchy_returns_root_and_children_summaries() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;

    // Root space: create a room with type=m.space and some chrome.
    let space = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "public_chat",
                "name": "My Space",
                "topic": "home of all the rooms",
                "creation_content": {"type": "m.space"},
            }),
        )
        .await;
    // Two public child rooms.
    let child_a = harness
        .create_room(
            &alice_tok,
            json!({"preset": "public_chat", "name": "General"}),
        )
        .await;
    let child_b = harness
        .create_room(
            &alice_tok,
            json!({"preset": "public_chat", "name": "Random"}),
        )
        .await;

    add_space_child(&harness, &alice_tok, &space, &child_a).await;
    add_space_child(&harness, &alice_tok, &space, &child_b).await;

    let result = hierarchy(&harness, &alice_tok, &space).await;
    let rooms = result["rooms"].as_array().expect("rooms array");
    let ids: Vec<&str> = rooms
        .iter()
        .map(|r| r["room_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&space.as_str()), "root space missing: {ids:?}");
    assert!(ids.contains(&child_a.as_str()), "child A missing: {ids:?}");
    assert!(ids.contains(&child_b.as_str()), "child B missing: {ids:?}");

    let root = rooms.iter().find(|r| r["room_id"] == space).unwrap();
    assert_eq!(root["name"], "My Space");
    assert_eq!(root["room_type"], "m.space");
    let children_state = root["children_state"].as_array().unwrap();
    assert_eq!(
        children_state.len(),
        2,
        "root must list both children_state entries: {children_state:?}"
    );
}

#[tokio::test]
async fn hierarchy_denies_non_member_on_invite_only_space() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (_bob, bob_tok) = harness.register("bob", "pw").await;

    let space = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "creation_content": {"type": "m.space"},
            }),
        )
        .await;

    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v1/rooms/{space}/hierarchy"))
                .header("authorization", format!("Bearer {bob_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn empty_via_removes_child_from_hierarchy() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;

    let space = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "public_chat",
                "creation_content": {"type": "m.space"},
            }),
        )
        .await;
    let child = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    // Add then "unlink" (empty via) — spec says this removes the child.
    add_space_child(&harness, &alice_tok, &space, &child).await;
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{space}/state/m.space.child/{child}"
            ))
            .header("authorization", format!("Bearer {alice_tok}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"via": []}).to_string()))
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let result = hierarchy(&harness, &alice_tok, &space).await;
    let rooms = result["rooms"].as_array().unwrap();
    assert!(
        !rooms.iter().any(|r| r["room_id"] == child),
        "unlinked child should not appear: {result}"
    );
}
