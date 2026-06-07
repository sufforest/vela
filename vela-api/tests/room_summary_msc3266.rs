//! `GET /_matrix/client/v1/rooms/{roomIdOrAlias}/summary` (MSC3266).
//!
//! Visibility gating is the interesting surface: members see their
//! `membership`, non-members may peek public/world-readable rooms but
//! get a 404 (not 403) on invite-only ones, and unauthenticated callers
//! are limited to world-readable rooms. Alias resolution is exercised too.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn summary(harness: &Harness, token: Option<&str>, target: &str) -> (StatusCode, Value) {
    let mut req = Request::get(format!("/_matrix/client/v1/rooms/{target}/summary"));
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = harness.request(req.body(Body::empty()).unwrap()).await;
    let status = resp.status();
    (status, read_json(resp).await)
}

#[tokio::test]
async fn member_sees_summary_with_membership() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(
            &tok,
            json!({"preset": "public_chat", "name": "Lounge", "topic": "hi"}),
        )
        .await;

    let (status, body) = summary(&harness, Some(&tok), &room).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room);
    assert_eq!(body["name"], "Lounge");
    assert_eq!(body["topic"], "hi");
    assert_eq!(body["join_rule"], "public");
    assert_eq!(body["num_joined_members"], 1);
    assert_eq!(body["membership"], "join");
    // children_state is hierarchy-only and must not leak into a summary.
    assert!(body.get("children_state").is_none());
}

#[tokio::test]
async fn non_member_can_peek_public_room_without_membership() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;
    let (_bob, btok) = harness.register("bob", "pw").await;
    let room = harness
        .create_room(&atok, json!({"preset": "public_chat"}))
        .await;

    let (status, body) = summary(&harness, Some(&btok), &room).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Non-member: no membership field.
    assert!(body.get("membership").is_none());
}

#[tokio::test]
async fn non_member_gets_404_on_invite_only_room() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;
    let (_bob, btok) = harness.register("bob", "pw").await;
    let room = harness
        .create_room(&atok, json!({"preset": "private_chat"}))
        .await;

    let (status, _) = summary(&harness, Some(&btok), &room).await;
    // 404, not 403 — don't leak existence to a non-peeker.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unauthenticated_allowed_only_for_world_readable() {
    let harness = Harness::new();
    let (_alice, atok) = harness.register("alice", "pw").await;

    // Plain public room (history_visibility = shared): unauth → 404.
    let shared = harness
        .create_room(&atok, json!({"preset": "public_chat"}))
        .await;
    let (status, _) = summary(&harness, None, &shared).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // World-readable room: unauth → 200.
    let wr = harness
        .create_room(
            &atok,
            json!({
                "preset": "public_chat",
                "initial_state": [{
                    "type": "m.room.history_visibility",
                    "state_key": "",
                    "content": {"history_visibility": "world_readable"}
                }]
            }),
        )
        .await;
    let (status, body) = summary(&harness, None, &wr).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["world_readable"], true);
}

#[tokio::test]
async fn resolves_alias_to_room() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(
            &tok,
            json!({"preset": "public_chat", "room_alias_name": "lounge"}),
        )
        .await;

    let alias = "#lounge:localhost:8008";
    // URL-encode the alias path segment (`#` and `:` are reserved).
    let encoded = "%23lounge%3Alocalhost%3A8008";
    let (status, body) = summary(&harness, Some(&tok), encoded).await;
    assert_eq!(status, StatusCode::OK, "alias {alias} -> {body}");
    assert_eq!(body["room_id"], room);
}
