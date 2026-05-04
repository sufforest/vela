//! /sync's per-room `summary.m.invited_member_count` and the back-compat
//! `m.room.create.content.creator` field both surface in /sync output.
//! These were independently broken (invited count hardcoded to 0; creator
//! never written into create content), and TestRoomSummary +
//! TestRoomCreationReportsEventsToMyself depend on them.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync(harness: &Harness, token: &str) -> Value {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/sync")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

#[tokio::test]
async fn room_summary_counts_invited_users() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, _bob_tok) = harness.register("bob", "pw").await;

    let room = harness
        .create_room(
            &alice_tok,
            json!({"preset": "public_chat", "invite": [bob_id]}),
        )
        .await;

    let resp = sync(&harness, &alice_tok).await;
    let summary = resp
        .pointer(&format!("/rooms/join/{room}/summary"))
        .expect("summary present in joined room");
    assert_eq!(
        summary
            .get("m.joined_member_count")
            .and_then(|v| v.as_u64()),
        Some(1),
        "alice is the only joined member: {summary}"
    );
    assert_eq!(
        summary
            .get("m.invited_member_count")
            .and_then(|v| v.as_u64()),
        Some(1),
        "bob is the only invited member, must be counted: {summary}"
    );
}

#[tokio::test]
async fn create_event_includes_content_creator_for_backward_compat() {
    // MSC4291 removes `content.creator` for v12 but most clients (and
    // the Complement TestRoomCreationReportsEventsToMyself) still read
    // it. We emit it for compatibility — auth still uses `sender`.
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let room = harness.create_room(&alice_tok, json!({})).await;

    let resp = sync(&harness, &alice_tok).await;
    let timeline = resp
        .pointer(&format!("/rooms/join/{room}/timeline/events"))
        .and_then(|v| v.as_array())
        .expect("timeline events");
    let create = timeline
        .iter()
        .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("m.room.create"))
        .expect("m.room.create in timeline");
    assert_eq!(
        create.pointer("/content/creator").and_then(|v| v.as_str()),
        Some(alice_id.as_str()),
        "content.creator must equal sender: {create}"
    );
}
