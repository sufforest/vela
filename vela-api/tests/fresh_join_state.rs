//! Regression test: after accepting an invite on an incremental /sync,
//! the newly-joined room must carry full state, not just the timeline
//! delta. Element otherwise sees an empty state and falls back to
//! per-event /rooms/{id}/state fetches that add seconds to the
//! user-perceived invite-to-room latency.

mod common;

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync(harness: &Harness, token: &str, since: Option<&str>) -> Value {
    let mut url = "/_matrix/client/v3/sync?timeout=0".to_string();
    if let Some(s) = since {
        url.push_str(&format!("&since={s}"));
    }
    let resp = harness
        .request(
            Request::get(&url)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    read_json(resp).await
}

#[tokio::test]
async fn incremental_sync_after_accept_invite_carries_full_state() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    // Bob's initial sync — no rooms yet.
    let initial = sync(&harness, &bob_tok, None).await;
    let since = initial["next_batch"].as_str().unwrap().to_string();

    // Alice creates an encrypted-looking room and invites bob.
    let room = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "name": "The DM",
                "invite": [bob_id],
                "initial_state": [{
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": {"algorithm": "m.megolm.v1.aes-sha2"},
                }],
            }),
        )
        .await;

    // Bob accepts. After this his next /sync must surface full state.
    harness.join(&bob_tok, &room).await;

    let synced = sync(&harness, &bob_tok, Some(&since)).await;
    let room_data = synced
        .pointer(&format!("/rooms/join/{room}"))
        .expect("joined room present");

    let state_events = room_data
        .pointer("/state/events")
        .and_then(|v| v.as_array())
        .expect("state.events present");

    let types: std::collections::HashSet<&str> = state_events
        .iter()
        .filter_map(|e| e["type"].as_str())
        .collect();

    // Bare minimum the client needs to render the room at all.
    assert!(
        types.contains("m.room.create"),
        "fresh-join state missing m.room.create: {state_events:?}"
    );
    assert!(
        types.contains("m.room.name"),
        "fresh-join state missing m.room.name: {state_events:?}"
    );
    assert!(
        types.contains("m.room.encryption"),
        "fresh-join state missing m.room.encryption — Element will not send E2EE messages: {state_events:?}"
    );
    // At least one member event must be present so Element knows who's here.
    assert!(
        types.contains("m.room.member"),
        "fresh-join state missing m.room.member: {state_events:?}"
    );
}

#[tokio::test]
async fn long_joined_room_still_uses_incremental_delta() {
    // Control case: a room the user has been in for a while should stay
    // incremental (only the delta events), not re-send full state every
    // sync. Guards against the fresh-join branch over-triggering.
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    let room = harness
        .create_room(
            &alice_tok,
            json!({"preset": "private_chat", "invite": [bob_id]}),
        )
        .await;
    harness.join(&bob_tok, &room).await;

    // Bob does an initial sync AFTER join — picks up full state. Grab the
    // since token from that point onward, so the join transition is now
    // behind us.
    let after_join = sync(&harness, &bob_tok, None).await;
    let since = after_join["next_batch"].as_str().unwrap().to_string();

    // Alice sends a message.
    let event_id = harness.send_message(&alice_tok, &room, "hi").await;

    let incremental = sync(&harness, &bob_tok, Some(&since)).await;
    let room_data = incremental
        .pointer(&format!("/rooms/join/{room}"))
        .expect("room in incremental sync");
    let state_events = room_data
        .pointer("/state/events")
        .and_then(|v| v.as_array())
        .expect("state.events");
    assert!(
        state_events.is_empty(),
        "stable room must not resend state: {state_events:?}"
    );
    let timeline_events = room_data
        .pointer("/timeline/events")
        .and_then(|v| v.as_array())
        .expect("timeline.events");
    assert!(
        timeline_events.iter().any(|e| e["event_id"] == event_id),
        "incremental sync missing the new message"
    );
}
