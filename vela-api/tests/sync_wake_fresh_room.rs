//! When a pending /sync wakes due to the caller creating or joining a
//! new room, the rebuilt response MUST include the new room. An earlier
//! bug captured the joined-rooms list before the long-poll started and
//! reused the stale list when rebuilding, so the newly-created room
//! never surfaced until the client force-refreshed.

mod common;

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync(harness: &Harness, token: &str, since: Option<&str>, timeout: u64) -> Value {
    let mut url = format!("/_matrix/client/v3/sync?timeout={timeout}");
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
async fn create_room_wakes_long_poll_with_fresh_room() {
    let harness = std::sync::Arc::new(Harness::new());
    let (_alice, alice_tok) = harness.register("alice", "pw").await;

    let initial = sync(&harness, &alice_tok, None, 0).await;
    let since = initial["next_batch"].as_str().unwrap().to_string();

    let h_clone = harness.clone();
    let tok_clone = alice_tok.clone();
    let since_clone = since.clone();
    let poll = tokio::spawn(async move {
        let start = Instant::now();
        let resp = sync(&h_clone, &tok_clone, Some(&since_clone), 30_000).await;
        (start.elapsed(), resp)
    });

    // Let the long-poll register its subscriptions.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let room = harness
        .create_room(&alice_tok, json!({"preset": "private_chat", "name": "New"}))
        .await;

    let (elapsed, resp) = poll.await.expect("poll task");
    assert!(
        elapsed < Duration::from_secs(3),
        "sync should wake on createRoom, took {elapsed:?}"
    );
    let joined = resp
        .pointer("/rooms/join")
        .and_then(|v| v.as_object())
        .expect("rooms.join");
    assert!(
        joined.contains_key(&room),
        "newly-created room missing from woken sync response: {resp}"
    );
    // Fresh-join branch must have populated state.
    let state_events = resp
        .pointer(&format!("/rooms/join/{room}/state/events"))
        .and_then(|v| v.as_array())
        .expect("state.events present");
    assert!(
        state_events.iter().any(|e| e["type"] == "m.room.create"),
        "fresh room missing m.room.create in state: {state_events:?}"
    );
}
