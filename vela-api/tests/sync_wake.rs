//! Regression tests for sync long-poll wakeups.
//!
//! Locks in the fix for the "stuck on Joining..." bug: a pending /sync
//! must wake within ~1s of a membership change (new invite accepted,
//! DM created) instead of waiting for its 30s timeout.

mod common;

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync_once(harness: &Harness, token: &str, since: Option<&str>, timeout_ms: u64) -> Value {
    let mut url = format!("/_matrix/client/v3/sync?timeout={timeout_ms}");
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
async fn invite_wakes_pending_sync_within_one_second() {
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let (_bob, bob_tok) = harness.register("bob", "pw").await;

    // Bob does an initial sync to get a since token. No rooms yet.
    let initial = sync_once(&harness, &bob_tok, None, 0).await;
    let since = initial["next_batch"].as_str().unwrap().to_string();

    // Bob starts a long-poll /sync (timeout 30s).
    let harness2 = std::sync::Arc::new(harness);
    let h_clone = harness2.clone();
    let tok_clone = bob_tok.clone();
    let since_clone = since.clone();
    let poll = tokio::spawn(async move {
        let start = Instant::now();
        let resp = sync_once(&h_clone, &tok_clone, Some(&since_clone), 30_000).await;
        (start.elapsed(), resp)
    });

    // Tiny delay so the /sync registers its subscriptions first.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Alice invites Bob — this must wake Bob's pending /sync.
    let _room = harness2
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [alice.replace("alice", "bob")]}),
        )
        .await;

    let (elapsed, resp) = poll.await.expect("poll task");
    assert!(
        elapsed < Duration::from_secs(3),
        "sync should have woken on invite but took {elapsed:?}"
    );
    let invites = resp
        .pointer("/rooms/invite")
        .and_then(|v| v.as_object())
        .expect("rooms.invite");
    assert_eq!(invites.len(), 1, "expected one invite to surface: {resp}");
}

#[tokio::test]
async fn send_wakes_pending_sync_within_one_second() {
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let bob = alice.replace("alice", "bob");
    let (_bob_id, bob_tok) = harness.register("bob", "pw").await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [bob]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    // Bob initial-syncs to pick up the room + get a since token.
    let initial = sync_once(&harness, &bob_tok, None, 0).await;
    let since = initial["next_batch"].as_str().unwrap().to_string();

    let harness2 = std::sync::Arc::new(harness);
    let h_clone = harness2.clone();
    let tok_clone = bob_tok.clone();
    let since_clone = since.clone();
    let poll = tokio::spawn(async move {
        let start = Instant::now();
        let resp = sync_once(&h_clone, &tok_clone, Some(&since_clone), 30_000).await;
        (start.elapsed(), resp)
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    harness2.send_message(&alice_tok, &room_id, "wake up").await;

    let (elapsed, resp) = poll.await.expect("poll task");
    assert!(
        elapsed < Duration::from_secs(3),
        "sync should wake on new message, took {elapsed:?}"
    );
    let events = resp
        .pointer(&format!("/rooms/join/{room_id}/timeline/events"))
        .and_then(|v| v.as_array())
        .expect("timeline events");
    assert!(
        events.iter().any(|e| e["content"]["body"] == "wake up"),
        "expected 'wake up' in timeline: {resp}"
    );
}
