//! Regression tests for the /sync delta-tracking bugs surfaced by the
//! first real deployment.
//!
//! Two distinct bugs in one code path (`build_receipts_event` + the
//! sync builder's receipt/account_data emission):
//!
//!   1. **Privacy leak — `m.read.private` visible to other users.**
//!      `m.read.private` is meant ONLY for the user who set it (so
//!      their other devices know what they've read). Vela was
//!      returning it to every room member, which Element renders as
//!      a duplicate "seen by" entry for the reader.
//!
//!   2. **Sync storm.** Receipts and room-scoped account_data were
//!      emitted on every /sync regardless of whether anything had
//!      changed since the client's `since` cursor. Because joined
//!      rooms always had non-empty `ephemeral.events` and/or
//!      `account_data.events`, the unchanged-room skip rule never
//!      fired, the long-poll never slept, and clients hammered /sync
//!      at ~0.5s rejection cadence.
//!
//! Both surfaced in one Element session. Worth real-deployment-shape
//! integration coverage so they can't sneak back in.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync_with_since(harness: &Harness, token: &str, since: Option<&str>) -> Value {
    let path = match since {
        Some(s) => format!("/_matrix/client/v3/sync?since={s}&timeout=0"),
        None => "/_matrix/client/v3/sync?timeout=0".to_string(),
    };
    let resp = harness
        .request(
            Request::get(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "/sync failed");
    read_json(resp).await
}

async fn post_receipt(
    harness: &Harness,
    token: &str,
    room_id: &str,
    receipt_type: &str,
    event_id: &str,
) {
    let resp = harness
        .request(
            Request::post(format!(
                "/_matrix/client/v3/rooms/{room_id}/receipt/{receipt_type}/{event_id}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST receipt {receipt_type} on {event_id} failed"
    );
}

// --- Privacy: m.read.private must NOT leak to other users -----------------

#[tokio::test]
async fn m_read_private_is_invisible_to_other_users() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    // Alice creates a room, invites Bob, Bob joins.
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({ "preset": "private_chat", "invite": [bob_id] }),
        )
        .await;
    let _ = harness
        .send_message(&alice_tok, &room_id, "hello bob")
        .await;
    let join_resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/join"))
                .header("authorization", format!("Bearer {bob_tok}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(join_resp.status(), StatusCode::OK);
    let event_id = harness.send_message(&alice_tok, &room_id, "second").await;

    // Alice records a PRIVATE read receipt on her own message.
    post_receipt(&harness, &alice_tok, &room_id, "m.read.private", &event_id).await;

    // Bob's full sync should NOT see Alice's m.read.private anywhere.
    let bob_sync = sync_with_since(&harness, &bob_tok, None).await;
    let bob_room = &bob_sync["rooms"]["join"][&room_id];
    let receipts: Vec<&Value> = bob_room["ephemeral"]["events"]
        .as_array()
        .map(|v| v.iter().filter(|e| e["type"] == "m.receipt").collect())
        .unwrap_or_default();
    for ev in &receipts {
        for (_event_id, types) in ev["content"]
            .as_object()
            .expect("receipt content is an object")
        {
            assert!(
                !types.as_object().unwrap().contains_key("m.read.private"),
                "Bob's /sync MUST NOT contain Alice's m.read.private: {ev:#?}"
            );
        }
    }

    // Alice's OWN sync SHOULD see her own m.read.private — it's how
    // her other devices know what she's read.
    let alice_sync = sync_with_since(&harness, &alice_tok, None).await;
    let alice_room = &alice_sync["rooms"]["join"][&room_id];
    let private_visible = alice_room["ephemeral"]["events"]
        .as_array()
        .map(|v| {
            v.iter().any(|ev| {
                ev["type"] == "m.receipt"
                    && ev["content"].as_object().is_some_and(|content| {
                        content.values().any(|types| {
                            types
                                .as_object()
                                .is_some_and(|t| t.contains_key("m.read.private"))
                        })
                    })
            })
        })
        .unwrap_or(false);
    assert!(
        private_visible,
        "Alice's /sync MUST include her own m.read.private — that's how her other devices learn read state. alice_id={alice_id:?}"
    );
}

// --- Storm fix: incremental sync omits unchanged rooms --------------------

#[tokio::test]
async fn incremental_sync_omits_room_with_no_new_activity() {
    let harness = Harness::new();
    let (_alice_id, _alice_tok) = harness.register("alice", "pw").await;
    let (_bob_id, bob_tok) = harness.register("bob", "pw").await;

    // Bob in a room with prior activity (receipts + account_data).
    let room_id = harness
        .create_room(&bob_tok, json!({ "preset": "private_chat" }))
        .await;
    let event_id = harness.send_message(&bob_tok, &room_id, "hi").await;
    post_receipt(&harness, &bob_tok, &room_id, "m.read", &event_id).await;
    // Set m.fully_read via the read_markers endpoint — exercises the
    // room_account_data write path.
    let _ = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/read_markers"))
                .header("authorization", format!("Bearer {bob_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"m.fully_read": event_id}).to_string()))
                .unwrap(),
        )
        .await;

    // Initial sync — Bob sees the room with full snapshot.
    let initial = sync_with_since(&harness, &bob_tok, None).await;
    let since_token = initial["next_batch"].as_str().unwrap().to_string();
    assert!(
        initial["rooms"]["join"][&room_id].is_object(),
        "initial sync MUST include the room"
    );

    // No new activity from Alice or anyone. Incremental sync at the
    // since cursor should omit the room entirely — that's the
    // unchanged-room rule, and it's what closes the polling-storm.
    let increment = sync_with_since(&harness, &bob_tok, Some(&since_token)).await;
    let join_object = increment["rooms"]["join"]
        .as_object()
        .map(|m| m.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        join_object.is_empty(),
        "incremental sync with no new activity must omit unchanged rooms; got: {join_object:?}"
    );

    // next_batch should still advance (timeline may stay at the same
    // global position; we only require that the response is well-formed
    // and the room isn't re-emitted).
    assert!(increment["next_batch"].as_str().is_some());
}

#[tokio::test]
async fn new_receipt_resurfaces_room_in_incremental_sync() {
    // The flip side of the above: when a new receipt IS written
    // after the client's `since`, the room MUST resurface in
    // `rooms.join` so the receipt actually reaches the user. The
    // skip rule must be "no change" not "always skip."
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({ "preset": "private_chat", "invite": [bob_id] }),
        )
        .await;
    let event_id = harness.send_message(&alice_tok, &room_id, "hello").await;
    let join_resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/join"))
                .header("authorization", format!("Bearer {bob_tok}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(join_resp.status(), StatusCode::OK);

    // Alice does an initial sync to capture a since token.
    let alice_initial = sync_with_since(&harness, &alice_tok, None).await;
    let since = alice_initial["next_batch"]
        .as_str()
        .expect("next_batch")
        .to_string();

    // Bob writes a public read receipt — strictly after Alice's
    // `since`, so Alice's next incremental MUST surface it.
    post_receipt(&harness, &bob_tok, &room_id, "m.read", &event_id).await;

    let alice_increment = sync_with_since(&harness, &alice_tok, Some(&since)).await;
    let bob_seen = alice_increment["rooms"]["join"][&room_id]["ephemeral"]["events"]
        .as_array()
        .map(|evs| {
            evs.iter().any(|ev| {
                ev["type"] == "m.receipt"
                    && ev["content"].as_object().is_some_and(|content| {
                        content.values().any(|types| {
                            types["m.read"]
                                .as_object()
                                .is_some_and(|users| users.contains_key("@bob:localhost:8008"))
                        })
                    })
            })
        })
        .unwrap_or(false);
    assert!(
        bob_seen,
        "Alice's incremental sync after Bob's receipt MUST contain Bob's read marker: {alice_increment:#?}"
    );
}
