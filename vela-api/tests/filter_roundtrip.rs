//! POST a filter, then use the returned filter_id in /sync. Lazy-load
//! filtering must apply, proving the filter_id round-tripped through
//! storage cleanly.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::{Harness, read_json};

async fn post_filter(
    harness: &Harness,
    user_id: &str,
    token: &str,
    def: serde_json::Value,
) -> String {
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/user/{user_id}/filter"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(def.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "post_filter failed");
    let v = read_json(resp).await;
    v["filter_id"].as_str().unwrap().to_string()
}

async fn sync_with_filter(harness: &Harness, token: &str, filter: &str) -> serde_json::Value {
    let url = format!("/_matrix/client/v3/sync?timeout=0&filter={filter}");
    let resp = harness
        .request(
            Request::get(url)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "sync failed");
    read_json(resp).await
}

#[tokio::test]
async fn filter_id_roundtrip_through_sync() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    let filter_id = post_filter(
        &harness,
        &alice_id,
        &alice_tok,
        json!({
            "room": {
                "state": {"lazy_load_members": true}
            }
        }),
    )
    .await;

    // The id must NOT begin with `{` — otherwise resolve_filter would
    // treat it as inline JSON. Spec calls this out as a server obligation.
    assert!(
        !filter_id.starts_with('{'),
        "filter_id must not start with '{{', got {filter_id}"
    );

    // Round-trip via GET endpoint to confirm storage is intact.
    let resp = harness
        .request(
            Request::get(format!(
                "/_matrix/client/v3/user/{alice_id}/filter/{filter_id}"
            ))
            .header("authorization", format!("Bearer {}", alice_tok))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let stored = read_json(resp).await;
    assert_eq!(stored["room"]["state"]["lazy_load_members"], json!(true));

    // Set up a room with two joined members so lazy-load has something to trim.
    let room_id = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    let (_bob_id, _bob_tok) = harness.register("bob", "pw").await;
    // Have bob join — keeps the test small without going through invites.
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/join"))
                .header("authorization", format!("Bearer {}", _bob_tok))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "bob join failed");

    // Sync with the stored filter — bob's m.room.member should be trimmed
    // because his id is not a sender of any timeline event in alice's view.
    let sync = sync_with_filter(&harness, &alice_tok, &filter_id).await;
    let state_events = sync["rooms"]["join"][&room_id]["state"]["events"]
        .as_array()
        .expect("state.events array")
        .clone();
    let bob_id = "@bob:example.com";
    let has_bob_member = state_events
        .iter()
        .any(|e| e["type"] == "m.room.member" && e["state_key"] == bob_id);
    assert!(
        !has_bob_member,
        "bob's member event should be trimmed when lazy-loading and bob has no timeline events: {state_events:#?}"
    );

    // Sanity: alice's own member event is kept.
    let alice_member = state_events
        .iter()
        .any(|e| e["type"] == "m.room.member" && e["state_key"] == alice_id);
    assert!(alice_member, "alice's own member event must always be kept");
}

#[tokio::test]
async fn unknown_filter_id_falls_through_to_unfiltered_sync() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;

    // Bogus filter_id — not stored. Spec leaves this implementation-defined;
    // vela's choice is to fall through unfiltered rather than 4xx.
    let sync = sync_with_filter(&harness, &alice_tok, "ZZZZZZZZZZZ").await;
    assert!(sync["next_batch"].is_string());
}
