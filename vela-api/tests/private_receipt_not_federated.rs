//! `m.read.private` is a per-user, per-server marker that the spec says MUST
//! NOT be federated. This test asserts a public `m.read` receipt enters the
//! federation `receipts_stream` (so peers receive it) while a private one does
//! not — closing a privacy leak where the user's private read position would
//! otherwise be sent to every server in the room.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::Harness;

async fn post_receipt(h: &Harness, tok: &str, room: &str, rtype: &str, event: &str) -> StatusCode {
    h.request(
        Request::post(format!(
            "/_matrix/client/v3/rooms/{room}/receipt/{rtype}/{event}"
        ))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap(),
    )
    .await
    .status()
}

#[tokio::test]
async fn private_read_receipt_is_not_federated() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room_id = harness.create_room(&alice_tok, json!({})).await;
    let event_id = harness.send_message(&alice_tok, &room_id, "hi").await;

    // Public m.read — should be fanned out over federation.
    assert_eq!(
        post_receipt(&harness, &alice_tok, &room_id, "m.read", &event_id).await,
        StatusCode::OK
    );
    // Private — must stay local.
    assert_eq!(
        post_receipt(&harness, &alice_tok, &room_id, "m.read.private", &event_id).await,
        StatusCode::OK
    );

    let (entries, _) = harness.state.db.scan_receipts_stream(0, 1000).unwrap();
    let types: Vec<String> = entries
        .iter()
        .filter_map(|(_, e)| e.get("type").and_then(|v| v.as_str()).map(String::from))
        .collect();

    assert!(
        types.iter().any(|t| t == "m.read"),
        "public m.read must be federated: {types:?}"
    );
    assert!(
        !types.iter().any(|t| t == "m.read.private"),
        "private receipt must NOT enter the federation stream: {types:?}"
    );
}
