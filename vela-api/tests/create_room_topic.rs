//! createRoom with a `topic` field emits an m.room.topic state event
//! whose content carries BOTH the legacy `topic` string and the
//! MSC3765 structured `m.topic.m.text` rich-text representation.
//!
//! Unit-level coverage exists in `vela-core/src/events/content.rs::
//! topic_content_includes_legacy_and_rich_representation`. This is the
//! end-to-end counterpart: prove the rich form survives the full
//! createRoom pipeline (handler → builder → persisted JSON → /sync).
//! Without it the unit test would still pass if a refactor swapped
//! `topic_content` for a different helper that emits only the legacy
//! string.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::{Harness, read_json};

#[tokio::test]
async fn create_room_topic_emits_legacy_and_msc3765_form() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "topic": "Plain text topic",
            }),
        )
        .await;

    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/sync?timeout=0")
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let timeline = body["rooms"]["join"][&room_id]["timeline"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let topic_event = timeline
        .iter()
        .find(|e| e["type"] == "m.room.topic")
        .expect("createRoom with topic must emit m.room.topic");

    // Legacy string form (clients pre-MSC3765 read this).
    assert_eq!(
        topic_event["content"]["topic"], "Plain text topic",
        "legacy `topic` string must be set"
    );

    // MSC3765 rich form: content.m.topic.m.text is a list of
    // {body, mimetype?} mapping objects. We default mimetype to
    // text/plain by omitting it; that's the spec-recommended shape
    // for a plain-text topic.
    let text = topic_event["content"]["m.topic"]["m.text"]
        .as_array()
        .expect("m.topic.m.text must be an array");
    assert_eq!(
        text.len(),
        1,
        "single representation expected for plain text"
    );
    assert_eq!(text[0]["body"], "Plain text topic");
    assert!(
        text[0].get("mimetype").is_none(),
        "mimetype omitted for the text/plain default per MSC3765",
    );
}
