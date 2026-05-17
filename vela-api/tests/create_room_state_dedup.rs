//! createRoom must not emit the same `(type, state_key)` twice when
//! `initial_state` overrides a preset default.
//!
//! Before this fix vela emitted preset defaults for
//! `m.room.history_visibility` / `m.room.guest_access` /
//! `m.room.join_rules` BEFORE the initial_state loop, without
//! deduping. A client supplying e.g.
//! `m.room.history_visibility = "invited"` in initial_state produced
//! TWO m.room.history_visibility events in the room timeline — the
//! preset's `"shared"` AND the client's `"invited"`. Element rendered
//! both lines in the room state-event tray. Visually noisy, and the
//! preset's earlier event is shadowed by the later one anyway via
//! topological state-res ordering.
//!
//! Spec: initial_state overrides preset defaults; only one event per
//! `(type, state_key)` should be emitted.
//!
//! Subtlety: querying `/rooms/{r}/state` is NOT enough to catch the
//! duplication — that endpoint returns CURRENT state, which is
//! always deduped by (type, state_key) by definition. The bug shows
//! up in the room TIMELINE (via /sync) where each state-event
//! emission is visible. This test queries /sync to see both events.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn get_timeline_events(harness: &Harness, token: &str, room_id: &str) -> Vec<Value> {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/sync?timeout=0")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    body["rooms"]["join"][room_id]["timeline"]["events"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

#[tokio::test]
async fn initial_state_history_visibility_overrides_preset_no_duplicate() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "initial_state": [
                    {
                        "type": "m.room.history_visibility",
                        "state_key": "",
                        "content": { "history_visibility": "invited" }
                    }
                ]
            }),
        )
        .await;

    let timeline = get_timeline_events(&harness, &alice_tok, &room_id).await;
    let history_vis: Vec<&Value> = timeline
        .iter()
        .filter(|e| e["type"] == "m.room.history_visibility")
        .collect();
    assert_eq!(
        history_vis.len(),
        1,
        "timeline must contain exactly one m.room.history_visibility — preset's value must be skipped when initial_state supplies its own. Got: {history_vis:#?}"
    );
    assert_eq!(
        history_vis[0]["content"]["history_visibility"], "invited",
        "initial_state value must win over preset default"
    );
}

#[tokio::test]
async fn initial_state_guest_access_overrides_preset_no_duplicate() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "initial_state": [
                    {
                        "type": "m.room.guest_access",
                        "state_key": "",
                        "content": { "guest_access": "forbidden" }
                    }
                ]
            }),
        )
        .await;

    let timeline = get_timeline_events(&harness, &alice_tok, &room_id).await;
    let guest_access: Vec<&Value> = timeline
        .iter()
        .filter(|e| e["type"] == "m.room.guest_access")
        .collect();
    assert_eq!(
        guest_access.len(),
        1,
        "timeline must contain exactly one m.room.guest_access — preset emit must be skipped. Got: {guest_access:#?}"
    );
    assert_eq!(
        guest_access[0]["content"]["guest_access"], "forbidden",
        "initial_state value must win over preset default"
    );
}

#[tokio::test]
async fn preset_only_emits_each_state_key_once() {
    // Sanity baseline: no initial_state at all → preset defaults
    // still emit exactly one event per (type, state_key) without
    // duplication. Lock-in so a future refactor can't accidentally
    // skip preset emits when no override is present.
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room_id = harness
        .create_room(&alice_tok, json!({ "preset": "private_chat" }))
        .await;
    let timeline = get_timeline_events(&harness, &alice_tok, &room_id).await;
    for etype in [
        "m.room.history_visibility",
        "m.room.guest_access",
        "m.room.join_rules",
    ] {
        let n = timeline.iter().filter(|e| e["type"] == etype).count();
        assert_eq!(n, 1, "preset alone must emit exactly one {etype}; got {n}");
    }
}
