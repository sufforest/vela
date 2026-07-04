//! `POST /v3/search` is index-backed: it matches against the jieba-tokenized
//! inverted index, so CJK text is searchable word-by-word, multi-term queries
//! are AND-intersected, and the `keys` filter is honored.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, read_json};
use serde_json::{Value, json};

async fn search(harness: &Harness, token: &str, room_events: Value) -> Value {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/search")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "search_categories": { "room_events": room_events } }).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "search returned non-200");
    read_json(resp).await
}

fn count(resp: &Value) -> u64 {
    resp["search_categories"]["room_events"]["count"]
        .as_u64()
        .unwrap()
}

async fn leave(harness: &Harness, token: &str, room: &str) {
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room}/leave"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "leave failed");
}

async fn ban(harness: &Harness, token: &str, room: &str, user_id: &str) {
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room}/ban"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ "user_id": user_id }).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "ban failed");
}

#[tokio::test]
async fn search_by_body_cjk_keys_and_and_semantics() {
    let harness = Harness::new();
    harness.state.db.set_search_indexing_enabled(true);
    let (_uid, token) = harness.register("alice", "password").await;
    let room = harness
        .create_room(&token, json!({"preset": "private_chat"}))
        .await;

    let eid = harness
        .send_message(&token, &room, "hello, 世界 world")
        .await;
    harness
        .send_message(&token, &room, "unrelated chatter")
        .await;

    let rooms = json!({ "rooms": [room] });

    // Body search finds the exact message.
    let r = search(
        &harness,
        &token,
        json!({"search_term": "hello", "keys": ["content.body"], "filter": rooms}),
    )
    .await;
    assert_eq!(count(&r), 1, "one hit for 'hello'");
    assert_eq!(
        r["search_categories"]["room_events"]["results"][0]["result"]["event_id"],
        json!(eid),
    );

    // CJK: 世界 was segmented into a token and is findable — the whole point.
    let r = search(
        &harness,
        &token,
        json!({"search_term": "世界", "filter": rooms}),
    )
    .await;
    assert_eq!(count(&r), 1, "CJK word 世界 must match");

    // Multi-term AND: both words present in the same event → match.
    let r = search(
        &harness,
        &token,
        json!({"search_term": "hello world", "filter": rooms}),
    )
    .await;
    assert_eq!(count(&r), 1, "'hello world' both present → match");

    // AND: a term where one token is absent → no match.
    let r = search(
        &harness,
        &token,
        json!({"search_term": "hello goodbye", "filter": rooms}),
    )
    .await;
    assert_eq!(count(&r), 0, "'goodbye' absent → no match");

    // An absent word → no hits.
    let r = search(
        &harness,
        &token,
        json!({"search_term": "goodbye", "filter": rooms}),
    )
    .await;
    assert_eq!(count(&r), 0);

    // `keys` filter: the word lives in a body, not a room name, so
    // restricting to content.name yields nothing.
    let r = search(
        &harness,
        &token,
        json!({"search_term": "hello", "keys": ["content.name"], "filter": rooms}),
    )
    .await;
    assert_eq!(count(&r), 0, "keys=content.name must exclude a body match");
}

/// A hit's `context` events must pass the same history-visibility gate as
/// the hit. Under `joined` visibility, a message sent before the searcher
/// joined must NOT leak into `context.events_before`.
#[tokio::test]
async fn context_events_are_visibility_gated() {
    let harness = Harness::new();
    harness.state.db.set_search_indexing_enabled(true);
    let (_a, alice) = harness.register("alice", "password").await;
    let (_b, bob) = harness.register("bob", "password").await;

    let room = harness
        .create_room(
            &alice,
            json!({
                "preset": "public_chat",
                "initial_state": [{
                    "type": "m.room.history_visibility",
                    "state_key": "",
                    "content": {"history_visibility": "joined"}
                }]
            }),
        )
        .await;

    // Alice posts before Bob joins — Bob must never see this, even as context.
    harness
        .send_message(&alice, &room, "secretbeforejoin apple")
        .await;

    harness.join(&bob, &room).await;
    let hit = harness.send_message(&bob, &room, "findme apple").await;

    let r = search(
        &harness,
        &bob,
        json!({
            "search_term": "findme",
            "filter": {"rooms": [room]},
            "event_context": {"before_limit": 10, "after_limit": 0}
        }),
    )
    .await;
    assert_eq!(count(&r), 1);
    let res0 = &r["search_categories"]["room_events"]["results"][0];
    assert_eq!(res0["result"]["event_id"], json!(hit));
    // The pre-join message must be absent from the context.
    let before = res0["context"]["events_before"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for ev in &before {
        let body = ev["content"]["body"].as_str().unwrap_or("");
        assert!(
            !body.contains("secretbeforejoin"),
            "pre-join event leaked into search context: {ev}"
        );
    }
}

#[tokio::test]
async fn groupings_partition_by_room_and_sender() {
    let harness = Harness::new();
    harness.state.db.set_search_indexing_enabled(true);
    let (_a, alice) = harness.register("alice", "password").await;
    let r1 = harness
        .create_room(&alice, json!({"preset":"private_chat"}))
        .await;
    let r2 = harness
        .create_room(&alice, json!({"preset":"private_chat"}))
        .await;
    harness.send_message(&alice, &r1, "apple pie").await;
    harness.send_message(&alice, &r2, "apple tart").await;

    let r = search(
        &harness,
        &alice,
        json!({
            "search_term": "apple",
            "filter": {"rooms": [r1, r2]},
            "groupings": {"group_by": [{"key":"room_id"}, {"key":"sender"}]}
        }),
    )
    .await;
    assert_eq!(count(&r), 2);
    let groups = &r["search_categories"]["room_events"]["groups"];

    // One room_id group per room, each holding its single result.
    let room_groups = groups["room_id"].as_object().unwrap();
    assert_eq!(room_groups.len(), 2, "one group per room");
    assert_eq!(room_groups[&r1]["results"].as_array().unwrap().len(), 1);
    assert_eq!(room_groups[&r2]["results"].as_array().unwrap().len(), 1);

    // One sender group (alice) holding both results.
    let sender_groups = groups["sender"].as_object().unwrap();
    assert_eq!(sender_groups.len(), 1, "one sender");
    let alice_id = sender_groups.keys().next().unwrap();
    assert_eq!(
        sender_groups[alice_id]["results"].as_array().unwrap().len(),
        2
    );
}

#[tokio::test]
async fn include_state_returns_current_room_state() {
    let harness = Harness::new();
    harness.state.db.set_search_indexing_enabled(true);
    let (_a, alice) = harness.register("alice", "password").await;
    let room = harness
        .create_room(&alice, json!({"preset":"private_chat"}))
        .await;
    harness.send_message(&alice, &room, "apple").await;

    let r = search(
        &harness,
        &alice,
        json!({"search_term": "apple", "filter": {"rooms": [room]}, "include_state": true}),
    )
    .await;
    assert_eq!(count(&r), 1);
    let room_state = r["search_categories"]["room_events"]["state"][&room]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!room_state.is_empty(), "state present for the result room");
    assert!(
        room_state.iter().any(|e| e["type"] == "m.room.create"),
        "current state includes m.room.create"
    );
}

/// A user can search a room they've left, but only for events they could see
/// before leaving — the per-event leave-cap bounds it.
#[tokio::test]
async fn search_left_room_bounded_by_leave() {
    let harness = Harness::new();
    harness.state.db.set_search_indexing_enabled(true);
    let (_b, bob) = harness.register("bob", "password").await;
    let (_a, alice) = harness.register("alice", "password").await;
    let room = harness
        .create_room(&bob, json!({"preset":"public_chat"}))
        .await;
    harness.join(&alice, &room).await;

    let before = harness
        .send_message(&alice, &room, "sharedword beforeleave")
        .await;
    leave(&harness, &alice, &room).await;
    // Bob keeps talking after alice left; she must not find this.
    harness
        .send_message(&bob, &room, "sharedword afteralice")
        .await;

    // No filter.rooms → the default seed must include the left room.
    // include_state must NOT expose the left room's current state.
    let r = search(
        &harness,
        &alice,
        json!({"search_term": "sharedword", "include_state": true}),
    )
    .await;
    assert_eq!(count(&r), 1, "only the pre-leave message is visible");
    assert_eq!(
        r["search_categories"]["room_events"]["results"][0]["result"]["event_id"],
        json!(before),
    );
    // A departed member must not get the left room's current state.
    assert!(
        r["search_categories"]["room_events"]["state"]
            .get(&room)
            .is_none(),
        "left room's current state must not be exposed via include_state"
    );
}

/// A banned user is treated like a departed one: they can search history up
/// to their ban, but not events after it, and get no current state.
#[tokio::test]
async fn banned_user_search_capped_at_ban() {
    let harness = Harness::new();
    harness.state.db.set_search_indexing_enabled(true);
    let (_b, bob) = harness.register("bob", "password").await;
    let (alice_id, alice) = harness.register("alice", "password").await;
    let room = harness
        .create_room(&bob, json!({"preset":"public_chat"}))
        .await;
    harness.join(&alice, &room).await;

    let before = harness
        .send_message(&alice, &room, "banword beforeban")
        .await;
    ban(&harness, &bob, &room, &alice_id).await;
    harness.send_message(&bob, &room, "banword afterban").await;

    let r = search(
        &harness,
        &alice,
        json!({"search_term": "banword", "include_state": true}),
    )
    .await;
    assert_eq!(count(&r), 1, "banned user sees only pre-ban events");
    assert_eq!(
        r["search_categories"]["room_events"]["results"][0]["result"]["event_id"],
        json!(before),
    );
    assert!(
        r["search_categories"]["room_events"]["state"]
            .get(&room)
            .is_none(),
        "no current state for a banned room"
    );
}

#[tokio::test]
async fn rank_orders_by_term_frequency() {
    let harness = Harness::new();
    harness.state.db.set_search_indexing_enabled(true);
    let (_uid, token) = harness.register("bob", "password").await;
    let room = harness
        .create_room(&token, json!({"preset": "private_chat"}))
        .await;

    harness.send_message(&token, &room, "apple once").await;
    let dense = harness
        .send_message(&token, &room, "apple apple apple")
        .await;

    let r = search(
        &harness,
        &token,
        json!({"search_term": "apple", "order_by": "rank", "filter": {"rooms": [room]}}),
    )
    .await;
    assert_eq!(count(&r), 2);
    // Higher term frequency ranks first.
    assert_eq!(
        r["search_categories"]["room_events"]["results"][0]["result"]["event_id"],
        json!(dense),
        "the message with more occurrences should rank first"
    );
}
