//! Regression tests: `/rooms/{roomId}/event/{eventId}` and
//! `/rooms/{roomId}/context/{eventId}` must apply the same history-visibility
//! read gate as `/messages`, on BOTH the direct events and their bundled
//! `unsigned.m.relations`.
//!
//! Spec (`client-server-api/#room-history-visibility`):
//!   "After a user has left a room, they may see any events which they were
//!    allowed to see before they left the room, but no events received after
//!    they left."
//! and the bundled-aggregations warning:
//!   "Due to history visibility restrictions, child events might not be
//!    visible to the user ... any aggregations which would normally include
//!    those events will be lacking them."
//!
//! Before the fix, both endpoints checked only the per-event history-visibility
//! rule and never applied the departed-caller leave-cap. Under the default
//! `shared` visibility that rule passes for ANY event when the caller's current
//! membership is leave, so a departed caller could read post-leave event bodies
//! directly (`/event`), post-leave `events_after` / pre-join `events_before`
//! (`/context`), and post-leave reply/edit/reaction content via the bundle.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn send_msg(
    h: &Harness,
    token: &str,
    room: &str,
    txn: &str,
    body: &str,
) -> (StatusCode, String) {
    let resp = h
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"msgtype": "m.text", "body": body}).to_string(),
            ))
            .unwrap(),
        )
        .await;
    let status = resp.status();
    let v = read_json(resp).await;
    let event_id = v
        .get("event_id")
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_string();
    (status, event_id)
}

/// Send an arbitrary event carrying an `m.relates_to` child relation.
async fn send_relation(
    h: &Harness,
    token: &str,
    room: &str,
    event_type: &str,
    txn: &str,
    content: Value,
) -> StatusCode {
    h.request(
        Request::put(format!(
            "/_matrix/client/v3/rooms/{room}/send/{event_type}/{txn}"
        ))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(content.to_string()))
        .unwrap(),
    )
    .await
    .status()
}

async fn get_event(h: &Harness, token: &str, room: &str, event_id: &str) -> (StatusCode, Value) {
    let resp = h
        .request(
            Request::get(format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let status = resp.status();
    (status, read_json(resp).await)
}

async fn get_context(
    h: &Harness,
    token: &str,
    room: &str,
    event_id: &str,
    limit: u32,
) -> (StatusCode, Value) {
    let resp = h
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{room}/context/{event_id}?limit={limit}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    let status = resp.status();
    (status, read_json(resp).await)
}

async fn leave_room(h: &Harness, token: &str, room: &str) -> StatusCode {
    h.request(
        Request::post(format!("/_matrix/client/v3/rooms/{room}/leave"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
    )
    .await
    .status()
}

async fn put_history_visibility(h: &Harness, token: &str, room: &str, vis: &str) -> StatusCode {
    h.request(
        Request::put(format!(
            "/_matrix/client/v3/rooms/{room}/state/m.room.history_visibility/"
        ))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"history_visibility": vis}).to_string()))
        .unwrap(),
    )
    .await
    .status()
}

/// Collect the `body` of every event in a `/context` `events_before` /
/// `events_after` array.
fn bodies(arr: Option<&Value>) -> Vec<String> {
    arr.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.pointer("/content/body").and_then(|b| b.as_str()))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// The keys of an event's `unsigned.m.relations` bundle (empty when absent).
fn bundle_keys(event: &Value) -> Vec<String> {
    event
        .pointer("/unsigned/m.relations")
        .and_then(|v| v.as_object())
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

// ---- /event: departed caller, direct pivot ---------------------------------

/// Spec rule 3 + the "no events received after they left" guarantee:
/// under the default `shared` visibility, an event sent AFTER the caller
/// left must 404 — not 200. This is the core leave-cap leak the gate closes.
#[tokio::test]
async fn event_after_leave_is_404_for_departed_under_shared() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "alice-pw").await;
    let (_bob, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    h.join(&bob_tok, &room).await;
    assert_eq!(leave_room(&h, &bob_tok, &room).await, StatusCode::OK);

    // Alice sends an event AFTER bob left.
    let (status, post_leave) = send_msg(&h, &alice_tok, &room, "after", "after-bob-left").await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = get_event(&h, &bob_tok, &room, &post_leave).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "departed caller must not read a post-leave event via /event under shared"
    );

    // Sanity: the room creator (still joined) reads it fine.
    let (status, _) = get_event(&h, &alice_tok, &room, &post_leave).await;
    assert_eq!(status, StatusCode::OK);
}

/// A pre-leave event the departed caller WAS allowed to see stays readable.
#[tokio::test]
async fn event_before_leave_still_readable_for_departed() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "alice-pw").await;
    let (_bob, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    h.join(&bob_tok, &room).await;

    let (status, pre_leave) = send_msg(&h, &alice_tok, &room, "before", "while-bob-here").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(leave_room(&h, &bob_tok, &room).await, StatusCode::OK);

    let (status, _) = get_event(&h, &bob_tok, &room, &pre_leave).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "departed caller must still read events visible to them before they left"
    );
}

// ---- /event: bundled relations gating --------------------------------------

/// The bundle on a pre-leave pivot must not leak reply/edit/reaction
/// content created AFTER the caller left. Alice reacts to, edits, and
/// thread-replies a message bob could see; all the child events land after
/// bob's leave. Bob still reads the pivot but its `m.relations` must be empty
/// of those children; alice (joined) sees the full bundle.
#[tokio::test]
async fn event_bundle_excludes_post_leave_children_for_departed() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "alice-pw").await;
    let (_bob, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    h.join(&bob_tok, &room).await;

    // Pivot bob can see (he's joined).
    let (status, pivot) = send_msg(&h, &alice_tok, &room, "pivot", "the-parent").await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(leave_room(&h, &bob_tok, &room).await, StatusCode::OK);

    // All three child relation types, sent AFTER bob left.
    assert_eq!(
        send_relation(
            &h,
            &alice_tok,
            &room,
            "m.reaction",
            "react",
            json!({"m.relates_to": {"rel_type": "m.annotation", "event_id": pivot, "key": "👍"}}),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        send_relation(
            &h,
            &alice_tok,
            &room,
            "m.room.message",
            "edit",
            json!({
                "msgtype": "m.text",
                "body": "* edited",
                "m.new_content": {"msgtype": "m.text", "body": "edited"},
                "m.relates_to": {"rel_type": "m.replace", "event_id": pivot},
            }),
        )
        .await,
        StatusCode::OK
    );
    assert_eq!(
        send_relation(
            &h,
            &alice_tok,
            &room,
            "m.room.message",
            "thread",
            json!({
                "msgtype": "m.text",
                "body": "thread-reply",
                "m.relates_to": {"rel_type": "m.thread", "event_id": pivot},
            }),
        )
        .await,
        StatusCode::OK
    );

    // Bob: pivot readable, but no leaked child aggregations.
    let (status, bob_view) = get_event(&h, &bob_tok, &room, &pivot).await;
    assert_eq!(status, StatusCode::OK);
    let keys = bundle_keys(&bob_view);
    assert!(
        keys.is_empty(),
        "departed caller's bundle must not contain post-leave children, got: {keys:?}"
    );

    // Alice: full bundle present (no over-restriction of a joined member).
    let (status, alice_view) = get_event(&h, &alice_tok, &room, &pivot).await;
    assert_eq!(status, StatusCode::OK);
    let keys = bundle_keys(&alice_view);
    for expected in ["m.annotation", "m.replace", "m.thread"] {
        assert!(
            keys.iter().any(|k| k == expected),
            "joined member must still see {expected} in the bundle, got: {keys:?}"
        );
    }
}

// ---- /context: flanking events ---------------------------------------------

/// `/context` must leave-cap `events_after`: a departed caller pivoting on a
/// pre-leave event must not see post-leave messages in the surrounding window.
#[tokio::test]
async fn context_excludes_post_leave_events_after_for_departed() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "alice-pw").await;
    let (_bob, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    h.join(&bob_tok, &room).await;

    let (_, pivot) = send_msg(&h, &alice_tok, &room, "pivot", "pivot-msg").await;
    assert_eq!(leave_room(&h, &bob_tok, &room).await, StatusCode::OK);

    // Post-leave traffic that must NOT surface in bob's context window.
    send_msg(&h, &alice_tok, &room, "n1", "secret-after-1").await;
    send_msg(&h, &alice_tok, &room, "n2", "secret-after-2").await;

    let (status, ctx) = get_context(&h, &bob_tok, &room, &pivot, 50).await;
    assert_eq!(status, StatusCode::OK);
    let after = bodies(ctx.get("events_after"));
    assert!(
        !after.iter().any(|b| b.starts_with("secret-after")),
        "departed caller's events_after leaked post-leave messages: {after:?}"
    );

    // Alice (joined) does see them.
    let (status, ctx) = get_context(&h, &alice_tok, &room, &pivot, 50).await;
    assert_eq!(status, StatusCode::OK);
    let after = bodies(ctx.get("events_after"));
    assert!(
        after.iter().any(|b| b == "secret-after-1"),
        "joined member must see post-pivot events: {after:?}"
    );
}

/// `/context` must history-visibility filter `events_before`: under `joined`
/// visibility a member pivoting on a post-join event must not see pre-join
/// history in the surrounding window.
#[tokio::test]
async fn context_excludes_pre_join_events_before_under_joined() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "alice-pw").await;
    let (_bob, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    assert_eq!(
        put_history_visibility(&h, &alice_tok, &room, "joined").await,
        StatusCode::OK
    );

    // Pre-join history bob must never see under `joined`.
    send_msg(&h, &alice_tok, &room, "p", "pre-join-secret").await;

    h.join(&bob_tok, &room).await;

    // Post-join pivot bob is allowed to read.
    let (_, pivot) = send_msg(&h, &alice_tok, &room, "pivot", "post-join-pivot").await;

    let (status, ctx) = get_context(&h, &bob_tok, &room, &pivot, 50).await;
    assert_eq!(status, StatusCode::OK);
    let before = bodies(ctx.get("events_before"));
    assert!(
        !before.iter().any(|b| b == "pre-join-secret"),
        "context events_before leaked pre-join history under hv=joined: {before:?}"
    );
}

/// Negative space: a fully-joined member's `/context` is NOT over-restricted —
/// they see the pre-pivot and post-pivot messages they're entitled to.
#[tokio::test]
async fn context_includes_visible_window_for_joined_member() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "alice-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    send_msg(&h, &alice_tok, &room, "a", "earlier").await;
    let (_, pivot) = send_msg(&h, &alice_tok, &room, "pivot", "pivot").await;
    send_msg(&h, &alice_tok, &room, "b", "later").await;

    let (status, ctx) = get_context(&h, &alice_tok, &room, &pivot, 50).await;
    assert_eq!(status, StatusCode::OK);
    let before = bodies(ctx.get("events_before"));
    let after = bodies(ctx.get("events_after"));
    assert!(
        before.iter().any(|b| b == "earlier"),
        "joined member must see the pre-pivot message: {before:?}"
    );
    assert!(
        after.iter().any(|b| b == "later"),
        "joined member must see the post-pivot message: {after:?}"
    );
}
