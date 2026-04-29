//! Regression tests for spec history-visibility rule 2: a user who
//! has left a room MUST still be able to read events visible to them
//! at the time of their leave (state snapshots, pre-leave messages,
//! the member list as it was when they left).
//!
//! See `client-server-api/#room-history-visibility`. Without these
//! tests, the implementation could silently regress to "departed
//! users get 403" without the Complement suite catching it.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn put_state(
    harness: &Harness,
    token: &str,
    room: &str,
    event_type: &str,
    state_key: &str,
    body: Value,
) -> StatusCode {
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room}/state/{event_type}/{state_key}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await;
    resp.status()
}

async fn get_state_content(
    harness: &Harness,
    token: &str,
    room: &str,
    event_type: &str,
    state_key: &str,
) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{room}/state/{event_type}/{state_key}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

async fn leave_room(harness: &Harness, token: &str, room: &str) -> StatusCode {
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room}/leave"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    resp.status()
}

async fn list_members(harness: &Harness, token: &str, room: &str) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v3/rooms/{room}/members"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let status = resp.status();
    let body = read_json(resp).await;
    (status, body)
}

async fn invite_user(harness: &Harness, token: &str, room: &str, user_id: &str) -> StatusCode {
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room}/invite"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_id": user_id}).to_string()))
                .unwrap(),
        )
        .await;
    resp.status()
}

async fn put_history_visibility(
    harness: &Harness,
    token: &str,
    room: &str,
    visibility: &str,
) -> StatusCode {
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room}/state/m.room.history_visibility/"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"history_visibility": visibility}).to_string(),
            ))
            .unwrap(),
        )
        .await;
    resp.status()
}

async fn send_message(
    harness: &Harness,
    token: &str,
    room: &str,
    txn: &str,
    body: &str,
) -> (StatusCode, Value) {
    let resp = harness
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
    let body = read_json(resp).await;
    (status, body)
}

async fn fetch_event(harness: &Harness, token: &str, room: &str, event_id: &str) -> StatusCode {
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v3/rooms/{room}/event/{event_id}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    resp.status()
}

#[tokio::test]
async fn departed_user_sees_state_as_of_leave_not_current() {
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (_bob_id, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;

    // Alice sets the room name BEFORE bob joins.
    assert_eq!(
        put_state(
            &h,
            &alice_tok,
            &room,
            "m.room.name",
            "",
            json!({"name": "v0-pre-bob-join"})
        )
        .await,
        StatusCode::OK
    );

    h.join(&bob_tok, &room).await;

    // Alice updates the name while bob is joined — this is the value
    // bob should see as his "as-of-leave" snapshot.
    assert_eq!(
        put_state(
            &h,
            &alice_tok,
            &room,
            "m.room.name",
            "",
            json!({"name": "v1-while-bob-joined"})
        )
        .await,
        StatusCode::OK
    );

    assert_eq!(leave_room(&h, &bob_tok, &room).await, StatusCode::OK);

    // Alice changes the name AFTER bob left. Bob must NOT see this.
    assert_eq!(
        put_state(
            &h,
            &alice_tok,
            &room,
            "m.room.name",
            "",
            json!({"name": "v2-after-bob-left"})
        )
        .await,
        StatusCode::OK
    );

    // Bob fetches the name. Expectation: "v1-while-bob-joined" — what
    // was current when he left, NOT the post-leave update.
    let (status, body) = get_state_content(&h, &bob_tok, &room, "m.room.name", "").await;
    assert_eq!(status, StatusCode::OK, "departed user must not get 403");
    assert_eq!(
        body.get("name").and_then(|v| v.as_str()),
        Some("v1-while-bob-joined"),
        "bob must see the room name as of his leave moment, not the live one"
    );

    // Alice fetches the name. Expectation: live value.
    let (status, body) = get_state_content(&h, &alice_tok, &room, "m.room.name", "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.get("name").and_then(|v| v.as_str()),
        Some("v2-after-bob-left"),
        "joined user must see live state"
    );
}

#[tokio::test]
async fn departed_user_sees_member_list_as_of_leave() {
    let h = Harness::new();
    let (alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (bob_id, bob_tok) = h.register("bob", "bob-pw").await;
    let (charlie_id, charlie_tok) = h.register("charlie", "charlie-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    h.join(&bob_tok, &room).await;
    assert_eq!(leave_room(&h, &bob_tok, &room).await, StatusCode::OK);

    // Charlie joins AFTER bob left. Bob must not see charlie when
    // listing members for this room.
    h.join(&charlie_tok, &room).await;

    let (status, body) = list_members(&h, &bob_tok, &room).await;
    assert_eq!(status, StatusCode::OK);
    let chunk = body
        .get("chunk")
        .and_then(|v| v.as_array())
        .expect("chunk array");
    let user_states: Vec<(String, String)> = chunk
        .iter()
        .filter_map(|ev| {
            let sk = ev.get("state_key")?.as_str()?.to_string();
            let m = ev.pointer("/content/membership")?.as_str()?.to_string();
            Some((sk, m))
        })
        .collect();

    assert!(
        user_states
            .iter()
            .any(|(u, m)| u == &alice_id && m == "join"),
        "alice should be visible as join in bob's view: {user_states:?}"
    );
    assert!(
        user_states
            .iter()
            .any(|(u, m)| u == &bob_id && m == "leave"),
        "bob's own leave must surface in his own view: {user_states:?}"
    );
    assert!(
        !user_states.iter().any(|(u, _)| u == &charlie_id),
        "charlie joined AFTER bob left — must not appear in bob's snapshot view: {user_states:?}"
    );

    // Alice sees the live member list including charlie.
    let (status, body) = list_members(&h, &alice_tok, &room).await;
    assert_eq!(status, StatusCode::OK);
    let chunk = body.get("chunk").and_then(|v| v.as_array()).expect("chunk");
    let alice_view_users: Vec<String> = chunk
        .iter()
        .filter_map(|ev| ev.get("state_key")?.as_str().map(String::from))
        .collect();
    assert!(
        alice_view_users.contains(&charlie_id),
        "joined user (alice) must see live state including charlie: {alice_view_users:?}"
    );
}

// ---- Per-event history-visibility (rule 2 + rule 4) ------------------

/// Spec rule 4 (`hv=invited`): a currently-joined user querying an
/// event sent BEFORE they were invited must be denied (404). Their
/// membership at the event was "none" — no rule allows.
#[tokio::test]
async fn hv_invited_event_before_user_invited_returns_404() {
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (bob_id, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    assert_eq!(
        put_history_visibility(&h, &alice_tok, &room, "invited").await,
        StatusCode::OK
    );

    // Alice sends an event BEFORE inviting bob. Bob's membership at
    // this event = none.
    let (status, send_body) = send_message(&h, &alice_tok, &room, "msg-1", "before-invite").await;
    assert_eq!(status, StatusCode::OK);
    let event_id = send_body.get("event_id").and_then(|v| v.as_str()).unwrap();

    // Now alice invites + bob joins. Bob's CURRENT membership=join,
    // but his membership AT THE EVENT was still none.
    assert_eq!(
        invite_user(&h, &alice_tok, &room, &bob_id).await,
        StatusCode::OK
    );
    h.join(&bob_tok, &room).await;

    let status = fetch_event(&h, &bob_tok, &room, event_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "events sent before user's invite must be 404 under hv=invited"
    );
}

/// Spec rule 4 (`hv=invited`): a currently-joined user querying an
/// event sent BETWEEN their invite and their join MUST be allowed
/// (200). Their membership at the event was "invite" — rule 4 hits.
/// This is the case my first Bug 1 implementation got wrong.
#[tokio::test]
async fn hv_invited_event_between_invite_and_join_returns_200() {
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (bob_id, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    assert_eq!(
        put_history_visibility(&h, &alice_tok, &room, "invited").await,
        StatusCode::OK
    );

    // Invite bob, then send the event, then bob joins. Bob's
    // membership AT THE EVENT = invite.
    assert_eq!(
        invite_user(&h, &alice_tok, &room, &bob_id).await,
        StatusCode::OK
    );
    let (status, send_body) =
        send_message(&h, &alice_tok, &room, "msg-2", "between-invite-join").await;
    assert_eq!(status, StatusCode::OK);
    let event_id = send_body.get("event_id").and_then(|v| v.as_str()).unwrap();

    h.join(&bob_tok, &room).await;

    let status = fetch_event(&h, &bob_tok, &room, event_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "events sent during invite period must be 200 under hv=invited"
    );
}

/// Spec rule 2 (hv=joined): bob joins AFTER alice's event. His
/// membership at the event was "leave" (or none) → deny (404).
#[tokio::test]
async fn hv_joined_event_before_user_joined_returns_404() {
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (_bob_id, bob_tok) = h.register("bob", "bob-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    assert_eq!(
        put_history_visibility(&h, &alice_tok, &room, "joined").await,
        StatusCode::OK
    );

    let (_, send_body) = send_message(&h, &alice_tok, &room, "msg-3", "before-bob").await;
    let event_id = send_body.get("event_id").and_then(|v| v.as_str()).unwrap();

    h.join(&bob_tok, &room).await;
    let status = fetch_event(&h, &bob_tok, &room, event_id).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "hv=joined: events before user's join must 404"
    );
}

/// Spec rule 1 (`world_readable`): even a non-member can read.
#[tokio::test]
async fn hv_world_readable_lets_non_member_read_event() {
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (_eve_id, eve_tok) = h.register("eve", "eve-pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    assert_eq!(
        put_history_visibility(&h, &alice_tok, &room, "world_readable").await,
        StatusCode::OK
    );

    let (_, send_body) = send_message(&h, &alice_tok, &room, "msg-4", "open-secret").await;
    let event_id = send_body.get("event_id").and_then(|v| v.as_str()).unwrap();

    let status = fetch_event(&h, &eve_tok, &room, event_id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "hv=world_readable: any user must read the event"
    );
}

#[tokio::test]
async fn never_member_still_403_on_state_endpoint() {
    let h = Harness::new();
    let (_alice_id, alice_tok) = h.register("alice", "alice-pw").await;
    let (_eve_id, eve_tok) = h.register("eve", "eve-pw").await;

    // Private room — eve has no membership at all.
    let room = h
        .create_room(&alice_tok, json!({"preset": "private_chat"}))
        .await;

    let (status, _body) = get_state_content(&h, &eve_tok, &room, "m.room.name", "").await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-member must still get 403; departed-view path is for past members only"
    );
}
