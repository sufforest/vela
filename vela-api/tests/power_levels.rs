//! Regression tests for power-level enforcement on membership ops.
//!
//! These exercise the auth-rule path through the full HTTP layer so we
//! catch the kind of regressions that pure auth_rules unit tests would
//! miss (e.g. a membership handler that forgets to call check_auth, or
//! one that builds the wrong content shape).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn invite(harness: &Harness, token: &str, room_id: &str, target: &str) -> StatusCode {
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/invite"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_id": target}).to_string()))
                .unwrap(),
        )
        .await;
    resp.status()
}

async fn kick(harness: &Harness, token: &str, room_id: &str, target: &str) -> StatusCode {
    let resp = harness
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room_id}/kick"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"user_id": target}).to_string()))
                .unwrap(),
        )
        .await;
    resp.status()
}

async fn put_state(
    harness: &Harness,
    token: &str,
    room_id: &str,
    event_type: &str,
    state_key: &str,
    content: Value,
) -> StatusCode {
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room_id}/state/{event_type}/{state_key}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(content.to_string()))
            .unwrap(),
        )
        .await;
    let status = resp.status();
    if !status.is_success() {
        let body = read_json(resp).await;
        eprintln!("put_state {event_type}/{state_key} failed: {status} {body}");
    }
    status
}

#[tokio::test]
async fn non_admin_cannot_kick_anyone() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;
    let (charlie_id, _charlie_tok) = harness.register("charlie", "pw").await;

    // Alice creates the room (admin) and invites both Bob and Charlie.
    let room = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "invite": [bob_id.clone(), charlie_id.clone()],
            }),
        )
        .await;
    harness.join(&bob_tok, &room).await;

    // Bob is just a regular user; trusted_private_chat preset gives invitees
    // power_level = 100 (per spec) — but kick power defaults to 50, so a
    // power-100 Bob *can* kick Charlie. Drop bob's power back to 0 to test
    // the actual rejection path.
    // v12 rule: the creator (alice) has implicit infinite power and MUST NOT
    // appear in power_levels.users. We just downgrade bob + charlie.
    let status = put_state(
        &harness,
        &alice_tok,
        &room,
        "m.room.power_levels",
        "",
        json!({
            "users": {bob_id.clone(): 0, charlie_id.clone(): 0},
            "kick": 50, "ban": 50, "invite": 0, "redact": 50,
            "events_default": 0, "state_default": 50, "users_default": 0,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "alice should set power levels");
    let _ = alice_id;

    // Bob now lacks kick power → 403.
    let status = kick(&harness, &bob_tok, &room, &charlie_id).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "non-admin should not be able to kick"
    );
}

#[tokio::test]
async fn invite_without_invite_power_is_rejected() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;
    let (carol_id, _) = harness.register("carol", "pw").await;

    let room = harness
        .create_room(
            &alice_tok,
            json!({"preset": "private_chat", "invite": [bob_id.clone()]}),
        )
        .await;
    harness.join(&bob_tok, &room).await;

    // Lock down: invite requires power 50, bob has 0. v12: don't list alice
    // (creator) in users.
    let _ = alice_id;
    let status = put_state(
        &harness,
        &alice_tok,
        &room,
        "m.room.power_levels",
        "",
        json!({
            "users": {bob_id.clone(): 0},
            "invite": 50, "kick": 50, "ban": 50, "redact": 50,
            "events_default": 0, "state_default": 50, "users_default": 0,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Bob tries to invite carol → 403.
    let status = invite(&harness, &bob_tok, &room, &carol_id).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "user without invite power should be rejected"
    );
}

#[tokio::test]
async fn admin_can_kick_normal_user() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    // private_chat (not trusted_) leaves invitees at power 0 — alice (creator)
    // is at 100. Trusted gives all invitees 100, which would equalise power
    // and forbid kicks per the auth rules.
    let room = harness
        .create_room(
            &alice_tok,
            json!({"preset": "private_chat", "invite": [bob_id.clone()]}),
        )
        .await;
    harness.join(&bob_tok, &room).await;

    let status = kick(&harness, &alice_tok, &room, &bob_id).await;
    assert_eq!(status, StatusCode::OK, "admin should kick freely");
}
