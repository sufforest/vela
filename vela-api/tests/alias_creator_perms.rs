//! Alias DELETE permission rules.
//!
//! Mirrors Complement's TestRoomDeleteAlias suite:
//! - Creator can delete own alias even with no power.
//! - Non-creator without sufficient power gets 403.
//! - Non-creator WITH sufficient power can delete (admin path).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn put_alias(harness: &Harness, token: &str, alias: &str, room_id: &str) -> StatusCode {
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/directory/room/{}",
                urlenc(alias)
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"room_id": room_id}).to_string()))
            .unwrap(),
        )
        .await;
    resp.status()
}

async fn delete_alias(harness: &Harness, token: &str, alias: &str) -> StatusCode {
    let resp = harness
        .request(
            Request::delete(format!(
                "/_matrix/client/v3/directory/room/{}",
                urlenc(alias)
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
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
async fn creator_can_delete_own_alias_without_power() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (_bob_id, bob_tok) = harness.register("bob", "pw").await;

    let room_id = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    harness.join(&bob_tok, &room_id).await;

    // Bob (no special power) creates an alias.
    let alias = format!("#bobs_alias:{}", harness.state.config.server_name);
    assert_eq!(
        put_alias(&harness, &bob_tok, &alias, &room_id).await,
        StatusCode::OK
    );

    // Bob (still no power) deletes it — allowed because he's the creator.
    assert_eq!(
        delete_alias(&harness, &bob_tok, &alias).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn non_creator_without_power_cannot_delete_someone_elses_alias() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "invite": [bob_id.clone()],
            }),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    // Lock bob's PL to 0 so the threshold check actually kicks in.
    // v12: creator (alice) is implicit and must be omitted from users.
    let _ = alice_id;
    let status = put_state(
        &harness,
        &alice_tok,
        &room_id,
        "m.room.power_levels",
        "",
        json!({
            "users": {bob_id.clone(): 0},
            "events_default": 0,
            "state_default": 50,
            "users_default": 0,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let alias = format!("#alices_alias:{}", harness.state.config.server_name);
    assert_eq!(
        put_alias(&harness, &alice_tok, &alias, &room_id).await,
        StatusCode::OK
    );

    // Bob is not creator, has PL=0, threshold falls back to state_default=50.
    assert_eq!(
        delete_alias(&harness, &bob_tok, &alias).await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn high_power_user_can_delete_others_alias() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;

    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "invite": [bob_id.clone()],
            }),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    // Promote bob to PL 100. v12: alice is creator, omit from users.
    let _ = alice_id;
    let status = put_state(
        &harness,
        &alice_tok,
        &room_id,
        "m.room.power_levels",
        "",
        json!({
            "users": {bob_id.clone(): 100},
            "events_default": 0,
            "state_default": 50,
            "users_default": 0,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let alias = format!("#alices_alias_for_pl:{}", harness.state.config.server_name);
    assert_eq!(
        put_alias(&harness, &alice_tok, &alias, &room_id).await,
        StatusCode::OK
    );

    // Bob isn't the creator, but PL 100 ≥ state_default 50 → delete OK.
    assert_eq!(
        delete_alias(&harness, &bob_tok, &alias).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn deleting_unknown_alias_returns_404() {
    let harness = Harness::new();
    let (_, alice_tok) = harness.register("alice", "pw").await;
    assert_eq!(
        delete_alias(
            &harness,
            &alice_tok,
            &format!("#never_existed:{}", harness.state.config.server_name)
        )
        .await,
        StatusCode::NOT_FOUND
    );
}

fn urlenc(s: &str) -> String {
    s.replace('#', "%23").replace(':', "%3A")
}
