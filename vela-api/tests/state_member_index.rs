//! Regression: a membership change made via the generic
//! `PUT /rooms/{id}/state/m.room.member/{user}` must keep the membership
//! INDEX consistent, not just room state. Every read gate (`/sync`,
//! `/messages`, `/members`) keys off the index via `get_membership`, so if
//! the generic state path updates room state but not the index, a
//! banned/removed user keeps unbounded read + sync access — a
//! confidentiality breach (they keep seeing post-ban traffic).
//!
//! The dedicated `/ban` / `/kick` endpoints already maintain the index;
//! this pins the spec-valid generic state path (used by bots/bridges/admin
//! tools).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn put_member(
    h: &Harness,
    tok: &str,
    room: &str,
    target: &str,
    membership: &str,
) -> StatusCode {
    h.request(
        Request::put(format!(
            "/_matrix/client/v3/rooms/{room}/state/m.room.member/{target}"
        ))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(json!({"membership": membership}).to_string()))
        .unwrap(),
    )
    .await
    .status()
}

async fn send_msg(h: &Harness, tok: &str, room: &str, txn: &str, body: &str) -> StatusCode {
    h.request(
        Request::put(format!(
            "/_matrix/client/v3/rooms/{room}/send/m.room.message/{txn}"
        ))
        .header("authorization", format!("Bearer {tok}"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"msgtype": "m.text", "body": body}).to_string(),
        ))
        .unwrap(),
    )
    .await
    .status()
}

async fn messages_bodies(h: &Harness, tok: &str, room: &str) -> Vec<String> {
    let resp = h
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=50"
            ))
            .header("authorization", format!("Bearer {tok}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    let body = read_json(resp).await;
    body.get("chunk")
        .and_then(|c| c.as_array())
        .map(|chunk| {
            chunk
                .iter()
                .filter_map(|e| e.pointer("/content/body").and_then(|b| b.as_str()))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn member_state(members: &Value, target: &str) -> Option<String> {
    members
        .get("chunk")
        .and_then(|c| c.as_array())
        .and_then(|chunk| {
            chunk
                .iter()
                .find(|ev| ev.get("state_key").and_then(|k| k.as_str()) == Some(target))
        })
        .and_then(|ev| ev.pointer("/content/membership"))
        .and_then(|m| m.as_str())
        .map(String::from)
}

#[tokio::test]
async fn ban_via_generic_state_path_revokes_post_ban_access() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "pw").await;
    let (bob_id, bob_tok) = h.register("bob", "pw").await;

    let room = h
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    h.join(&bob_tok, &room).await;

    // Alice (admin) bans bob via the generic state endpoint — spec-valid,
    // and what bridges/admin tools use.
    assert_eq!(
        put_member(&h, &alice_tok, &room, &bob_id, "ban").await,
        StatusCode::OK,
        "admin should be able to ban via PUT /state/m.room.member"
    );

    // Alice sends a message AFTER the ban. A banned user is bounded to their
    // pre-ban view and must NOT see it. Before the fix the membership index
    // still said `join`, so bob got unbounded access and saw post-ban traffic.
    assert_eq!(
        send_msg(&h, &alice_tok, &room, "post-ban", "after-ban-secret").await,
        StatusCode::OK
    );

    let bob_view = messages_bodies(&h, &bob_tok, &room).await;
    assert!(
        !bob_view.iter().any(|b| b == "after-ban-secret"),
        "a user banned via /state must not see post-ban messages: {bob_view:?}"
    );

    // Sanity: alice's member list reflects the ban (room state was updated).
    let resp = h
        .request(
            Request::get(format!("/_matrix/client/v3/rooms/{room}/members"))
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let members = read_json(resp).await;
    assert_eq!(
        member_state(&members, &bob_id).as_deref(),
        Some("ban"),
        "member list must show bob banned"
    );
}
