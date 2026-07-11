//! Directory visibility + state-access hardening:
//!  - createRoom persists the `visibility` param (default private), so a
//!    publicly-joinable room created `private` is NOT listed in /publicRooms.
//!  - PUT /directory/list/room requires power to change room state, not
//!    just membership.
//!  - GET /rooms/{id}/state returns 403 (not 404) for an unknown room, so
//!    the directory/state pair can't be used to probe room existence.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, read_json};
use serde_json::{Value, json};

async fn create_room(h: &Harness, tok: &str, body: Value) -> String {
    let resp = h
        .request(
            Request::post("/_matrix/client/v3/createRoom")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "createRoom failed");
    read_json(resp).await["room_id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn public_room_ids(h: &Harness, tok: &str) -> Vec<String> {
    let resp = h
        .request(
            Request::get("/_matrix/client/v3/publicRooms")
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await["chunk"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["room_id"].as_str().map(String::from))
        .collect()
}

#[tokio::test]
async fn create_room_respects_directory_visibility() {
    let h = Harness::new();
    let (_id, tok) = h.register("alice", "pw").await;

    // Publicly-joinable room but visibility:private → must NOT be listed.
    let private = create_room(
        &h,
        &tok,
        json!({"preset": "public_chat", "visibility": "private"}),
    )
    .await;
    // Explicit visibility:public → listed.
    let public = create_room(&h, &tok, json!({"visibility": "public"})).await;

    let ids = public_room_ids(&h, &tok).await;
    assert!(
        ids.contains(&public),
        "visibility:public room must be listed: {ids:?}"
    );
    assert!(
        !ids.contains(&private),
        "visibility:private room must NOT be listed even with a public join_rule: {ids:?}"
    );
}

#[tokio::test]
async fn state_unknown_room_is_forbidden_not_found() {
    let h = Harness::new();
    let (_id, tok) = h.register("alice", "pw").await;

    let resp = h
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{}/state",
                "!nonexistent:test"
            ))
            .header("authorization", format!("Bearer {tok}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "/state on an unknown room must 403, not leak existence via 404"
    );
}

#[tokio::test]
async fn put_room_visibility_requires_power_level() {
    let h = Harness::new();
    let (_alice, alice_tok) = h.register("alice", "pw").await;
    let (_bob, bob_tok) = h.register("bob", "pw").await;

    let room = create_room(&h, &alice_tok, json!({"preset": "public_chat"})).await;

    // bob joins (power 0).
    let resp = h
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{}/join", room))
                .header("authorization", format!("Bearer {bob_tok}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "bob should join the public room"
    );

    let put_visibility = |tok: &str| {
        Request::put(format!("/_matrix/client/v3/directory/list/room/{}", room))
            .header("authorization", format!("Bearer {tok}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"visibility": "public"}).to_string()))
            .unwrap()
    };

    // bob is a member but has power 0 < state_default (50) → forbidden.
    let resp = h.request(put_visibility(&bob_tok)).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a non-privileged member must not change directory visibility"
    );

    // alice is the creator (effectively infinite power) → allowed.
    let resp = h.request(put_visibility(&alice_tok)).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the room creator can change directory visibility"
    );
}
