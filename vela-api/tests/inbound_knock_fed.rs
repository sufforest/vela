//! End-to-end inbound knock federation test.
//!
//! Exercises the full pipeline: signed X-Matrix request → federation_auth
//! middleware → `make_knock` template → bob signs that template → signed
//! `send_knock` → membership flips to knock → response carries
//! knock_room_state with our chrome events.
//!
//! This is the "trust ladder" version of the knock unit tests in
//! `federation_knock.rs::tests`: those exercise the handler in isolation;
//! this one drives the entire HTTP+middleware stack.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, StubRemote, read_json};

#[tokio::test]
async fn inbound_knock_round_trip_via_federation_endpoints() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;

    // Alice creates a room with join_rule=knock so our server allows
    // remote knocks against it.
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({
                "preset": "private_chat",
                "name": "Knock Test Room",
                "initial_state": [{
                    "type": "m.room.join_rules",
                    "state_key": "",
                    "content": {"join_rule": "knock"},
                }],
            }),
        )
        .await;

    let remote = StubRemote::new("remote.example");
    remote.install(&harness);
    let bob = format!("@bob:{}", remote.server_name);
    let dest = harness.state.config.server_name.clone();

    // 1. make_knock — GET, signed.
    let make_knock_uri = format!(
        "/_matrix/federation/v1/make_knock/{}/{}?ver=12",
        urlenc(&room_id),
        urlenc(&bob),
    );
    let auth = remote.auth_header("GET", &make_knock_uri, &dest, None);
    let resp = harness
        .request(
            Request::get(&make_knock_uri)
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "make_knock should succeed: {resp:?}"
    );
    let body = read_json(resp).await;
    assert_eq!(body["room_version"], "12");
    let mut template = body["event"].as_object().expect("event template").clone();

    // 2. Bob signs the template, computes the event id, then PUT send_knock.
    let event_id = remote.sign_event(&mut template);
    let signed_body = Value::Object(template);

    let send_knock_uri = format!(
        "/_matrix/federation/v1/send_knock/{}/{}",
        urlenc(&room_id),
        urlenc(&event_id),
    );
    let auth = remote.auth_header("PUT", &send_knock_uri, &dest, Some(&signed_body));
    let resp = harness
        .request(
            Request::put(&send_knock_uri)
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(signed_body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "send_knock should succeed: {resp:?}"
    );
    let body = read_json(resp).await;
    let stripped = body["knock_room_state"]
        .as_array()
        .expect("knock_room_state");
    assert!(
        stripped.iter().any(|e| e["type"] == "m.room.create"),
        "stripped state must include m.room.create: {body}"
    );
    assert!(
        stripped.iter().any(|e| e["type"] == "m.room.join_rules"),
        "stripped state must include m.room.join_rules: {body}"
    );
    assert!(
        stripped.iter().any(|e| e["type"] == "m.room.name"),
        "stripped state must include m.room.name: {body}"
    );

    // 3. Bob's membership in our DB is now "knock" (4).
    let bob_nid = harness.state.db.get_or_create_nid(&bob).unwrap();
    let room_nid = harness.state.db.get_nid(&room_id).unwrap().unwrap();
    assert_eq!(
        harness.state.db.get_membership(room_nid, bob_nid).unwrap(),
        Some(4),
        "bob should be marked as knocking locally"
    );
}

#[tokio::test]
async fn inbound_make_knock_rejects_room_with_invite_rule() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;

    // Default preset (private_chat) is invite-only — knocking is forbidden.
    let room_id = harness
        .create_room(&alice_tok, json!({"preset": "private_chat"}))
        .await;

    let remote = StubRemote::new("remote.example");
    remote.install(&harness);
    let bob = format!("@bob:{}", remote.server_name);
    let dest = harness.state.config.server_name.clone();

    let uri = format!(
        "/_matrix/federation/v1/make_knock/{}/{}?ver=12",
        urlenc(&room_id),
        urlenc(&bob),
    );
    let auth = remote.auth_header("GET", &uri, &dest, None);
    let resp = harness
        .request(
            Request::get(&uri)
                .header("authorization", auth)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

fn urlenc(s: &str) -> String {
    s.replace('!', "%21")
        .replace(':', "%3A")
        .replace('#', "%23")
        .replace('@', "%40")
        .replace('$', "%24")
}
