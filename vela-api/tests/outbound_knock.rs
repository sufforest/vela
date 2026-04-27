//! Outbound federation knock: make_knock → sign → send_knock → local persist.
//!
//! Stubs a resident server with wiremock so we can exercise the full
//! round-trip without real federation. Verifies the knock lands in the
//! `rooms.knock.{room_id}` section of /sync and the right HTTP calls
//! were made in the right order.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{Harness, read_json};

async fn sync(harness: &Harness, token: &str) -> Value {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/sync?timeout=0")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    read_json(resp).await
}

#[tokio::test]
async fn knock_falls_through_to_federation_when_room_unknown() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    // Stub the "resident" server — plain HTTP via wiremock. We route the
    // federation client to it by registering a base-URL override so the
    // test doesn't need real TLS or .well-known.
    let remote = MockServer::start().await;
    let remote_server_name = "remote.example"; // doesn't actually resolve
    harness
        .state
        .federation_client
        .set_base_url_override(remote_server_name, &remote.uri());

    let room_id = format!("!remote-knock:{remote_server_name}");
    let user_id = alice_id.clone();

    // make_knock: return a template the joining server will sign.
    let template = json!({
        "type": "m.room.member",
        "room_id": room_id,
        "sender": user_id,
        "state_key": user_id,
        "content": {"membership": "knock"},
        "depth": 5,
        "prev_events": [],
        "auth_events": [],
    });
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/make_knock/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "room_version": "12",
            "event": template,
        })))
        .expect(1)
        .mount(&remote)
        .await;

    // send_knock: accept and return stripped state for client chrome.
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/federation/v1/send_knock/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "knock_room_state": [
                {
                    "type": "m.room.name",
                    "state_key": "",
                    "sender": format!("@resident:{remote_server_name}"),
                    "content": {"name": "Cool Room"},
                }
            ]
        })))
        .expect(1)
        .mount(&remote)
        .await;

    // Client hits POST /knock/{roomId}?server_name={remote}. Because
    // the room is unknown locally, we fall through to the federated path.
    let url = format!(
        "/_matrix/client/v3/knock/{}?server_name={remote_server_name}",
        urlencoding(&room_id)
    );
    let resp = harness
        .request(
            Request::post(&url)
                .header("authorization", format!("Bearer {}", alice_tok))
                .header("content-type", "application/json")
                .body(Body::from(json!({"reason": "let me in"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "knock should succeed: {resp:?}"
    );
    let body = read_json(resp).await;
    assert_eq!(body["room_id"], room_id);

    // Sync should now surface rooms.knock.{room_id}.
    let synced = sync(&harness, &alice_tok).await;
    let knock = synced
        .pointer(&format!("/rooms/knock/{room_id}"))
        .expect("rooms.knock.{room_id} should be present");
    let events = knock
        .pointer("/knock_state/events")
        .and_then(|v| v.as_array())
        .expect("knock_state.events");
    // Our persisted stripped state event should show up as m.room.name.
    assert!(
        events.iter().any(|e| e["type"] == "m.room.name"),
        "expected m.room.name in stripped state: {events:?}"
    );
}

#[tokio::test]
async fn knock_without_server_hint_fails_when_room_unknown() {
    let harness = Harness::new();
    let (_, alice_tok) = harness.register("alice", "pw").await;

    // No wiremock — no federation expected.
    let url = "/_matrix/client/v3/knock/%21ghost%3Aexample.com";
    let resp = harness
        .request(
            Request::post(url)
                .header("authorization", format!("Bearer {}", alice_tok))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

fn urlencoding(s: &str) -> String {
    s.replace('!', "%21").replace(':', "%3A")
}
