//! Outbound restricted-room federation test.
//!
//! When we join a remote restricted room, the remote's make_join template
//! already carries `join_authorised_via_users_server` (the remote picked a
//! qualifying local user for us). We sign the template as-is and send_join.
//! This test stubs a remote with wiremock and inspects the body we PUT to
//! `/send_join/`, asserting the authoriser field survives signing.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::Harness;

#[tokio::test]
async fn outbound_restricted_join_signs_template_with_authoriser() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    let remote = MockServer::start().await;
    let remote_sn = "remote.example";
    harness
        .state
        .federation_client
        .set_base_url_override(remote_sn, &remote.uri());

    let room_id = format!("!restricted:{remote_sn}");
    let authoriser = format!("@bob:{remote_sn}");

    // The remote's make_join response — already includes the authoriser.
    let template = json!({
        "type": "m.room.member",
        "room_id": room_id,
        "sender": alice_id,
        "state_key": alice_id,
        "content": {
            "membership": "join",
            "join_authorised_via_users_server": authoriser,
        },
        "depth": 10,
        "prev_events": [],
        "auth_events": [],
    });
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/make_join/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "room_version": "12",
            "event": template,
        })))
        .expect(1)
        .mount(&remote)
        .await;

    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/federation/v2/send_join/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth_chain": [],
            "state": [],
            "event": {},
        })))
        .expect(1)
        .mount(&remote)
        .await;

    let url = format!(
        "/_matrix/client/v3/join/{}?server_name={remote_sn}",
        urlenc(&room_id)
    );
    let resp = harness
        .request(
            Request::post(&url)
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "restricted join should succeed: {resp:?}"
    );

    let sent = remote.received_requests().await.unwrap();
    let send_join_req = sent
        .iter()
        .find(|r| {
            r.url
                .path()
                .starts_with("/_matrix/federation/v2/send_join/")
        })
        .expect("send_join was made");
    let body: Value = serde_json::from_slice(&send_join_req.body).unwrap();
    assert_eq!(
        body["content"]["join_authorised_via_users_server"], authoriser,
        "signed send_join body must preserve authoriser: {body}"
    );
    assert!(
        body["signatures"].as_object().is_some(),
        "signed event must carry signatures: {body}"
    );
}

fn urlenc(s: &str) -> String {
    s.replace('!', "%21")
        .replace(':', "%3A")
        .replace('#', "%23")
        .replace('@', "%40")
}
