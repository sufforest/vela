//! MSC3266 room-summary federation fallback.
//!
//! For a room we don't host, the summary endpoint fetches the federation
//! hierarchy root from a candidate server (`via` hint) and returns its
//! `room` chunk, stripped of hierarchy-only fields. Authenticated callers
//! only; unauth remote requests 404 without touching federation.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{Harness, read_json};

// `!preview:remote.example` url-encoded as a single path segment.
const REMOTE_ROOM_ENC: &str = "%21preview%3Aremote.example";

async fn summary(
    harness: &Harness,
    token: Option<&str>,
    path_and_query: &str,
) -> (StatusCode, Value) {
    let mut req = Request::get(format!("/_matrix/client/v1/rooms/{path_and_query}"));
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = harness.request(req.body(Body::empty()).unwrap()).await;
    let status = resp.status();
    (status, read_json(resp).await)
}

#[tokio::test]
async fn remote_summary_via_federation_hierarchy() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;

    let remote = MockServer::start().await;
    let remote_sn = "remote.example";
    harness
        .state
        .federation_client
        .set_base_url_override(remote_sn, &remote.uri());

    let room_id = format!("!preview:{remote_sn}");
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/hierarchy/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "room": {
                "room_id": room_id,
                "name": "Remote Lounge",
                "topic": "hi from afar",
                "num_joined_members": 7,
                "world_readable": true,
                "guest_can_join": false,
                "join_rule": "public",
                // hierarchy-only — must be stripped from the summary:
                "children_state": [{"type": "m.space.child", "state_key": "!c:x"}],
            },
            "children": [],
            "inaccessible_children": [],
        })))
        .mount(&remote)
        .await;

    let (status, body) = summary(
        &harness,
        Some(&tok),
        &format!("{REMOTE_ROOM_ENC}/summary?via={remote_sn}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["room_id"], room_id);
    assert_eq!(body["name"], "Remote Lounge");
    assert_eq!(body["num_joined_members"], 7);
    // hierarchy-only field must not leak into a summary:
    assert!(body.get("children_state").is_none());
}

#[tokio::test]
async fn unauthenticated_remote_summary_404s_without_federation() {
    // No token → federation fallback is never attempted; pure 404.
    let harness = Harness::new();
    let (status, _) = summary(
        &harness,
        None,
        &format!("{REMOTE_ROOM_ENC}/summary?via=remote.example"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn remote_summary_404_when_no_candidate_answers() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;

    let remote = MockServer::start().await;
    let remote_sn = "remote.example";
    harness
        .state
        .federation_client
        .set_base_url_override(remote_sn, &remote.uri());

    // Remote refuses the hierarchy fetch → our endpoint 404s.
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/hierarchy/"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&remote)
        .await;

    let (status, _) = summary(
        &harness,
        Some(&tok),
        &format!("{REMOTE_ROOM_ENC}/summary?via={remote_sn}"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
