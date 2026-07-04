//! Idempotent (safe) federation reads retry once on a transient transport
//! failure; unsafe verbs do not.
//!
//! Regression for the dominant main-branch Complement flake: vela's outbound
//! `make_join` / partial-state-filler `/state(_ids)` GETs would fail on a
//! single transport hiccup (a reset on a fresh connect, or a keep-alive
//! connection the peer closed while it sat idle in reqwest's pool). With no
//! retry, one blip 403'd the whole partial-state join — surfacing as
//! `TestPartialStateJoin/{CanReceiveDeviceListUpdateDuringPartialStateJoin,
//! Outgoing_device_list_updates/...departed_servers...}` failing ~1-in-3 runs.
//!
//! wiremock can't drop a live TCP connection, so a 200 with an unparseable
//! body stands in for the "body dropped mid-stream" shape — it drives the
//! same retry branch (the body read errors). The request COUNT is the
//! assertion: a safe GET is attempted twice, an unsafe PUT once.

mod common;

use common::Harness;
use serde_json::json;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn safe_get_retries_once_on_transport_failure() {
    let harness = Harness::new();
    let remote = MockServer::start().await;
    let peer = "peer.example"; // doesn't resolve; routed via base-URL override
    harness
        .state
        .federation_client
        .set_base_url_override(peer, &remote.uri());

    // 200 but an unparseable body on every hit — stands in for a body that
    // dropped mid-stream. The read fails, so the safe GET retries.
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/make_join/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&remote)
        .await;

    let res = harness
        .state
        .federation_client
        .signed_request(
            reqwest::Method::GET,
            peer,
            "/_matrix/federation/v1/make_join/!r:peer.example/@u:us.example?ver=12",
            None,
        )
        .await;

    assert!(
        res.is_err(),
        "unparseable body is still a failure, got {res:?}"
    );
    let hits = remote.received_requests().await.unwrap().len();
    assert_eq!(
        hits, 2,
        "a safe GET must be retried exactly once (2 attempts)"
    );
}

#[tokio::test]
async fn unsafe_put_is_not_retried() {
    let harness = Harness::new();
    let remote = MockServer::start().await;
    let peer = "peer.example";
    harness
        .state
        .federation_client
        .set_base_url_override(peer, &remote.uri());

    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/federation/v2/send_join/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&remote)
        .await;

    let res = harness
        .state
        .federation_client
        .signed_request(
            reqwest::Method::PUT,
            peer,
            "/_matrix/federation/v2/send_join/!r:peer.example/$e:us.example",
            Some(json!({})),
        )
        .await;

    assert!(
        res.is_err(),
        "unparseable body is still a failure, got {res:?}"
    );
    let hits = remote.received_requests().await.unwrap().len();
    assert_eq!(hits, 1, "an unsafe PUT must NOT be retried (1 attempt)");
}

#[tokio::test]
async fn safe_get_recovers_when_retry_succeeds() {
    let harness = Harness::new();
    let remote = MockServer::start().await;
    let peer = "peer.example";
    harness
        .state
        .federation_client
        .set_base_url_override(peer, &remote.uri());

    // First hit: unparseable body (drives the retry). Higher priority + a
    // one-shot cap so it serves exactly once, then the good mock takes over.
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/make_join/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&remote)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/make_join/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"room_version": "12", "event": {}})),
        )
        .with_priority(5)
        .mount(&remote)
        .await;

    let res = harness
        .state
        .federation_client
        .signed_request(
            reqwest::Method::GET,
            peer,
            "/_matrix/federation/v1/make_join/!r:peer.example/@u:us.example?ver=12",
            None,
        )
        .await;

    assert!(
        res.is_ok(),
        "a transport hiccup on the first attempt must be recovered by the retry, got {res:?}"
    );
    let hits = remote.received_requests().await.unwrap().len();
    assert_eq!(hits, 2, "one failed attempt + one successful retry");
}
