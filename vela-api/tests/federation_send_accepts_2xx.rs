//! A 2xx response to `PUT /_matrix/federation/v1/send/{txnId}` must count
//! as a successful delivery even when the response body can't be parsed.
//!
//! Regression for the msc3902 leave-delivery flake: under CI load the peer
//! would return 2xx but the body read would fail ("error decoding response
//! body" — connection dropped mid-body). The sender treated that as a
//! delivery failure, re-sent + backed off a transaction the peer had
//! already accepted, and — because the outbox is per-room FIFO — stalled
//! every later event (including a leave a teardown was waiting for) behind
//! the phantom-failed batch. The /send response body is informational
//! (per-PDU results the sender doesn't use), so a 2xx is delivered.

mod common;

use common::Harness;
use serde_json::json;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn send_transaction_accepts_2xx_with_unparseable_body() {
    let harness = Harness::new();
    let remote = MockServer::start().await;
    let peer = "peer.example"; // doesn't resolve; routed via base-URL override
    harness
        .state
        .federation_client
        .set_base_url_override(peer, &remote.uri());

    // 200 OK but a non-JSON body — stands in for a body that can't be read
    // or parsed (truncated/odd peer).
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/federation/v1/send/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
        .mount(&remote)
        .await;

    let body = json!({
        "origin": "us.example", "origin_server_ts": 0, "pdus": [], "edus": []
    });
    let res = harness
        .state
        .federation_client
        .send_transaction(peer, "txn1", body)
        .await;
    assert!(
        res.is_ok(),
        "a 2xx /send must be a successful delivery even with an unparseable body, got {res:?}"
    );
}

#[tokio::test]
async fn send_transaction_errors_on_non_2xx() {
    let harness = Harness::new();
    let remote = MockServer::start().await;
    let peer = "peer.example";
    harness
        .state
        .federation_client
        .set_base_url_override(peer, &remote.uri());

    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/federation/v1/send/"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&remote)
        .await;

    let body = json!({"origin": "us.example", "origin_server_ts": 0, "pdus": [], "edus": []});
    let res = harness
        .state
        .federation_client
        .send_transaction(peer, "txn1", body)
        .await;
    assert!(res.is_err(), "a 5xx /send must be a delivery failure");
}
