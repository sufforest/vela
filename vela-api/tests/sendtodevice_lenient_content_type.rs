//! `PUT /_matrix/client/v3/sendToDevice/...` must accept a valid JSON
//! body even when the client omits the `Content-Type` header or sends
//! something other than `application/json`.
//!
//! Background: Element X sends the `m.key.verification.request`
//! to-device PUT without setting `Content-Type`. Axum's stock
//! `Json<T>` extractor rejected this with 400 and the literal error
//! `Expected request with \`Content-Type: application/json\``, which
//! killed the verification handshake before it started.

#![cfg(test)]

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::Harness;

#[tokio::test]
async fn sendtodevice_accepts_body_without_content_type_header() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, _bob_tok) = harness.register("bob", "pw").await;

    // Build the request WITHOUT a Content-Type header. Body is valid JSON.
    let body = json!({
        "messages": {
            &bob_id: {
                "*": { "what": "verify request" }
            }
        }
    });
    let resp = harness
        .request(
            Request::put("/_matrix/client/v3/sendToDevice/m.key.verification.request/txn-abc")
                .header("authorization", format!("Bearer {alice_tok}"))
                // intentionally NO content-type header
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "sendToDevice must not reject a JSON body just because Content-Type is missing",
    );
}

#[tokio::test]
async fn sendtodevice_accepts_body_with_text_plain_content_type() {
    // Some clients send Content-Type: text/plain even though the body
    // is JSON. We accept it as long as the body parses.
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, _bob_tok) = harness.register("bob", "pw").await;

    let body = json!({
        "messages": {
            &bob_id: {
                "*": { "k": "v" }
            }
        }
    });
    let resp = harness
        .request(
            Request::put("/_matrix/client/v3/sendToDevice/m.key.verification.request/txn-xyz")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "text/plain")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn sendtodevice_rejects_invalid_json_with_m_not_json() {
    let harness = Harness::new();
    let (_alice_id, alice_tok) = harness.register("alice", "pw").await;

    let resp = harness
        .request(
            Request::put("/_matrix/client/v3/sendToDevice/m.key.verification.request/txn-bad")
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::from("this is not json"))
                .unwrap(),
        )
        .await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), 1024).await.unwrap())
            .unwrap();
    assert_eq!(body["errcode"], "M_NOT_JSON");
}
