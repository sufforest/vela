//! End-to-end Application Service delivery test.
//!
//! Spins up a wiremock HTTP server posing as a registered AS, drives
//! vela's outbox worker by enqueueing an event, and asserts the
//! wiremock received the exact wire shape the AS spec mandates:
//! `PUT /_matrix/app/v1/transactions/{txnId}`, `Authorization: Bearer
//! <hs_token>` header, JSON body with an `events` array.

use serde_json::{Value, json};
use vela_api::appservice::registration;
use wiremock::matchers::{header, method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;
use common::Harness;

#[tokio::test]
async fn outbox_worker_posts_transaction_to_registered_as() {
    let mock = MockServer::start().await;

    // The wiremock stands in for the AS at `<mock.uri()>`. Register
    // an AS via vela's parser + registry — bypasses the admin-bot
    // command parser since we're testing the delivery path, not the
    // chat surface.
    let h = Harness::new();
    let yaml = format!(
        r#"
id: "stub-as"
url: "{}"
as_token: "as-cleartext"
hs_token: "hs-cleartext"
sender_localpart: "_stub_bot"
namespaces:
  rooms:
    - regex: "^!.*$"
      exclusive: false
"#,
        mock.uri()
    );
    let parsed = registration::parse(&yaml).expect("parse");
    let cleartext_hs = parsed.hs_token_cleartext.clone();
    let asv = h
        .state
        .appservice_registry
        .register(parsed.appservice)
        .expect("register");
    h.state
        .appservice_outbox
        .set_hs_token(asv.nid, cleartext_hs);
    h.state.appservice_outbox.start_worker(asv.nid);

    // Set up wiremock expectation. Match the spec-shaped path, the
    // Bearer header, and respond 200 `{}` like a real AS would.
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/app/v1/transactions/.+$"))
        .and(header("authorization", "Bearer hs-cleartext"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&mock)
        .await;

    // Persist a minimal event row so the worker has something to
    // load and ship. We don't need a real PDU — just bytes the
    // worker can fetch via get_event.
    let room_nid = h.state.db.get_or_create_nid("!room:example.com").unwrap();
    let type_nid = h.state.db.get_or_create_nid("m.room.message").unwrap();
    let sender_nid = h.state.db.get_or_create_nid("@alice:example.com").unwrap();
    let event_nid = h.state.db.next_nid().unwrap();
    let event_json = json!({
        "type": "m.room.message",
        "sender": "@alice:example.com",
        "room_id": "!room:example.com",
        "content": {"msgtype": "m.text", "body": "hello AS"},
        "origin_server_ts": 1000u64,
        "depth": 1,
    });
    h.state
        .db
        .persist_event(
            event_nid,
            "$evt:example.com",
            room_nid,
            type_nid,
            sender_nid,
            0,
            1000,
            1,
            &serde_json::to_vec(&event_json).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();

    // Enqueue via the framework. The worker should drain + deliver.
    h.state
        .appservice_outbox
        .enqueue(asv.nid, vec![event_nid], vec!["!room:example.com".into()])
        .unwrap();

    // Give the worker time to run. wiremock will fail the assertion
    // on Mock::drop if the expectation wasn't met.
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if !mock.received_requests().await.unwrap().is_empty() {
            break;
        }
    }

    let reqs = mock.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "AS should have received exactly one PUT");
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    let events = body.get("events").and_then(|v| v.as_array()).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["content"]["body"], "hello AS");
    assert_eq!(events[0]["room_id"], "!room:example.com");
}

#[tokio::test]
async fn outbox_worker_retries_on_5xx() {
    let mock = MockServer::start().await;
    let h = Harness::new();

    let yaml = format!(
        r#"
id: "retry-as"
url: "{}"
as_token: "as-r"
hs_token: "hs-r"
sender_localpart: "_retry_bot"
namespaces:
  rooms:
    - regex: "^!.*$"
      exclusive: false
"#,
        mock.uri()
    );
    let parsed = registration::parse(&yaml).unwrap();
    let cleartext_hs = parsed.hs_token_cleartext.clone();
    let asv = h
        .state
        .appservice_registry
        .register(parsed.appservice)
        .unwrap();
    h.state
        .appservice_outbox
        .set_hs_token(asv.nid, cleartext_hs);
    h.state.appservice_outbox.start_worker(asv.nid);

    // First two responses 502 (Retryable), third 200 (success).
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/app/v1/transactions/.+$"))
        .respond_with(ResponseTemplate::new(502))
        .up_to_n_times(2)
        .mount(&mock)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/app/v1/transactions/.+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&mock)
        .await;

    let room_nid = h.state.db.get_or_create_nid("!retry:example.com").unwrap();
    let type_nid = h.state.db.get_or_create_nid("m.room.message").unwrap();
    let sender_nid = h.state.db.get_or_create_nid("@bob:example.com").unwrap();
    let event_nid = h.state.db.next_nid().unwrap();
    let event_json = json!({
        "type": "m.room.message",
        "sender": "@bob:example.com",
        "room_id": "!retry:example.com",
        "content": {"msgtype": "m.text", "body": "retry me"},
        "origin_server_ts": 2000u64,
        "depth": 1,
    });
    h.state
        .db
        .persist_event(
            event_nid,
            "$retry:example.com",
            room_nid,
            type_nid,
            sender_nid,
            0,
            2000,
            1,
            &serde_json::to_vec(&event_json).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();

    h.state
        .appservice_outbox
        .enqueue(asv.nid, vec![event_nid], vec!["!retry:example.com".into()])
        .unwrap();

    // Backoff is 2s -> 4s; allow up to 10s for three attempts.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if mock.received_requests().await.unwrap().len() >= 3 {
            break;
        }
        if std::time::Instant::now() > deadline {
            panic!(
                "expected 3 attempts, got {}",
                mock.received_requests().await.unwrap().len()
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        h.state
            .db
            .peek_appservice_outbox(asv.nid)
            .unwrap()
            .is_none(),
        "outbox should be drained after successful retry"
    );
}
