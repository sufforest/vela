//! Regression test: setting account_data must stream back via /sync
//! (incremental since token). Element's cross-signing setup writes
//! m.cross_signing.* and waits for them to reflect before proceeding;
//! without this, the whole "Reset cryptographic identity" flow stalls.

mod common;

use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync(harness: &Harness, token: &str, since: Option<&str>, timeout: u64) -> Value {
    let mut url = format!("/_matrix/client/v3/sync?timeout={timeout}");
    if let Some(s) = since {
        url.push_str(&format!("&since={s}"));
    }
    let resp = harness
        .request(
            Request::get(&url)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    read_json(resp).await
}

async fn put_account_data(
    harness: &Harness,
    token: &str,
    user_id: &str,
    data_type: &str,
    value: Value,
) {
    let uid_enc = user_id.replace('@', "%40").replace(':', "%3A");
    let resp = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/user/{uid_enc}/account_data/{data_type}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "set_account_data failed");
}

#[tokio::test]
async fn account_data_write_appears_in_incremental_sync() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    // Snapshot an initial sync so the client has a since token.
    let initial = sync(&harness, &alice_tok, None, 0).await;
    let since = initial["next_batch"].as_str().unwrap().to_string();

    // Write a cross-signing-ish account data entry.
    put_account_data(
        &harness,
        &alice_tok,
        &alice_id,
        "m.cross_signing.master",
        json!({"encrypted": {"keyid": {"iv": "aa", "ciphertext": "bb", "mac": "cc"}}}),
    )
    .await;

    // Incremental sync must surface it.
    let after = sync(&harness, &alice_tok, Some(&since), 0).await;
    let events = after
        .pointer("/account_data/events")
        .and_then(|v| v.as_array())
        .expect("account_data.events");
    assert!(
        events.iter().any(|e| e["type"] == "m.cross_signing.master"),
        "incremental sync missing cross_signing.master write: {events:?}"
    );
}

#[tokio::test]
async fn account_data_write_wakes_pending_long_poll() {
    let harness = std::sync::Arc::new(Harness::new());
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    let initial = sync(&harness, &alice_tok, None, 0).await;
    let since = initial["next_batch"].as_str().unwrap().to_string();

    let h = harness.clone();
    let tok = alice_tok.clone();
    let s = since.clone();
    let poll = tokio::spawn(async move {
        let start = Instant::now();
        let resp = sync(&h, &tok, Some(&s), 30_000).await;
        (start.elapsed(), resp)
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    put_account_data(&harness, &alice_tok, &alice_id, "m.direct", json!({})).await;

    let (elapsed, resp) = poll.await.expect("poll task");
    assert!(
        elapsed < Duration::from_secs(3),
        "account_data write must wake pending sync, took {elapsed:?}"
    );
    let events = resp
        .pointer("/account_data/events")
        .and_then(|v| v.as_array())
        .expect("account_data.events");
    assert!(
        events.iter().any(|e| e["type"] == "m.direct"),
        "woken sync missing m.direct: {events:?}"
    );
}
