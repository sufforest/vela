//! Regression tests for the key-backup load-mutate-save race that
//! deletion-truncated Element's first-Secure-Backup-setup upload to
//! N concurrent batches, only one of which won.
//!
//! Before this fix, `PUT /room_keys/keys` followed:
//!
//!   1. load entire backup blob from user account_data
//!   2. merge incoming sessions into in-memory blob
//!   3. save blob back
//!
//! Two parallel PUTs from the same user both read the same baseline,
//! each merged in their own sessions, each wrote back. The second
//! save overwrote the first → sessions in the first batch silently
//! disappeared. Element observed `count=3` for a backup that should
//! have had dozens.
//!
//! After the fix: sessions go to distinct CF rows. Two concurrent
//! PUTs touching different `(room_id, session_id)` keys never collide
//! at the storage layer; the per-user lock protects the (read,
//! modify, write) cycle on the small stats row.
//!
//! This test fires N=20 parallel PUTs, asserts every session lands.

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

fn session_blob(first_message_index: u64) -> Value {
    json!({
        "first_message_index": first_message_index,
        "forwarded_count": 0,
        "is_verified": false,
        "session_data": {"ciphertext": "stub", "ephemeral": "stub", "mac": "stub"},
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_session_uploads_all_persist() {
    let harness = Arc::new(Harness::new());
    let (_alice, alice_tok) = harness.register("alice", "pw").await;

    // Create a backup version.
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/room_keys/version")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
                        "auth_data": { "public_key": "stub" }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let version = body["version"].as_str().unwrap().to_string();

    let room_id = "!testroom:localhost".to_string();

    // Fire 20 concurrent PUTs, each writing one distinct session.
    let mut handles = Vec::new();
    for i in 0..20u64 {
        let h = harness.clone();
        let tok = alice_tok.clone();
        let v = version.clone();
        let r = room_id.clone();
        handles.push(tokio::spawn(async move {
            let session_id = format!("session-{i}");
            let path = format!("/_matrix/client/v3/room_keys/keys/{r}/{session_id}?version={v}");
            let resp = h
                .request(
                    Request::put(&path)
                        .header("authorization", format!("Bearer {tok}"))
                        .header("content-type", "application/json")
                        .body(Body::from(session_blob(i).to_string()))
                        .unwrap(),
                )
                .await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "PUT session-{i} failed: {resp:?}"
            );
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // Read back the full backup — every session must be present.
    // Before the fix, this would return ~1-3 of 20 due to the
    // lost-write race.
    let path = format!("/_matrix/client/v3/room_keys/keys?version={version}");
    let resp = harness
        .request(
            Request::get(&path)
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let sessions = body["rooms"][&room_id]["sessions"].as_object().unwrap();
    assert_eq!(
        sessions.len(),
        20,
        "all 20 concurrent uploads must persist; got {}: {sessions:#?}",
        sessions.len()
    );

    // Stats reflect the count too.
    let path = format!("/_matrix/client/v3/room_keys/version/{version}");
    let resp = harness
        .request(
            Request::get(&path)
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let body = read_json(resp).await;
    assert_eq!(
        body["count"].as_u64(),
        Some(20),
        "version count must reflect actual stored sessions"
    );
}

// (No test for "session_id contains `/`" — Matrix Megolm session_ids
// are unpadded base64URL (chars `A-Za-z0-9-_`), so `/` never appears
// in real client traffic. The old code's JSON-Pointer escaping bug
// was theoretical, not a real client-facing issue. The per-row CF
// design eliminates it incidentally; not worth a dedicated test.)
