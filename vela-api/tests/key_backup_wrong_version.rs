//! A `/room_keys` PUT must target the CURRENT backup version (spec): a stale
//! version → 403 M_WRONG_ROOM_KEYS_VERSION with `current_version`, and no
//! backup at all → 404. Without this a client silently writes keys to a backup
//! nobody restores from and loses them on recovery.

mod common;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use serde_json::json;

use common::{Harness, read_json};

async fn create_version(h: &Harness, tok: &str) -> String {
    let resp = h
        .request(
            Request::post("/_matrix/client/v3/room_keys/version")
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "algorithm": "m.megolm_backup.v1.curve25519-aes-sha2",
                        "auth_data": {"public_key": "stub"}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await["version"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn put_session(h: &Harness, tok: &str, version: &str) -> Response<Body> {
    let path = format!("/_matrix/client/v3/room_keys/keys/!r:localhost/sess1?version={version}");
    h.request(
        Request::put(&path)
            .header("authorization", format!("Bearer {tok}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "first_message_index": 0,
                    "forwarded_count": 0,
                    "is_verified": false,
                    "session_data": {"ciphertext": "c", "ephemeral": "e", "mac": "m"},
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn put_to_non_current_version_is_rejected() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;
    let version = create_version(&harness, &tok).await;

    // PUT to a version that isn't current → 403 with the current version.
    let resp = put_session(&harness, &tok, "does-not-exist").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = read_json(resp).await;
    assert_eq!(body["errcode"], "M_WRONG_ROOM_KEYS_VERSION");
    assert_eq!(
        body["current_version"], version,
        "the 403 must carry the current version: {body}"
    );

    // PUT to the current version still succeeds.
    let resp = put_session(&harness, &tok, &version).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn put_with_no_backup_is_not_found() {
    let harness = Harness::new();
    let (_alice, tok) = harness.register("alice", "pw").await;
    let resp = put_session(&harness, &tok, "1").await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "PUT with no backup version must 404"
    );
}
