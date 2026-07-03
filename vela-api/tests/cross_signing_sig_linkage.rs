//! `/keys/device_signing/upload` must verify that a self-signing or
//! user-signing key is signed by the user's master cross-signing key before
//! persisting it (CS-API: the SSK/USK "must be signed by the accompanying
//! master signing key, or by the user's most recently uploaded master signing
//! key if no master signing key is included in the request"). Storing an
//! unsigned or mis-signed key would serve a broken cross-signing identity to
//! `/keys/query`, which every other client then rejects. A bad link must be
//! refused with 400 `M_INVALID_SIGNATURE` and nothing persisted.

mod common;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use serde_json::{Map, Value, json};

use common::{Harness, read_json};
use vela_core::events::sign::ServerSigningKey;

/// A signer whose `key_id` is the full cross-signing form
/// `ed25519:<unpadded-b64-pubkey>` (not the truncated 6-char server-key
/// form), so a signature it makes lands under the same `key_id` that a master
/// key's `keys` map advertises — which is what verification looks up.
fn full_signer() -> ServerSigningKey {
    let key = ServerSigningKey::generate();
    let pub_b64 = key.public_key_base64();
    ServerSigningKey::from_bytes(format!("ed25519:{pub_b64}"), key.secret_bytes())
}

/// Build a cross-signing key object `{user_id, usage, keys}` (unsigned).
fn cross_signing_key(user_id: &str, usage: &str, pub_b64: &str) -> Map<String, Value> {
    let mut keys = Map::new();
    keys.insert(format!("ed25519:{pub_b64}"), json!(pub_b64));
    let mut m = Map::new();
    m.insert("user_id".into(), json!(user_id));
    m.insert("usage".into(), json!([usage]));
    m.insert("keys".into(), Value::Object(keys));
    m
}

async fn upload(harness: &Harness, token: &str, body: Value) -> Response<Body> {
    harness
        .request(
            Request::post("/_matrix/client/v3/keys/device_signing/upload")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
}

fn stored_is_empty(harness: &Harness, user_id: &str) -> bool {
    let nid = harness.state.db.get_nid(user_id).unwrap().unwrap();
    harness
        .state
        .db
        .get_cross_signing_keys(nid)
        .unwrap()
        .is_empty()
}

#[tokio::test]
async fn valid_first_time_upload_succeeds() {
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;

    let master = full_signer();
    let master_key = cross_signing_key(&alice, "master", &master.public_key_base64());

    let mut ssk = cross_signing_key(&alice, "self_signing", &full_signer().public_key_base64());
    master.sign_json(&mut ssk, &alice);

    let mut usk = cross_signing_key(&alice, "user_signing", &full_signer().public_key_base64());
    master.sign_json(&mut usk, &alice);

    let resp = upload(
        &harness,
        &tok,
        json!({
            "master_key": Value::Object(master_key),
            "self_signing_key": Value::Object(ssk),
            "user_signing_key": Value::Object(usk),
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "valid cross-signing upload was rejected"
    );
    assert!(
        !stored_is_empty(&harness, &alice),
        "valid keys not persisted"
    );
}

#[tokio::test]
async fn self_signing_key_without_master_signature_is_rejected() {
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;

    let master = full_signer();
    let master_key = cross_signing_key(&alice, "master", &master.public_key_base64());
    // SSK carries no signature at all.
    let ssk = cross_signing_key(&alice, "self_signing", &full_signer().public_key_base64());

    let resp = upload(
        &harness,
        &tok,
        json!({
            "master_key": Value::Object(master_key),
            "self_signing_key": Value::Object(ssk),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp).await;
    assert_eq!(body["errcode"], "M_INVALID_SIGNATURE");
    assert!(
        stored_is_empty(&harness, &alice),
        "a rejected upload must not persist any key"
    );
}

#[tokio::test]
async fn user_signing_key_signed_by_a_different_key_is_rejected() {
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;

    let master = full_signer();
    let master_key = cross_signing_key(&alice, "master", &master.public_key_base64());

    // USK signed by a wholly different key — its signature lands under that
    // key's key_id, so the master's key_id is absent from `signatures`.
    let stranger = full_signer();
    let mut usk = cross_signing_key(&alice, "user_signing", &full_signer().public_key_base64());
    stranger.sign_json(&mut usk, &alice);

    let resp = upload(
        &harness,
        &tok,
        json!({
            "master_key": Value::Object(master_key),
            "user_signing_key": Value::Object(usk),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp).await;
    assert_eq!(body["errcode"], "M_INVALID_SIGNATURE");
    assert!(stored_is_empty(&harness, &alice));
}

#[tokio::test]
async fn forged_signature_under_master_key_id_is_rejected() {
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;

    let master = full_signer();
    let master_pub = master.public_key_base64();
    let master_key = cross_signing_key(&alice, "master", &master_pub);

    // A signature PRESENT under the master's key_id but produced by a
    // different secret — exercises the crypto-verify failure path, not just a
    // missing-key-id lookup. Reuse the master's key_id with a stranger's key.
    let stranger = full_signer();
    let forger =
        ServerSigningKey::from_bytes(format!("ed25519:{master_pub}"), stranger.secret_bytes());
    let mut ssk = cross_signing_key(&alice, "self_signing", &full_signer().public_key_base64());
    forger.sign_json(&mut ssk, &alice);

    let resp = upload(
        &harness,
        &tok,
        json!({
            "master_key": Value::Object(master_key),
            "self_signing_key": Value::Object(ssk),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp).await;
    assert_eq!(body["errcode"], "M_INVALID_SIGNATURE");
    assert!(stored_is_empty(&harness, &alice));
}

#[tokio::test]
async fn idempotent_bare_reupload_verifies_against_stored_master() {
    // A client re-uploading an unchanged self-signing key often sends it
    // bare — the master signature lives only in the stored copy and is folded
    // back in by signature preservation. This must still verify (against the
    // stored master) rather than be rejected as unsigned. It also exercises
    // the "no master key in the request" branch, where the anchor is the
    // most-recently-stored master.
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;

    let master = full_signer();
    let master_key = cross_signing_key(&alice, "master", &master.public_key_base64());
    let ssk_pub = full_signer().public_key_base64();
    let mut ssk = cross_signing_key(&alice, "self_signing", &ssk_pub);
    master.sign_json(&mut ssk, &alice);

    let resp = upload(
        &harness,
        &tok,
        json!({
            "master_key": Value::Object(master_key),
            "self_signing_key": Value::Object(ssk),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Re-upload the SSK bare (same key material, no signature carried). UIA is
    // skipped (nothing changed) and the master signature is restored from
    // storage before verification, so this is accepted.
    let bare = cross_signing_key(&alice, "self_signing", &ssk_pub);
    let resp = upload(
        &harness,
        &tok,
        json!({ "self_signing_key": Value::Object(bare) }),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "idempotent bare re-upload of a previously-verified SSK should be accepted"
    );
}

#[tokio::test]
async fn a_bad_key_rejects_the_whole_batch_atomically() {
    // A single upload with a valid self-signing key but an invalid
    // user-signing key must be rejected whole: verification runs before any
    // storage, so NOTHING — not even the valid SSK or the master — is
    // persisted.
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;

    let master = full_signer();
    let master_key = cross_signing_key(&alice, "master", &master.public_key_base64());

    let mut ssk = cross_signing_key(&alice, "self_signing", &full_signer().public_key_base64());
    master.sign_json(&mut ssk, &alice);

    // USK signed by a stranger, not the master.
    let stranger = full_signer();
    let mut usk = cross_signing_key(&alice, "user_signing", &full_signer().public_key_base64());
    stranger.sign_json(&mut usk, &alice);

    let resp = upload(
        &harness,
        &tok,
        json!({
            "master_key": Value::Object(master_key),
            "self_signing_key": Value::Object(ssk),
            "user_signing_key": Value::Object(usk),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_json(resp).await["errcode"], "M_INVALID_SIGNATURE");
    assert!(
        stored_is_empty(&harness, &alice),
        "one bad key must not leave a partial write (master/SSK persisted)"
    );
}

#[tokio::test]
async fn signing_key_with_no_master_at_all_is_rejected() {
    // A self-signing key uploaded with neither a master in the request nor a
    // stored master has no trust anchor and cannot be validated.
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;

    let ssk = cross_signing_key(&alice, "self_signing", &full_signer().public_key_base64());
    let resp = upload(
        &harness,
        &tok,
        json!({ "self_signing_key": Value::Object(ssk) }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_json(resp).await["errcode"], "M_INVALID_SIGNATURE");
    assert!(stored_is_empty(&harness, &alice));
}
