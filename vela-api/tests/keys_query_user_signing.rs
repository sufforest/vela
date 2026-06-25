//! `/keys/query` must return `user_signing_keys` ONLY for the requesting
//! user (CS-API spec). Master + self_signing keys are public; the
//! user-signing key is not. Leaking another user's user-signing key both
//! exposes it AND corrupts matrix-rust-sdk's cross-signing trust — it
//! builds OTHER users' identities with master + self_signing only, so an
//! unexpected user-signing key breaks that identity's processing and a
//! verified user is shown as untrusted.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn keys_query(harness: &Harness, token: &str, target: &str) -> Value {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/keys/query")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "device_keys": { target: [] } }).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

/// Seed master/self_signing/user_signing cross-signing records for a user
/// directly in the DB (the real upload path requires UIA; we only need the
/// keys to exist so /keys/query has something to return).
fn seed_cross_signing(harness: &Harness, user_id: &str) {
    let nid = harness.state.db.get_nid(user_id).unwrap().unwrap();
    for (key_type, usage) in [
        ("master_key", "master"),
        ("self_signing_key", "self_signing"),
        ("user_signing_key", "user_signing"),
    ] {
        let mut keys = serde_json::Map::new();
        keys.insert(
            format!("ed25519:{usage}_pub"),
            json!(format!("{usage}_pub")),
        );
        harness
            .state
            .db
            .set_cross_signing_keys(
                nid,
                key_type,
                &json!({
                    "user_id": user_id,
                    "usage": [usage],
                    "keys": Value::Object(keys),
                }),
            )
            .unwrap();
    }
}

#[tokio::test]
async fn keys_query_does_not_leak_other_users_user_signing_key() {
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let (_bob, bob_tok) = harness.register("bob", "pw").await;
    seed_cross_signing(&harness, &alice);

    // Bob queries Alice (cross-user): master + self_signing are public and
    // must be present, but Alice's user_signing key must NEVER be returned.
    let resp = keys_query(&harness, &bob_tok, &alice).await;
    assert!(
        resp["master_keys"].get(alice.as_str()).is_some(),
        "master key is public and should be returned cross-user"
    );
    assert!(
        resp["self_signing_keys"].get(alice.as_str()).is_some(),
        "self_signing key is public and should be returned cross-user"
    );
    assert!(
        resp["user_signing_keys"]
            .as_object()
            .map(|m| m.is_empty())
            .unwrap_or(true),
        "user_signing_keys leaked to a cross-user query: {:?}",
        resp["user_signing_keys"]
    );

    // Alice querying herself DOES get her own user_signing key.
    let own = keys_query(&harness, &alice_tok, &alice).await;
    assert!(
        own["user_signing_keys"].get(alice.as_str()).is_some(),
        "a self-query must return the caller's own user_signing key"
    );
}
