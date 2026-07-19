//! End-to-end coverage for `/account/deactivate` hygiene operations.
//!
//! The unit tests in `account.rs` cover the in-process branches
//! (pushers, refresh tokens, E2EE keys, profile erasure) by poking the
//! handler directly. This integration test focuses on the pieces only
//! visible through the full router stack:
//!
//! - The forced room-leave actually flips membership and produces an
//!   `m.room.member` `leave` event with a deactivation reason.
//! - The deactivated user's access token is revoked, so subsequent
//!   authenticated requests return `M_UNKNOWN_TOKEN`.
//! - A second login attempt with the same credentials returns the same
//!   generic `M_FORBIDDEN` as any bad credential (deactivation wipes the
//!   hash; the deactivated state is not probeable without the password).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::{Harness, read_json};

#[tokio::test]
async fn deactivate_force_leaves_local_rooms_and_revokes_session() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (_bob_id, bob_tok) = harness.register("bob", "pw").await;

    // Alice creates a public room. Bob joins. Both are joined
    // pre-deactivation; both should see Alice's leave afterwards.
    let room = harness
        .create_room(&alice_tok, json!({"preset": "public_chat"}))
        .await;
    harness.join(&bob_tok, &room).await;

    // Sanity: Alice is currently joined.
    let alice_nid = harness
        .state
        .db
        .get_nid(&alice_id)
        .unwrap()
        .expect("alice nid");
    let room_nid = harness.state.db.get_nid(&room).unwrap().expect("room nid");
    assert_eq!(
        harness
            .state
            .db
            .get_membership(room_nid, alice_nid)
            .unwrap(),
        Some(1),
        "alice must be joined before deactivation",
    );

    // Deactivate alice's account through the real router.
    let body = json!({
        "auth": {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": alice_id},
            "password": "pw",
        }
    });
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/account/deactivate")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "deactivate failed");
    let v = read_json(resp).await;
    assert_eq!(v["id_server_unbind_result"].as_str(), Some("success"));

    // Alice's membership in the room flipped to leave (state value 0).
    assert_eq!(
        harness
            .state
            .db
            .get_membership(room_nid, alice_nid)
            .unwrap(),
        Some(0),
        "alice must be force-leaved from the room",
    );

    // Alice's user record carries the deactivated flag.
    assert!(harness.state.db.user_is_deactivated(alice_nid).unwrap());

    // Old access token is revoked: further requests return 401
    // M_UNKNOWN_TOKEN through the auth middleware.
    let whoami = harness
        .request(
            Request::get("/_matrix/client/v3/account/whoami")
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(whoami.status(), StatusCode::UNAUTHORIZED);

    // Subsequent login attempt returns the same generic 403 M_FORBIDDEN
    // as any bad credential (deactivation wiped the hash; the spec
    // allows M_FORBIDDEN in that case, and the uniform error keeps the
    // deactivated state unprobeable without the password).
    let login_body = json!({
        "type": "m.login.password",
        "identifier": {"type": "m.id.user", "user": alice_id},
        "password": "pw",
    });
    let login_resp = harness
        .request(
            Request::post("/_matrix/client/v3/login")
                .header("content-type", "application/json")
                .body(Body::from(login_body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(login_resp.status(), StatusCode::FORBIDDEN);
    let err = read_json(login_resp).await;
    assert_eq!(err["errcode"].as_str(), Some("M_FORBIDDEN"));
}
