//! Regression tests for the two presence bugs surfaced by the
//! first real deployment:
//!
//! 1. **/sync didn't emit the caller's own presence.** Element X (and
//!    any client that derives its own profile indicator from the
//!    /sync feed rather than local state) showed the user as offline
//!    in their own UI because the sync response had no presence
//!    event for them. Fix: `collect_presence_events` now includes
//!    the caller in the peers set.
//!
//! 2. **Stored presence never decayed.** A user who set themselves
//!    online and then closed the browser stayed "online" in every
//!    other client forever. Fix: `effective_presence` computes the
//!    decayed value at read time from `last_active_ms`, and the
//!    background sweeper persists the transitions for federation.
//!
//! These tests cover the API-surface behaviour for both bugs. The
//! sweeper's persisted-transition behaviour is unit-tested in the
//! `presence_sweeper` module itself.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn put_presence(harness: &Harness, token: &str, user_id: &str, body: Value) {
    let resp = harness
        .request(
            Request::put(format!("/_matrix/client/v3/presence/{user_id}/status"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "PUT /presence failed");
}

async fn sync(harness: &Harness, token: &str) -> Value {
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/sync?timeout=0")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

fn presence_event_for<'a>(sync_body: &'a Value, user_id: &str) -> Option<&'a Value> {
    sync_body["presence"]["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|e| e["sender"].as_str() == Some(user_id))
}

#[tokio::test]
async fn sync_includes_own_presence() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    // Alice explicitly sets herself online so a record exists. Without
    // a record, `collect_presence_events` correctly skips the user
    // (no point emitting fabricated offlines). The sync-includes-self
    // contract applies once a record exists.
    put_presence(
        &harness,
        &alice_tok,
        &alice_id,
        json!({"presence": "online"}),
    )
    .await;

    let body = sync(&harness, &alice_tok).await;
    let own = presence_event_for(&body, &alice_id)
        .expect("alice's own /sync must include her own m.presence event");
    assert_eq!(own["type"], "m.presence");
    assert_eq!(own["content"]["presence"], "online");
}

#[tokio::test]
async fn stale_online_presence_decays_to_unavailable_at_read_time() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (_bob_id, bob_tok) = harness.register("bob", "pw").await;

    // Alice + Bob share a room so bob's /sync emits alice's presence.
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [&_bob_id]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    // Alice sets online. Now we want to simulate "alice closed her
    // browser ages ago" — the cleanest way without a clock-injection
    // shim is to backdate the stored `last_active_ms` field directly
    // via the database handle the harness exposes.
    put_presence(
        &harness,
        &alice_tok,
        &alice_id,
        json!({"presence": "online"}),
    )
    .await;
    let alice_nid = harness.state.db.get_nid(&alice_id).unwrap().unwrap();
    // Backdate `last_active_ms` to 10 minutes ago — past the
    // default `idle_after` of 5 min, before `offline_after` of 30
    // min. Effective should be "unavailable".
    let backdated = serde_json::json!({
        "presence": "online",
        "last_active_ms": (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
            .saturating_sub(10 * 60 * 1000),
    });
    harness
        .state
        .db
        .set_presence(alice_nid, &backdated)
        .expect("set_presence");

    // Bob's /sync now sees alice as unavailable, not online, even
    // though the stored record still says "online" — the decay is
    // computed at read time.
    let body = sync(&harness, &bob_tok).await;
    let alice_pres = presence_event_for(&body, &alice_id)
        .expect("bob's /sync must contain alice's m.presence event");
    assert_eq!(
        alice_pres["content"]["presence"], "unavailable",
        "stale online presence must decay to unavailable when shown"
    );
}

#[tokio::test]
async fn very_stale_online_presence_decays_to_offline() {
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (_bob_id, bob_tok) = harness.register("bob", "pw").await;
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [&_bob_id]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    // Alice online, then backdate to 45 minutes ago — past the
    // default `offline_after` of 30 minutes.
    put_presence(
        &harness,
        &alice_tok,
        &alice_id,
        json!({"presence": "online"}),
    )
    .await;
    let alice_nid = harness.state.db.get_nid(&alice_id).unwrap().unwrap();
    let backdated = serde_json::json!({
        "presence": "online",
        "last_active_ms": (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
            .saturating_sub(45 * 60 * 1000),
    });
    harness
        .state
        .db
        .set_presence(alice_nid, &backdated)
        .unwrap();

    let body = sync(&harness, &bob_tok).await;
    let alice_pres = presence_event_for(&body, &alice_id).unwrap();
    assert_eq!(alice_pres["content"]["presence"], "offline");
}

#[tokio::test]
async fn explicit_offline_is_visible_to_other_users_as_offline() {
    // Defensive: the decay logic should ONLY transition `online`
    // records. A user who explicitly sets themselves offline (e.g.
    // "appear offline") must be visible to other users as offline,
    // not promoted to online by /sync activity.
    //
    // Note we check via *bob's* /sync, not alice's. /sync has a
    // `set_presence` query parameter (default "online") that
    // updates the requesting user's own stored presence — so an
    // alice-checks-her-own-/sync test would be racing that logic.
    // The stable contract is "what other users see," which is what
    // this checks.
    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;
    let (bob_id, bob_tok) = harness.register("bob", "pw").await;
    let room_id = harness
        .create_room(
            &alice_tok,
            json!({"preset": "trusted_private_chat", "invite": [&bob_id]}),
        )
        .await;
    harness.join(&bob_tok, &room_id).await;

    put_presence(
        &harness,
        &alice_tok,
        &alice_id,
        json!({"presence": "offline"}),
    )
    .await;

    let body = sync(&harness, &bob_tok).await;
    let alice_pres =
        presence_event_for(&body, &alice_id).expect("bob's /sync must include alice's presence");
    assert_eq!(alice_pres["content"]["presence"], "offline");
}

#[tokio::test]
async fn sweeper_persists_decay_transition_for_federation() {
    use vela_api::presence_sweeper;

    let harness = Harness::new();
    let (alice_id, alice_tok) = harness.register("alice", "pw").await;

    put_presence(
        &harness,
        &alice_tok,
        &alice_id,
        json!({"presence": "online"}),
    )
    .await;
    let alice_nid = harness.state.db.get_nid(&alice_id).unwrap().unwrap();

    // Backdate Alice's record so the sweeper sees a transition is due.
    let backdated = serde_json::json!({
        "presence": "online",
        "last_active_ms": (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64)
            .saturating_sub(10 * 60 * 1000),
    });
    harness
        .state
        .db
        .set_presence(alice_nid, &backdated)
        .unwrap();

    // Drive a single sweeper tick (not via the spawned timer — we
    // want determinism). Asserts:
    //   1. the sweeper reports the transition;
    //   2. the on-disk record now stores "unavailable", so any
    //      federation EDU reader sees the new state.
    let stats = presence_sweeper::sweep_once(&harness.state)
        .await
        .expect("sweep_once");
    assert!(
        stats.transitioned >= 1,
        "sweeper must transition the stale online record"
    );

    let rec = harness.state.db.get_presence(alice_nid).unwrap().unwrap();
    assert_eq!(
        rec.get("presence").and_then(|v| v.as_str()),
        Some("unavailable"),
        "stored record must reflect the persisted transition"
    );
}
