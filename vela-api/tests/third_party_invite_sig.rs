//! Integration test for matrix-spec v1.18 §5.4.1.7 — identity-server
//! signature verification on `m.room.third_party_invite` member events.
//!
//! Drives the public `vela_api::auth_check::authorise_event` entrypoint
//! against a real RocksDB-backed `AppState`. `authorise_event` is the
//! same gate `/send_join` runs (via `check_auth`), so a forged-invite
//! rejection here proves the federation path also rejects: the auth
//! engine is shared (`vela_core::auth_rules::check_auth`) and runs after
//! signature/structural validation in both paths.

mod common;

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use vela_api::auth_check::{InFlightState, authorise_event};
use vela_api::middleware::error::ApiError;
use vela_core::error::VelaError;
use vela_core::events::pdu::Pdu;
use vela_core::events::sign::ServerSigningKey;
use vela_core::identifiers::EventId;

use common::Harness;

const ROOM_ID: &str = "!room12";
const CREATE_EID: &str = "$room12";
const ALICE: &str = "@alice:example.com";
const BOB: &str = "@bob:example.com";
const TOKEN: &str = "tok-3pid";

/// Seed the harness DB with a room where alice is the creator and a
/// `m.room.third_party_invite` state event advertises `id_pub_b64` as the
/// identity server's signing key (legacy `public_key` form). Returns
/// `(room_nid, state_map_with_create_alice_tpi)` for downstream use.
fn seed_room_with_tpi(harness: &Harness, id_pub_b64: &str) -> u64 {
    let db = &harness.state.db;

    // Intern nids we need.
    let type_create_nid = db.get_or_create_nid("m.room.create").unwrap();
    let type_member_nid = db.get_or_create_nid("m.room.member").unwrap();
    let type_tpi_nid = db.get_or_create_nid("m.room.third_party_invite").unwrap();
    let skey_empty_nid = db.get_or_create_nid("").unwrap();
    let alice_nid = db.get_or_create_nid(ALICE).unwrap();
    let token_nid = db.get_or_create_nid(TOKEN).unwrap();
    let room_nid = db.get_or_create_nid(ROOM_ID).unwrap();

    // Create event.
    let create_json = json!({
        "type": "m.room.create",
        "sender": ALICE,
        "state_key": "",
        "room_id": ROOM_ID,
        "content": {"room_version": "12"},
        "origin_server_ts": 1,
        "depth": 1,
        "prev_events": [],
        "auth_events": [],
    });
    db.persist_event(
        100,
        CREATE_EID,
        room_nid,
        type_create_nid,
        alice_nid,
        skey_empty_nid,
        1,
        1,
        &serde_json::to_vec(&create_json).unwrap(),
        &[],
        &[],
        true,
        false,
    )
    .unwrap();

    // Alice's join.
    let alice_join_json = json!({
        "type": "m.room.member",
        "sender": ALICE,
        "state_key": ALICE,
        "room_id": ROOM_ID,
        "content": {"membership": "join"},
        "origin_server_ts": 2,
        "depth": 2,
        "prev_events": [CREATE_EID],
        "auth_events": [CREATE_EID],
    });
    db.persist_event(
        101,
        "$alice_join",
        room_nid,
        type_member_nid,
        alice_nid,
        alice_nid, // state_key=alice
        2,
        2,
        &serde_json::to_vec(&alice_join_json).unwrap(),
        &[100],
        &[100],
        true,
        false,
    )
    .unwrap();

    // m.room.third_party_invite advertising the identity server's pubkey.
    let tpi_json = json!({
        "type": "m.room.third_party_invite",
        "sender": ALICE,
        "state_key": TOKEN,
        "room_id": ROOM_ID,
        "content": {
            "display_name": "bob",
            "key_validity_url": "https://identity.example/_matrix/identity/v2/pubkey/isvalid",
            "public_key": id_pub_b64,
        },
        "origin_server_ts": 3,
        "depth": 3,
        "prev_events": ["$alice_join"],
        "auth_events": ["$alice_join"],
    });
    db.persist_event(
        102,
        "$tpi",
        room_nid,
        type_tpi_nid,
        alice_nid,
        token_nid,
        3,
        3,
        &serde_json::to_vec(&tpi_json).unwrap(),
        &[101],
        &[101],
        true,
        false,
    )
    .unwrap();

    room_nid
}

/// Build a m.room.member invite event from alice → bob carrying a
/// third-party-invite `signed` bundle. Caller picks which key signs.
fn build_member_invite(signed: Map<String, Value>) -> Map<String, Value> {
    json!({
        "type": "m.room.member",
        "sender": ALICE,
        "state_key": BOB,
        "room_id": ROOM_ID,
        "content": {
            "membership": "invite",
            "third_party_invite": {
                "display_name": "bob",
                "signed": signed,
            },
        },
        "origin_server_ts": 4,
        "depth": 4,
        "prev_events": ["$tpi"],
        // auth_events: alice's join + tpi state event. send_join requires
        // these — see federation_join.rs::send_join's auth_events load.
        "auth_events": ["$alice_join", "$tpi"],
    })
    .as_object()
    .unwrap()
    .clone()
}

/// Canonical `signed` block signed by `key`. Identity-server origin name
/// can be arbitrary — we only consult the pubkey for verification.
fn make_signed(target: &str, token: &str, key: &ServerSigningKey) -> Map<String, Value> {
    let mut signed = Map::new();
    signed.insert("mxid".into(), json!(target));
    signed.insert("token".into(), json!(token));
    key.sign_json(&mut signed, "identity.example");
    signed
}

#[tokio::test]
async fn third_party_invite_with_valid_signature_accepted() {
    let harness = Harness::new();
    let id_key = ServerSigningKey::generate();
    let _room_nid = seed_room_with_tpi(&harness, &id_key.public_key_base64());

    let signed = make_signed(BOB, TOKEN, &id_key);
    let event = build_member_invite(signed);

    let event_id = EventId::from_reference_hash("bob_invite_valid");
    let in_flight: InFlightState = HashMap::new();
    let result = authorise_event(
        &harness.state,
        _room_nid,
        &event_id,
        &event,
        Some(&in_flight),
    );
    assert!(
        result.is_ok(),
        "valid 3pid invite signature must authorise: {result:?}"
    );
}

#[tokio::test]
async fn third_party_invite_with_forged_signature_rejected() {
    // The room advertises id_key's pubkey, but the member event's `signed`
    // is signed by a different key. authorise_event must return Forbidden.
    let harness = Harness::new();
    let id_key = ServerSigningKey::generate();
    let attacker_key = ServerSigningKey::generate();
    let _room_nid = seed_room_with_tpi(&harness, &id_key.public_key_base64());

    let signed = make_signed(BOB, TOKEN, &attacker_key);
    let event = build_member_invite(signed);

    let event_id = EventId::from_reference_hash("bob_invite_forged");
    let in_flight: InFlightState = HashMap::new();
    let result = authorise_event(
        &harness.state,
        _room_nid,
        &event_id,
        &event,
        Some(&in_flight),
    );
    match result {
        Err(ApiError(VelaError::Forbidden(reason))) => {
            assert!(
                reason.contains("no signature verified"),
                "forged sig should be rejected with crypto-failure reason: {reason}"
            );
        }
        other => panic!("expected Forbidden, got {other:?}"),
    }
}

#[tokio::test]
async fn third_party_invite_tampered_after_signing_rejected() {
    // Sign legitimately, then mutate `mxid` post-signature. Canonical
    // bytes diverge → verify fails. Bob's state_key is updated to the
    // tampered mxid so we exercise the crypto path, not the structural
    // mxid != state_key check.
    let harness = Harness::new();
    let id_key = ServerSigningKey::generate();
    let _room_nid = seed_room_with_tpi(&harness, &id_key.public_key_base64());

    let mut signed = make_signed(BOB, TOKEN, &id_key);
    signed.insert("mxid".into(), json!("@eve:example.com"));

    let mut event = build_member_invite(signed);
    event.insert("state_key".into(), json!("@eve:example.com"));

    let event_id = EventId::from_reference_hash("bob_invite_tampered");
    let in_flight: InFlightState = HashMap::new();
    let result = authorise_event(
        &harness.state,
        _room_nid,
        &event_id,
        &event,
        Some(&in_flight),
    );
    assert!(
        matches!(result, Err(ApiError(VelaError::Forbidden(_)))),
        "tampered signed block should be rejected: {result:?}"
    );
}

/// Belt-and-suspenders: the parsed `Pdu` carries the same content the rule
/// engine sees, so changes to the auth rule's input wiring don't silently
/// regress this test.
#[test]
fn pdu_round_trip_preserves_signed_block() {
    let id_key = ServerSigningKey::generate();
    let signed = make_signed(BOB, TOKEN, &id_key);
    let event = build_member_invite(signed.clone());

    let pdu = Pdu::from_json("$id".to_string(), &event).unwrap();
    let parsed_signed = pdu
        .content
        .get("third_party_invite")
        .and_then(|tpi| tpi.get("signed"))
        .and_then(|s| s.as_object())
        .unwrap();
    assert_eq!(parsed_signed.get("mxid"), Some(&json!(BOB)));
    assert_eq!(parsed_signed.get("token"), Some(&json!(TOKEN)));
    assert!(parsed_signed.get("signatures").is_some());
}
