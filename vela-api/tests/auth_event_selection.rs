//! Receipt rule 3.2: every auth event a PDU cites must be one the auth
//! events selection algorithm could have picked for it, and (3.4) through
//! v11 the room's create must be among them. Vela used to accept any
//! well-formed auth_events list, which let its own malformed events (no
//! create cited in v11 rooms, creator power assumed) pass vela↔vela while
//! other servers rejected them.

mod common;

use serde_json::{Value, json};

use common::{Harness, StubRemote};
use vela_api::federation::federation_receive::{PduOutcome, process_pdu};

/// Event id of the current `(type, state_key)` state event in `room`.
fn state_event_id(harness: &Harness, room: &str, event_type: &str, state_key: &str) -> String {
    let db = &harness.state.db;
    let room_nid = db.get_nid(room).unwrap().unwrap();
    let type_nid = db.get_nid(event_type).unwrap().unwrap();
    let sk_nid = db.get_nid(state_key).unwrap().unwrap();
    let nid = db
        .get_state_event_nid(room_nid, type_nid, sk_nid)
        .unwrap()
        .unwrap();
    db.get_event_id_by_nid(nid).unwrap().unwrap()
}

async fn remote_message(
    harness: &Harness,
    sender: &StubRemote,
    room: &str,
    auth_events: Vec<String>,
) -> PduOutcome {
    let mut event = json!({
        "type": "m.room.message",
        "room_id": room,
        "sender": format!("@x:{}", sender.server_name),
        "content": {"msgtype": "m.text", "body": "hi"},
        "origin_server_ts": 1_700_000_000_000u64,
        "depth": 5,
        "prev_events": [],
        "auth_events": auth_events,
    })
    .as_object()
    .unwrap()
    .clone();
    sender.sign_event(&mut event);
    process_pdu(&harness.state, &Value::Object(event), &sender.server_name)
        .await
        .1
}

fn rejected_with(outcome: PduOutcome, needle: &str) {
    match outcome {
        PduOutcome::Rejected(r) => assert!(r.contains(needle), "expected {needle:?}, got: {r}"),
        other => panic!("expected rejection mentioning {needle:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn unselected_state_event_in_auth_events_is_rejected() {
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(&alice_tok, json!({"room_version": "12", "name": "n"}))
        .await;
    let pl = state_event_id(&harness, &room, "m.room.power_levels", "");
    let name = state_event_id(&harness, &room, "m.room.name", "");
    let _ = alice;

    let sender = StubRemote::new("sender.example");
    sender.install(&harness);
    // m.room.name is never selected for a message.
    let outcome = remote_message(&harness, &sender, &room, vec![pl, name]).await;
    rejected_with(outcome, "m.room.name");
}

/// From v12 the create is not selected, but peers still cite it; the
/// event must get through the structural layer to the auth rules.
#[tokio::test]
async fn create_in_auth_events_is_tolerated_in_v12() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(&alice_tok, json!({"room_version": "12"}))
        .await;
    let create = state_event_id(&harness, &room, "m.room.create", "");
    let pl = state_event_id(&harness, &room, "m.room.power_levels", "");

    let sender = StubRemote::new("sender.example");
    sender.install(&harness);
    let outcome = remote_message(&harness, &sender, &room, vec![create, pl]).await;
    rejected_with(outcome, "auth_events check failed");
}

#[tokio::test]
async fn duplicate_slot_in_auth_events_is_rejected() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(&alice_tok, json!({"room_version": "12"}))
        .await;
    let pl = state_event_id(&harness, &room, "m.room.power_levels", "");

    let sender = StubRemote::new("sender.example");
    sender.install(&harness);
    let outcome = remote_message(&harness, &sender, &room, vec![pl.clone(), pl]).await;
    rejected_with(outcome, "duplicate");
}

#[tokio::test]
async fn missing_create_in_auth_events_is_rejected_in_v11() {
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(&alice_tok, json!({"room_version": "11"}))
        .await;
    let pl = state_event_id(&harness, &room, "m.room.power_levels", "");

    let sender = StubRemote::new("sender.example");
    sender.install(&harness);
    let outcome = remote_message(&harness, &sender, &room, vec![pl]).await;
    rejected_with(outcome, "no m.room.create in auth_events");
}

#[tokio::test]
async fn well_formed_auth_events_reach_the_auth_rules() {
    // The structural layer passes; the event then fails on substance (the
    // remote sender is not a member), which proves rule 3 did not fire.
    let harness = Harness::new();
    let (_alice, alice_tok) = harness.register("alice", "pw").await;
    let room = harness
        .create_room(&alice_tok, json!({"room_version": "11"}))
        .await;
    let create = state_event_id(&harness, &room, "m.room.create", "");
    let pl = state_event_id(&harness, &room, "m.room.power_levels", "");

    let sender = StubRemote::new("sender.example");
    sender.install(&harness);
    let outcome = remote_message(&harness, &sender, &room, vec![create, pl]).await;
    rejected_with(outcome, "auth_events check failed");
}
