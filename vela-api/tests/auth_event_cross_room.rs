//! An inbound PDU's auth_events must belong to the SAME room (receipt rule
//! 3.5). Without this a peer could cite a state event from a DIFFERENT room
//! (e.g. a power_levels where it holds authority) as an auth event to fake
//! authority in the target room. m.room.create is exempt (it's bound to the
//! room by check_auth rule 2 via the room_id↔create-id relation).

mod common;

use serde_json::{Value, json};

use common::{Harness, StubRemote};
use vela_api::federation::federation_receive::{PduOutcome, process_pdu};

#[tokio::test]
async fn auth_event_from_a_different_room_is_rejected() {
    let harness = Harness::new();
    let (alice, alice_tok) = harness.register("alice", "pw").await;
    let room_a = harness
        .create_room(&alice_tok, json!({"room_version": "12"}))
        .await;
    let room_b = harness
        .create_room(&alice_tok, json!({"room_version": "12"}))
        .await;

    // A non-create state event id from room B: alice's own member event.
    let db = &harness.state.db;
    let room_b_nid = db.get_nid(&room_b).unwrap().unwrap();
    let member_type = db.get_nid("m.room.member").unwrap().unwrap();
    let alice_sk = db.get_nid(&alice).unwrap().unwrap();
    let member_nid = db
        .get_state_event_nid(room_b_nid, member_type, alice_sk)
        .unwrap()
        .unwrap();
    let foreign_auth_id = db.get_event_id_by_nid(member_nid).unwrap().unwrap();

    let sender = StubRemote::new("sender.example");
    sender.install(&harness);

    // An event in room A citing room B's member event as an auth event.
    let mut event = json!({
        "type": "m.room.message",
        "room_id": room_a,
        "sender": format!("@x:{}", sender.server_name),
        "content": {"msgtype": "m.text", "body": "hi"},
        "origin_server_ts": 1_700_000_000_000u64,
        "depth": 5,
        "prev_events": [],
        "auth_events": [foreign_auth_id],
    })
    .as_object()
    .unwrap()
    .clone();
    sender.sign_event(&mut event);

    let (_, outcome) =
        process_pdu(&harness.state, &Value::Object(event), &sender.server_name).await;
    match outcome {
        PduOutcome::Rejected(r) => assert!(
            r.contains("different room"),
            "a cross-room auth event must be rejected, got: {r}"
        ),
        other => panic!("expected rejection for cross-room auth event, got {other:?}"),
    }
}
