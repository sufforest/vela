//! Authorisation gate for the client-server write path.
//!
//! Every event built via `build_event` must pass through `authorise_event`
//! before `persist_event` commits it. This wires `vela_core::auth_rules::check_auth`
//! into the API layer.
//!
//! The state view is built by pre-loading every state event the rule engine
//! might consult:
//! - All events listed in the candidate event's `auth_events` (covers
//!   power_levels, sender/target member, join_rules — the types selected by
//!   the auth events selection algorithm).
//! - `m.room.create` loaded directly from persisted state. Room v12
//!   (MSC4291) forbids `m.room.create` in `auth_events` — the `room_id`
//!   (being the create event's id) implies it — so callers that only
//!   populate from `auth_events` miss it.
//! - For member events with a `third_party_invite` content block, the matching
//!   `m.room.third_party_invite` event (rule 5.4.1.5).
//! - Any events in `in_flight` (shadow map for flows like `createRoom` that
//!   build a batch before persisting any of it). In-flight wins over DB.

use std::collections::HashMap;

use serde_json::{Map, Value};
use vela_core::auth_rules::{AuthError, check_auth};
use vela_core::error::VelaError;
use vela_core::events::pdu::Pdu;
use vela_core::identifiers::EventId;

use crate::middleware::error::ApiError;
use crate::router::AppState;

/// State events built in the current request but not yet persisted to the DB.
/// Passed to `authorise_event` by flows like `createRoom` that accumulate a
/// sequence of events. Keyed by `(event_type, state_key)`.
pub type InFlightState = HashMap<(String, String), Pdu>;

/// Authorise an event against current room state plus any in-flight state.
///
/// Returns `Ok(())` when `check_auth` accepts the event.
/// Returns `Err(ApiError(VelaError::Forbidden(reason)))` on rejection —
/// this maps to HTTP 403 with errcode `M_FORBIDDEN`.
pub fn authorise_event(
    state: &AppState,
    room_nid: u64,
    event_id: &EventId,
    event: &Map<String, Value>,
    in_flight: Option<&InFlightState>,
) -> Result<(), ApiError> {
    let pdu = Pdu::from_json(event_id.as_str().to_string(), event).ok_or_else(|| {
        ApiError(VelaError::Unknown(
            "failed to parse built event as Pdu".into(),
        ))
    })?;

    // Materialise everything the rule engine might look up into a single map.
    let mut state_view: HashMap<(String, String), Pdu> = HashMap::new();

    // 1. Load events from the candidate's auth_events. These cover every
    //    (type, state_key) that check_auth consults for a well-formed event,
    //    EXCEPT m.room.create in v12+.
    for auth_event_id in &pdu.auth_events {
        if let Some(auth_pdu) = load_pdu_by_event_id(state, auth_event_id)
            && let Some(sk) = auth_pdu.state_key.as_deref()
        {
            let key = (auth_pdu.event_type.clone(), sk.to_string());
            state_view.insert(key, auth_pdu);
        }
    }

    // 1a. Inject m.room.create from persisted state if still missing.
    //     Room v12 (MSC4291) excludes m.room.create from auth_events, so
    //     step 1 never loads it; rule 2 in check_auth still needs it.
    //     Skip when the event is itself the create (check_auth short-circuits).
    if pdu.event_type != "m.room.create" {
        let create_key = ("m.room.create".to_string(), String::new());
        if let std::collections::hash_map::Entry::Vacant(e) = state_view.entry(create_key)
            && let Some(create) = load_state_event(state, room_nid, "m.room.create", "")
        {
            e.insert(create);
        }
    }

    // 2. For member events carrying a third_party_invite, pull in the matching
    //    m.room.third_party_invite event by token (rule 5.4.1.5).
    if pdu.event_type == "m.room.member"
        && let Some(token) = pdu
            .content
            .get("third_party_invite")
            .and_then(|tpi| tpi.get("signed"))
            .and_then(|s| s.get("token"))
            .and_then(|t| t.as_str())
    {
        let key = ("m.room.third_party_invite".to_string(), token.to_string());
        if let Some(tpi_pdu) = load_state_event(state, room_nid, &key.0, &key.1) {
            state_view.insert(key, tpi_pdu);
        }
    }

    // 3. Overlay in-flight state. In-flight wins because it represents events
    //    already accepted in the current batch (e.g. createRoom sequence) that
    //    haven't been persisted yet.
    if let Some(in_flight_map) = in_flight {
        for (k, v) in in_flight_map {
            state_view.insert(k.clone(), v.clone());
        }
    }

    let state_fn = |t: &str, sk: &str| state_view.get(&(t.to_string(), sk.to_string()));

    match check_auth(&pdu, &state_fn) {
        Ok(()) => Ok(()),
        Err(AuthError::Rejected(reason)) => Err(ApiError(VelaError::Forbidden(reason))),
    }
}

fn load_state_event(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Option<Pdu> {
    let type_nid = state.db.get_nid(event_type).ok().flatten()?;
    let skey_nid = state.db.get_nid(state_key).ok().flatten()?;
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .ok()
        .flatten()?;
    load_pdu_by_nid(state, event_nid)
}

fn load_pdu_by_nid(state: &AppState, event_nid: u64) -> Option<Pdu> {
    let (_header, json_bytes) = state.db.get_event(event_nid).ok().flatten()?;
    let event_id = state.db.get_event_id_by_nid(event_nid).ok().flatten()?;
    let json: Map<String, Value> = serde_json::from_slice::<Value>(&json_bytes)
        .ok()?
        .as_object()?
        .clone();
    Pdu::from_json(event_id, &json)
}

fn load_pdu_by_event_id(state: &AppState, event_id: &str) -> Option<Pdu> {
    let event_nid = state.db.get_event_nid_by_id(event_id).ok().flatten()?;
    load_pdu_by_nid(state, event_nid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use vela_core::auth_rules::check_auth;
    use vela_core::events::pdu::Pdu;

    fn pdu(
        event_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        sender: &str,
        content: Value,
        room_id: &str,
    ) -> Pdu {
        Pdu {
            event_id: event_id.to_string(),
            room_id: room_id.to_string(),
            event_type: event_type.to_string(),
            state_key: state_key.map(String::from),
            sender: sender.to_string(),
            origin_server_ts: 1000,
            content,
            auth_events: vec![],
            prev_events: vec![],
            depth: 1,
            signatures: None,
        }
    }

    /// Sanity check that the underlying rule engine rejects what we expect.
    /// Full end-to-end testing of authorise_event happens via the write-path
    /// integration tests in membership.rs / rooms.rs.
    #[test]
    fn bare_check_auth_rejects_low_power_ban() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = pdu(
            "$alice_m",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        let bob_member = pdu(
            "$bob_m",
            "m.room.member",
            Some("@bob:example.com"),
            "@bob:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        let pl = pdu(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@alice:example.com",
            json!({"ban": 50, "users": {}}),
            "!create",
        );

        let mut state_map: HashMap<(String, String), Pdu> = HashMap::new();
        state_map.insert(("m.room.create".into(), "".into()), create);
        state_map.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            alice_member,
        );
        state_map.insert(
            ("m.room.member".into(), "@bob:example.com".into()),
            bob_member,
        );
        state_map.insert(("m.room.power_levels".into(), "".into()), pl);

        let sf = |t: &str, sk: &str| state_map.get(&(t.to_string(), sk.to_string()));

        let bob_bans_alice = pdu(
            "$bob_bans",
            "m.room.member",
            Some("@alice:example.com"),
            "@bob:example.com",
            json!({"membership": "ban"}),
            "!create",
        );
        let result = check_auth(&bob_bans_alice, &sf);
        assert!(
            matches!(result, Err(AuthError::Rejected(_))),
            "expected rejection: {result:?}"
        );
    }

    #[test]
    fn in_flight_state_compiles() {
        let mut m: InFlightState = HashMap::new();
        m.insert(
            ("m.room.create".to_string(), "".to_string()),
            pdu(
                "$c",
                "m.room.create",
                Some(""),
                "@a:x",
                json!({"room_version": "12"}),
                "",
            ),
        );
        assert_eq!(m.len(), 1);
    }

    // --- End-to-end test against a real Database ---

    use crate::test_helpers::build_test_state;

    /// Build a JSON object Map from a Pdu for feeding into authorise_event.
    fn pdu_to_event_json(p: &Pdu) -> Map<String, Value> {
        let mut m = Map::new();
        m.insert("type".into(), json!(p.event_type));
        m.insert("sender".into(), json!(p.sender));
        m.insert("origin_server_ts".into(), json!(p.origin_server_ts));
        m.insert("content".into(), p.content.clone());
        m.insert("depth".into(), json!(p.depth));
        if let Some(sk) = &p.state_key {
            m.insert("state_key".into(), json!(sk));
        }
        if !p.room_id.is_empty() {
            m.insert("room_id".into(), json!(p.room_id));
        }
        let prev: Vec<Value> = p.prev_events.iter().map(|s| json!(s)).collect();
        let auth: Vec<Value> = p.auth_events.iter().map(|s| json!(s)).collect();
        m.insert("prev_events".into(), Value::Array(prev));
        m.insert("auth_events".into(), Value::Array(auth));
        m
    }

    #[test]
    fn authorise_event_accepts_with_in_flight_state() {
        let (state, _tmp) = build_test_state();
        // Room where alice is the creator.
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = Pdu {
            event_id: "$alice_member".into(),
            room_id: "!create".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 2,
            content: json!({"membership": "join"}),
            auth_events: vec!["$create".into()],
            prev_events: vec!["$create".into()],
            depth: 2,
            signatures: None,
        };

        let mut in_flight = InFlightState::new();
        in_flight.insert(("m.room.create".into(), "".into()), create.clone());

        // First member event: alice joining via rule 5.3.1 (only prev is create, sender is creator).
        let event_json = pdu_to_event_json(&alice_member);
        let event_id = EventId::from_reference_hash("alice_member");
        let result = authorise_event(&state, 1, &event_id, &event_json, Some(&in_flight));
        assert!(
            result.is_ok(),
            "creator's initial join must authorise: {result:?}"
        );
    }

    /// Regression test for Complement Bug A:
    /// In room v12 (MSC4291), m.room.create MUST NOT appear in auth_events.
    /// `authorise_event` must still find the create in state by loading it
    /// from persisted state, not just from auth_events.
    #[test]
    fn authorise_event_injects_create_from_persisted_state_for_v12() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        // Intern the strings we'll reference.
        let type_create_nid = db.get_or_create_nid("m.room.create").unwrap();
        let type_member_nid = db.get_or_create_nid("m.room.member").unwrap();
        let type_message_nid = db.get_or_create_nid("m.room.message").unwrap();
        let skey_empty_nid = db.get_or_create_nid("").unwrap();
        let alice_sender = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice_sender).unwrap();
        let alice_skey_nid = alice_nid;

        // v12: room_id = "!" + create_event_id[1..], so room_id "!room12" pairs
        // with create event_id "$room12".
        let room_id = "!room12";
        let create_eid = "$room12";
        let room_nid = db.get_or_create_nid(room_id).unwrap();

        // Persist the create event as current state.
        let create_json = json!({
            "type": "m.room.create",
            "sender": alice_sender,
            "state_key": "",
            "room_id": room_id,
            "content": {"room_version": "12"},
            "origin_server_ts": 1,
            "depth": 1,
            "prev_events": [],
            "auth_events": [],
        });
        db.persist_event(
            100,
            create_eid,
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

        // Persist alice's join member event.
        let alice_join_eid = "$alice_join";
        let alice_join_json = json!({
            "type": "m.room.member",
            "sender": alice_sender,
            "state_key": alice_sender,
            "room_id": room_id,
            "content": {"membership": "join"},
            "origin_server_ts": 2,
            "depth": 2,
            "prev_events": [create_eid],
            "auth_events": [create_eid],
        });
        db.persist_event(
            101,
            alice_join_eid,
            room_nid,
            type_member_nid,
            alice_nid,
            alice_skey_nid,
            2,
            2,
            &serde_json::to_vec(&alice_join_json).unwrap(),
            &[100],
            &[100],
            true,
            false,
        )
        .unwrap();

        // New message from alice. v12: auth_events MUST NOT include create.
        let message_json = json!({
            "type": "m.room.message",
            "sender": alice_sender,
            "room_id": room_id,
            "content": {"msgtype": "m.text", "body": "hi"},
            "origin_server_ts": 3,
            "depth": 3,
            "prev_events": [alice_join_eid],
            "auth_events": [alice_join_eid],
        });
        let event_map: Map<String, Value> = message_json.as_object().unwrap().clone();
        let event_id = EventId::from_reference_hash("msg_v12_no_create_in_auth");

        let result = authorise_event(&state, room_nid, &event_id, &event_map, None);
        assert!(
            result.is_ok(),
            "v12 message with no create in auth_events must authorise once create is pulled from state: {result:?}"
        );
        let _ = type_message_nid;
    }

    #[test]
    fn authorise_event_rejects_low_power_ban() {
        let (state, _tmp) = build_test_state();

        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = pdu(
            "$alice_m",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        let bob_member = pdu(
            "$bob_m",
            "m.room.member",
            Some("@bob:example.com"),
            "@bob:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        let pl = pdu(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@alice:example.com",
            json!({"ban": 50, "users": {}}),
            "!create",
        );

        let mut in_flight = InFlightState::new();
        in_flight.insert(("m.room.create".into(), "".into()), create);
        in_flight.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            alice_member,
        );
        in_flight.insert(
            ("m.room.member".into(), "@bob:example.com".into()),
            bob_member,
        );
        in_flight.insert(("m.room.power_levels".into(), "".into()), pl);

        // Bob (power 0) tries to ban alice. Rule 5.6.2 rejects (power 0 < ban level 50).
        let bob_bans = Pdu {
            event_id: "$bob_bans".into(),
            room_id: "!create".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:example.com".into()),
            sender: "@bob:example.com".into(),
            origin_server_ts: 100,
            content: json!({"membership": "ban"}),
            // auth_events reference the events the rules consult
            auth_events: vec![
                "$create".into(),
                "$pl".into(),
                "$bob_m".into(),
                "$alice_m".into(),
            ],
            prev_events: vec![],
            depth: 10,
            signatures: None,
        };

        let event_json = pdu_to_event_json(&bob_bans);
        let event_id = EventId::from_reference_hash("bob_bans");
        let result = authorise_event(&state, 1, &event_id, &event_json, Some(&in_flight));
        match result {
            Err(ApiError(VelaError::Forbidden(reason))) => {
                assert!(
                    reason.contains("ban"),
                    "rejection reason should mention ban: {reason}"
                );
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn auth_chain_bfs_is_transitive_and_bounded() {
        // Build a tiny chain A ← B ← C ← D, where D is our target. Auth chain of D
        // should include A, B, C (not D itself) in some order.
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        // Persist events with hand-crafted auth_events pointers.
        // We call persist_event directly. No hashes/signatures — we're just
        // exercising the auth_events graph storage.
        let persist = |nid: u64, eid: &str, auth: &[u64]| {
            db.persist_event(
                nid,
                eid,
                1, // room_nid
                1, // type_nid
                1, // sender_nid
                0, // state_key_nid
                0, // origin_ts
                0, // depth
                b"{}",
                &[],
                auth,
                false, // is_state
                false, // soft_failed
            )
            .unwrap();
        };
        persist(10, "$A", &[]);
        persist(11, "$B", &[10]);
        persist(12, "$C", &[11]);
        persist(13, "$D", &[12]);

        let chain = db.get_auth_chain(13, 100).unwrap();
        assert_eq!(chain.len(), 3, "chain {chain:?} should contain A, B, C");
        assert!(chain.contains(&10));
        assert!(chain.contains(&11));
        assert!(chain.contains(&12));
        assert!(!chain.contains(&13));

        // max_events cap is respected.
        let truncated = db.get_auth_chain(13, 2).unwrap();
        assert!(truncated.len() <= 2);
    }

    #[test]
    fn auth_chain_including_seeds_walks_transitively_for_unpersisted_event() {
        // The bug fixed in #1: send_join needs the auth chain for an event
        // we haven't persisted yet. We must walk pdu.auth_events (which point
        // to PERSISTED events) transitively, NOT look up the unpersisted event_id.
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        // Persist chain $A ← $B ← $C. The "join event" $J would point to $C
        // as one of its auth_events; $J is NOT in the DB.
        let persist = |nid: u64, eid: &str, auth: &[u64]| {
            db.persist_event(
                nid,
                eid,
                1,
                1,
                1,
                0,
                0,
                0,
                b"{\"foo\": 1}",
                &[],
                auth,
                false,
                false,
            )
            .unwrap();
        };
        persist(10, "$A", &[]);
        persist(11, "$B", &[10]);
        persist(12, "$C", &[11]);

        // Caller passes the (unpersisted) join event's auth_events = [$C].
        let unpersisted_auths = vec!["$C".to_string()];
        let chain =
            crate::federation::federation_state::auth_chain_including_seeds(db, &unpersisted_auths)
                .expect("walk succeeds");

        // Should include $C plus its ancestors $B, $A.
        assert!(
            chain.contains(&"$C".to_string()),
            "chain {chain:?} missing $C"
        );
        assert!(
            chain.contains(&"$B".to_string()),
            "chain {chain:?} missing $B"
        );
        assert!(
            chain.contains(&"$A".to_string()),
            "chain {chain:?} missing $A"
        );
        assert_eq!(chain.len(), 3);

        // Calling with empty roots returns empty chain.
        let empty =
            crate::federation::federation_state::auth_chain_including_seeds(db, &[]).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn auth_chain_union_dedupes_across_multiple_roots() {
        // Roots [$X, $Y] sharing a common ancestor $Common. Union should
        // include $Common only once, and NOT include $X / $Y themselves.
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let persist = |nid: u64, eid: &str, auth: &[u64]| {
            db.persist_event(nid, eid, 1, 1, 1, 0, 0, 0, b"{}", &[], auth, false, false)
                .unwrap();
        };
        // $Common is the bottom; $X and $Y both depend on it.
        persist(20, "$Common", &[]);
        persist(21, "$X", &[20]);
        persist(22, "$Y", &[20]);

        let roots = ["$X", "$Y"];
        let union =
            crate::federation::federation_state::auth_chain_union_event_ids(db, &roots).unwrap();

        // Expected: [$Common] only — roots themselves are excluded.
        assert_eq!(union, vec!["$Common".to_string()]);
    }

    #[test]
    fn remote_servers_in_room_dedupes_and_excludes_us() {
        let (state, _tmp) = build_test_state(); // server_name = example.com

        // Seed NIDs for user IDs spanning multiple remote servers and one local.
        let alice_remote_a = state
            .db
            .get_or_create_nid("@alice:remote-a.example")
            .unwrap();
        let bob_remote_a = state.db.get_or_create_nid("@bob:remote-a.example").unwrap();
        let carol_remote_b = state
            .db
            .get_or_create_nid("@carol:remote-b.example")
            .unwrap();
        let dave_local = state.db.get_or_create_nid("@dave:example.com").unwrap();

        let room_nid = 42;
        for user in [alice_remote_a, bob_remote_a, carol_remote_b, dave_local] {
            state.db.set_membership(room_nid, user, 1).unwrap();
        }

        let mut servers = state
            .db
            .get_remote_servers_in_room(room_nid, "example.com")
            .unwrap();
        servers.sort();
        assert_eq!(servers, vec!["remote-a.example", "remote-b.example"]);
    }

    #[test]
    fn soft_failed_roundtrip() {
        let (state, _tmp) = build_test_state();
        // Initially not soft-failed.
        assert!(!state.db.is_soft_failed(42).unwrap());
        // Mark and verify.
        state.db.mark_soft_failed(42).unwrap();
        assert!(state.db.is_soft_failed(42).unwrap());
        // Different nid is unaffected.
        assert!(!state.db.is_soft_failed(43).unwrap());
    }

    #[test]
    fn remote_keys_roundtrip() {
        let (state, _tmp) = build_test_state();
        // Initially absent.
        assert!(
            state
                .db
                .load_remote_server_keys("them.example")
                .unwrap()
                .is_none()
        );
        // Store and retrieve.
        let payload = br#"{"verify_keys":{"ed25519:x":"stub"}}"#;
        state
            .db
            .store_remote_server_keys("them.example", payload)
            .unwrap();
        let got = state
            .db
            .load_remote_server_keys("them.example")
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
        // Different server name is independent.
        assert!(
            state
                .db
                .load_remote_server_keys("other.example")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn federation_sender_broadcast_enqueues_remote_destinations_only() {
        // Seed a room with members on our server, server-a, and server-b.
        // Broadcast must enqueue the event to server-a and server-b but NOT
        // our own server. With the persistent outbox, the assertion is on
        // the on-disk queue rather than an in-memory channel.
        let (state, _tmp) = build_test_state(); // server_name = example.com
        let room_nid = 99;

        let alice_remote_a = state
            .db
            .get_or_create_nid("@alice:server-a.example")
            .unwrap();
        let bob_remote_b = state.db.get_or_create_nid("@bob:server-b.example").unwrap();
        let dave_local = state.db.get_or_create_nid("@dave:example.com").unwrap();

        for u in [alice_remote_a, bob_remote_b, dave_local] {
            state.db.set_membership(room_nid, u, 1).unwrap();
        }

        let event_nid: u64 = 12345;
        state.federation_sender.broadcast(room_nid, event_nid);

        // Both remote destinations have the event in their outbox; our
        // own server does not get an outbox entry.
        let outbox_a = state.db.peek_outbound("server-a.example", 10).unwrap();
        let outbox_b = state.db.peek_outbound("server-b.example", 10).unwrap();
        let outbox_self = state.db.peek_outbound("example.com", 10).unwrap();

        assert!(
            outbox_a.iter().any(|(_, nid)| *nid == event_nid),
            "server-a outbox should hold the broadcast event: {outbox_a:?}"
        );
        assert!(
            outbox_b.iter().any(|(_, nid)| *nid == event_nid),
            "server-b outbox should hold the broadcast event: {outbox_b:?}"
        );
        assert!(
            outbox_self.is_empty(),
            "broadcast must not enqueue to our own server: {outbox_self:?}"
        );
    }

    #[test]
    fn historical_events_skip_room_timeline() {
        // Regression for the stream-position bug: events persisted with
        // suppress_current_state=true must NOT appear in room_timeline
        // (they'd sort at the end under the monotonic counter, scrambling
        // backwards pagination).
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        // Persist one normal event, then one historical.
        db.persist_event(
            100,
            "$normal",
            1,
            1,
            1,
            0,
            0,
            0,
            b"{}",
            &[],
            &[],
            false, // is_state
            false, // suppress_current_state: normal
        )
        .unwrap();
        db.persist_event(
            101,
            "$hist",
            1,
            1,
            1,
            0,
            0,
            0,
            b"{}",
            &[],
            &[],
            false, // is_state
            true,  // suppress_current_state: historical
        )
        .unwrap();

        // Backwards query from u64::MAX: should return the normal event only.
        let tl = db.get_timeline_before(1, u64::MAX, 10).unwrap();
        assert_eq!(tl.len(), 1, "timeline should contain only the normal event");
        assert_eq!(
            tl[0].1, 100,
            "timeline entry should be the normal event_nid"
        );

        // But the historical event is addressable by event_id — still usable
        // for federation lookups, just invisible to client pagination.
        assert_eq!(db.get_event_nid_by_id("$hist").unwrap(), Some(101));
    }

    #[test]
    fn dag_walk_returns_events_depth_descending() {
        // Build a small DAG: $A (depth 1) ← $B (depth 2) ← $C (depth 3).
        // Walk back from $C: should return [$B, $A]. Start event excluded.
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let persist = |nid: u64, eid: &str, depth: u64, prev: &[u64]| {
            db.persist_event(
                nid,
                eid,
                1,
                1,
                1,
                0,
                depth * 100,
                depth,
                b"{}",
                prev,
                &[],
                false,
                true, // historical
            )
            .unwrap();
        };
        persist(400, "$A", 1, &[]);
        persist(401, "$B", 2, &[400]);
        persist(402, "$C", 3, &[401]);

        let walk = db.walk_dag_backwards(402, 10).unwrap();
        // $C is excluded (it's the cursor); $B then $A.
        assert_eq!(walk, vec![401, 400]);
    }

    #[test]
    fn dag_walk_respects_limit() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let persist = |nid: u64, eid: &str, depth: u64, prev: &[u64]| {
            db.persist_event(
                nid,
                eid,
                1,
                1,
                1,
                0,
                depth * 100,
                depth,
                b"{}",
                prev,
                &[],
                false,
                true,
            )
            .unwrap();
        };
        persist(500, "$Z0", 1, &[]);
        persist(501, "$Z1", 2, &[500]);
        persist(502, "$Z2", 3, &[501]);
        persist(503, "$Z3", 4, &[502]);
        persist(504, "$Z4", 5, &[503]);

        let walk = db.walk_dag_backwards(504, 2).unwrap();
        assert_eq!(walk.len(), 2);
        // Must be the two deepest ancestors.
        assert_eq!(walk, vec![503, 502]);
    }

    #[test]
    fn dag_walk_skips_unknown_prev_without_crashing() {
        // $A (depth 5) references unknown_nid as prev. Walk should return [].
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        // Persist event with prev_events pointing to a nid we never created.
        db.persist_event(
            600,
            "$only",
            1,
            1,
            1,
            0,
            500,
            5,
            b"{}",
            &[999], // unknown prev
            &[],
            false,
            true,
        )
        .unwrap();

        let walk = db.walk_dag_backwards(600, 10).unwrap();
        // Unknown prev is silently skipped. Walk yields nothing.
        assert!(walk.is_empty(), "got {walk:?}");
    }

    #[test]
    fn dag_walk_handles_diamond_dedupe() {
        // $A ← $B, $A ← $C, $B+$C ← $D. Walk from $D should return [$B,$C,$A] or
        // [$C,$B,$A] (depth 2 events first, A at depth 1) — A should only appear once.
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let persist = |nid: u64, eid: &str, depth: u64, prev: &[u64]| {
            db.persist_event(
                nid,
                eid,
                1,
                1,
                1,
                0,
                depth * 100,
                depth,
                b"{}",
                prev,
                &[],
                false,
                true,
            )
            .unwrap();
        };
        persist(700, "$A", 1, &[]);
        persist(701, "$B", 2, &[700]);
        persist(702, "$C", 2, &[700]);
        persist(703, "$D", 3, &[701, 702]);

        let walk = db.walk_dag_backwards(703, 10).unwrap();
        assert_eq!(walk.len(), 3, "got {walk:?}");
        assert!(walk.contains(&700));
        assert!(walk.contains(&701));
        assert!(walk.contains(&702));
        // A (depth 1) must come last.
        assert_eq!(walk[2], 700);
    }

    #[test]
    fn auth_edges_persist_when_batch_ordered_by_depth() {
        // Regression for the out-of-order batch bug: when federated batches
        // (auth_chain, state, backfill) arrive without topological ordering,
        // persisting event C before its auth_event B silently drops B's NID
        // from C's auth_edges — later auth-chain walks return a partial chain.
        //
        // The fix is depth-sort before persisting. This test verifies the
        // DEPTH-ORDERED path produces the correct auth_edges; the wrong-order
        // path (without sorting) is what we've eliminated from callers.
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        // Persist ancestor first (depth 1), then descendant (depth 2) that
        // references the ancestor as an auth_event.
        let persist = |nid: u64, eid: &str, depth: u64, auth: &[u64]| {
            db.persist_event(
                nid,
                eid,
                1,
                1,
                1,
                0,
                0,
                depth,
                b"{}",
                &[],
                auth,
                false,
                true, // historical
            )
            .unwrap();
        };
        persist(300, "$ancestor", 1, &[]);
        persist(301, "$descendant", 2, &[300]);

        // Now walking the auth chain of $descendant should find $ancestor.
        let chain = db.get_auth_chain(301, 100).unwrap();
        assert!(
            chain.contains(&300),
            "auth chain must include ancestor when batch was depth-ordered"
        );
    }

    #[test]
    fn historical_events_dont_bump_stream_counter() {
        // Second prong of the stream_position fix: historical events shouldn't
        // consume a stream position at all (otherwise we waste monotonic
        // counter values on events that'll never appear in the timeline).
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let before = db.current_stream_position();

        db.persist_event(
            200,
            "$hist_only",
            1,
            1,
            1,
            0,
            0,
            0,
            b"{}",
            &[],
            &[],
            false,
            true, // is_state=false, suppress_current_state=true
        )
        .unwrap();

        assert_eq!(
            db.current_stream_position(),
            before,
            "historical persist must not advance the stream counter"
        );
    }

    #[tokio::test]
    async fn federation_sender_broadcast_is_noop_for_local_only_room() {
        // Room with only local members: broadcast should not enqueue
        // anything to any remote outbox.
        let (state, _tmp) = build_test_state();
        let room_nid = 100;

        let alice_local = state.db.get_or_create_nid("@alice:example.com").unwrap();
        let bob_local = state.db.get_or_create_nid("@bob:example.com").unwrap();
        state.db.set_membership(room_nid, alice_local, 1).unwrap();
        state.db.set_membership(room_nid, bob_local, 1).unwrap();

        state.federation_sender.broadcast(room_nid, 999);

        let dests = state.db.list_outbound_destinations().unwrap();
        assert!(
            dests.is_empty(),
            "no destination should have been enqueued, got: {dests:?}"
        );
    }

    #[test]
    fn authorise_event_rejects_non_joined_sender() {
        let (state, _tmp) = build_test_state();

        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        // No member event for bob → bob is not joined.

        let mut in_flight = InFlightState::new();
        in_flight.insert(("m.room.create".into(), "".into()), create);

        // Bob (not joined) tries to send a message.
        let bob_msg = Pdu {
            event_id: "$bob_msg".into(),
            room_id: "!create".into(),
            event_type: "m.room.message".into(),
            state_key: None,
            sender: "@bob:example.com".into(),
            origin_server_ts: 5,
            content: json!({"msgtype": "m.text", "body": "hi"}),
            auth_events: vec!["$create".into()],
            prev_events: vec!["$create".into()],
            depth: 5,
            signatures: None,
        };
        let event_json = pdu_to_event_json(&bob_msg);
        let event_id = EventId::from_reference_hash("bob_msg");
        let result = authorise_event(&state, 1, &event_id, &event_json, Some(&in_flight));
        match result {
            Err(ApiError(VelaError::Forbidden(reason))) => {
                assert!(reason.contains("not joined"), "unexpected reason: {reason}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }
}
