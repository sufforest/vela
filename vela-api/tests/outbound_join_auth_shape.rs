//! Rule 3 on the state and auth chain of an outbound join.
//!
//! The send_join response is persisted on the resident's word: signature
//! and hash are checked, the state-dependent auth rules are not. The
//! `auth_events` citation of every bundle entry is still judged as on the
//! live path; a violating entry is marked rejected and left out of the
//! room's state, and the join itself still succeeds — the hole is the
//! resident's, and the room would be equally broken for any other joiner.
//! An entry whose citations are not persisted yet (the create event sits
//! in `state`, after the auth chain that cites it) is left unjudged.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, StubRemote};
use serde_json::{Map, Value, json};
use vela_core::events::hash::{add_content_hash, compute_event_id_for_version};
use vela_core::events::room_version::RoomVersion;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REMOTE: &str = "remote.example";
const VERSION: RoomVersion = RoomVersion::V10;

struct Resident {
    remote: StubRemote,
    room_id: String,
}

impl Resident {
    fn new() -> Self {
        Self {
            remote: StubRemote::new(REMOTE),
            room_id: format!("!room:{REMOTE}"),
        }
    }

    fn user(&self, local: &str) -> String {
        format!("@{local}:{REMOTE}")
    }

    fn pdu(
        &self,
        etype: &str,
        sender: &str,
        state_key: &str,
        content: Value,
        auth_events: &[&str],
        depth: u64,
    ) -> (String, Value) {
        let mut ev: Map<String, Value> = json!({
            "type": etype,
            "room_id": self.room_id,
            "sender": sender,
            "state_key": state_key,
            "content": content,
            "origin_server_ts": 1_700_000_000_000u64 + depth,
            "depth": depth,
            "prev_events": [],
            "auth_events": auth_events,
        })
        .as_object()
        .unwrap()
        .clone();
        add_content_hash(&mut ev);
        self.remote
            .key
            .sign_event_for_version(&mut ev, REMOTE, VERSION);
        let id = compute_event_id_for_version(&ev, VERSION)
            .as_str()
            .to_string();
        (id, Value::Object(ev))
    }
}

/// The resident's well-formed core: create, the creator's join, power
/// levels and join rules, each citing exactly what the selector picks.
struct Core {
    create: (String, Value),
    bob_join: (String, Value),
    power_levels: (String, Value),
    join_rules: (String, Value),
}

fn core(r: &Resident) -> Core {
    let bob = r.user("bob");
    let create = r.pdu(
        "m.room.create",
        &bob,
        "",
        json!({"room_version": "10", "creator": bob}),
        &[],
        1,
    );
    let bob_join = r.pdu(
        "m.room.member",
        &bob,
        &bob,
        json!({"membership": "join"}),
        &[&create.0],
        2,
    );
    let power_levels = r.pdu(
        "m.room.power_levels",
        &bob,
        "",
        json!({"users": {bob.clone(): 100}}),
        &[&create.0, &bob_join.0],
        3,
    );
    let join_rules = r.pdu(
        "m.room.join_rules",
        &bob,
        "",
        json!({"join_rule": "restricted", "allow": []}),
        &[&create.0, &power_levels.0, &bob_join.0],
        4,
    );
    Core {
        create,
        bob_join,
        power_levels,
        join_rules,
    }
}

struct Joined {
    harness: Harness,
    status: StatusCode,
}

impl Joined {
    fn persisted(&self, id: &str) -> bool {
        self.harness
            .state
            .db
            .get_event_nid_by_id(id)
            .unwrap()
            .is_some()
    }

    fn rejected(&self, id: &str) -> bool {
        self.harness.state.db.is_event_rejected(id).unwrap()
    }

    fn in_state(&self, room_id: &str, etype: &str, state_key: &str) -> Option<String> {
        let db = &self.harness.state.db;
        let room_nid = db.get_nid(room_id).unwrap()?;
        let t = db.get_nid(etype).unwrap()?;
        let k = db.get_nid(state_key).unwrap()?;
        let nid = db.get_state_event_nid(room_nid, t, k).unwrap()?;
        db.get_event_id_by_nid(nid).unwrap()
    }
}

/// Join the resident's room from a fresh harness, with the given
/// send_join bundle.
async fn join_with(r: &Resident, auth_chain: Vec<Value>, state: Vec<Value>) -> Joined {
    let harness = Harness::new();
    let (alice, tok) = harness.register("alice", "pw").await;
    r.remote.install(&harness);
    let mock = MockServer::start().await;
    harness
        .state
        .federation_client
        .set_base_url_override(REMOTE, &mock.uri());

    Mock::given(method("GET"))
        .and(path_regex(r"^/_matrix/federation/v1/make_join/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "room_version": "10",
            "event": {
                "type": "m.room.member",
                "room_id": r.room_id,
                "sender": alice,
                "state_key": alice,
                "content": {"membership": "join"},
                "depth": 10,
                "prev_events": [],
                "auth_events": [],
            },
        })))
        .mount(&mock)
        .await;
    Mock::given(method("PUT"))
        .and(path_regex(r"^/_matrix/federation/v2/send_join/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth_chain": auth_chain,
            "state": state,
            "event": {},
        })))
        .mount(&mock)
        .await;

    let url = format!(
        "/_matrix/client/v3/join/{}?server_name={REMOTE}",
        r.room_id.replace('!', "%21").replace(':', "%3A")
    );
    let resp = harness
        .request(
            Request::post(&url)
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    let status = resp.status();
    Joined { harness, status }
}

#[tokio::test]
async fn malformed_state_entry_is_rejected_and_the_join_still_succeeds() {
    let r = Resident::new();
    let c = core(&r);
    // A topic citing join_rules: never selected for a non-member event.
    let topic = r.pdu(
        "m.room.topic",
        &r.user("bob"),
        "",
        json!({"topic": "t"}),
        &[
            &c.create.0,
            &c.power_levels.0,
            &c.bob_join.0,
            &c.join_rules.0,
        ],
        5,
    );

    let j = join_with(
        &r,
        vec![
            c.create.1.clone(),
            c.bob_join.1.clone(),
            c.power_levels.1.clone(),
        ],
        vec![
            c.create.1,
            c.bob_join.1,
            c.power_levels.1,
            c.join_rules.1,
            topic.1,
        ],
    )
    .await;

    assert_eq!(j.status, StatusCode::OK);
    assert!(j.rejected(&topic.0), "unselected citation in state");
    assert!(!j.persisted(&topic.0));
    assert_eq!(j.in_state(&r.room_id, "m.room.topic", ""), None);
    assert_eq!(
        j.in_state(&r.room_id, "m.room.join_rules", "").as_deref(),
        Some(c.join_rules.0.as_str()),
        "the rest of the bundle is room state"
    );
}

#[tokio::test]
async fn malformed_auth_chain_entry_is_rejected() {
    let r = Resident::new();
    let c = core(&r);
    // Duplicate citation (rule 3.1) with every cited event already known.
    let dup_jr = r.pdu(
        "m.room.join_rules",
        &r.user("bob"),
        "",
        json!({"join_rule": "public"}),
        &[&c.create.0, &c.create.0, &c.power_levels.0, &c.bob_join.0],
        4,
    );

    let j = join_with(
        &r,
        vec![
            c.create.1.clone(),
            c.bob_join.1.clone(),
            c.power_levels.1.clone(),
            dup_jr.1,
        ],
        vec![c.create.1, c.bob_join.1, c.power_levels.1, c.join_rules.1],
    )
    .await;

    assert_eq!(j.status, StatusCode::OK);
    assert!(j.rejected(&dup_jr.0));
    assert!(!j.persisted(&dup_jr.0));
    assert!(j.persisted(&c.join_rules.0));
    assert!(!j.rejected(&c.join_rules.0));
}

#[tokio::test]
async fn create_arriving_after_its_citers_is_not_a_violation() {
    let r = Resident::new();
    let c = core(&r);

    // The create sits only in `state`; the auth chain entries citing it
    // are persisted first, with the citation unresolved.
    let j = join_with(
        &r,
        vec![c.bob_join.1.clone(), c.power_levels.1.clone()],
        vec![c.create.1, c.bob_join.1, c.power_levels.1, c.join_rules.1],
    )
    .await;

    assert_eq!(j.status, StatusCode::OK);
    for id in [&c.bob_join.0, &c.power_levels.0, &c.join_rules.0] {
        assert!(j.persisted(id), "{id} is history");
        assert!(
            !j.rejected(id),
            "{id} must not be judged on a partial chain"
        );
    }
    assert_eq!(
        j.in_state(&r.room_id, "m.room.create", "").as_deref(),
        Some(c.create.0.as_str())
    );
}

#[tokio::test]
async fn restricted_join_citing_its_authoriser_is_accepted() {
    let r = Resident::new();
    let c = core(&r);
    let carol = r.user("carol");
    let carol_join = r.pdu(
        "m.room.member",
        &carol,
        &carol,
        json!({
            "membership": "join",
            "join_authorised_via_users_server": r.user("bob"),
        }),
        &[
            &c.create.0,
            &c.power_levels.0,
            &c.join_rules.0,
            &c.bob_join.0,
        ],
        5,
    );

    let j = join_with(
        &r,
        vec![
            c.create.1.clone(),
            c.bob_join.1.clone(),
            c.power_levels.1.clone(),
            c.join_rules.1.clone(),
        ],
        vec![
            c.create.1,
            c.bob_join.1,
            c.power_levels.1,
            c.join_rules.1,
            carol_join.1,
        ],
    )
    .await;

    assert_eq!(j.status, StatusCode::OK);
    assert!(j.persisted(&carol_join.0));
    assert!(!j.rejected(&carol_join.0));
    assert_eq!(
        j.in_state(&r.room_id, "m.room.member", &carol).as_deref(),
        Some(carol_join.0.as_str())
    );
}
