//! Rule 3 on backfilled history.
//!
//! A backfill page is signature- and hash-checked but never run through
//! the state-dependent auth rules (it is history, the resident vouched for
//! it). The `auth_events` citation itself is still judged, exactly as on
//! the live receive path: an entry the selection algorithm would never
//! pick, a cited event this server rejected, or a missing create below
//! v12 rejects the event, which is marked so descendants citing it fail
//! the same way. A citation that is merely unknown leaves the event
//! unjudged — the rest of the chain may still be on its way, and these
//! paths do not fetch it.
//!
//! The remote is a wiremock server answering `/backfill` with PDUs signed
//! by a stub identity; `attempt_backfill` is driven directly.

mod common;

use common::{Harness, StubRemote};
use serde_json::{Map, Value, json};
use vela_api::federation::federation_backfill::attempt_backfill;
use vela_core::events::hash::{add_content_hash, compute_event_id_for_version};
use vela_core::events::room_version::RoomVersion;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const REMOTE: &str = "remote.example";
const JOIN: u8 = 1;

struct Room {
    harness: Harness,
    remote: StubRemote,
    mock: MockServer,
    room_id: String,
    room_nid: u64,
    version: RoomVersion,
    alice: String,
    create: String,
    power_levels: String,
    join_rules: String,
    alice_member: String,
}

impl Room {
    async fn new(version: &str) -> Self {
        let harness = Harness::new();
        let (alice, tok) = harness.register("alice", "pw").await;
        let room_id = harness
            .create_room(&tok, json!({"room_version": version}))
            .await;
        let db = &harness.state.db;
        let room_nid = db.get_nid(&room_id).unwrap().unwrap();
        let state_id = |etype: &str, sk: &str| -> String {
            let t = db.get_nid(etype).unwrap().unwrap();
            let k = db.get_nid(sk).unwrap().unwrap();
            let nid = db.get_state_event_nid(room_nid, t, k).unwrap().unwrap();
            db.get_event_id_by_nid(nid).unwrap().unwrap()
        };
        let create = state_id("m.room.create", "");
        let power_levels = state_id("m.room.power_levels", "");
        let join_rules = state_id("m.room.join_rules", "");
        let alice_member = state_id("m.room.member", &alice);

        // A joined remote member makes `remote.example` a backfill peer.
        let bob_nid = db.get_or_create_nid(&format!("@bob:{REMOTE}")).unwrap();
        db.set_membership(room_nid, bob_nid, JOIN).unwrap();

        let remote = StubRemote::new(REMOTE);
        remote.install(&harness);
        let mock = MockServer::start().await;
        harness
            .state
            .federation_client
            .set_base_url_override(REMOTE, &mock.uri());

        Self {
            harness,
            remote,
            mock,
            room_id,
            room_nid,
            version: RoomVersion::parse(version).unwrap(),
            alice,
            create,
            power_levels,
            join_rules,
            alice_member,
        }
    }

    fn bob(&self) -> String {
        format!("@bob:{REMOTE}")
    }

    /// A PDU from bob, hashed and signed by the remote. `tamper` runs
    /// after hashing and before signing, so a change there leaves the
    /// signature valid but the content hash wrong: the event is redacted
    /// on ingest, which is how a legitimately redacted event arrives.
    fn pdu(
        &self,
        etype: &str,
        state_key: Option<&str>,
        content: Value,
        auth_events: &[&str],
        depth: u64,
        tamper: impl FnOnce(&mut Map<String, Value>),
    ) -> (String, Value) {
        let mut ev = json!({
            "type": etype,
            "room_id": self.room_id,
            "sender": self.bob(),
            "content": content,
            "origin_server_ts": 1_700_000_000_000u64 + depth,
            "depth": depth,
            "prev_events": [self.create],
            "auth_events": auth_events,
        })
        .as_object()
        .unwrap()
        .clone();
        if let Some(sk) = state_key {
            ev.insert("state_key".into(), json!(sk));
        }
        add_content_hash(&mut ev);
        tamper(&mut ev);
        self.remote
            .key
            .sign_event_for_version(&mut ev, REMOTE, self.version);
        let id = compute_event_id_for_version(&ev, self.version)
            .as_str()
            .to_string();
        (id, Value::Object(ev))
    }

    fn bob_join(&self, auth_events: &[&str]) -> (String, Value) {
        self.pdu(
            "m.room.member",
            Some(&self.bob()),
            json!({"membership": "join"}),
            auth_events,
            2,
            |_| {},
        )
    }

    fn message(&self, auth_events: &[&str], depth: u64) -> (String, Value) {
        self.pdu(
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": format!("d{depth}")}),
            auth_events,
            depth,
            |_| {},
        )
    }

    async fn backfill(&self, pdus: Vec<Value>) -> usize {
        Mock::given(method("GET"))
            .and(path_regex(r"^/_matrix/federation/v1/backfill/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "origin": REMOTE,
                "origin_server_ts": 1_700_000_000_000u64,
                "pdus": pdus,
            })))
            .expect(1)
            .mount(&self.mock)
            .await;
        attempt_backfill(
            &self.harness.state,
            self.room_nid,
            &self.room_id,
            std::slice::from_ref(&self.create),
            50,
        )
        .await
    }

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
}

#[tokio::test]
async fn unselected_citation_is_rejected_and_siblings_survive() {
    let r = Room::new("10").await;
    let (join_id, join) = r.bob_join(&[&r.create, &r.power_levels, &r.join_rules]);
    let (good_id, good) = r.message(&[&r.create, &r.power_levels, &join_id], 3);
    // join_rules is selectable for member events only.
    let (bad_id, bad) = r.message(&[&r.create, &r.power_levels, &join_id, &r.join_rules], 4);

    let accepted = r.backfill(vec![join, good, bad]).await;

    assert_eq!(accepted, 2, "join and the well-formed message are history");
    assert!(r.persisted(&join_id));
    assert!(r.persisted(&good_id));
    assert!(
        !r.persisted(&bad_id),
        "unselected citation must not persist"
    );
    assert!(r.rejected(&bad_id), "and is marked so descendants cascade");
    assert!(!r.rejected(&good_id));
}

#[tokio::test]
async fn citing_a_rejected_event_cascades_instead_of_skipping() {
    let r = Room::new("10").await;
    // bob's join cites alice's membership: not selectable for a join
    // whose sender and target are bob.
    let (bad_join_id, bad_join) =
        r.bob_join(&[&r.create, &r.power_levels, &r.join_rules, &r.alice_member]);
    let (msg_id, msg) = r.message(&[&r.create, &r.power_levels, &bad_join_id], 3);

    let accepted = r.backfill(vec![bad_join, msg]).await;

    assert_eq!(accepted, 0);
    assert!(r.rejected(&bad_join_id));
    assert!(
        !r.persisted(&msg_id),
        "a rejected citation is a violation, not a missing one"
    );
    assert!(r.rejected(&msg_id), "rule 3.3 marks the descendant too");
}

#[tokio::test]
async fn unknown_citation_leaves_the_event_unjudged() {
    let r = Room::new("10").await;
    let (join_id, join) = r.bob_join(&[&r.create, &r.power_levels, &r.join_rules]);
    let ghost = "$ghostghostghostghostghostghostghostghostghost";
    let (msg_id, msg) = r.message(&[&r.create, &r.power_levels, &join_id, ghost], 3);

    let accepted = r.backfill(vec![join, msg]).await;

    assert_eq!(accepted, 2);
    assert!(r.persisted(&msg_id), "an incomplete chain is not a verdict");
    assert!(!r.rejected(&msg_id));
}

#[tokio::test]
async fn missing_create_citation_is_rejected_below_v12() {
    let r = Room::new("10").await;
    let (join_id, join) = r.bob_join(&[&r.power_levels, &r.join_rules]);

    let accepted = r.backfill(vec![join]).await;

    assert_eq!(accepted, 0);
    assert!(r.rejected(&join_id));
}

/// A restricted join redacted on ingest: redaction keeps the authoriser
/// field only from v9, so in a v8 room the pruned content no longer
/// selects the authoriser's membership and the citation is a violation —
/// the same verdict the live path gives such an event. In a v9 room the
/// field survives and the event is history.
async fn redacted_restricted_join(version: &str) -> (Room, String, usize) {
    let r = Room::new(version).await;
    let authorised = json!({
        "membership": "join",
        "join_authorised_via_users_server": r.alice,
    });
    let auth: Vec<&str> = vec![&r.create, &r.power_levels, &r.join_rules, &r.alice_member];
    let (id, join) = r.pdu(
        "m.room.member",
        Some(&r.bob()),
        authorised,
        &auth,
        2,
        |ev| {
            // Hash computed over the content above; the wire content
            // differs, so the receiver redacts before judging.
            ev["content"]["tampered"] = json!(true);
        },
    );
    let accepted = r.backfill(vec![join]).await;
    (r, id, accepted)
}

#[tokio::test]
async fn redacted_restricted_join_is_rejected_in_v8() {
    let (r, id, accepted) = redacted_restricted_join("8").await;
    assert_eq!(accepted, 0);
    assert!(r.rejected(&id));
}

#[tokio::test]
async fn redacted_restricted_join_is_history_from_v9() {
    let (r, id, accepted) = redacted_restricted_join("9").await;
    assert_eq!(accepted, 1);
    assert!(r.persisted(&id));
    assert!(!r.rejected(&id));
}
