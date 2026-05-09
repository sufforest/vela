//! Event builder that constructs properly-formed Matrix events.
//!
//! Handles the full event lifecycle:
//! 1. Build event JSON with correct fields
//! 2. Add content hash
//! 3. Sign the event
//! 4. Compute event_id (reference hash)
//!
//! Auth events are selected per the auth events selection algorithm
//! (server-server-api.md:528-554), respecting room version differences.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::events::hash::add_content_hash;
use crate::events::room_version::RoomVersion;
use crate::events::sign::ServerSigningKey;
use crate::identifiers::{EventId, RoomId};

/// Strictly-increasing counter scoped to `m.room.create` events only.
/// v12 derives `room_id` from `hash(redacted create event)`, so two
/// parallel createRoom calls with identical content, identical sender,
/// and identical ms-resolution timestamps would collide on the same
/// room_id and cross-contaminate state. Bumping the create event's ts
/// by at least 1ms over the last create guarantees a unique reference
/// hash. Non-create events use plain wall-clock — MSC3030 jump-to-date
/// relies on event tses tracking real time, and a process-wide
/// monotonic counter pushes state-event tses ahead of the test
/// client's `time.Now()` even when wall-clock hasn't moved.
static LAST_CREATE_TS_MS: AtomicU64 = AtomicU64::new(0);

fn wall_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn monotonic_create_ts_ms() -> u64 {
    let now = wall_now_ms();
    let mut prev = LAST_CREATE_TS_MS.load(Ordering::Acquire);
    loop {
        let next = now.max(prev.saturating_add(1));
        match LAST_CREATE_TS_MS.compare_exchange(prev, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(actual) => prev = actual,
        }
    }
}

/// Build a complete, signed Matrix event.
///
/// Returns (event_json, event_id). The event_json includes hashes and signatures.
pub fn build_event(
    event_type: &str,
    state_key: Option<&str>,
    content: Value,
    sender: &str,
    room_id: Option<&RoomId>,
    prev_events: &[EventId],
    auth_events: &[EventId],
    depth: u64,
    signing_key: &ServerSigningKey,
    server_name: &str,
    _room_version: RoomVersion,
) -> (Map<String, Value>, EventId) {
    let is_create = event_type == "m.room.create";
    let now = if is_create {
        monotonic_create_ts_ms()
    } else {
        wall_now_ms()
    };

    let mut event = Map::new();
    event.insert("type".to_string(), json!(event_type));
    event.insert("sender".to_string(), json!(sender));
    event.insert("origin_server_ts".to_string(), json!(now));
    event.insert("content".to_string(), content);
    event.insert("depth".to_string(), json!(depth));

    if let Some(sk) = state_key {
        event.insert("state_key".to_string(), json!(sk));
    }

    // room_id: required on all events EXCEPT m.room.create in v12
    if let Some(rid) = room_id
        && !(is_create && _room_version.omit_room_id_from_create())
    {
        event.insert("room_id".to_string(), json!(rid.as_str()));
    }

    // prev_events and auth_events as string arrays
    let prev: Vec<Value> = prev_events.iter().map(|e| json!(e.as_str())).collect();
    let auth: Vec<Value> = auth_events.iter().map(|e| json!(e.as_str())).collect();
    event.insert("prev_events".to_string(), Value::Array(prev));
    event.insert("auth_events".to_string(), Value::Array(auth));

    // Step 1: compute content hash and add to hashes field
    // (content hash is version-independent — it's the full event
    // before redaction).
    add_content_hash(&mut event);

    // Step 2: sign the event under the room's redaction shape
    signing_key.sign_event_for_version(&mut event, server_name, _room_version);

    // Step 3: compute event_id from version-aware reference hash
    let event_id = crate::events::hash::compute_event_id_for_version(&event, _room_version);

    (event, event_id)
}

/// Sign a pre-built event template (e.g. the one returned by a remote
/// server's `make_join` response). The template already has all logical
/// fields populated (type, sender, state_key, content, prev_events,
/// auth_events, depth, origin_server_ts). We add:
///
/// 1. The content hash (`hashes.sha256`).
/// 2. Our signature under `signatures[server_name]`.
///
/// Returns the completed event + the computed `event_id`. The `room_version`
/// argument is the version returned by `make_join`/`make_knock`; sign + ref-hash
/// must match that or the receiving peer will reject the event.
pub fn sign_unsigned_template(
    mut template: Map<String, Value>,
    signing_key: &ServerSigningKey,
    server_name: &str,
    room_version: RoomVersion,
) -> (Map<String, Value>, EventId) {
    // Step 1: compute + insert content hash (version-independent).
    crate::events::hash::add_content_hash(&mut template);

    // Step 2: sign under the room's redaction shape.
    signing_key.sign_event_for_version(&mut template, server_name, room_version);

    // Step 3: compute event_id from version-aware reference hash.
    let event_id = crate::events::hash::compute_event_id_for_version(&template, room_version);

    (template, event_id)
}

/// Select auth_events for a new event based on current room state.
///
/// This is a pure function — it takes an explicit state map, NOT a database reference.
/// Sprint 1: populate from DB's current room_state.
/// Sprint 2 (federation): populate from incoming PDU's auth_events.
///
/// Per spec (server-server-api.md:528-554):
/// - m.room.create: auth_events = []
/// - All others (v12): power_levels + sender's member + (for m.room.member: target's member, join_rules)
/// - v12: m.room.create MUST NOT be included
pub fn select_auth_events(
    event_type: &str,
    sender: &str,
    state_key: Option<&str>,
    content: Option<&Value>,
    room_version: RoomVersion,
    current_state: &dyn Fn(&str, &str) -> Option<EventId>,
) -> Vec<EventId> {
    if event_type == "m.room.create" {
        return vec![];
    }

    let mut auth = Vec::new();

    // 1. m.room.create — NOT in v12
    if room_version.include_create_in_auth_events()
        && let Some(eid) = current_state("m.room.create", "")
    {
        auth.push(eid);
    }

    // 2. Current m.room.power_levels
    if let Some(eid) = current_state("m.room.power_levels", "") {
        auth.push(eid);
    }

    // 3. Sender's current m.room.member
    if let Some(eid) = current_state("m.room.member", sender) {
        auth.push(eid);
    }

    // 4. If type is m.room.member, additional events
    if event_type == "m.room.member" {
        let target = state_key.unwrap_or("");
        let membership = content
            .and_then(|c| c.get("membership"))
            .and_then(|m| m.as_str())
            .unwrap_or("");

        // Target's current m.room.member (if different from sender)
        if target != sender
            && let Some(eid) = current_state("m.room.member", target)
        {
            auth.push(eid);
        }

        // join_rules for join/invite/knock
        if matches!(membership, "join" | "invite" | "knock")
            && let Some(eid) = current_state("m.room.join_rules", "")
        {
            auth.push(eid);
        }

        // Per server-server spec auth_events selection: when a join carries
        // `join_authorised_via_users_server`, that user's current member
        // event MUST be in auth_events so the rule engine can verify the
        // authoriser is joined and powered to invite.
        if membership == "join"
            && let Some(authoriser) = content
                .and_then(|c| c.get("join_authorised_via_users_server"))
                .and_then(|v| v.as_str())
            && authoriser != sender
            && authoriser != target
            && let Some(eid) = current_state("m.room.member", authoriser)
        {
            auth.push(eid);
        }
    }

    auth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::room_version::RoomVersion;
    use std::collections::HashMap;

    #[test]
    fn create_event_has_empty_auth() {
        let state = HashMap::<(String, String), EventId>::new();
        let lookup = |t: &str, sk: &str| state.get(&(t.to_string(), sk.to_string())).cloned();

        let auth = select_auth_events(
            "m.room.create",
            "@alice:example.com",
            Some(""),
            None,
            RoomVersion::V12,
            &lookup,
        );
        assert!(auth.is_empty());
    }

    #[test]
    fn member_join_includes_power_levels_and_sender_member() {
        let mut state = HashMap::<(String, String), EventId>::new();
        let pl_eid = EventId::from_reference_hash("powerlevels");
        let member_eid = EventId::from_reference_hash("member");
        state.insert(("m.room.power_levels".into(), "".into()), pl_eid.clone());
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            member_eid.clone(),
        );

        let lookup = |t: &str, sk: &str| state.get(&(t.to_string(), sk.to_string())).cloned();

        let content = serde_json::json!({"membership": "join"});
        let auth = select_auth_events(
            "m.room.member",
            "@alice:example.com",
            Some("@alice:example.com"),
            Some(&content),
            RoomVersion::V12,
            &lookup,
        );

        // v12: no create, has power_levels and member, plus join_rules for join
        assert!(auth.contains(&pl_eid));
        assert!(auth.contains(&member_eid));
        // No m.room.create in v12
        assert!(!auth.iter().any(|e| e.as_str().contains("create")));
    }

    #[test]
    fn v12_no_create_in_auth() {
        let mut state = HashMap::<(String, String), EventId>::new();
        let create_eid = EventId::from_reference_hash("create");
        state.insert(("m.room.create".into(), "".into()), create_eid.clone());

        let lookup = |t: &str, sk: &str| state.get(&(t.to_string(), sk.to_string())).cloned();

        let auth = select_auth_events(
            "m.room.power_levels",
            "@alice:example.com",
            Some(""),
            None,
            RoomVersion::V12,
            &lookup,
        );

        // v12: create MUST NOT be in auth_events
        assert!(!auth.contains(&create_eid));
    }

    #[test]
    fn sign_unsigned_template_adds_hashes_signature_and_event_id() {
        // Simulates receiving a template from a remote server's make_join,
        // then signing it on our end for send_join submission.
        let key = ServerSigningKey::generate();

        let mut template = Map::new();
        template.insert("type".into(), json!("m.room.member"));
        template.insert("state_key".into(), json!("@us:our.example"));
        template.insert("sender".into(), json!("@us:our.example"));
        template.insert("room_id".into(), json!("!abc:remote.example"));
        template.insert("origin".into(), json!("our.example"));
        template.insert("origin_server_ts".into(), json!(1_700_000_000_000u64));
        template.insert("depth".into(), json!(10));
        template.insert("content".into(), json!({"membership": "join"}));
        template.insert("prev_events".into(), json!(["$prev"]));
        template.insert("auth_events".into(), json!(["$pl", "$cr"]));

        let (signed, event_id) =
            sign_unsigned_template(template, &key, "our.example", RoomVersion::V12);

        // Hashes + signatures added.
        assert!(signed.contains_key("hashes"));
        assert!(signed.contains_key("signatures"));
        let sig = signed["signatures"]["our.example"][key.key_id()]
            .as_str()
            .expect("signature is a string");
        assert!(!sig.is_empty());

        // Event ID is reference-hash-derived and stable.
        assert!(event_id.as_str().starts_with('$'));
    }

    /// Monotonic timestamp guard for `m.room.create`: even when called
    /// in rapid succession inside a single millisecond, every call must
    /// return a strictly greater value than the previous. v12 derives
    /// `room_id` from the hash of the redacted create event, which
    /// includes `origin_server_ts` — duplicates would collide rooms
    /// across parallel createRoom requests.
    #[test]
    fn monotonic_create_ts_ms_strictly_increases_under_rapid_calls() {
        let mut prev = 0u64;
        for _ in 0..10_000 {
            let now = monotonic_create_ts_ms();
            assert!(
                now > prev,
                "monotonic_create_ts_ms returned {now} after {prev}; must strictly increase"
            );
            prev = now;
        }
    }

    /// Two `m.room.create` events built back-to-back must hash
    /// differently — that's the property the v12 room_id collision
    /// fix relies on. Non-create events can share an `origin_server_ts`
    /// with their predecessor; their uniqueness comes from prev_events
    /// chaining in real flows, not from the timestamp counter.
    #[test]
    fn build_create_event_back_to_back_has_distinct_timestamps_and_ids() {
        let key = ServerSigningKey::generate();
        let mut prev_id: Option<EventId> = None;
        let mut prev_ts: Option<u64> = None;
        for _ in 0..50 {
            let (event, event_id) = build_event(
                "m.room.create",
                Some(""),
                json!({"creator": "@alice:example.com", "room_version": "12"}),
                "@alice:example.com",
                None,
                &[],
                &[],
                1,
                &key,
                "example.com",
                RoomVersion::V12,
            );
            let ts = event["origin_server_ts"].as_u64().unwrap();
            if let Some(p) = prev_ts {
                assert!(ts > p, "create ts not strictly increasing: {p} -> {ts}");
            }
            if let Some(p) = prev_id {
                assert_ne!(
                    p, event_id,
                    "back-to-back identical create events must hash differently"
                );
            }
            prev_ts = Some(ts);
            prev_id = Some(event_id);
        }
    }

    #[test]
    fn build_event_produces_valid_structure() {
        let key = ServerSigningKey::generate();
        let room_id = RoomId::parse("!test:example.com").unwrap();

        let (event, event_id) = build_event(
            "m.room.message",
            None,
            json!({"msgtype": "m.text", "body": "hello"}),
            "@alice:example.com",
            Some(&room_id),
            &[],
            &[],
            1,
            &key,
            "example.com",
            RoomVersion::V12,
        );

        assert!(event.contains_key("type"));
        assert!(event.contains_key("sender"));
        assert!(event.contains_key("origin_server_ts"));
        assert!(event.contains_key("content"));
        assert!(event.contains_key("depth"));
        assert!(event.contains_key("hashes"));
        assert!(event.contains_key("signatures"));
        assert!(event.contains_key("prev_events"));
        assert!(event.contains_key("auth_events"));
        assert!(event.contains_key("room_id"));
        assert!(event_id.as_str().starts_with('$'));
    }
}
