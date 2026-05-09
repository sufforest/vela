//! Per-room-version event redaction, faithful to gomatrixserverlib's
//! `redactEventJSONV1`..`V5` mapping. See:
//!   github.com/matrix-org/gomatrixserverlib/blob/HEAD/redactevent.go
//!   github.com/matrix-org/gomatrixserverlib/blob/HEAD/eventversion.go
//!
//! That library is the canonical signing/verification implementation
//! used by Complement's federation mock and by Dendrite. Cross-checked
//! against synapse/synapse/events/utils.py::prune_event_dict for
//! agreement on every branch we cover (v6-v12).
//!
//! The rules differ across two axes — top-level allowed fields and
//! per-event-type content fields — and the boundaries don't always
//! line up neatly with version numbers. The table below summarises
//! what we keep:
//!
//! ```text
//! version | top-level extras            | PL invite | create content | member content                | join_rules | redaction
//! --------|-----------------------------|-----------|----------------|-------------------------------|------------|----------
//! v6, v7  | prev_state, origin, member  | strip     | creator only   | membership                    | join_rule  | strip
//! v8      | prev_state, origin, member  | strip     | creator only   | membership                    | + allow    | strip
//! v9, v10 | prev_state, origin, member  | strip     | creator only   | + join_authorised_via_users   | + allow    | strip
//! v11, v12| (none)                      | keep      | all content    | + tpinvite.signed             | + allow    | keep redacts
//! ```
//!
//! Mismatching the sender's redaction shape produces canonical bytes
//! that disagree with the signature; every federated event then fails
//! to verify. This module is the single load-bearing point for
//! getting it right.

use serde_json::{Map, Value};

use crate::events::room_version::RoomVersion;

/// Top-level fields preserved for v6-v10. v11+ uses the shorter
/// `PRESERVED_TOP_LEVEL_V11_PLUS` list.
const PRESERVED_TOP_LEVEL_PRE_V11: &[&str] = &[
    "type",
    "room_id",
    "sender",
    "state_key",
    "content",
    "hashes",
    "signatures",
    "depth",
    "prev_events",
    "prev_state",
    "auth_events",
    "origin",
    "origin_server_ts",
    "membership",
];

/// Top-level fields preserved for v11+. MSC4288 dropped `prev_state`,
/// `origin`, and `membership` — vela's hash/sign pipeline operates on
/// v12 events which never set those fields, so the trimmer list is
/// sufficient when receiving from v11+ peers too.
const PRESERVED_TOP_LEVEL_V11_PLUS: &[&str] = &[
    "type",
    "room_id",
    "sender",
    "state_key",
    "content",
    "hashes",
    "signatures",
    "depth",
    "prev_events",
    "auth_events",
    "origin_server_ts",
];

fn top_level_preserved(version: RoomVersion) -> &'static [&'static str] {
    if version.at_least(RoomVersion::V11) {
        PRESERVED_TOP_LEVEL_V11_PLUS
    } else {
        PRESERVED_TOP_LEVEL_PRE_V11
    }
}

/// Redact an event for the supplied room version, producing the
/// canonical-bytes input that signatures are computed over. Mismatched
/// version is a sig-verify regression — pre-v11 events stripped under
/// v11+ rules disagree with the sender's bytes by `prev_state`,
/// `origin`, `membership`, plus `m.room.power_levels.invite` and
/// `m.room.create` content shape.
pub fn redact_event_for_version(
    event: &Map<String, Value>,
    version: RoomVersion,
) -> Map<String, Value> {
    let mut redacted = Map::new();

    for &key in top_level_preserved(version) {
        if let Some(v) = event.get(key) {
            redacted.insert(key.to_string(), v.clone());
        }
    }

    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let stripped_content = strip_content(event_type, event.get("content"), version);
    redacted.insert("content".to_string(), Value::Object(stripped_content));

    redacted
}

/// Backward-compat wrapper. Defaults to v12 redaction shape — used by
/// vela's hash/sign pipeline (which only ever operates on v12 events
/// it locally minted) and by tests. Federation paths threaded a
/// `RoomVersion` and call `redact_event_for_version` directly.
pub fn redact_event(event: &Map<String, Value>) -> Map<String, Value> {
    redact_event_for_version(event, RoomVersion::V12)
}

fn strip_content(
    event_type: &str,
    content: Option<&Value>,
    version: RoomVersion,
) -> Map<String, Value> {
    let content = match content.and_then(|v| v.as_object()) {
        Some(c) => c,
        None => return Map::new(),
    };

    match event_type {
        "m.room.create" => {
            // v11+ keeps the entire content (room_version,
            // additional_creators, predecessor, etc.). Pre-v11 keeps
            // only `creator`.
            if version.at_least(RoomVersion::V11) {
                content.clone()
            } else {
                keep_keys(content, &["creator"])
            }
        }
        "m.room.member" => {
            let mut keep: Vec<&str> = vec!["membership"];
            // v9 (gomatrixserverlib's V4 content rules) added
            // `join_authorised_via_users_server` for restricted joins.
            if version.at_least(RoomVersion::V9) {
                keep.push("join_authorised_via_users_server");
            }
            let mut result = keep_keys(content, &keep);
            // v11+ additionally preserves `third_party_invite.signed`.
            if version.at_least(RoomVersion::V11)
                && let Some(tpi) = content.get("third_party_invite")
                && let Some(signed) = tpi.get("signed")
            {
                let mut tpi_obj = Map::new();
                tpi_obj.insert("signed".to_string(), signed.clone());
                result.insert("third_party_invite".to_string(), Value::Object(tpi_obj));
            }
            result
        }
        "m.room.join_rules" => {
            if version.at_least(RoomVersion::V8) {
                keep_keys(content, &["join_rule", "allow"])
            } else {
                keep_keys(content, &["join_rule"])
            }
        }
        "m.room.power_levels" => {
            // v11+ keeps `invite`; v6-v10 strips it. Neither keeps
            // `notifications` — the field was never in the signed
            // canonical form on any vela-supported version.
            let mut keep: Vec<&str> = vec![
                "ban",
                "events",
                "events_default",
                "kick",
                "redact",
                "state_default",
                "users",
                "users_default",
            ];
            if version.at_least(RoomVersion::V11) {
                keep.push("invite");
            }
            keep_keys(content, &keep)
        }
        "m.room.history_visibility" => keep_keys(content, &["history_visibility"]),
        "m.room.redaction" => {
            // v11+ began preserving `redacts` in content; pre-v11
            // strips content entirely.
            if version.at_least(RoomVersion::V11) {
                keep_keys(content, &["redacts"])
            } else {
                Map::new()
            }
        }
        _ => Map::new(),
    }
}

fn keep_keys(content: &Map<String, Value>, keys: &[&str]) -> Map<String, Value> {
    let mut result = Map::new();
    for &key in keys {
        if let Some(v) = content.get(key) {
            result.insert(key.to_string(), v.clone());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_event(event_type: &str, content: Value) -> Map<String, Value> {
        let v = json!({
            "type": event_type,
            "sender": "@alice:example.com",
            "room_id": "!abc:example.com",
            "event_id": "$xyz",
            "origin_server_ts": 1234567890,
            "depth": 1,
            "content": content,
        });
        v.as_object().unwrap().clone()
    }

    #[test]
    fn redact_drops_event_id_top_level() {
        let event = make_event("m.room.message", json!({"body": "hi"}));
        let redacted = redact_event(&event);
        assert!(!redacted.contains_key("event_id"));
    }

    #[test]
    fn redact_message_clears_content() {
        let event = make_event("m.room.message", json!({"body": "hi"}));
        let redacted = redact_event(&event);
        assert!(
            redacted
                .get("content")
                .unwrap()
                .as_object()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn redact_create_keeps_all_content() {
        let event = make_event(
            "m.room.create",
            json!({"creator": "@a:b", "room_version": "12", "extra": "x"}),
        );
        let redacted = redact_event(&event);
        let content = redacted.get("content").unwrap().as_object().unwrap();
        assert_eq!(content.get("creator").unwrap(), "@a:b");
        assert_eq!(content.get("extra").unwrap(), "x");
    }

    #[test]
    fn redact_power_levels_keeps_invite() {
        let event = make_event(
            "m.room.power_levels",
            json!({
                "ban": 50, "invite": 0, "kick": 50, "redact": 50,
                "events": {}, "users": {}, "users_default": 0,
                "events_default": 0, "state_default": 50,
            }),
        );
        let redacted = redact_event(&event);
        let content = redacted.get("content").unwrap().as_object().unwrap();
        assert_eq!(content.get("invite").unwrap(), 0);
    }
}
