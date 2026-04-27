//! Redaction algorithm for room v11/v12.
//! Source: content/rooms/fragments/v11-redactions.md

use serde_json::{Map, Value};

/// Top-level fields preserved after redaction.
///
/// Per spec: room v3+ removed `event_id` from this list because event_ids
/// are derived from the reference hash, not stored. Including it here
/// would let an injected `event_id` field corrupt the canonical bytes
/// used for both signature verification and the reference-hash-based
/// event_id itself — every PDU received over federation would fail to
/// verify the moment the sender's transport added event_id back.
const PRESERVED_TOP_LEVEL: &[&str] = &[
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

/// Redact an event per the v11/v12 algorithm.
/// Returns a new JSON object with only preserved fields and
/// content stripped according to the event type.
pub fn redact_event(event: &Map<String, Value>) -> Map<String, Value> {
    let mut redacted = Map::new();

    // Keep only preserved top-level fields
    for &key in PRESERVED_TOP_LEVEL {
        if let Some(v) = event.get(key) {
            redacted.insert(key.to_string(), v.clone());
        }
    }

    // Strip content based on event type
    let event_type = event.get("type").and_then(|v| v.as_str()).unwrap_or("");

    let stripped_content = strip_content(event_type, event.get("content"));
    redacted.insert("content".to_string(), Value::Object(stripped_content));

    redacted
}

fn strip_content(event_type: &str, content: Option<&Value>) -> Map<String, Value> {
    let content = match content.and_then(|v| v.as_object()) {
        Some(c) => c,
        None => return Map::new(),
    };

    match event_type {
        "m.room.create" => {
            // All keys preserved
            content.clone()
        }
        "m.room.member" => {
            let mut result =
                keep_keys(content, &["membership", "join_authorised_via_users_server"]);
            // Preserve third_party_invite.signed per spec
            if let Some(tpi) = content.get("third_party_invite")
                && let Some(signed) = tpi.get("signed")
            {
                let mut tpi_obj = Map::new();
                tpi_obj.insert("signed".to_string(), signed.clone());
                result.insert("third_party_invite".to_string(), Value::Object(tpi_obj));
            }
            result
        }
        "m.room.join_rules" => keep_keys(content, &["join_rule", "allow"]),
        "m.room.power_levels" => keep_keys(
            content,
            &[
                "ban",
                "events",
                "events_default",
                "invite",
                "kick",
                "redact",
                "state_default",
                "users",
                "users_default",
            ],
        ),
        "m.room.history_visibility" => keep_keys(content, &["history_visibility"]),
        "m.room.redaction" => keep_keys(content, &["redacts"]),
        _ => {
            // All other event types: content cleared to {}
            Map::new()
        }
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
            "prev_events": [],
            "auth_events": [],
            "hashes": {"sha256": "test"},
            "signatures": {},
            "content": content,
            "unsigned": {"age": 100},
            "extra_field": "should be stripped"
        });
        v.as_object().unwrap().clone()
    }

    #[test]
    fn redact_message_clears_content() {
        let event = make_event(
            "m.room.message",
            json!({"msgtype": "m.text", "body": "hello"}),
        );
        let redacted = redact_event(&event);
        assert_eq!(redacted.get("content").unwrap(), &json!({}));
        assert!(redacted.get("unsigned").is_none());
        assert!(redacted.get("extra_field").is_none());
    }

    #[test]
    fn redact_create_preserves_all_content() {
        let event = make_event(
            "m.room.create",
            json!({"room_version": "12", "custom": "value"}),
        );
        let redacted = redact_event(&event);
        let content = redacted.get("content").unwrap().as_object().unwrap();
        assert_eq!(content.get("room_version").unwrap(), "12");
        assert_eq!(content.get("custom").unwrap(), "value");
    }

    #[test]
    fn redact_member_keeps_membership() {
        let event = make_event(
            "m.room.member",
            json!({"membership": "join", "displayname": "Alice", "avatar_url": "mxc://..."}),
        );
        let redacted = redact_event(&event);
        let content = redacted.get("content").unwrap().as_object().unwrap();
        assert_eq!(content.get("membership").unwrap(), "join");
        assert!(content.get("displayname").is_none());
        assert!(content.get("avatar_url").is_none());
    }

    #[test]
    fn redact_power_levels_keeps_correct_keys() {
        let event = make_event(
            "m.room.power_levels",
            json!({
                "ban": 50, "kick": 50, "invite": 0,
                "events": {}, "users": {}, "users_default": 0,
                "events_default": 0, "state_default": 50,
                "redact": 50, "custom_key": "stripped"
            }),
        );
        let redacted = redact_event(&event);
        let content = redacted.get("content").unwrap().as_object().unwrap();
        assert!(content.contains_key("ban"));
        assert!(content.contains_key("users"));
        assert!(!content.contains_key("custom_key"));
    }

    #[test]
    fn redact_strips_unsigned() {
        let event = make_event("m.room.message", json!({"body": "test"}));
        let redacted = redact_event(&event);
        assert!(redacted.get("unsigned").is_none());
    }

    #[test]
    fn redact_preserves_required_top_level() {
        let event = make_event("m.room.message", json!({}));
        let redacted = redact_event(&event);
        assert!(redacted.contains_key("type"));
        assert!(redacted.contains_key("sender"));
        assert!(redacted.contains_key("origin_server_ts"));
        assert!(redacted.contains_key("depth"));
        assert!(redacted.contains_key("prev_events"));
        assert!(redacted.contains_key("auth_events"));
        assert!(redacted.contains_key("hashes"));
        assert!(redacted.contains_key("signatures"));
    }
}
