//! Per-spec event size limits ("Size limits" in the client-server and
//! server-server APIs). These bound an event's canonical encoding and a few
//! individual fields. Conforming servers reject events that exceed them, so we
//! must too — otherwise vela accepts an event into the room DAG that peers drop
//! and the room state diverges.

use serde_json::{Map, Value};

/// Maximum size of a single event's canonical JSON encoding.
pub const MAX_EVENT_BYTES: usize = 65_536;

/// Maximum size (bytes) of the `sender`, `type`, `state_key`, `room_id`, and
/// `event_id` fields. The spec caps each at 255 bytes.
pub const MAX_FIELD_BYTES: usize = 255;

/// Validate an inbound event object against the spec size limits. Returns the
/// reason string on the first violation, or `Ok(())` when within limits.
///
/// `event_id` is passed separately because in modern room versions it is
/// derived (not a field on `obj`); pass `""` to skip its check.
pub fn check_inbound_event_limits(obj: &Map<String, Value>, event_id: &str) -> Result<(), String> {
    let size = crate::canonical::canonical_json_object(obj).len();
    if size > MAX_EVENT_BYTES {
        return Err(format!(
            "event canonical JSON is {size} bytes, exceeds {MAX_EVENT_BYTES} limit"
        ));
    }
    if event_id.len() > MAX_FIELD_BYTES {
        return Err(format!("event_id exceeds {MAX_FIELD_BYTES} bytes"));
    }
    for field in ["sender", "type", "state_key", "room_id"] {
        if let Some(s) = obj.get(field).and_then(|v| v.as_str())
            && s.len() > MAX_FIELD_BYTES
        {
            return Err(format!("`{field}` exceeds {MAX_FIELD_BYTES} bytes"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn accepts_normal_event() {
        let e = obj(json!({
            "type": "m.room.message",
            "sender": "@a:b.com",
            "room_id": "!r:b.com",
            "content": {"body": "hi"},
        }));
        assert!(check_inbound_event_limits(&e, "$abc").is_ok());
    }

    #[test]
    fn rejects_oversized_canonical() {
        let big = "x".repeat(70_000);
        let e = obj(json!({
            "type": "m.room.message",
            "sender": "@a:b.com",
            "content": {"body": big},
        }));
        assert!(check_inbound_event_limits(&e, "$abc").is_err());
    }

    #[test]
    fn rejects_oversized_field() {
        let long_type = "m.".to_string() + &"a".repeat(300);
        let e = obj(json!({
            "type": long_type,
            "sender": "@a:b.com",
            "content": {},
        }));
        assert!(check_inbound_event_limits(&e, "$abc").is_err());
    }

    #[test]
    fn rejects_oversized_event_id() {
        let e = obj(json!({"type": "m.room.message", "sender": "@a:b.com", "content": {}}));
        let long_id = "$".to_string() + &"a".repeat(300);
        assert!(check_inbound_event_limits(&e, &long_id).is_err());
    }

    #[test]
    fn empty_event_id_skips_id_check() {
        let e = obj(json!({"type": "m.room.message", "sender": "@a:b.com", "content": {}}));
        assert!(check_inbound_event_limits(&e, "").is_ok());
    }
}
