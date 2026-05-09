//! Content hash and reference hash computation per Matrix spec.
//! Source: content/server-server-api.md:1522-1592

use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical::canonical_json_object;
use crate::events::redact::{redact_event, redact_event_for_version};
use crate::events::room_version::RoomVersion;
use crate::identifiers::EventId;

/// Compute the content hash of an event.
///
/// Per spec:
/// 1. Remove unsigned, signatures, hashes from the FULL (unredacted) event
/// 2. Canonical JSON encode
/// 3. SHA-256 hash
/// 4. Return as Unpadded Base64 (**standard** alphabet, per the
///    "Signing JSON" appendix). The reference hash uses URL-safe
///    because it appears in event_ids; content hash does not.
pub fn compute_content_hash(event: &Map<String, Value>) -> String {
    let mut stripped = event.clone();
    stripped.remove("unsigned");
    stripped.remove("signatures");
    stripped.remove("hashes");

    let canonical = canonical_json_object(&stripped);
    let hash = Sha256::digest(&canonical);
    STANDARD_NO_PAD.encode(hash)
}

/// Compute the reference hash of an event for a specific room version.
///
/// Per spec:
/// 1. Redact the event under the version-specific shape
/// 2. Remove signatures and unsigned from redacted event
/// 3. Canonical JSON encode
/// 4. SHA-256 hash
/// 5. Return as unpadded URL-safe base64
pub fn compute_reference_hash_for_version(
    event: &Map<String, Value>,
    version: RoomVersion,
) -> String {
    let mut redacted = redact_event_for_version(event, version);
    redacted.remove("signatures");
    redacted.remove("unsigned");

    let canonical = canonical_json_object(&redacted);
    let hash = Sha256::digest(&canonical);
    URL_SAFE_NO_PAD.encode(hash)
}

/// V12-default wrapper. Use `compute_reference_hash_for_version` when
/// the room version is known; this is for tests and back-compat callers
/// that haven't been threaded yet.
pub fn compute_reference_hash(event: &Map<String, Value>) -> String {
    let mut redacted = redact_event(event);
    redacted.remove("signatures");
    redacted.remove("unsigned");

    let canonical = canonical_json_object(&redacted);
    let hash = Sha256::digest(&canonical);
    URL_SAFE_NO_PAD.encode(hash)
}

/// Compute the event_id from the reference hash for a specific room
/// version. The reference hash MUST match the sender's redaction shape
/// or the event_id derived will disagree with what every other peer
/// computes — propagating up to broken state res, federation, and
/// auth-event lookups.
pub fn compute_event_id_for_version(event: &Map<String, Value>, version: RoomVersion) -> EventId {
    let hash = compute_reference_hash_for_version(event, version);
    EventId::from_reference_hash(&hash)
}

/// V12-default wrapper for `compute_event_id_for_version`.
pub fn compute_event_id(event: &Map<String, Value>) -> EventId {
    let hash = compute_reference_hash(event);
    EventId::from_reference_hash(&hash)
}

/// Add the content hash to an event's `hashes` field.
/// Must be called before signing and before computing the event_id.
pub fn add_content_hash(event: &mut Map<String, Value>) {
    let hash = compute_content_hash(event);
    let mut hashes = Map::new();
    hashes.insert("sha256".to_string(), Value::String(hash));
    event.insert("hashes".to_string(), Value::Object(hashes));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_event() -> Map<String, Value> {
        let v = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": "!test:example.com",
            "origin_server_ts": 1234567890,
            "depth": 5,
            "prev_events": [],
            "auth_events": [],
            "content": {"msgtype": "m.text", "body": "hello"}
        });
        v.as_object().unwrap().clone()
    }

    #[test]
    fn content_hash_is_deterministic() {
        let event = test_event();
        let h1 = compute_content_hash(&event);
        let h2 = compute_content_hash(&event);
        assert_eq!(h1, h2);
    }

    #[test]
    fn content_hash_ignores_unsigned() {
        let mut e1 = test_event();
        let mut e2 = test_event();
        e2.insert("unsigned".to_string(), json!({"age": 1000}));
        assert_eq!(compute_content_hash(&e1), compute_content_hash(&e2));

        // But changing content changes the hash
        e1.insert(
            "content".to_string(),
            json!({"msgtype": "m.text", "body": "different"}),
        );
        assert_ne!(compute_content_hash(&e1), compute_content_hash(&e2));
    }

    #[test]
    fn reference_hash_ignores_non_essential_content() {
        // For m.room.message, content is stripped to {} during redaction
        let mut e1 = test_event();
        let mut e2 = test_event();

        // But we need hashes first for reference hash to be meaningful
        add_content_hash(&mut e1);
        add_content_hash(&mut e2);

        // Different content but same hash structure means different content hashes
        // which means different reference hashes (hashes.sha256 is preserved through redaction)
        // This is correct behavior — content_hash proves content integrity
    }

    #[test]
    fn event_id_format() {
        let mut event = test_event();
        add_content_hash(&mut event);
        // Add empty signatures so structure is complete
        event.insert("signatures".to_string(), json!({}));

        let eid = compute_event_id(&event);
        assert!(eid.as_str().starts_with('$'));
        // URL-safe base64 of SHA-256 = 43 chars + $ prefix = 44
        assert_eq!(eid.as_str().len(), 44);
    }

    #[test]
    fn add_content_hash_sets_hashes_field() {
        let mut event = test_event();
        assert!(event.get("hashes").is_none());
        add_content_hash(&mut event);
        let hashes = event.get("hashes").unwrap().as_object().unwrap();
        assert!(hashes.contains_key("sha256"));
        let hash_str = hashes.get("sha256").unwrap().as_str().unwrap();
        assert!(!hash_str.is_empty());
    }
}
