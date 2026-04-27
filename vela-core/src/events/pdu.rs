//! Parsed event data shared by authorization rules and state resolution.
//!
//! The `Pdu` struct is a lightweight, memory-efficient representation
//! of a Matrix event with only the fields required for auth/state-res.

use serde_json::{Map, Value};

/// A parsed Matrix event suitable for auth rules and state resolution.
///
/// This is a materialised view — callers populate it from stored event
/// JSON or incoming federation PDUs. Fields not used by auth/state-res
/// (e.g. hashes, full signatures) are intentionally omitted.
#[derive(Debug, Clone)]
pub struct Pdu {
    pub event_id: String,
    pub room_id: String,
    pub event_type: String,
    /// None for non-state (message) events, Some(_) for state events (may be "")
    pub state_key: Option<String>,
    pub sender: String,
    pub origin_server_ts: u64,
    pub content: Value,
    /// event_id strings referenced by auth_events
    pub auth_events: Vec<String>,
    /// event_id strings referenced by prev_events
    pub prev_events: Vec<String>,
    pub depth: u64,
    /// Pre-redaction signatures block — kept for signature verification.
    /// Auth rules may need to check signed third-party invites.
    pub signatures: Option<Value>,
}

impl Pdu {
    /// Parse a PDU from a JSON object. Returns None on malformed events.
    ///
    /// This is tolerant: fields defined in the spec but not required by
    /// auth/state-res are ignored, and missing optional fields yield
    /// reasonable defaults.
    pub fn from_json(event_id: String, json: &Map<String, Value>) -> Option<Self> {
        let event_type = json.get("type")?.as_str()?.to_string();
        let sender = json.get("sender")?.as_str()?.to_string();
        let origin_server_ts = json.get("origin_server_ts")?.as_u64()?;
        let content = json.get("content").cloned().unwrap_or(Value::Null);
        let depth = json.get("depth").and_then(|v| v.as_u64()).unwrap_or(0);

        // state_key is optional — only set for state events
        let state_key = json
            .get("state_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // auth_events and prev_events: arrays of event_id strings (v3+)
        // or [event_id, hash] tuples (v1/v2). We only support v3+ format (strings).
        let auth_events = json
            .get("auth_events")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        let prev_events = json
            .get("prev_events")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // room_id is absent from m.room.create in v12, present on all others.
        // We allow empty for create events — callers that need it enforce presence.
        let room_id = json
            .get("room_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let signatures = json.get("signatures").cloned();

        Some(Pdu {
            event_id,
            room_id,
            event_type,
            state_key,
            sender,
            origin_server_ts,
            content,
            auth_events,
            prev_events,
            depth,
            signatures,
        })
    }

    /// True if this is a state event (has a state_key).
    pub fn is_state(&self) -> bool {
        self.state_key.is_some()
    }

    /// Return the (type, state_key) tuple for state events.
    pub fn state_tuple(&self) -> Option<(&str, &str)> {
        self.state_key
            .as_deref()
            .map(|sk| (self.event_type.as_str(), sk))
    }

    /// Shortcut for a string-valued `content.<key>` field. Centralises the
    /// ubiquitous `pdu.content.get("x").and_then(|v| v.as_str())` pattern
    /// so callers read at domain level (`pdu.content_str("membership")`)
    /// rather than at JSON-traversal level.
    pub fn content_str(&self, key: &str) -> Option<&str> {
        self.content.get(key).and_then(|v| v.as_str())
    }

    /// `content.membership` — the most-accessed content field across
    /// auth rules, push rules, and membership handlers.
    pub fn membership(&self) -> Option<&str> {
        self.content_str("membership")
    }

    /// `content.body` — message body for m.room.message events. Used
    /// by push rules (display-name mention) and search.
    pub fn body(&self) -> Option<&str> {
        self.content_str("body")
    }

    /// `content.join_rule` — the join policy for m.room.join_rules
    /// events. Present alongside `allow` for restricted rooms.
    pub fn join_rule(&self) -> Option<&str> {
        self.content_str("join_rule")
    }

    /// Extract the server (domain part) from the sender user ID.
    /// Example: "@alice:example.com" → "example.com"
    pub fn sender_domain(&self) -> Option<&str> {
        self.sender.split_once(':').map(|(_, domain)| domain)
    }
}
