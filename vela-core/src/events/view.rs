//! Small extension trait that collapses the most common event-field
//! access patterns into named methods.
//!
//! Every module that reads Matrix event JSON hit the same shape
//! dozens of times:
//!
//! ```ignore
//! ev.get("content")
//!     .and_then(|c| c.get("membership"))
//!     .and_then(|v| v.as_str())
//! ```
//!
//! That's readable once, noisy when it repeats 20 times in one file,
//! and easy to mistype (`"memebership"`). The methods below name those
//! accesses once. Zero allocation, zero runtime cost — they're thin
//! wrappers over `serde_json::Value` traversal.
//!
//! The trait is intentionally small. New accessors land here when the
//! same path is used in two or more modules. If it's used in one
//! place, keep it local.

use serde_json::{Map, Value};

/// Accessors for Matrix event JSON. Implemented for `Value` so any
/// event-shaped `Value` gets the methods for free.
///
/// Conventions:
/// - `*_str()` returns `Option<&str>` — present and stringly-valued, else None.
/// - `content_str(key)` dives into `content.<key>` with the same semantics.
/// - `content()` returns the `content` sub-object as a `Value` reference.
pub trait EventView {
    fn event_type(&self) -> Option<&str>;
    fn sender(&self) -> Option<&str>;
    fn state_key(&self) -> Option<&str>;
    fn room_id(&self) -> Option<&str>;
    fn content(&self) -> Option<&Value>;
    fn content_str(&self, key: &str) -> Option<&str>;

    /// Convenience: `content.membership`. Used by auth rules and push
    /// rules, which check membership transitions constantly.
    fn membership(&self) -> Option<&str> {
        self.content_str("membership")
    }

    /// Convenience: `content.join_rule`. Used by join / knock /
    /// restricted-room logic.
    fn join_rule(&self) -> Option<&str> {
        self.content_str("join_rule")
    }

    /// Convenience: `content.body` on m.room.message. Used by
    /// search / push-rule display-name matching.
    fn body(&self) -> Option<&str> {
        self.content_str("body")
    }
}

impl EventView for Value {
    fn event_type(&self) -> Option<&str> {
        self.get("type").and_then(|v| v.as_str())
    }

    fn sender(&self) -> Option<&str> {
        self.get("sender").and_then(|v| v.as_str())
    }

    fn state_key(&self) -> Option<&str> {
        self.get("state_key").and_then(|v| v.as_str())
    }

    fn room_id(&self) -> Option<&str> {
        self.get("room_id").and_then(|v| v.as_str())
    }

    fn content(&self) -> Option<&Value> {
        self.get("content")
    }

    fn content_str(&self, key: &str) -> Option<&str> {
        self.get("content")
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_str())
    }
}

/// Parallel impl for `Map<String, Value>` — common when receiving
/// federation event bodies decoded as objects directly.
impl EventView for Map<String, Value> {
    fn event_type(&self) -> Option<&str> {
        self.get("type").and_then(|v| v.as_str())
    }

    fn sender(&self) -> Option<&str> {
        self.get("sender").and_then(|v| v.as_str())
    }

    fn state_key(&self) -> Option<&str> {
        self.get("state_key").and_then(|v| v.as_str())
    }

    fn room_id(&self) -> Option<&str> {
        self.get("room_id").and_then(|v| v.as_str())
    }

    fn content(&self) -> Option<&Value> {
        self.get("content")
    }

    fn content_str(&self, key: &str) -> Option<&str> {
        self.get("content")
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_top_level_fields() {
        let ev = json!({
            "type": "m.room.member",
            "sender": "@alice:example.com",
            "state_key": "@bob:example.com",
            "room_id": "!room:example.com",
            "content": {"membership": "invite", "reason": "come join"},
        });
        assert_eq!(ev.event_type(), Some("m.room.member"));
        assert_eq!(ev.sender(), Some("@alice:example.com"));
        assert_eq!(ev.state_key(), Some("@bob:example.com"));
        assert_eq!(ev.room_id(), Some("!room:example.com"));
        assert_eq!(ev.membership(), Some("invite"));
        assert_eq!(ev.content_str("reason"), Some("come join"));
    }

    #[test]
    fn missing_fields_return_none() {
        let ev = json!({"type": "m.room.message"});
        assert_eq!(ev.sender(), None);
        assert_eq!(ev.membership(), None);
        assert_eq!(ev.body(), None);
    }

    #[test]
    fn non_string_field_returns_none() {
        // content.body is int, not str → caller gets None, not a panic.
        let ev = json!({"content": {"body": 42}});
        assert_eq!(ev.body(), None);
    }
}
