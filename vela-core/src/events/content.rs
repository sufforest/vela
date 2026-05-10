//! Typed content builders for Matrix event types.

use serde_json::{Value, json};

use crate::events::room_version::RoomVersion;

pub fn create_content(room_version: RoomVersion) -> Value {
    json!({
        "room_version": room_version.as_str()
    })
}

pub fn member_content_join(displayname: Option<&str>, avatar_url: Option<&str>) -> Value {
    let mut content = json!({"membership": "join"});
    let obj = content.as_object_mut().unwrap();
    if let Some(name) = displayname {
        obj.insert("displayname".to_string(), Value::String(name.to_string()));
    }
    if let Some(avatar) = avatar_url {
        obj.insert("avatar_url".to_string(), Value::String(avatar.to_string()));
    }
    content
}

pub fn member_content_invite() -> Value {
    json!({"membership": "invite"})
}

pub fn member_content_leave() -> Value {
    json!({"membership": "leave"})
}

pub fn member_content_knock(reason: Option<&str>) -> Value {
    let mut content = json!({"membership": "knock"});
    if let Some(r) = reason
        && !r.is_empty()
    {
        content
            .as_object_mut()
            .unwrap()
            .insert("reason".to_string(), Value::String(r.to_string()));
    }
    content
}

pub fn power_levels_content(room_version: RoomVersion) -> Value {
    // Default power levels per spec.
    // In v12: creator has infinite power and MUST NOT be in users.
    // Tombstone must be >= 150 (higher than state_default).
    // Spec default for `invite` in m.room.power_levels is 0, but the value
    // synapse stamps at room-create time is 50, and Complement's
    // restricted-rooms tests assume that baseline (e.g. "alice cannot
    // invite due to the default power levels"). Match synapse's
    // createRoom default so a fresh room behaves the same way other
    // homeservers produce it.
    let mut content = json!({
        "ban": 50,
        "events": {
            "m.room.name": 50,
            "m.room.power_levels": 100,
            "m.room.history_visibility": 100,
            "m.room.canonical_alias": 50,
            "m.room.avatar": 50,
            "m.room.encryption": 100,
            "m.room.server_acl": 100
        },
        "events_default": 0,
        "invite": 50,
        "kick": 50,
        "redact": 50,
        "state_default": 50,
        "users": {},
        "users_default": 0
    });

    if room_version.creators_have_infinite_power() {
        content["events"]["m.room.tombstone"] = json!(150);
    }

    content
}

pub fn join_rules_content(join_rule: &str) -> Value {
    json!({"join_rule": join_rule})
}

pub fn history_visibility_content(visibility: &str) -> Value {
    json!({"history_visibility": visibility})
}

pub fn guest_access_content(access: &str) -> Value {
    json!({"guest_access": access})
}

pub fn name_content(name: &str) -> Value {
    json!({"name": name})
}

/// Build `m.room.topic` content. Includes both the legacy `topic` string
/// and the structured `m.topic` rich-text representation (MSC3765).
/// Mimetype is omitted; clients default to `text/plain`.
pub fn topic_content(topic: &str) -> Value {
    json!({
        "topic": topic,
        "m.topic": {
            "m.text": [{"body": topic}]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_content_includes_legacy_and_rich_representation() {
        let c = topic_content("Test Room");
        assert_eq!(c["topic"], "Test Room");
        let text = c["m.topic"]["m.text"].as_array().expect("m.text array");
        assert_eq!(text.len(), 1);
        assert_eq!(text[0]["body"], "Test Room");
        // Mimetype intentionally absent — default is text/plain.
        assert!(text[0].get("mimetype").is_none());
    }
}
