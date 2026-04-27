//! Push-rule evaluation engine.
//!
//! Spec: `client-server-api/#push-rules`.
//!
//! A user's rule set has five kinds processed in strict priority order:
//!   override → content → room → sender → underride
//!
//! The first enabled rule whose conditions match an event decides the
//! `actions`. Common actions are `notify`, `dont_notify`, and
//! `{"set_tweak": key, "value": v}` for `sound` and `highlight`.
//!
//! We implement the subset needed for real Element usage: per-room mute
//! (`room` kind), keyword highlights (`content` kind with pattern), and
//! the server-defined defaults (suppress notices/reactions, notify on
//! mentions, notify on regular messages). Fancier conditions like
//! `event_property_is` / `event_property_contains` are scaffolded but
//! only cover `content.msgtype` for now since that's what the default
//! rules actually test.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::events::view::EventView;

/// Result of evaluating the rule set against a single event for a single
/// recipient. `notify` determines whether to dispatch push; `tweaks` are
/// the resolved `{key: value}` pairs from `set_tweak` actions (e.g.
/// `sound -> "default"`, `highlight -> true`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PushAction {
    pub notify: bool,
    pub tweaks: HashMap<String, Value>,
}

/// Minimal view of room state the evaluator needs. The evaluator never
/// calls back for state it doesn't have; callers should pre-compute.
#[derive(Debug, Clone, Default)]
pub struct RoomContext {
    /// Current count of joined members; drives `room_member_count` conditions.
    pub joined_member_count: u64,
    /// The recipient's display name, if set. Used for the deprecated
    /// `contains_display_name` condition.
    pub recipient_display_name: Option<String>,
    /// The recipient's Matrix user id (`@alice:example.com`). Used for
    /// user-mention / user-name conditions.
    pub recipient_user_id: String,
}

/// Evaluate `rules` (a `{override: [...], content: [...], room: [...], sender: [...], underride: [...]}`
/// object) against `event` for `ctx`. Returns the `PushAction` for the
/// first matching enabled rule, or a default `notify: false` when no rule
/// matches.
pub fn evaluate(event: &Value, rules: &Value, ctx: &RoomContext) -> PushAction {
    // .m.rule.master, when enabled, suppresses everything. It's an
    // override rule — we still iterate override in priority order and it
    // sits at the top, so no short-circuit needed beyond normal walk.
    for kind in ["override", "content", "room", "sender", "underride"] {
        let Some(arr) = rules.get(kind).and_then(|v| v.as_array()) else {
            continue;
        };
        for rule in arr {
            if !rule_enabled(rule) {
                continue;
            }
            if rule_matches(rule, kind, event, ctx) {
                return actions_to_push_action(rule.get("actions"));
            }
        }
    }
    PushAction::default()
}

fn rule_enabled(rule: &Value) -> bool {
    rule.get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
}

fn rule_matches(rule: &Value, kind: &str, event: &Value, ctx: &RoomContext) -> bool {
    match kind {
        "override" | "underride" => match_conditions(rule, event, ctx),
        // `content` rules use a `pattern` field, matched against the
        // event's `content.body`. Glob-ish matching with `*` wildcards.
        "content" => {
            let Some(pat) = rule.get("pattern").and_then(|v| v.as_str()) else {
                return false;
            };
            glob_match(pat, event.body().unwrap_or(""))
        }
        // `room` rules match if `rule_id == event.room_id`.
        "room" => {
            let Some(rid) = rule.get("rule_id").and_then(|v| v.as_str()) else {
                return false;
            };
            event.room_id() == Some(rid)
        }
        // `sender` rules match if `rule_id == event.sender`.
        "sender" => {
            let Some(uid) = rule.get("rule_id").and_then(|v| v.as_str()) else {
                return false;
            };
            event.sender() == Some(uid)
        }
        _ => false,
    }
}

fn match_conditions(rule: &Value, event: &Value, ctx: &RoomContext) -> bool {
    let Some(conds) = rule.get("conditions").and_then(|v| v.as_array()) else {
        // An override/underride rule with no conditions matches every event.
        return true;
    };
    conds.iter().all(|c| match_one_condition(c, event, ctx))
}

fn match_one_condition(cond: &Value, event: &Value, ctx: &RoomContext) -> bool {
    let Some(kind) = cond.get("kind").and_then(|v| v.as_str()) else {
        return false;
    };
    match kind {
        "event_match" => {
            let Some(key) = cond.get("key").and_then(|v| v.as_str()) else {
                return false;
            };
            let Some(pattern) = cond.get("pattern").and_then(|v| v.as_str()) else {
                return false;
            };
            let looked_up = json_pointer_get(event, key);
            let val = looked_up.as_ref().and_then(|v| v.as_str()).unwrap_or("");
            glob_match(pattern, val)
        }
        "event_property_is" => {
            let key = cond.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let expected = cond.get("value");
            let actual = json_pointer_get(event, key);
            expected.is_some() && expected == actual.as_ref()
        }
        "contains_display_name" => {
            let Some(name) = ctx.recipient_display_name.as_deref() else {
                return false;
            };
            contains_whole_word(event.body().unwrap_or(""), name)
        }
        "room_member_count" => {
            let Some(is_spec) = cond.get("is").and_then(|v| v.as_str()) else {
                return false;
            };
            member_count_matches(ctx.joined_member_count, is_spec)
        }
        // Not implemented (sender_notification_permission, event_property_contains,
        // m.call.notify): returning false means the rule doesn't match, which is
        // safer than false-positive notifications.
        _ => false,
    }
}

/// Resolve a Matrix-style dotted key path (`content.body`, `content.m.relates_to.rel_type`)
/// by splitting on unescaped dots. Matrix allows `\.` to embed literal dots
/// but the default rules don't use it — we handle the simple case.
fn json_pointer_get(event: &Value, key: &str) -> Option<Value> {
    let mut cursor = event;
    for part in key.split('.') {
        cursor = cursor.get(part)?;
    }
    Some(cursor.clone())
}

/// Matrix glob: `*` matches any substring, `?` any single character.
/// Case-insensitive per spec.
pub fn glob_match(pattern: &str, input: &str) -> bool {
    // Convert to a regex under the hood — but keep it simple: split on `*`
    // and check each chunk appears in order. `?` handled by treating each
    // non-wildcard char as needing exact match against one input char when
    // walking the chunk, but we simplify by only handling `*`. Real
    // Element default rules don't use `?`.
    let pattern_lc = pattern.to_lowercase();
    let input_lc = input.to_lowercase();
    let parts: Vec<&str> = pattern_lc.split('*').collect();
    if parts.len() == 1 {
        // No wildcard: exact match.
        return input_lc == pattern_lc;
    }
    let mut cursor = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 && !input_lc[cursor..].starts_with(part) {
            return false;
        }
        match input_lc[cursor..].find(part) {
            Some(idx) => cursor += idx + part.len(),
            None => return false,
        }
    }
    // Last part must match end if the pattern doesn't end in `*`.
    if let Some(last) = parts.last()
        && !last.is_empty()
        && !input_lc.ends_with(last)
    {
        return false;
    }
    true
}

/// Word-boundary contains check for `contains_display_name`. A display
/// name matches if it appears surrounded by non-word chars (or at string
/// boundary). Prevents "Alice" matching "malice".
fn contains_whole_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    let hay_lc = haystack.to_lowercase();
    let word_lc = word.to_lowercase();
    let mut start = 0;
    while let Some(idx) = hay_lc[start..].find(&word_lc) {
        let abs = start + idx;
        let before_ok = abs == 0
            || !hay_lc
                .as_bytes()
                .get(abs - 1)
                .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .unwrap_or(false);
        let after = abs + word_lc.len();
        let after_ok = after >= hay_lc.len()
            || !hay_lc
                .as_bytes()
                .get(after)
                .map(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .unwrap_or(false);
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
}

/// Parse `is` field from `room_member_count`: `"2"`, `"<=2"`, `">3"`, `"==1"`.
fn member_count_matches(count: u64, spec: &str) -> bool {
    let s = spec.trim();
    let (op, num_str) = if let Some(rest) = s.strip_prefix(">=") {
        (">=", rest)
    } else if let Some(rest) = s.strip_prefix("<=") {
        ("<=", rest)
    } else if let Some(rest) = s.strip_prefix("==") {
        ("==", rest)
    } else if let Some(rest) = s.strip_prefix('>') {
        (">", rest)
    } else if let Some(rest) = s.strip_prefix('<') {
        ("<", rest)
    } else {
        ("==", s)
    };
    let Ok(num) = num_str.trim().parse::<u64>() else {
        return false;
    };
    match op {
        ">" => count > num,
        "<" => count < num,
        ">=" => count >= num,
        "<=" => count <= num,
        "==" => count == num,
        _ => false,
    }
}

fn actions_to_push_action(actions: Option<&Value>) -> PushAction {
    let mut out = PushAction::default();
    let Some(arr) = actions.and_then(|v| v.as_array()) else {
        return out;
    };
    for act in arr {
        match act {
            Value::String(s) if s == "notify" => out.notify = true,
            Value::String(s) if s == "dont_notify" => out.notify = false,
            Value::Object(map) if map.get("set_tweak").and_then(|v| v.as_str()).is_some() => {
                let key = map
                    .get("set_tweak")
                    .and_then(|v| v.as_str())
                    .unwrap()
                    .to_string();
                // `set_tweak` with no `value` defaults to `true` (used for
                // `{"set_tweak": "highlight"}` with no value).
                let val = map.get("value").cloned().unwrap_or(json!(true));
                out.tweaks.insert(key, val);
            }
            _ => {}
        }
    }
    out
}

/// Server-defined default rules. Users who haven't customised get this
/// baseline: suppress notices/reactions/membership events; notify on
/// regular messages + display-name mentions. Subset of the spec default
/// rules — enough to make Element's out-of-the-box experience sane.
pub fn default_global_rules() -> Value {
    json!({
        "override": [
            // Master switch — disabled by default; when user enables,
            // everything suppresses.
            {
                "rule_id": ".m.rule.master",
                "default": true,
                "enabled": false,
                "conditions": [],
                "actions": ["dont_notify"],
            },
            // Suppress m.notice events (auto-sent bot messages).
            {
                "rule_id": ".m.rule.suppress_notices",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "content.msgtype",
                    "pattern": "m.notice",
                }],
                "actions": ["dont_notify"],
            },
            // Reactions (m.reaction) shouldn't push.
            {
                "rule_id": ".m.rule.reaction",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.reaction",
                }],
                "actions": ["dont_notify"],
            },
            // Membership changes shouldn't push.
            {
                "rule_id": ".m.rule.member_event",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.room.member",
                }],
                "actions": ["dont_notify"],
            },
            // Display-name mention (deprecated but still a Matrix default).
            {
                "rule_id": ".m.rule.contains_display_name",
                "default": true,
                "enabled": true,
                "conditions": [{"kind": "contains_display_name"}],
                "actions": [
                    "notify",
                    {"set_tweak": "sound", "value": "default"},
                    {"set_tweak": "highlight"},
                ],
            },
        ],
        "content": [],
        "room": [],
        "sender": [],
        "underride": [
            // Plain m.room.message events — notify, quietly.
            {
                "rule_id": ".m.rule.message",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.room.message",
                }],
                "actions": [
                    "notify",
                    {"set_tweak": "sound", "value": "default"},
                ],
            },
            // Encrypted events — notify without peeking at content.
            {
                "rule_id": ".m.rule.encrypted",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.room.encrypted",
                }],
                "actions": [
                    "notify",
                    {"set_tweak": "sound", "value": "default"},
                ],
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(body: &str) -> Value {
        json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": "!room:example.com",
            "content": {"msgtype": "m.text", "body": body},
        })
    }

    fn ctx(display_name: Option<&str>) -> RoomContext {
        RoomContext {
            joined_member_count: 3,
            recipient_display_name: display_name.map(|s| s.to_string()),
            recipient_user_id: "@bob:example.com".into(),
        }
    }

    #[test]
    fn default_rules_notify_on_plain_message() {
        let r = evaluate(&msg("hi"), &default_global_rules(), &ctx(None));
        assert!(r.notify);
        assert_eq!(
            r.tweaks.get("sound").and_then(|v| v.as_str()),
            Some("default")
        );
    }

    #[test]
    fn default_rules_suppress_notices() {
        let mut e = msg("announcement");
        e["content"]["msgtype"] = json!("m.notice");
        let r = evaluate(&e, &default_global_rules(), &ctx(None));
        assert!(!r.notify);
    }

    #[test]
    fn default_rules_suppress_reactions_and_member_events() {
        let mut reaction =
            json!({"type": "m.reaction", "sender":"@a:x", "room_id":"!r:x", "content":{}});
        let r = evaluate(&reaction, &default_global_rules(), &ctx(None));
        assert!(!r.notify);
        reaction["type"] = json!("m.room.member");
        let r = evaluate(&reaction, &default_global_rules(), &ctx(None));
        assert!(!r.notify);
    }

    #[test]
    fn display_name_mention_highlights() {
        let r = evaluate(
            &msg("hey bob, look here"),
            &default_global_rules(),
            &ctx(Some("bob")),
        );
        assert!(r.notify);
        assert_eq!(r.tweaks.get("highlight"), Some(&json!(true)));
    }

    #[test]
    fn display_name_substring_does_not_match() {
        // "bobby" should not trigger a "bob" mention.
        let r = evaluate(&msg("hi bobby"), &default_global_rules(), &ctx(Some("bob")));
        // Still notifies because the underride rule fires — but NOT highlighted.
        assert!(r.notify);
        assert!(!r.tweaks.contains_key("highlight"));
    }

    #[test]
    fn room_rule_mutes_specific_room() {
        let rules = json!({
            "override": [], "content": [],
            "room": [{
                "rule_id": "!room:example.com",
                "enabled": true,
                "actions": ["dont_notify"],
            }],
            "sender": [], "underride": default_global_rules()["underride"],
        });
        let r = evaluate(&msg("hi"), &rules, &ctx(None));
        assert!(!r.notify, "muted room should suppress push");
    }

    #[test]
    fn master_rule_when_enabled_suppresses_all() {
        let mut rules = default_global_rules();
        let master = &mut rules["override"][0];
        master["enabled"] = json!(true);
        let r = evaluate(&msg("hi"), &rules, &ctx(None));
        assert!(!r.notify);
    }

    #[test]
    fn disabled_override_is_skipped() {
        let mut rules = default_global_rules();
        rules["override"][1]["enabled"] = json!(false); // disable suppress_notices
        let mut e = msg("bot says");
        e["content"]["msgtype"] = json!("m.notice");
        let r = evaluate(&e, &rules, &ctx(None));
        assert!(
            r.notify,
            "with suppress_notices disabled, notice should fall through to underride"
        );
    }

    #[test]
    fn content_rule_keyword_highlights() {
        let rules = json!({
            "override": [],
            "content": [{
                "rule_id": "urgent",
                "enabled": true,
                "pattern": "urgent*",
                "actions": ["notify", {"set_tweak":"highlight"}],
            }],
            "room": [], "sender": [],
            "underride": default_global_rules()["underride"],
        });
        let r = evaluate(&msg("urgent: see ops channel"), &rules, &ctx(None));
        assert!(r.notify);
        assert_eq!(r.tweaks.get("highlight"), Some(&json!(true)));
    }

    #[test]
    fn glob_match_wildcards() {
        assert!(glob_match("*foo*", "hello foo bar"));
        assert!(glob_match("foo*", "foobar"));
        assert!(glob_match("*bar", "foobar"));
        assert!(!glob_match("foo*", "barfoo"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "inexact"));
    }

    #[test]
    fn member_count_comparisons() {
        assert!(member_count_matches(2, "2"));
        assert!(member_count_matches(2, "==2"));
        assert!(member_count_matches(3, ">2"));
        assert!(member_count_matches(2, "<=2"));
        assert!(!member_count_matches(1, ">=2"));
    }
}
