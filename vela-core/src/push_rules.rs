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
    /// The event sender's effective power level. Drives
    /// `sender_notification_permission` (the @room mention gate).
    pub sender_power_level: i64,
    /// The room's `notifications.room` power-level threshold (default 50).
    /// A sender at or above this may trigger `.m.rule.is_room_mention`.
    pub notifications_room_level: i64,
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
            let looked_up = json_pointer_get(event, key);
            let val = looked_up.as_ref().and_then(|v| v.as_str()).unwrap_or("");
            match cond.get("pattern").and_then(|v| v.as_str()) {
                Some(pattern) => glob_match(pattern, val),
                // No `pattern` → match the recipient's own mxid. The spec's
                // `.m.rule.invite_for_me` templates the user id into a
                // `state_key` event_match; vela keeps one shared default rule
                // and resolves the recipient from context instead (same
                // approach as `event_property_contains` / `contains_display_name`).
                None => val == ctx.recipient_user_id,
            }
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
        // MSC3952 intentional mentions: the array at `key` must contain
        // `value`. When `value` is omitted we test for the recipient's own
        // mxid — the spec's `.m.rule.is_user_mention` templates each user's
        // id into the rule; Vela keeps one shared default rule and resolves
        // the recipient from the eval context instead (same approach as
        // `contains_display_name`).
        "event_property_contains" => {
            let Some(key) = cond.get("key").and_then(|v| v.as_str()) else {
                return false;
            };
            let recipient = Value::String(ctx.recipient_user_id.clone());
            let expected = cond.get("value").unwrap_or(&recipient);
            json_pointer_get(event, key)
                .as_ref()
                .and_then(|v| v.as_array())
                .is_some_and(|arr| arr.iter().any(|item| item == expected))
        }
        // MSC3952 @room gate: the event sender's power level must be at or
        // above the room's `notifications.<key>` threshold. We only model
        // the `room` key (the only one the spec defines today).
        "sender_notification_permission" => {
            let key = cond.get("key").and_then(|v| v.as_str()).unwrap_or("room");
            if key != "room" {
                return false;
            }
            ctx.sender_power_level >= ctx.notifications_room_level
        }
        // Not implemented (m.call.notify): returning false means the rule
        // doesn't match, which is safer than false-positive notifications.
        _ => false,
    }
}

/// Resolve a Matrix-style dotted key path (`content.body`,
/// `content.m\.mentions.user_ids`) by splitting on unescaped dots. Per the
/// spec, `\.` embeds a literal dot and `\\` a literal backslash — required
/// for keys like `m.mentions` whose own name contains a dot (MSC3952).
fn json_pointer_get(event: &Value, key: &str) -> Option<Value> {
    let mut cursor = event;
    for part in split_unescaped_dots(key) {
        cursor = cursor.get(&part)?;
    }
    Some(cursor.clone())
}

/// Split a push-rule key on unescaped `.`, unescaping `\.` → `.` and
/// `\\` → `\` within each segment.
fn split_unescaped_dots(key: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = key.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            '.' => parts.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    parts.push(cur);
    parts
}

/// Matrix glob: `*` matches any substring, `?` any single character.
/// Case-insensitive per spec.
///
/// Iterative two-pointer matcher with single-star backtracking — O(pattern ×
/// input) worst case, no recursion. The previous recursive backtracker was
/// EXPONENTIAL on patterns like `*a*a*…*z` (stars separated by literals)
/// against a long non-matching input. The pattern is attacker-controlled (a
/// client-set `content` / `event_match` push rule) and the input is a message
/// body, and `evaluate` runs synchronously on the `/sync` hot path — so a
/// crafted rule plus a long message could pin a worker core and DoS the
/// server. This form is bounded regardless of pattern shape.
pub fn glob_match(pattern: &str, input: &str) -> bool {
    let pat: Vec<char> = pattern.to_lowercase().chars().collect();
    let inp: Vec<char> = input.to_lowercase().chars().collect();
    let (mut pi, mut ii) = (0usize, 0usize);
    // The last `*` seen, and the input index to resume from if a later
    // literal/`?` mismatch forces that `*` to consume one more char.
    let mut star_pi: Option<usize> = None;
    let mut star_ii = 0usize;
    while ii < inp.len() {
        if pi < pat.len() && (pat[pi] == '?' || pat[pi] == inp[ii]) {
            pi += 1;
            ii += 1;
        } else if pi < pat.len() && pat[pi] == '*' {
            star_pi = Some(pi);
            star_ii = ii;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ii += 1;
            ii = star_ii;
        } else {
            return false;
        }
    }
    // Trailing `*`s match the empty remainder.
    while pi < pat.len() && pat[pi] == '*' {
        pi += 1;
    }
    pi == pat.len()
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
            // Notify (with sound) when the recipient themselves is invited.
            // MUST precede `.m.rule.member_event` — that rule suppresses ALL
            // membership events, so without this an invite would never push.
            // The `state_key` event_match carries no pattern: the evaluator
            // matches it against the recipient's own mxid.
            {
                "rule_id": ".m.rule.invite_for_me",
                "default": true,
                "enabled": true,
                "conditions": [
                    {"kind": "event_match", "key": "type", "pattern": "m.room.member"},
                    {"kind": "event_match", "key": "content.membership", "pattern": "invite"},
                    {"kind": "event_match", "key": "state_key"},
                ],
                "actions": ["notify", {"set_tweak": "sound", "value": "default"}],
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
            // MSC3952 intentional user mention: notify when the recipient is
            // listed in content.m.mentions.user_ids. Takes priority over the
            // deprecated text-matching rules below. (No explicit `value` —
            // the evaluator fills in the recipient's mxid.)
            {
                "rule_id": ".m.rule.is_user_mention",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_property_contains",
                    "key": "content.m\\.mentions.user_ids",
                }],
                "actions": [
                    "notify",
                    {"set_tweak": "sound", "value": "default"},
                    {"set_tweak": "highlight"},
                ],
            },
            // MSC3952 intentional @room mention: notify when content.m.mentions
            // .room is true AND the sender has power to notify the room
            // (notifications.room, default 50). Gates @room spam from
            // low-power users.
            {
                "rule_id": ".m.rule.is_room_mention",
                "default": true,
                "enabled": true,
                "conditions": [
                    {
                        "kind": "event_property_is",
                        "key": "content.m\\.mentions.room",
                        "value": true,
                    },
                    {"kind": "sender_notification_permission", "key": "room"},
                ],
                "actions": ["notify", {"set_tweak": "highlight"}],
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
            // Room upgrade: notify + highlight the tombstone so members follow
            // the room to its successor.
            {
                "rule_id": ".m.rule.tombstone",
                "default": true,
                "enabled": true,
                "conditions": [
                    {"kind": "event_match", "key": "type", "pattern": "m.room.tombstone"},
                    {"kind": "event_match", "key": "state_key", "pattern": ""},
                ],
                "actions": ["notify", {"set_tweak": "highlight"}],
            },
            // MSC3930: poll responses must not generate push notifications
            // (the user already cast the vote; pushing on it is noise).
            {
                "rule_id": ".org.matrix.msc3930.rule.poll_response",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "org.matrix.msc3381.poll.response",
                }],
                "actions": [],
            },
            // MSC3958: an edit (m.replace) must not re-notify — the original
            // event already did. Last override so a mention inside an edit can
            // still notify via the higher-priority mention rules above.
            {
                "rule_id": ".m.rule.suppress_edits",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "content.m\\.relates_to.rel_type",
                    "pattern": "m.replace",
                }],
                "actions": [],
            },
        ],
        "content": [],
        "room": [],
        "sender": [],
        "underride": [
            // Incoming VoIP call — ring. Must precede the generic message
            // rules (first matching underride wins).
            {
                "rule_id": ".m.rule.call",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.call.invite",
                }],
                "actions": ["notify", {"set_tweak": "sound", "value": "ring"}],
            },
            // Encrypted message in a 1:1 room — sound. Must precede
            // `.m.rule.encrypted` (more specific).
            {
                "rule_id": ".m.rule.encrypted_room_one_to_one",
                "default": true,
                "enabled": true,
                "conditions": [
                    {"kind": "room_member_count", "is": "2"},
                    {"kind": "event_match", "key": "type", "pattern": "m.room.encrypted"},
                ],
                "actions": ["notify", {"set_tweak": "sound", "value": "default"}],
            },
            // Plaintext message in a 1:1 room — sound. Must precede
            // `.m.rule.message`.
            {
                "rule_id": ".m.rule.room_one_to_one",
                "default": true,
                "enabled": true,
                "conditions": [
                    {"kind": "room_member_count", "is": "2"},
                    {"kind": "event_match", "key": "type", "pattern": "m.room.message"},
                ],
                "actions": ["notify", {"set_tweak": "sound", "value": "default"}],
            },
            // Plain m.room.message in a group room — notify, NO sound (spec
            // reserves sound for 1:1 + mentions).
            {
                "rule_id": ".m.rule.message",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.room.message",
                }],
                "actions": ["notify"],
            },
            // Encrypted event in a group room — notify without peeking, no sound.
            {
                "rule_id": ".m.rule.encrypted",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "m.room.encrypted",
                }],
                "actions": ["notify"],
            },
            // MSC3930: poll starts in 1:1 rooms get sound. The
            // room_member_count condition mirrors the .m.rule.room_one_to_one
            // pattern.
            {
                "rule_id": ".org.matrix.msc3930.rule.poll_start_one_to_one",
                "default": true,
                "enabled": true,
                "conditions": [
                    {"kind": "room_member_count", "is": "2"},
                    {
                        "kind": "event_match",
                        "key": "type",
                        "pattern": "org.matrix.msc3381.poll.start",
                    },
                ],
                "actions": [
                    "notify",
                    {"set_tweak": "sound", "value": "default"},
                ],
            },
            // MSC3930: poll ends in 1:1 rooms get sound.
            {
                "rule_id": ".org.matrix.msc3930.rule.poll_end_one_to_one",
                "default": true,
                "enabled": true,
                "conditions": [
                    {"kind": "room_member_count", "is": "2"},
                    {
                        "kind": "event_match",
                        "key": "type",
                        "pattern": "org.matrix.msc3381.poll.end",
                    },
                ],
                "actions": [
                    "notify",
                    {"set_tweak": "sound", "value": "default"},
                ],
            },
            // MSC3930: poll starts in larger rooms notify quietly.
            {
                "rule_id": ".org.matrix.msc3930.rule.poll_start",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "org.matrix.msc3381.poll.start",
                }],
                "actions": ["notify"],
            },
            // MSC3930: poll ends in larger rooms notify quietly.
            {
                "rule_id": ".org.matrix.msc3930.rule.poll_end",
                "default": true,
                "enabled": true,
                "conditions": [{
                    "kind": "event_match",
                    "key": "type",
                    "pattern": "org.matrix.msc3381.poll.end",
                }],
                "actions": ["notify"],
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
            sender_power_level: 0,
            notifications_room_level: 50,
        }
    }

    // MSC3952 intentional mention. `m.mentions` carries a literal dot in
    // its key, exercising the escaped-key path.
    fn mention_event(user_ids: &[&str], room: bool) -> Value {
        json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": "!room:example.com",
            "content": {
                "msgtype": "m.text",
                "body": "hey",
                "m.mentions": { "user_ids": user_ids, "room": room },
            },
        })
    }

    #[test]
    fn is_user_mention_highlights_recipient() {
        let ev = mention_event(&["@bob:example.com"], false);
        let r = evaluate(&ev, &default_global_rules(), &ctx(None));
        assert!(r.notify);
        assert!(r.tweaks.contains_key("highlight"));
    }

    #[test]
    fn unmentioned_user_notifies_without_highlight() {
        // @carol mentioned, not @bob → plain-message notify, no highlight.
        let ev = mention_event(&["@carol:example.com"], false);
        let r = evaluate(&ev, &default_global_rules(), &ctx(None));
        assert!(r.notify);
        assert!(!r.tweaks.contains_key("highlight"));
    }

    #[test]
    fn room_mention_with_power_highlights() {
        let ev = mention_event(&[], true);
        let mut c = ctx(None);
        c.sender_power_level = 50; // == notifications.room threshold
        let r = evaluate(&ev, &default_global_rules(), &c);
        assert!(r.notify);
        assert!(r.tweaks.contains_key("highlight"));
    }

    #[test]
    fn room_mention_without_power_not_highlighted() {
        // sender_power_level 0 < 50 → @room gate fails; no highlight.
        let ev = mention_event(&[], true);
        let r = evaluate(&ev, &default_global_rules(), &ctx(None));
        assert!(!r.tweaks.contains_key("highlight"));
    }

    #[test]
    fn plain_message_group_room_notifies_without_sound() {
        // Spec reserves sound for 1:1 rooms + mentions. A plain message in a
        // group room (ctx = 3 members) notifies quietly.
        let r = evaluate(&msg("hi"), &default_global_rules(), &ctx(None));
        assert!(r.notify);
        assert_eq!(r.tweaks.get("sound"), None, "group message must not ring");
    }

    #[test]
    fn plain_message_one_to_one_notifies_with_sound() {
        let mut c = ctx(None);
        c.joined_member_count = 2;
        let r = evaluate(&msg("hi"), &default_global_rules(), &c);
        assert!(r.notify);
        assert_eq!(
            r.tweaks.get("sound").and_then(|v| v.as_str()),
            Some("default"),
            "1:1 message should ring"
        );
    }

    fn member_event(membership: &str, state_key: &str) -> Value {
        json!({
            "type": "m.room.member",
            "sender": "@alice:example.com",
            "room_id": "!r:x",
            "state_key": state_key,
            "content": {"membership": membership},
        })
    }

    #[test]
    fn invite_for_me_notifies_with_sound() {
        // An invite whose state_key is the recipient pushes (with sound),
        // beating the member_event suppression.
        let r = evaluate(
            &member_event("invite", "@bob:example.com"),
            &default_global_rules(),
            &ctx(None),
        );
        assert!(r.notify, "my own invite must push");
        assert_eq!(
            r.tweaks.get("sound").and_then(|v| v.as_str()),
            Some("default")
        );
    }

    #[test]
    fn invite_for_someone_else_does_not_notify_me() {
        // An invite of a different user is just a membership event → suppressed.
        let r = evaluate(
            &member_event("invite", "@carol:example.com"),
            &default_global_rules(),
            &ctx(None),
        );
        assert!(!r.notify, "another user's invite must not push me");
    }

    #[test]
    fn edit_is_suppressed() {
        let mut e = msg("* edited");
        e["content"]["m.relates_to"] = json!({"rel_type": "m.replace", "event_id": "$x"});
        let r = evaluate(&e, &default_global_rules(), &ctx(None));
        assert!(!r.notify, "an edit must not re-notify");
    }

    #[test]
    fn mention_inside_an_edit_still_notifies() {
        // suppress_edits is the LAST override, so a mention rule (higher
        // priority) fires first — an edit that mentions the recipient still
        // notifies + highlights.
        let mut e = msg("* @bob look");
        e["content"]["m.relates_to"] = json!({"rel_type": "m.replace", "event_id": "$x"});
        e["content"]["m.mentions"] = json!({"user_ids": ["@bob:example.com"]});
        let r = evaluate(&e, &default_global_rules(), &ctx(None));
        assert!(r.notify, "a mention inside an edit must still notify");
        assert!(r.tweaks.contains_key("highlight"));
    }

    #[test]
    fn call_invite_rings() {
        let ev = json!({
            "type": "m.call.invite",
            "sender": "@alice:example.com",
            "room_id": "!r:x",
            "content": {"call_id": "c1"},
        });
        let r = evaluate(&ev, &default_global_rules(), &ctx(None));
        assert!(r.notify);
        assert_eq!(r.tweaks.get("sound").and_then(|v| v.as_str()), Some("ring"));
    }

    #[test]
    fn tombstone_highlights() {
        let ev = json!({
            "type": "m.room.tombstone",
            "sender": "@alice:example.com",
            "room_id": "!r:x",
            "state_key": "",
            "content": {"replacement_room": "!new:x"},
        });
        let r = evaluate(&ev, &default_global_rules(), &ctx(None));
        assert!(r.notify);
        assert!(r.tweaks.contains_key("highlight"));
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

    /// `?` matches exactly one character; `*` matches zero or more.
    /// Exercises the MSC4155-style globs like `@user-?*`.
    #[test]
    fn glob_match_question_mark_single_char() {
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("a?c", "axc"));
        assert!(!glob_match("a?c", "ac"), "? must consume one char");
        assert!(!glob_match("a?c", "abbc"), "? consumes exactly one");
    }

    #[test]
    fn glob_match_combined_wildcards() {
        // @user-?* — `@user-` literal, then exactly one char, then
        // anything. The single-char slot is content-agnostic: `:` is
        // a valid match for `?` here.
        assert!(glob_match("@user-?*", "@user-1"));
        assert!(glob_match("@user-?*", "@user-1:hs2"));
        assert!(glob_match("@user-?*", "@user-:hs2"));
        assert!(!glob_match("@user-?*", "@user-"));
        assert!(!glob_match("@user-?*", "@admin-1"));
    }

    #[test]
    fn glob_match_runs_of_stars_collapse() {
        // `**` shouldn't blow up exponentially or change semantics.
        assert!(glob_match("a**b", "ab"));
        assert!(glob_match("a**b", "axxxxxxxxb"));
        assert!(glob_match("**", ""));
        assert!(glob_match("**", "anything"));
    }

    /// Regression: many stars separated by literals against a long
    /// non-matching input made the old recursive backtracker exponential —
    /// a ReDoS, since the pattern is an attacker-set push rule evaluated on
    /// the /sync hot path. The iterative matcher is O(pattern × input):
    /// this test completing at all is the proof, and the results must stay
    /// correct.
    #[test]
    fn glob_match_pathological_pattern_is_bounded() {
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*z";
        let no_match = "a".repeat(200); // no trailing 'z'
        assert!(
            !glob_match(pattern, &no_match),
            "long non-matching input must fail fast, not hang"
        );
        let does_match = format!("{}z", "a".repeat(200));
        assert!(
            glob_match(pattern, &does_match),
            "the matching variant must still match"
        );
    }

    #[test]
    fn glob_match_case_insensitive() {
        assert!(glob_match("FOO*", "foobar"));
        assert!(glob_match("*BAR", "FooBar"));
        assert!(glob_match("e?act", "EXACT"));
    }

    #[test]
    fn glob_match_unicode_input_doesnt_panic() {
        // Multi-byte chars in the input would break naive byte
        // indexing; the matcher walks chars so this should match.
        assert!(glob_match("h*ø*", "høllø"));
        assert!(glob_match("?", "Ω"));
        assert!(!glob_match("?", "ΩΩ"));
    }

    #[test]
    fn glob_match_empty_pattern_matches_empty_input() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        assert!(glob_match("*", ""));
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
