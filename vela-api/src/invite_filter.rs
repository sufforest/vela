//! MSC4155: server-side invite filtering driven by the invitee's
//! `org.matrix.msc4155.invite_permission_config` account_data.
//!
//! The config lists `allowed_users`, `blocked_users`, `ignored_users`,
//! and the matching `_servers` variants. Each entry is a glob (`*` /
//! `?`) checked against the inviter's user_id (for `_users`) or domain
//! (for `_servers`).
//!
//! Precedence per the MSC: explicit Allow beats everything; Block
//! beats Ignore. Default when nothing matches is Allow.

use serde_json::Value;
use vela_core::push_rules::glob_match;
use vela_store::db::Database;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteAction {
    /// Deliver the invite to the user normally.
    Allow,
    /// Reject the invite outright (return 403 to the inviter; nothing
    /// reaches the invitee).
    Block,
    /// Accept the invite on the server (no error to the inviter) but
    /// don't surface it to the invitee. Mirrors a client-side ignore
    /// without exposing whether the user has them blocked.
    Ignore,
}

/// Look up the invitee's invite_permission_config and decide what to
/// do with an inbound invite from `sender_user_id`. Returns `Allow`
/// when there's no config on file, or when no rule matches.
pub fn check_invite(db: &Database, invitee_nid: u64, sender_user_id: &str) -> InviteAction {
    let cfg = match db.get_account_data(invitee_nid, "org.matrix.msc4155.invite_permission_config")
    {
        Ok(Some(v)) => v,
        _ => return InviteAction::Allow,
    };
    decide(&cfg, sender_user_id)
}

/// Pure-function form of the rule evaluation — public so the unit
/// tests can drive it without a Database fixture.
pub fn decide(cfg: &Value, sender_user_id: &str) -> InviteAction {
    let sender_domain = sender_user_id.split_once(':').map(|(_, d)| d).unwrap_or("");

    let list = |key: &str| -> Vec<String> {
        cfg.get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let matches = |patterns: &[String], target: &str| -> bool {
        patterns.iter().any(|p| glob_match(p, target))
    };

    // Per MSC4155: user-level rules win over server-level rules so
    // operators can carve specific exceptions out of an
    // allowed/blocked server bucket. Within each level, allow >
    // block > ignore.
    let allowed_users = list("allowed_users");
    let blocked_users = list("blocked_users");
    let ignored_users = list("ignored_users");
    if matches(&allowed_users, sender_user_id) {
        return InviteAction::Allow;
    }
    if matches(&blocked_users, sender_user_id) {
        return InviteAction::Block;
    }
    if matches(&ignored_users, sender_user_id) {
        return InviteAction::Ignore;
    }
    let allowed_servers = list("allowed_servers");
    let blocked_servers = list("blocked_servers");
    let ignored_servers = list("ignored_servers");
    if matches(&allowed_servers, sender_domain) {
        return InviteAction::Allow;
    }
    if matches(&blocked_servers, sender_domain) {
        return InviteAction::Block;
    }
    if matches(&ignored_servers, sender_domain) {
        return InviteAction::Ignore;
    }
    InviteAction::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_config_allows() {
        assert_eq!(decide(&json!({}), "@bob:example.com"), InviteAction::Allow);
    }

    #[test]
    fn blocked_user_exact_match() {
        let cfg = json!({"blocked_users": ["@bob:example.com"]});
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Block);
        assert_eq!(decide(&cfg, "@carol:example.com"), InviteAction::Allow);
    }

    #[test]
    fn blocked_server_glob_match() {
        let cfg = json!({"blocked_servers": ["hs*"]});
        assert_eq!(decide(&cfg, "@bob:hs2"), InviteAction::Block);
        assert_eq!(decide(&cfg, "@bob:hs1"), InviteAction::Block);
        assert_eq!(decide(&cfg, "@bob:other.example"), InviteAction::Allow);
    }

    #[test]
    fn user_level_allow_overrides_server_block() {
        let cfg = json!({
            "blocked_servers": ["hs2"],
            "allowed_users": ["@friendly_bob:hs2"],
        });
        assert_eq!(decide(&cfg, "@friendly_bob:hs2"), InviteAction::Allow);
        assert_eq!(decide(&cfg, "@evil_bob:hs2"), InviteAction::Block);
    }

    #[test]
    fn user_level_block_overrides_server_allow() {
        let cfg = json!({
            "allowed_servers": ["hs2"],
            "blocked_users": ["@evil_bob:hs2"],
        });
        assert_eq!(decide(&cfg, "@evil_bob:hs2"), InviteAction::Block);
        assert_eq!(decide(&cfg, "@friendly_bob:hs2"), InviteAction::Allow);
    }

    #[test]
    fn ignored_user_returns_ignore() {
        let cfg = json!({"ignored_users": ["@bob:example.com"]});
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Ignore);
    }

    #[test]
    fn user_ignore_beats_server_block() {
        // Per MSC4155 user-level rules dominate server-level — a user
        // marked Ignore stays Ignore even when their server is on the
        // block list.
        let cfg = json!({
            "ignored_users": ["@bob:example.com"],
            "blocked_servers": ["example.com"],
        });
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Ignore);
    }

    /// Within a level (user OR server), allow > block > ignore. Both
    /// listed at the same level → first one wins.
    #[test]
    fn allow_at_same_level_overrides_block() {
        let cfg = json!({
            "allowed_users": ["@bob:example.com"],
            "blocked_users": ["@bob:example.com"],
            "ignored_users": ["@bob:example.com"],
        });
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Allow);
    }

    #[test]
    fn block_at_same_level_overrides_ignore() {
        let cfg = json!({
            "blocked_users": ["@bob:example.com"],
            "ignored_users": ["@bob:example.com"],
        });
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Block);
    }

    /// `?` matches exactly one character (push-rules glob, exercised
    /// by MSC4155 patterns like `@user-?*`).
    #[test]
    fn glob_question_mark_matches_one_char() {
        let cfg = json!({"blocked_users": ["@user-?:example.com"]});
        assert_eq!(decide(&cfg, "@user-1:example.com"), InviteAction::Block);
        assert_eq!(decide(&cfg, "@user-12:example.com"), InviteAction::Allow);
    }

    /// `_servers` list values are interpreted as domain globs without
    /// any user_id parsing, so `*` alone blocks everyone.
    #[test]
    fn star_server_blocks_every_domain() {
        let cfg = json!({"blocked_servers": ["*"]});
        assert_eq!(decide(&cfg, "@a:hs1"), InviteAction::Block);
        assert_eq!(decide(&cfg, "@b:another.example"), InviteAction::Block);
    }

    /// Configs that put non-string entries in the lists must not
    /// panic — they're silently skipped.
    #[test]
    fn non_string_entries_are_ignored() {
        let cfg = json!({
            "blocked_users": [42, true, null, {"x": 1}, "@bob:example.com"],
        });
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Block);
        assert_eq!(decide(&cfg, "@alice:example.com"), InviteAction::Allow);
    }

    /// A user_id without a `:` separator (malformed) shouldn't crash
    /// the domain extraction; it just doesn't match server lists.
    #[test]
    fn missing_separator_falls_through_server_rules() {
        let cfg = json!({"blocked_servers": ["hs1"]});
        // Domain extraction returns "" — no match.
        assert_eq!(decide(&cfg, "no-colon-here"), InviteAction::Allow);
    }

    /// Empty list keys behave the same as missing keys — no false
    /// match against the empty pattern set.
    #[test]
    fn empty_lists_are_inert() {
        let cfg = json!({
            "allowed_users": [],
            "blocked_users": [],
            "ignored_users": [],
        });
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Allow);
    }
}
