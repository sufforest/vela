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

    // Explicit allow short-circuits everything else.
    if matches(&list("allowed_users"), sender_user_id)
        || matches(&list("allowed_servers"), sender_domain)
    {
        return InviteAction::Allow;
    }
    // Block beats ignore.
    if matches(&list("blocked_users"), sender_user_id)
        || matches(&list("blocked_servers"), sender_domain)
    {
        return InviteAction::Block;
    }
    if matches(&list("ignored_users"), sender_user_id)
        || matches(&list("ignored_servers"), sender_domain)
    {
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
    fn allow_overrides_block() {
        let cfg = json!({
            "blocked_servers": ["hs2"],
            "allowed_users": ["@friendly_bob:hs2"],
        });
        assert_eq!(decide(&cfg, "@friendly_bob:hs2"), InviteAction::Allow);
        assert_eq!(decide(&cfg, "@evil_bob:hs2"), InviteAction::Block);
    }

    #[test]
    fn ignored_user_returns_ignore() {
        let cfg = json!({"ignored_users": ["@bob:example.com"]});
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Ignore);
    }

    #[test]
    fn block_beats_ignore() {
        let cfg = json!({
            "ignored_users": ["@bob:example.com"],
            "blocked_servers": ["example.com"],
        });
        assert_eq!(decide(&cfg, "@bob:example.com"), InviteAction::Block);
    }
}
