//! Native moderation / policy-list enforcement.
//!
//! Implements the server side of the Matrix "Moderation policy lists" module
//! (`m.policy.rule.user` / `.room` / `.server` state events). The spec
//! standardizes the *data*; enforcement is implementation-defined, so this is
//! an opt-in value-add for public deployments — off unless `[moderation]
//! enabled = true`.
//!
//! A watched *policy room* carries policy-rule state events; we compile the
//! `recommendation: "m.ban"` rules of all watched rooms into an in-memory
//! [`BanList`] (glob buckets for users / servers / rooms), held on `AppState`
//! behind `ArcSwap`. The enforcement sites (invite / join, local + federation)
//! consult it via [`ModerationState::check_user`] /
//! [`ModerationState::check_server`] / [`ModerationState::check_room`].
//!
//! PR-1 sources rules from *local* policy rooms only — vela already holds their
//! state, so no join is required. Subscribing to a remote/shared list (admin-bot
//! auto-join) is a later step.

use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde_json::Value;
use vela_core::push_rules::glob_match;
use vela_store::db::Database;

/// Only these `recommendation` values are treated as bans. `m.ban` is the
/// spec value; `org.matrix.mjolnir.ban` is the historical alias every real
/// ban list still ships.
const BAN_RECOMMENDATIONS: [&str; 2] = ["m.ban", "org.matrix.mjolnir.ban"];

/// Cadence of the background safety-net rebuild (see [`ModerationState::spawn_sweeper`]).
const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// One compiled ban rule: a glob entity + the moderator's reason.
#[derive(Debug, Clone)]
struct Rule {
    entity: String,
    reason: String,
}

/// The compiled ban list — three glob buckets. Empty = nothing banned.
#[derive(Debug, Clone, Default)]
pub struct BanList {
    users: Vec<Rule>,
    servers: Vec<Rule>,
    rooms: Vec<Rule>,
}

impl BanList {
    fn match_reason<'a>(rules: &'a [Rule], target: &str) -> Option<&'a str> {
        rules
            .iter()
            .find(|r| glob_match(&r.entity, target))
            .map(|r| r.reason.as_str())
    }

    /// `(users, servers, rooms)` rule counts — for boot/refresh logging.
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.users.len(), self.servers.len(), self.rooms.len())
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty() && self.servers.is_empty() && self.rooms.is_empty()
    }
}

/// Runtime moderation state, carried on `AppState` (cheaply cloneable).
///
/// When `enabled` is false every `check_*` returns `None` after a single bool
/// test — disabled deployments pay essentially nothing.
#[derive(Clone)]
pub struct ModerationState {
    pub enabled: bool,
    /// Watched policy-room nids, resolved from `[moderation].policy_rooms` at
    /// boot. The refresh hooks ignore state changes in any other room.
    policy_rooms: Arc<HashSet<u64>>,
    /// Lock-free-swappable compiled list. Refreshed on policy-rule changes.
    ban_list: Arc<ArcSwap<BanList>>,
}

impl ModerationState {
    /// Inert instance — no policy rooms, empty list. Used by test harnesses
    /// and embedders that build `AppState` without moderation.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            policy_rooms: Arc::new(HashSet::new()),
            ban_list: Arc::new(ArcSwap::from_pointee(BanList::default())),
        }
    }

    /// Build from `[moderation]` at boot: resolve the configured policy-room
    /// ids to nids (skipping any not held locally), compile their current
    /// rules, and log the result. Cheap enough to run inline on the boot path.
    pub fn init(db: &Database, enabled: bool, policy_room_ids: &[String]) -> Self {
        let mut policy_rooms = HashSet::new();
        if enabled {
            for rid in policy_room_ids {
                match db.get_nid(rid) {
                    Ok(Some(nid)) => {
                        policy_rooms.insert(nid);
                    }
                    Ok(None) => tracing::warn!(
                        room = %rid,
                        "moderation: policy room not present locally; its rules are ignored until \
                         the room exists here (remote-list subscription is a later feature)"
                    ),
                    Err(e) => tracing::error!(
                        room = %rid, error = %e,
                        "moderation: failed to resolve policy room id"
                    ),
                }
            }
        }
        let list = build_ban_list(db, &policy_rooms);
        if enabled {
            let (u, s, r) = list.counts();
            tracing::info!(
                policy_rooms = policy_rooms.len(),
                banned_users = u,
                banned_servers = s,
                banned_rooms = r,
                "moderation enabled"
            );
        }
        Self {
            enabled,
            policy_rooms: Arc::new(policy_rooms),
            ban_list: Arc::new(ArcSwap::from_pointee(list)),
        }
    }

    /// Rebuild the ban list if `event_type` is a policy rule applied to a
    /// watched policy room. Called from the two state-observation points
    /// (local send + federation persist) right after `promote_state_event`.
    /// Whole-list rebuild — policy rooms are small, so this is microseconds
    /// and avoids any delta-tracking bugs (redactions, entity edits, …).
    pub fn maybe_refresh(&self, db: &Database, room_nid: u64, event_type: &str) {
        if !self.enabled
            || !event_type.starts_with("m.policy.rule.")
            || !self.policy_rooms.contains(&room_nid)
        {
            return;
        }
        let list = build_ban_list(db, &self.policy_rooms);
        let (u, s, r) = list.counts();
        tracing::info!(
            banned_users = u,
            banned_servers = s,
            banned_rooms = r,
            "moderation: policy rules changed, ban list refreshed"
        );
        self.ban_list.store(Arc::new(list));
    }

    /// Unconditionally recompile the ban list from the watched rooms' *current*
    /// state, logging only if it actually changed. Backs the periodic sweeper —
    /// [`Self::maybe_refresh`] catches the common live paths, but a policy rule can
    /// also change via routes that don't run the two hooks (redaction-based
    /// revoke, federated state-resolution / backfill promoting a different
    /// rule). Reading current state here converges regardless of how it moved.
    fn rebuild(&self, db: &Database) {
        if !self.enabled {
            return;
        }
        let before = self.ban_list.load().counts();
        let list = build_ban_list(db, &self.policy_rooms);
        let after = list.counts();
        self.ban_list.store(Arc::new(list));
        if before != after {
            tracing::info!(
                ?before,
                ?after,
                "moderation: ban list changed on periodic rebuild (a change arrived outside the live hooks)"
            );
        }
    }

    /// Spawn the background safety-net rebuilder. No-op (nothing spawned) when
    /// moderation is off or nothing is watched. Bounds worst-case staleness
    /// from the un-hooked mutation paths to one `SWEEP_INTERVAL`.
    pub fn spawn_sweeper(&self, db: Arc<Database>) {
        if !self.enabled || self.policy_rooms.is_empty() {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SWEEP_INTERVAL);
            ticker.tick().await; // fires immediately; boot already seeded, skip it
            loop {
                ticker.tick().await;
                this.rebuild(&db);
            }
        });
    }

    /// Is this user banned — directly (user rule) or via their server (server
    /// rule)? Returns the moderator's reason (possibly empty) when banned.
    pub fn check_user(&self, user_id: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let list = self.ban_list.load();
        if let Some(reason) = BanList::match_reason(&list.users, user_id) {
            return Some(reason.to_string());
        }
        // A banned server bans all of its users.
        let domain = user_id.split_once(':').map(|(_, d)| d).unwrap_or("");
        if !domain.is_empty()
            && let Some(reason) = BanList::match_reason(&list.servers, domain)
        {
            return Some(reason.to_string());
        }
        None
    }

    /// Is this server banned? Returns the reason when so.
    pub fn check_server(&self, server_name: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let list = self.ban_list.load();
        BanList::match_reason(&list.servers, server_name).map(str::to_string)
    }

    /// Is this room banned? Returns the reason when so.
    pub fn check_room(&self, room_id: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let list = self.ban_list.load();
        BanList::match_reason(&list.rooms, room_id).map(str::to_string)
    }
}

/// Compile the current `m.policy.rule.*` rules of every watched policy room
/// into a fresh [`BanList`].
fn build_ban_list(db: &Database, policy_rooms: &HashSet<u64>) -> BanList {
    let mut list = BanList::default();
    for &room_nid in policy_rooms {
        collect_rules(db, room_nid, "m.policy.rule.user", &mut list.users);
        collect_rules(db, room_nid, "m.policy.rule.server", &mut list.servers);
        collect_rules(db, room_nid, "m.policy.rule.room", &mut list.rooms);
    }
    list
}

/// Pull the ban rules of one policy type from one room into `out`.
fn collect_rules(db: &Database, room_nid: u64, type_str: &str, out: &mut Vec<Rule>) {
    // No event of this type ever interned → no rules of this type exist.
    let type_nid = match db.get_nid(type_str) {
        Ok(Some(nid)) => nid,
        _ => return,
    };
    let nids = match db.get_state_events_of_type(room_nid, type_nid) {
        Ok(nids) => nids,
        Err(e) => {
            tracing::error!(room_nid, type_str, error = %e, "moderation: state scan failed");
            return;
        }
    };
    for nid in nids {
        // Fail-open on a per-event read/parse error (the rule is dropped from
        // the list), but WARN — a silently-vanished ban is exactly the kind of
        // thing an operator must be able to see. A missing event (None) is not
        // an error: a current-state pointer to an unreadable event is skipped.
        let json = match db.get_event(nid) {
            Ok(Some((_, json))) => json,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(nid, type_str, error = %e, "moderation: policy event read failed, rule dropped");
                continue;
            }
        };
        let content = match serde_json::from_slice::<Value>(&json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(nid, type_str, error = %e, "moderation: policy event parse failed, rule dropped");
                continue;
            }
        };
        if let Some(rule) = parse_rule(content.get("content")) {
            out.push(rule);
        }
    }
}

/// Turn a policy event's `content` into a [`Rule`], or `None` when it isn't an
/// active ban: non-ban recommendation, missing/empty entity, or a redacted
/// event whose content was stripped (a revoked rule).
fn parse_rule(content: Option<&Value>) -> Option<Rule> {
    let content = content?;
    let rec = content.get("recommendation").and_then(Value::as_str)?;
    if !BAN_RECOMMENDATIONS.contains(&rec) {
        return None;
    }
    let entity = content.get("entity").and_then(Value::as_str)?;
    if entity.is_empty() {
        return None;
    }
    // Reject an all-wildcard entity (`*`, `?*`, …). It matches essentially
    // everything, so a single such rule would reject every join/invite/PDU
    // server-wide — a DoS footgun, especially once shared/remote lists land.
    // A legitimate rule always anchors on some literal (a domain, a localpart).
    if entity.chars().all(|c| c == '*' || c == '?') {
        tracing::warn!(
            entity,
            "moderation: ignoring policy rule with an all-wildcard entity"
        );
        return None;
    }
    let reason = content
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Some(Rule {
        entity: entity.to_string(),
        reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn banlist(users: &[&str], servers: &[&str], rooms: &[&str]) -> BanList {
        let mk = |es: &[&str]| {
            es.iter()
                .map(|e| Rule {
                    entity: e.to_string(),
                    reason: "spam".into(),
                })
                .collect()
        };
        BanList {
            users: mk(users),
            servers: mk(servers),
            rooms: mk(rooms),
        }
    }

    fn state_with(list: BanList) -> ModerationState {
        ModerationState {
            enabled: true,
            policy_rooms: Arc::new(HashSet::new()),
            ban_list: Arc::new(ArcSwap::from_pointee(list)),
        }
    }

    #[test]
    fn parse_rule_accepts_m_ban() {
        let c = json!({"entity": "@bad:evil.com", "recommendation": "m.ban", "reason": "spam"});
        let r = parse_rule(Some(&c)).unwrap();
        assert_eq!(r.entity, "@bad:evil.com");
        assert_eq!(r.reason, "spam");
    }

    #[test]
    fn parse_rule_accepts_mjolnir_alias() {
        let c = json!({"entity": "evil.com", "recommendation": "org.matrix.mjolnir.ban"});
        assert!(parse_rule(Some(&c)).is_some());
    }

    #[test]
    fn parse_rule_rejects_non_ban_recommendation() {
        let c = json!({"entity": "@x:y", "recommendation": "m.mute"});
        assert!(parse_rule(Some(&c)).is_none());
    }

    #[test]
    fn parse_rule_rejects_empty_or_missing_entity() {
        assert!(parse_rule(Some(&json!({"recommendation": "m.ban"}))).is_none());
        assert!(parse_rule(Some(&json!({"entity": "", "recommendation": "m.ban"}))).is_none());
    }

    #[test]
    fn parse_rule_rejects_all_wildcard_entity() {
        // `*`, `?`, and any combination of only-wildcards match ~everything —
        // a server-wide DoS footgun — so they're ignored.
        for e in ["*", "**", "?", "*?*", "???"] {
            let c = json!({"entity": e, "recommendation": "m.ban"});
            assert!(
                parse_rule(Some(&c)).is_none(),
                "entity {e:?} should be rejected"
            );
        }
        // A wildcard anchored on a literal is fine.
        assert!(
            parse_rule(Some(
                &json!({"entity": "*.evil.com", "recommendation": "m.ban"})
            ))
            .is_some()
        );
        assert!(
            parse_rule(Some(
                &json!({"entity": "@spam_*:*", "recommendation": "m.ban"})
            ))
            .is_some()
        );
    }

    #[test]
    fn parse_rule_rejects_redacted_content() {
        // A redacted policy event keeps the type but strips content.
        assert!(parse_rule(Some(&json!({}))).is_none());
        assert!(parse_rule(None).is_none());
    }

    #[test]
    fn check_user_direct_match() {
        let s = state_with(banlist(&["@bad:evil.com"], &[], &[]));
        assert!(s.check_user("@bad:evil.com").is_some());
        assert!(s.check_user("@good:nice.com").is_none());
    }

    #[test]
    fn check_user_glob_match() {
        let s = state_with(banlist(&["@spam_*:*"], &[], &[]));
        assert!(s.check_user("@spam_bot:anywhere.net").is_some());
        assert!(s.check_user("@real:anywhere.net").is_none());
    }

    #[test]
    fn server_ban_implies_user_ban() {
        // A user rule bucket is empty but the server is banned → the user is
        // banned via their domain.
        let s = state_with(banlist(&[], &["evil.com"], &[]));
        assert!(s.check_user("@anyone:evil.com").is_some());
        assert!(s.check_user("@anyone:good.com").is_none());
        assert!(s.check_server("evil.com").is_some());
    }

    #[test]
    fn server_glob_ban() {
        let s = state_with(banlist(&[], &["*.evil.com"], &[]));
        assert!(s.check_user("@x:mail.evil.com").is_some());
        assert!(s.check_server("mail.evil.com").is_some());
        assert!(s.check_server("evil.com").is_none()); // *.evil.com needs a label
    }

    #[test]
    fn check_room_match() {
        let s = state_with(banlist(&[], &[], &["!bad:evil.com"]));
        assert!(s.check_room("!bad:evil.com").is_some());
        assert!(s.check_room("!ok:nice.com").is_none());
    }

    #[test]
    fn disabled_never_matches() {
        let mut s = state_with(banlist(
            &["@bad:evil.com"],
            &["evil.com"],
            &["!bad:evil.com"],
        ));
        s.enabled = false;
        assert!(s.check_user("@bad:evil.com").is_none());
        assert!(s.check_server("evil.com").is_none());
        assert!(s.check_room("!bad:evil.com").is_none());
    }

    #[test]
    fn malformed_user_id_without_colon_is_safe() {
        let s = state_with(banlist(&[], &["evil.com"], &[]));
        // No `:` → empty domain → no server match, no panic.
        assert!(s.check_user("no-colon").is_none());
    }
}
