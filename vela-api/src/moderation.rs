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

/// One compiled ban rule: a glob entity, the moderator's reason, and the nid of
/// the policy room it came from (so a listing can show the source and whether
/// `!unban` applies — only rules from the admin room are locally revocable).
#[derive(Debug, Clone)]
struct Rule {
    entity: String,
    reason: String,
    source_room_nid: u64,
}

/// A ban list entry flattened for display (`!bans`).
#[derive(Debug, Clone)]
pub struct BanEntry {
    /// `"user"` | `"server"` | `"room"`.
    pub kind: &'static str,
    pub entity: String,
    pub reason: String,
    /// The policy room this rule was compiled from.
    pub source_room_nid: u64,
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

    /// All entries, grouped users → servers → rooms and sorted by entity within
    /// each group, for `!bans` listing. The stable order keeps pagination
    /// deterministic across calls (the underlying scan order isn't).
    fn entries(&self) -> Vec<BanEntry> {
        let mut out = Vec::with_capacity(self.users.len() + self.servers.len() + self.rooms.len());
        for (kind, rules) in [
            ("user", &self.users),
            ("server", &self.servers),
            ("room", &self.rooms),
        ] {
            let start = out.len();
            for r in rules {
                out.push(BanEntry {
                    kind,
                    entity: r.entity.clone(),
                    reason: r.reason.clone(),
                    source_room_nid: r.source_room_nid,
                });
            }
            out[start..].sort_by(|a, b| a.entity.cmp(&b.entity));
        }
        out
    }
}

/// Runtime moderation state, carried on `AppState` (cheaply cloneable).
///
/// When `enabled` is false every `check_*` returns `None` after a single bool
/// test — disabled deployments pay essentially nothing.
#[derive(Clone)]
pub struct ModerationState {
    pub enabled: bool,
    /// When true (default), an operator `!ban` of an exact local user also
    /// force-leaves them from every room (see the admin command). Set false to
    /// ban-without-removing (block re-entry but preserve membership/history).
    pub remove_on_ban: bool,
    /// Watched policy-room nids. Seeded at boot from `[moderation].policy_rooms`
    /// (static) unioned with the persisted runtime set, and mutated at runtime by
    /// the `!watch` / `!unwatch` admin commands — hence `ArcSwap`, so the refresh
    /// hooks read a lock-free snapshot. The refresh hooks ignore state changes in
    /// any other room.
    policy_rooms: Arc<ArcSwap<HashSet<u64>>>,
    /// Lock-free-swappable compiled list. Refreshed on policy-rule changes.
    ban_list: Arc<ArcSwap<BanList>>,
    /// Serializes `watch_room` / `unwatch_room` so the in-memory set and the
    /// persisted meta list update together — concurrent admin commands (each on
    /// its own spawned task) would otherwise lost-update either one and diverge.
    mutation_lock: Arc<std::sync::Mutex<()>>,
}

impl ModerationState {
    /// Inert instance — no policy rooms, empty list. Used by test harnesses
    /// and embedders that build `AppState` without moderation.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            remove_on_ban: false,
            policy_rooms: Arc::new(ArcSwap::from_pointee(HashSet::new())),
            ban_list: Arc::new(ArcSwap::from_pointee(BanList::default())),
            mutation_lock: Arc::new(std::sync::Mutex::new(())),
        }
    }

    /// Build from `[moderation]` at boot: resolve the watched policy rooms — the
    /// static `[moderation].policy_rooms` config unioned with the persisted
    /// runtime set (added via `!watch`) — to nids, compile their current rules,
    /// and log the result. Cheap enough to run inline on the boot path.
    pub fn init(
        db: &Database,
        enabled: bool,
        remove_on_ban: bool,
        policy_room_ids: &[String],
    ) -> Self {
        let mut policy_rooms = HashSet::new();
        if enabled {
            let persisted = db.get_moderation_watched_rooms().unwrap_or_default();
            for rid in policy_room_ids.iter().chain(persisted.iter()) {
                match db.get_nid(rid) {
                    Ok(Some(nid)) => {
                        policy_rooms.insert(nid);
                    }
                    Ok(None) => tracing::warn!(
                        room = %rid,
                        "moderation: policy room not present locally; its rules are ignored until \
                         the room exists here (join it, or `!watch` a remote one)"
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
            remove_on_ban,
            policy_rooms: Arc::new(ArcSwap::from_pointee(policy_rooms)),
            ban_list: Arc::new(ArcSwap::from_pointee(list)),
            mutation_lock: Arc::new(std::sync::Mutex::new(())),
        }
    }

    /// Add `room_nid` (id `room_id`) to the watched set, persist it, and
    /// recompile the ban list — all under the mutation lock so a concurrent
    /// command can't lose the update or diverge the persisted list from the live
    /// set. Idempotent (no rebuild when already watched). No-op when disabled.
    pub fn watch_room(
        &self,
        db: &Database,
        room_nid: u64,
        room_id: &str,
    ) -> Result<(), rocksdb::Error> {
        if !self.enabled {
            return Ok(());
        }
        let _guard = self.mutation_lock.lock().unwrap();
        let mut persisted = db.get_moderation_watched_rooms()?;
        if !persisted.iter().any(|r| r == room_id) {
            persisted.push(room_id.to_string());
            db.set_moderation_watched_rooms(&persisted)?;
        }
        let mut set = HashSet::clone(&self.policy_rooms.load());
        if set.insert(room_nid) {
            self.policy_rooms.store(Arc::new(set));
            self.rebuild(db);
        }
        Ok(())
    }

    /// Remove `room_id` from the watched set (persisted + in-memory) and
    /// recompile. Returns whether it was actually being watched. Removing from
    /// the persisted list always happens even if the room isn't locally
    /// resolvable. No-op when disabled. Held under the mutation lock.
    pub fn unwatch_room(&self, db: &Database, room_id: &str) -> Result<bool, rocksdb::Error> {
        if !self.enabled {
            return Ok(false);
        }
        let _guard = self.mutation_lock.lock().unwrap();
        let mut persisted = db.get_moderation_watched_rooms()?;
        let before = persisted.len();
        persisted.retain(|r| r != room_id);
        if persisted.len() != before {
            db.set_moderation_watched_rooms(&persisted)?;
        }
        let Some(room_nid) = db.get_nid(room_id)? else {
            return Ok(false);
        };
        let mut set = HashSet::clone(&self.policy_rooms.load());
        let was_watched = set.remove(&room_nid);
        if was_watched {
            self.policy_rooms.store(Arc::new(set));
            self.rebuild(db);
        }
        Ok(was_watched)
    }

    /// Whether a room is currently watched.
    pub fn is_watched(&self, room_nid: u64) -> bool {
        self.policy_rooms.load().contains(&room_nid)
    }

    /// Snapshot of the watched room nids (for status display).
    pub fn watched_rooms(&self) -> Vec<u64> {
        self.policy_rooms.load().iter().copied().collect()
    }

    /// `(users, servers, rooms)` ban counts for the current list.
    pub fn ban_counts(&self) -> (usize, usize, usize) {
        self.ban_list.load().counts()
    }

    /// All current ban entries (users → servers → rooms) for the `!bans`
    /// listing. Cloned out of the `ArcSwap` snapshot so the caller isn't tied to
    /// the guard's lifetime.
    pub fn list_bans(&self) -> Vec<BanEntry> {
        self.ban_list.load().entries()
    }

    /// Rebuild the ban list if `event_type` is a policy rule applied to a
    /// watched policy room. Called from the two state-observation points
    /// (local send + federation persist) right after `promote_state_event`.
    /// Whole-list rebuild — policy rooms are small, so this is microseconds
    /// and avoids any delta-tracking bugs (redactions, entity edits, …).
    pub fn maybe_refresh(&self, db: &Database, room_nid: u64, event_type: &str) {
        if !self.enabled
            || !event_type.starts_with("m.policy.rule.")
            || !self.policy_rooms.load().contains(&room_nid)
        {
            return;
        }
        let list = build_ban_list(db, &self.policy_rooms.load());
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
        let list = build_ban_list(db, &self.policy_rooms.load());
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
    /// moderation is off. Runs even with an empty watched set, since `!watch`
    /// can add rooms at runtime. Bounds worst-case staleness from the un-hooked
    /// mutation paths to one `SWEEP_INTERVAL`.
    pub fn spawn_sweeper(&self, db: Arc<Database>) {
        if !self.enabled {
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
        if let Some(mut rule) = parse_rule(content.get("content")) {
            rule.source_room_nid = room_nid;
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
        // Set by collect_rules, which knows the source room.
        source_room_nid: 0,
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
                    source_room_nid: 0,
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
            remove_on_ban: false,
            policy_rooms: Arc::new(ArcSwap::from_pointee(HashSet::new())),
            ban_list: Arc::new(ArcSwap::from_pointee(list)),
            mutation_lock: Arc::new(std::sync::Mutex::new(())),
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

#[cfg(test)]
mod db_tests {
    use super::*;
    use vela_store::db::Database;

    fn temp_db() -> (Database, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open(tmp.path()).unwrap();
        (db, tmp)
    }

    #[test]
    fn watch_unwatch_roundtrip() {
        let (db, _tmp) = temp_db();
        let ms = ModerationState::init(&db, true, true, &[]);
        let nid = db.get_or_create_nid("!p:local").unwrap();
        assert!(!ms.is_watched(nid));
        ms.watch_room(&db, nid, "!p:local").unwrap();
        assert!(ms.is_watched(nid));
        assert_eq!(ms.watched_rooms(), vec![nid]);
        // persisted
        assert_eq!(db.get_moderation_watched_rooms().unwrap(), vec!["!p:local"]);
        ms.watch_room(&db, nid, "!p:local").unwrap(); // idempotent
        assert_eq!(ms.watched_rooms().len(), 1);
        assert_eq!(db.get_moderation_watched_rooms().unwrap().len(), 1);
        assert!(ms.unwatch_room(&db, "!p:local").unwrap());
        assert!(!ms.is_watched(nid));
        assert!(db.get_moderation_watched_rooms().unwrap().is_empty());
        assert!(!ms.unwatch_room(&db, "!p:local").unwrap()); // already gone
    }

    #[test]
    fn concurrent_watch_has_no_lost_update() {
        // 16 threads each watch a distinct room; the mutation lock must keep
        // both the in-memory set and the persisted list consistent (without it,
        // the load-clone-store on each side loses updates).
        let (db, _tmp) = temp_db();
        let db = std::sync::Arc::new(db);
        let ms = ModerationState::init(&db, true, true, &[]);
        // Pre-intern nids so the threads only exercise watch_room.
        let rooms: Vec<(u64, String)> = (0..16)
            .map(|i| {
                let rid = format!("!room{i}:local");
                (db.get_or_create_nid(&rid).unwrap(), rid)
            })
            .collect();
        let handles: Vec<_> = rooms
            .into_iter()
            .map(|(nid, rid)| {
                let ms = ms.clone();
                let db = db.clone();
                std::thread::spawn(move || ms.watch_room(&db, nid, &rid).unwrap())
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(ms.watched_rooms().len(), 16, "in-memory set");
        assert_eq!(
            db.get_moderation_watched_rooms().unwrap().len(),
            16,
            "persisted list"
        );
    }

    #[test]
    fn init_merges_config_and_persisted_watched_rooms() {
        let (db, _tmp) = temp_db();
        let cfg_nid = db.get_or_create_nid("!cfg:local").unwrap();
        let persisted_nid = db.get_or_create_nid("!persisted:local").unwrap();
        db.set_moderation_watched_rooms(&["!persisted:local".to_string()])
            .unwrap();
        let ms = ModerationState::init(&db, true, true, &["!cfg:local".to_string()]);
        assert!(ms.is_watched(cfg_nid), "config room watched");
        assert!(ms.is_watched(persisted_nid), "persisted room watched");
    }

    #[test]
    fn disabled_init_watches_nothing_and_watch_is_noop() {
        let (db, _tmp) = temp_db();
        let nid = db.get_or_create_nid("!p:local").unwrap();
        db.set_moderation_watched_rooms(&["!p:local".to_string()])
            .unwrap();
        let ms = ModerationState::init(&db, false, false, &["!p:local".to_string()]);
        assert!(!ms.is_watched(nid)); // disabled → empty set
        ms.watch_room(&db, nid, "!p:local").unwrap(); // no-op when disabled
        assert!(!ms.is_watched(nid));
    }
}
