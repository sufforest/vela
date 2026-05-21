//! `M_EXCLUSIVE` enforcement. Per the AS spec, normal users cannot
//! create entities (users / aliases) inside namespaces an AS has
//! claimed `exclusive: true`, and an AS cannot create entities outside
//! its own namespaces.
//!
//! The handlers that mint user IDs (`/register`) or aliases
//! (`/directory/room/...`) call these helpers before persistence.

use std::sync::Arc;

use crate::appservice::namespace::NamespaceScope;
use crate::appservice::registry::AsRegistry;

/// Outcome of a creation-permission check.
#[derive(Debug)]
pub enum ExclusiveCheck {
    Ok,
    /// Spec error: callers receive `M_EXCLUSIVE` + 400. Message
    /// names the offending AS for debuggability.
    Refused(String),
}

/// Can a caller create a user with `target_user_id`?
///
/// - `caller_as_nid = Some(_)`: an AS is masquerading. It can create
///   inside *its own* exclusive namespaces only; refused if the target
///   is inside *another* AS's exclusive namespace.
/// - `caller_as_nid = None`: a regular user (or the operator). Refused
///   if the target falls inside *any* AS's exclusive user namespace.
pub fn check_user(
    registry: &Arc<AsRegistry>,
    target_user_id: &str,
    caller_as_nid: Option<u64>,
) -> ExclusiveCheck {
    check(
        registry,
        NamespaceScope::User,
        target_user_id,
        caller_as_nid,
    )
}

/// Same shape for aliases.
pub fn check_alias(
    registry: &Arc<AsRegistry>,
    target_alias: &str,
    caller_as_nid: Option<u64>,
) -> ExclusiveCheck {
    check(registry, NamespaceScope::Alias, target_alias, caller_as_nid)
}

/// Walk the full registry — do NOT return on the first exclusive
/// match. The registry only de-duplicates exclusive claims by exact
/// regex string equality; two ASes can legitimately have textually
/// distinct exclusive regexes that overlap (e.g. `^@_irc_.*$` and
/// `^.*_alice:.*$` both match `@_irc_alice:e.c`). Returning on the
/// first match would mean iteration order (DashMap is unordered)
/// decides whether the caller's own AS is recognised or not. Instead:
/// if any iteration finds the caller as an exclusive owner, allow.
/// Otherwise, if any other AS claims exclusively, refuse.
fn check(
    registry: &Arc<AsRegistry>,
    scope: NamespaceScope,
    target: &str,
    caller_as_nid: Option<u64>,
) -> ExclusiveCheck {
    let mut other_owner: Option<String> = None;
    for live in registry.list() {
        if !live.matcher.matches_exclusive(scope, target) {
            continue;
        }
        if Some(live.appservice.nid) == caller_as_nid {
            return ExclusiveCheck::Ok;
        }
        // Hold the first foreign-AS conflict but keep iterating in
        // case the caller's own AS appears later.
        if other_owner.is_none() {
            other_owner = Some(live.appservice.id.clone());
        }
    }
    match other_owner {
        Some(id) => ExclusiveCheck::Refused(match scope {
            NamespaceScope::User => {
                format!("user id `{target}` is inside the exclusive namespace of appservice `{id}`")
            }
            NamespaceScope::Alias => {
                format!("alias `{target}` is inside the exclusive namespace of appservice `{id}`")
            }
            NamespaceScope::Room => {
                format!("room `{target}` is inside the exclusive namespace of appservice `{id}`")
            }
        }),
        None => ExclusiveCheck::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appservice::namespace::Namespace;
    use crate::appservice::{AppService, AppServiceConfig};
    use crate::test_helpers::build_test_state;

    fn make_as(id: &str, regex: &str, scope: NamespaceScope) -> AppService {
        AppService {
            nid: 0,
            id: id.into(),
            config: AppServiceConfig {
                url: "http://localhost".into(),
                hs_token_hash: format!("hs-{id}"),
                as_token_hash: format!("as-{id}"),
                sender_localpart: format!("_{id}_bot"),
                receive_ephemeral: false,
            },
            namespaces: vec![Namespace {
                scope,
                regex: regex.into(),
                exclusive: true,
            }],
            enabled: true,
            owner_nid: None,
            created_at_ms: 0,
        }
    }

    #[test]
    fn normal_user_refused_inside_exclusive_namespace() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make_as("irc", r"^@_irc_.*", NamespaceScope::User))
            .unwrap();
        let r = check_user(&reg, "@_irc_alice:example.com", None);
        assert!(matches!(r, ExclusiveCheck::Refused(_)));
    }

    #[test]
    fn normal_user_allowed_outside_exclusive_namespace() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make_as("irc", r"^@_irc_.*", NamespaceScope::User))
            .unwrap();
        assert!(matches!(
            check_user(&reg, "@alice:example.com", None),
            ExclusiveCheck::Ok
        ));
    }

    #[test]
    fn owning_as_allowed_inside_own_namespace() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let asv = reg
            .register(make_as("irc", r"^@_irc_.*", NamespaceScope::User))
            .unwrap();
        assert!(matches!(
            check_user(&reg, "@_irc_alice:example.com", Some(asv.nid)),
            ExclusiveCheck::Ok
        ));
    }

    #[test]
    fn other_as_refused_inside_someone_elses_namespace() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let _irc = reg
            .register(make_as("irc", r"^@_irc_.*", NamespaceScope::User))
            .unwrap();
        let dis = reg
            .register(make_as("discord", r"^@_discord_.*", NamespaceScope::User))
            .unwrap();
        // Discord AS trying to mint an IRC-namespace user.
        let r = check_user(&reg, "@_irc_alice:example.com", Some(dis.nid));
        assert!(matches!(r, ExclusiveCheck::Refused(_)));
    }

    /// Two ASes with textually distinct exclusive regexes that both
    /// match the same user_id. The registry only de-duplicates
    /// exact-string regex collisions, so this configuration registers
    /// successfully. The owning AS must still be allowed; the check
    /// must not return Refused just because the OTHER AS was visited
    /// first in iteration order.
    #[test]
    fn caller_allowed_even_when_overlapping_exclusive_seen_first() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let irc = reg
            .register(make_as("irc", r"^@_irc_.*$", NamespaceScope::User))
            .unwrap();
        // Distinct regex string but overlapping match space.
        let _other = reg
            .register(make_as(
                "wildcard",
                r"^@_irc_alice:.*$",
                NamespaceScope::User,
            ))
            .unwrap();
        // IRC AS minting its own user must succeed regardless of
        // which AS the registry iterator visits first.
        assert!(matches!(
            check_user(&reg, "@_irc_alice:example.com", Some(irc.nid)),
            ExclusiveCheck::Ok
        ));
    }

    #[test]
    fn alias_checks_mirror_user_checks() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let asv = reg
            .register(make_as("irc", r"^#_irc_.*", NamespaceScope::Alias))
            .unwrap();
        assert!(matches!(
            check_alias(&reg, "#_irc_chan:example.com", None),
            ExclusiveCheck::Refused(_)
        ));
        assert!(matches!(
            check_alias(&reg, "#_irc_chan:example.com", Some(asv.nid)),
            ExclusiveCheck::Ok
        ));
    }
}
