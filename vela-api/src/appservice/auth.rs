//! AS masquerading auth. When an incoming CS-API request carries
//! `Authorization: Bearer <as_token>`, the auth middleware falls
//! through to here to:
//!   1. resolve the as_token (hash-lookup) to a registered AS,
//!   2. honour the `?user_id=` query param to pick the virtual user,
//!   3. validate the target user is in the AS's user namespace,
//!   4. provision the user record if it doesn't exist yet,
//!   5. issue an `AuthenticatedUser` that the rest of the CS API
//!      treats as a normal session.
//!
//! Spec: client-server-api "Identity assertion" + application-service
//! spec "Server admin style permissions" §1.4.

use std::sync::Arc;

use thiserror::Error;

use vela_store::db::Database;

use crate::appservice::namespace::NamespaceScope;
use crate::appservice::registry::AsRegistry;
use crate::appservice::{LiveAppService, hash_token};

#[derive(Debug, Error)]
pub enum AsAuthError {
    #[error("no AS matches that as_token")]
    UnknownToken,
    #[error("AS is disabled")]
    Disabled,
    #[error("user `{0}` is outside the AS's user namespaces")]
    ExclusiveViolation(String),
    #[error("storage error: {0}")]
    Storage(String),
}

/// Look up the AS owning this cleartext as_token. `None` when the
/// token doesn't match any registered AS.
pub fn lookup_appservice(
    registry: &Arc<AsRegistry>,
    cleartext_token: &str,
) -> Option<LiveAppService> {
    let hash = hash_token(cleartext_token);
    registry.get_by_as_token_hash(&hash)
}

/// Resolve the target virtual user for an AS-authenticated request.
/// Returns the `(user_id, user_nid)` pair the rest of the request
/// should run as. Provisions the user if it doesn't exist yet.
///
/// - `query_user_id`: value of the `?user_id=` query param, or None
///   to fall back to the AS's `sender_localpart`.
pub fn resolve_masquerade(
    db: &Arc<Database>,
    server_name: &str,
    appservice: &LiveAppService,
    query_user_id: Option<&str>,
) -> Result<(String, u64), AsAuthError> {
    if !appservice.appservice.enabled {
        return Err(AsAuthError::Disabled);
    }

    let target_user_id = match query_user_id {
        Some(uid) => uid.to_string(),
        None => format!(
            "@{}:{}",
            appservice.appservice.config.sender_localpart, server_name
        ),
    };

    // Target MUST be homed on THIS server. An AS can only act as users it
    // homes locally, never as a user on another homeserver — a namespace
    // regex that isn't anchored to our domain (e.g. `^@_irc_.*`) would
    // otherwise let it masquerade as, and impersonate, a remote user.
    let is_local = target_user_id
        .split_once(':')
        .map(|(_, domain)| domain == server_name)
        .unwrap_or(false);
    if !is_local {
        return Err(AsAuthError::ExclusiveViolation(target_user_id));
    }

    // Target MUST be in the AS's user namespaces.
    if !appservice
        .matcher
        .matches(NamespaceScope::User, &target_user_id)
    {
        return Err(AsAuthError::ExclusiveViolation(target_user_id));
    }

    // Provision the user row if absent. AS users can be created
    // on-demand by virtue of the AS spec: the AS is allowed to act
    // as any user inside its namespace, and they're not required to
    // exist beforehand.
    let user_nid = db
        .get_or_create_nid(&target_user_id)
        .map_err(|e| AsAuthError::Storage(e.to_string()))?;
    // Ensure a `users` row exists (empty password — AS users can't
    // log in via /login). `create_user` is idempotent on the nid
    // side and overwriting with the same hash is a no-op.
    if db
        .get_user(user_nid)
        .map_err(|e| AsAuthError::Storage(e.to_string()))?
        .is_none()
    {
        let _ = db.create_user(&target_user_id, "");
    }

    Ok((target_user_id, user_nid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appservice::namespace::Namespace;
    use crate::appservice::{AppService, AppServiceConfig};
    use crate::test_helpers::build_test_state;

    fn make_as(id: &str, regex: &str, _server: &str) -> AppService {
        AppService {
            nid: 0,
            id: id.into(),
            config: AppServiceConfig {
                url: "http://localhost".into(),
                hs_token_hash: format!("hs-{id}"),
                as_token_hash: hash_token("as-cleartext"),
                sender_localpart: format!("_{id}_bot"),
                receive_ephemeral: false,
            },
            namespaces: vec![Namespace {
                scope: NamespaceScope::User,
                regex: regex.into(),
                exclusive: true,
            }],
            enabled: true,
            owner_nid: None,
            created_at_ms: 0,
        }
    }

    #[test]
    fn lookup_token_resolves_appservice() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make_as("irc", r"^@_irc_.*:example\.com$", "example.com"))
            .unwrap();
        let live = lookup_appservice(&reg, "as-cleartext").expect("found");
        assert_eq!(live.appservice.id, "irc");
    }

    #[test]
    fn masquerade_falls_back_to_sender_localpart() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        // Allow the sender_localpart user — namespace permits it.
        reg.register(make_as("irc", r"^@_irc_bot:example\.com$", "example.com"))
            .unwrap();
        let live = reg.get_by_id("irc").unwrap();
        let (uid, nid) = resolve_masquerade(&state.db, "example.com", &live, None).unwrap();
        assert_eq!(uid, "@_irc_bot:example.com");
        assert!(nid > 0);
    }

    #[test]
    fn masquerade_rejects_user_outside_namespace() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make_as("irc", r"^@_irc_.*:example\.com$", "example.com"))
            .unwrap();
        let live = reg.get_by_id("irc").unwrap();
        let err = resolve_masquerade(&state.db, "example.com", &live, Some("@alice:example.com"))
            .unwrap_err();
        assert!(matches!(err, AsAuthError::ExclusiveViolation(_)));
    }

    #[test]
    fn masquerade_rejects_remote_user_even_within_loose_namespace() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        // A loosely-anchored namespace that also matches a remote domain.
        reg.register(make_as("irc", r"^@_irc_.*", "example.com"))
            .unwrap();
        let live = reg.get_by_id("irc").unwrap();
        // The regex matches, but the user is homed on ANOTHER server → refused.
        let err = resolve_masquerade(
            &state.db,
            "example.com",
            &live,
            Some("@_irc_alice:evil.com"),
        )
        .unwrap_err();
        assert!(
            matches!(err, AsAuthError::ExclusiveViolation(_)),
            "an AS must not masquerade as a user on another homeserver"
        );
        // A LOCAL user in the same loose namespace is still allowed.
        let (uid, _) = resolve_masquerade(
            &state.db,
            "example.com",
            &live,
            Some("@_irc_alice:example.com"),
        )
        .unwrap();
        assert_eq!(uid, "@_irc_alice:example.com");
    }

    #[test]
    fn masquerade_accepts_user_inside_namespace() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make_as("irc", r"^@_irc_.*:example\.com$", "example.com"))
            .unwrap();
        let live = reg.get_by_id("irc").unwrap();
        let (uid, nid) = resolve_masquerade(
            &state.db,
            "example.com",
            &live,
            Some("@_irc_alice:example.com"),
        )
        .unwrap();
        assert_eq!(uid, "@_irc_alice:example.com");
        assert!(nid > 0);
    }
}
