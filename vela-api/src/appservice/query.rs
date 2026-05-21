//! HS → AS queries. When a federated or local request references a
//! namespaced entity that doesn't exist locally yet, the homeserver
//! asks the owning AS "do you own this?" via these GET endpoints.
//! Per AS spec, a 200 means yes (and the AS is expected to have
//! provisioned the entity by the time the response returns); 404
//! means no.
//!
//! Used by:
//!   - `directory::resolve_local_alias` for unknown aliases
//!   - `membership::invite_user_internal` for unknown user_ids
//!
//! The HS authenticates these calls with its cleartext `hs_token`
//! (the same one used on transaction delivery), via `Bearer`.

use std::sync::Arc;
use std::time::Duration;

use crate::appservice::LiveAppService;
use crate::appservice::namespace::NamespaceScope;
use crate::appservice::registry::AsRegistry;

/// Per-call timeout for HS→AS queries. Shorter than the 35s
/// transaction-delivery timeout: a slow AS here blocks the client's
/// /directory/room/... or /invite request, so we'd rather 404 fast
/// than make the user wait a full half-minute for a sluggish bridge.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// First registered AS whose namespaces match this user_id (exclusive
/// or not). `None` if no AS claims it.
pub fn find_as_owning_user(registry: &Arc<AsRegistry>, user_id: &str) -> Option<LiveAppService> {
    for live in registry.list() {
        if !live.appservice.enabled {
            continue;
        }
        if live.matcher.matches(NamespaceScope::User, user_id) {
            return Some(live);
        }
    }
    None
}

/// Same for aliases.
pub fn find_as_owning_alias(registry: &Arc<AsRegistry>, alias: &str) -> Option<LiveAppService> {
    for live in registry.list() {
        if !live.appservice.enabled {
            continue;
        }
        if live.matcher.matches(NamespaceScope::Alias, alias) {
            return Some(live);
        }
    }
    None
}

/// Outcome of a single query call.
#[derive(Debug)]
pub enum QueryOutcome {
    /// AS confirmed ownership (200). The HS should re-read its local
    /// state — the AS is expected to have provisioned by now.
    Owned,
    /// AS disclaimed ownership (404). Treat as if no AS owns it.
    NotOwned,
    /// Network / 5xx / unparseable response. The HS should treat this
    /// as "no answer" and fall through to its usual 404 path; we
    /// don't want a flaky AS to block client requests indefinitely.
    Unavailable(String),
}

/// `GET {as_url}/_matrix/app/v1/users/{userId}`. Spec: HS uses the
/// AS's `hs_token` (cleartext) as a `Bearer`.
pub async fn query_user(
    http: &reqwest::Client,
    cleartext_hs_token: &str,
    live: &LiveAppService,
    user_id: &str,
) -> QueryOutcome {
    let url = format!(
        "{}/_matrix/app/v1/users/{}",
        live.appservice.config.url.trim_end_matches('/'),
        urlencode_segment(user_id),
    );
    send_get(http, &url, cleartext_hs_token).await
}

/// `GET {as_url}/_matrix/app/v1/rooms/{roomAlias}`.
pub async fn query_alias(
    http: &reqwest::Client,
    cleartext_hs_token: &str,
    live: &LiveAppService,
    alias: &str,
) -> QueryOutcome {
    let url = format!(
        "{}/_matrix/app/v1/rooms/{}",
        live.appservice.config.url.trim_end_matches('/'),
        urlencode_segment(alias),
    );
    send_get(http, &url, cleartext_hs_token).await
}

async fn send_get(http: &reqwest::Client, url: &str, hs_token: &str) -> QueryOutcome {
    let resp = match http
        .get(url)
        .bearer_auth(hs_token)
        .timeout(QUERY_TIMEOUT)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => return QueryOutcome::Unavailable(format!("network: {e}")),
    };
    match resp.status().as_u16() {
        200 => QueryOutcome::Owned,
        404 => QueryOutcome::NotOwned,
        other => QueryOutcome::Unavailable(format!("status: {other}")),
    }
}

/// Percent-encode a single path segment. user_ids and aliases can
/// contain `:` / `@` / `#` and the spec mandates URL-encoding before
/// substitution.
fn urlencode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write;
            write!(&mut out, "%{:02X}", b).unwrap();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appservice::namespace::{Namespace, NamespaceScope};
    use crate::appservice::{AppService, AppServiceConfig, hash_token};
    use crate::test_helpers::build_test_state;

    fn make_as(id: &str, regex: &str, scope: NamespaceScope, url: &str) -> AppService {
        AppService {
            nid: 0,
            id: id.into(),
            config: AppServiceConfig {
                url: url.into(),
                hs_token_hash: hash_token("hs-cleartext"),
                as_token_hash: hash_token("as-cleartext"),
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
    fn find_owning_user_returns_matching_as() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make_as(
            "irc",
            r"^@_irc_.*:example\.com$",
            NamespaceScope::User,
            "http://localhost",
        ))
        .unwrap();
        let found = find_as_owning_user(&reg, "@_irc_alice:example.com").expect("found");
        assert_eq!(found.appservice.id, "irc");
        assert!(find_as_owning_user(&reg, "@alice:example.com").is_none());
    }

    #[test]
    fn find_owning_user_skips_disabled() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let asv = reg
            .register(make_as(
                "irc",
                r"^@_irc_.*:example\.com$",
                NamespaceScope::User,
                "http://localhost",
            ))
            .unwrap();
        reg.set_enabled(asv.nid, false).unwrap();
        assert!(find_as_owning_user(&reg, "@_irc_alice:example.com").is_none());
    }

    #[tokio::test]
    async fn query_user_200_is_owned() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(r"^/_matrix/app/v1/users/.*"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let asv = reg
            .register(make_as(
                "irc",
                r"^@_irc_.*$",
                NamespaceScope::User,
                &server.uri(),
            ))
            .unwrap();
        let live = reg.get(asv.nid).unwrap();
        let http = reqwest::Client::new();
        let outcome = query_user(&http, "hs-cleartext", &live, "@_irc_alice:example.com").await;
        assert!(matches!(outcome, QueryOutcome::Owned));
    }

    #[tokio::test]
    async fn query_alias_404_is_not_owned() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(r"^/_matrix/app/v1/rooms/.*"))
            .respond_with(wiremock::ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let asv = reg
            .register(make_as(
                "irc",
                r"^#_irc_.*$",
                NamespaceScope::Alias,
                &server.uri(),
            ))
            .unwrap();
        let live = reg.get(asv.nid).unwrap();
        let http = reqwest::Client::new();
        let outcome = query_alias(&http, "hs-cleartext", &live, "#_irc_unknown:example.com").await;
        assert!(matches!(outcome, QueryOutcome::NotOwned));
    }
}
