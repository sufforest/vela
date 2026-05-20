//! Event interest filter. Given a persisted event, find every AS
//! whose namespaces cover it. Called from local `send` and from
//! `federation_receive` so federated events also trigger delivery.

use std::sync::Arc;

use crate::appservice::namespace::NamespaceScope;
use crate::appservice::registry::{AsRegistry, LiveAppService};

#[derive(Debug, Clone)]
pub struct InterestEvent<'a> {
    pub room_id: &'a str,
    pub sender: &'a str,
    pub state_key: Option<&'a str>,
}

/// Return every enabled AS whose namespaces include this event.
pub fn matching(registry: &Arc<AsRegistry>, event: &InterestEvent<'_>) -> Vec<LiveAppService> {
    registry
        .list()
        .into_iter()
        .filter(|live| {
            live.appservice.enabled
                && (live.matcher.matches(NamespaceScope::Room, event.room_id)
                    || live.matcher.matches(NamespaceScope::User, event.sender)
                    || event
                        .state_key
                        .is_some_and(|sk| live.matcher.matches(NamespaceScope::User, sk)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appservice::namespace::Namespace;
    use crate::appservice::{AppService, AppServiceConfig};
    use crate::test_helpers::build_test_state;

    fn ns(scope: NamespaceScope, regex: &str) -> Namespace {
        Namespace {
            scope,
            regex: regex.into(),
            exclusive: false,
        }
    }

    fn make(id: &str, namespaces: Vec<Namespace>) -> AppService {
        AppService {
            nid: 0,
            id: id.into(),
            config: AppServiceConfig {
                url: "http://localhost".into(),
                hs_token_hash: format!("hs-{id}"),
                as_token_hash: format!("as-{id}"),
                sender_localpart: "_bot".into(),
                receive_ephemeral: false,
            },
            namespaces,
            enabled: true,
            owner_nid: None,
            created_at_ms: 0,
        }
    }

    #[test]
    fn room_namespace_match() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make(
            "bridge",
            vec![ns(NamespaceScope::Room, r"^!bridge:.*$")],
        ))
        .unwrap();
        let hits = matching(
            &reg,
            &InterestEvent {
                room_id: "!bridge:example.com",
                sender: "@anyone:other.com",
                state_key: None,
            },
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn user_namespace_on_sender() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make(
            "irc",
            vec![ns(NamespaceScope::User, r"^@_irc_.*:example\.com$")],
        ))
        .unwrap();
        let hits = matching(
            &reg,
            &InterestEvent {
                room_id: "!unrelated:example.com",
                sender: "@_irc_alice:example.com",
                state_key: None,
            },
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn user_namespace_on_member_state_key() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        reg.register(make("irc", vec![ns(NamespaceScope::User, r"^@_irc_.*$")]))
            .unwrap();
        let hits = matching(
            &reg,
            &InterestEvent {
                room_id: "!any:example.com",
                sender: "@alice:example.com",
                state_key: Some("@_irc_bob:example.com"),
            },
        );
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn disabled_skipped() {
        let (state, _tmp) = build_test_state();
        let reg = Arc::new(AsRegistry::open(state.db.clone()).unwrap());
        let asv = reg
            .register(make("b", vec![ns(NamespaceScope::Room, r"^!.*$")]))
            .unwrap();
        reg.set_enabled(asv.nid, false).unwrap();
        let hits = matching(
            &reg,
            &InterestEvent {
                room_id: "!x:example.com",
                sender: "@a:example.com",
                state_key: None,
            },
        );
        assert!(hits.is_empty());
    }
}
