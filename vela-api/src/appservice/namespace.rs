//! AS namespace matching. An AS declares which user IDs, room IDs,
//! and aliases it's interested in via regex patterns; the
//! `NamespaceMatcher` compiles those once at registration time and
//! matches events in O(N namespaces) per lookup.

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceScope {
    User,
    Alias,
    Room,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    pub scope: NamespaceScope,
    pub regex: String,
    pub exclusive: bool,
}

#[derive(Debug, Clone)]
pub struct NamespaceMatcher {
    compiled: Vec<(NamespaceScope, Regex, bool)>,
}

#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("invalid regex `{pattern}`: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },
}

impl NamespaceMatcher {
    pub fn compile(namespaces: &[Namespace]) -> Result<Self, NamespaceError> {
        let mut compiled = Vec::with_capacity(namespaces.len());
        for ns in namespaces {
            let re = Regex::new(&ns.regex).map_err(|e| NamespaceError::InvalidRegex {
                pattern: ns.regex.clone(),
                source: e,
            })?;
            compiled.push((ns.scope, re, ns.exclusive));
        }
        Ok(Self { compiled })
    }

    pub fn matches(&self, scope: NamespaceScope, identifier: &str) -> bool {
        self.compiled
            .iter()
            .any(|(s, r, _)| *s == scope && r.is_match(identifier))
    }

    pub fn matches_exclusive(&self, scope: NamespaceScope, identifier: &str) -> bool {
        self.compiled
            .iter()
            .any(|(s, r, excl)| *s == scope && *excl && r.is_match(identifier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(scope: NamespaceScope, regex: &str, exclusive: bool) -> Namespace {
        Namespace {
            scope,
            regex: regex.into(),
            exclusive,
        }
    }

    #[test]
    fn matches_basic_patterns() {
        let m = NamespaceMatcher::compile(&[
            ns(NamespaceScope::User, r"^@_irc_.*:example\.com$", true),
            ns(NamespaceScope::Alias, r"^#_irc_.*:example\.com$", false),
        ])
        .unwrap();
        assert!(m.matches(NamespaceScope::User, "@_irc_alice:example.com"));
        assert!(!m.matches(NamespaceScope::User, "@alice:example.com"));
        assert!(!m.matches(NamespaceScope::User, "@_irc_alice:other.com"));
        assert!(m.matches(NamespaceScope::Alias, "#_irc_chan:example.com"));
        assert!(!m.matches(NamespaceScope::Room, "@_irc_alice:example.com"));
    }

    #[test]
    fn exclusive_is_distinct_from_match() {
        let m = NamespaceMatcher::compile(&[
            ns(NamespaceScope::User, r"^@_irc_.*", true),
            ns(NamespaceScope::User, r"^@bot_.*", false),
        ])
        .unwrap();
        assert!(m.matches(NamespaceScope::User, "@_irc_x:s"));
        assert!(m.matches(NamespaceScope::User, "@bot_x:s"));
        assert!(m.matches_exclusive(NamespaceScope::User, "@_irc_x:s"));
        assert!(!m.matches_exclusive(NamespaceScope::User, "@bot_x:s"));
    }

    #[test]
    fn invalid_regex_errors() {
        let err =
            NamespaceMatcher::compile(&[ns(NamespaceScope::User, "[invalid(", false)]).unwrap_err();
        assert!(matches!(err, NamespaceError::InvalidRegex { .. }));
    }
}
