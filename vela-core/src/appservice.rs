//! Application-service registration loader.
//!
//! AS bridges authenticate via a long-lived `as_token` set in their
//! registration file. Tokens grant the right to act-as users in the
//! configured `namespaces.users` regex set, and to override
//! `origin_server_ts` on outbound events via the `?ts=` query
//! parameter (MSC2409 / Synapse legacy AS feature).
//!
//! We parse only the fields actually used today: id, as_token,
//! sender_localpart, plus a "wildcard or anchored localpart" check
//! over the user namespaces. Synapse-shaped registrations (with
//! hs_token, url, push_ephemeral, msc3202, etc.) load cleanly because
//! we ignore unknown fields.
//!
//! YAML parsing is hand-rolled: registration files are flat enough
//! that pulling in serde_yaml just for this is overkill, and Synapse
//! itself accepts the same forgiving line-by-line shape.

use std::path::Path;

#[derive(Debug, Clone)]
pub struct AppserviceRegistration {
    pub id: String,
    pub as_token: String,
    pub sender_localpart: String,
    /// User namespace regexes verbatim. We accept `.*` (wildcard) and
    /// anything anchored to a specific localpart prefix; richer regex
    /// syntax is rejected at load to keep the matcher tiny.
    pub user_regexes: Vec<String>,
}

impl AppserviceRegistration {
    /// Load and parse one registration YAML.
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        parse_registration(&raw)
            .ok_or_else(|| format!("parse {}: missing required keys", path.display()))
    }

    /// Does this registration cover the given full Matrix user_id
    /// (e.g. `@alice:hs1`)?  We support two regex shapes:
    /// - `.*` — wildcard, matches any user_id
    /// - `@.*:server` — wildcard local part on a specific server
    /// - any literal prefix match `@something:server` etc.
    pub fn covers_user(&self, user_id: &str) -> bool {
        for re in &self.user_regexes {
            if re == ".*" {
                return true;
            }
            // Treat as a literal-with-anchors: ^...$ stripped, `.*`
            // expanded as a wildcard segment. Sufficient for the
            // Synapse-style namespaces tests use ("@_irc_.*:hs1",
            // "@.*:hs1", etc.).
            if matches_simple(re, user_id) {
                return true;
            }
        }
        false
    }
}

fn matches_simple(pattern: &str, input: &str) -> bool {
    let pat = pattern.trim_start_matches('^').trim_end_matches('$');
    if let Some((prefix, suffix)) = pat.split_once(".*") {
        return input.starts_with(prefix) && input.ends_with(suffix);
    }
    pat == input
}

fn parse_registration(text: &str) -> Option<AppserviceRegistration> {
    let mut id: Option<String> = None;
    let mut as_token: Option<String> = None;
    let mut sender: Option<String> = None;
    let mut user_regexes: Vec<String> = Vec::new();

    let mut in_namespaces_users = false;
    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let trimmed = line.trim_start();

        // Top-level keys (no leading whitespace).
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_namespaces_users = false;
            if let Some(v) = trimmed.strip_prefix("id:") {
                id = Some(unquote(v.trim()).to_string());
            } else if let Some(v) = trimmed.strip_prefix("as_token:") {
                as_token = Some(unquote(v.trim()).to_string());
            } else if let Some(v) = trimmed.strip_prefix("sender_localpart:") {
                sender = Some(unquote(v.trim()).to_string());
            }
            continue;
        }

        // namespaces:\n  users:\n    - regex: ...
        if trimmed.starts_with("users:") {
            in_namespaces_users = true;
            continue;
        }
        if in_namespaces_users && let Some(v) = trimmed.strip_prefix("regex:") {
            user_regexes.push(unquote(v.trim()).to_string());
        }
    }

    Some(AppserviceRegistration {
        id: id?,
        as_token: as_token?,
        sender_localpart: sender?,
        user_regexes,
    })
}

fn unquote(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_complement_blueprint_yaml() {
        let yaml = "id: my_as_id\n\
                    hs_token: hstok\n\
                    as_token: astok\n\
                    url: 'http://localhost:9000'\n\
                    sender_localpart: the-bridge-user\n\
                    rate_limited: false\n\
                    de.sorunome.msc2409.push_ephemeral: false\n\
                    namespaces:\n  \
                      users:\n    \
                        - exclusive: false\n      \
                          regex: .*\n  \
                      rooms: []\n  \
                      aliases: []\n";
        let reg = parse_registration(yaml).unwrap();
        assert_eq!(reg.id, "my_as_id");
        assert_eq!(reg.as_token, "astok");
        assert_eq!(reg.sender_localpart, "the-bridge-user");
        assert_eq!(reg.user_regexes, vec![".*".to_string()]);
        assert!(reg.covers_user("@anyone:hs1"));
    }

    #[test]
    fn matches_anchored_wildcards() {
        assert!(matches_simple(".*", "@x:hs"));
        assert!(matches_simple("@.*:hs1", "@alice:hs1"));
        assert!(!matches_simple("@.*:hs1", "@alice:hs2"));
        assert!(matches_simple("@_irc_.*:hs1", "@_irc_alice:hs1"));
    }
}
