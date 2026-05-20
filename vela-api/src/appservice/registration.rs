//! Parse an Application Service registration document into the
//! framework's `AppService` shape. Input is the YAML the AS process
//! generated (per the AS spec's `info` example) or operator-authored
//! equivalent. We accept both YAML and JSON since the spec doesn't
//! formally mandate either.

use serde::Deserialize;
use thiserror::Error;

use crate::appservice::namespace::{Namespace, NamespaceScope};
use crate::appservice::{AppService, AppServiceConfig, hash_token};

/// Output of a successful parse, ready to hand to `AsRegistry::register`.
/// The cleartext tokens are *also* returned so the admin command can
/// show them to the operator once — they're not stored anywhere
/// except the registry's hashed form.
#[derive(Debug, Clone)]
pub struct ParsedRegistration {
    pub appservice: AppService,
    /// Cleartext `as_token` from the YAML. Operator copy/pastes once.
    pub as_token_cleartext: String,
    /// Cleartext `hs_token` from the YAML. Operator forwards to the AS.
    pub hs_token_cleartext: String,
}

#[derive(Debug, Error)]
pub enum RegistrationError {
    #[error("malformed registration document: {0}")]
    Parse(String),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid {field}: {reason}")]
    InvalidField { field: &'static str, reason: String },
}

/// Raw deserialised shape, mirroring the AS spec's YAML schema.
#[derive(Debug, Deserialize)]
struct RawRegistration {
    id: String,
    url: String,
    as_token: String,
    hs_token: String,
    sender_localpart: String,
    #[serde(default)]
    namespaces: RawNamespaces,
    #[serde(default)]
    receive_ephemeral: bool,
}

#[derive(Debug, Default, Deserialize)]
struct RawNamespaces {
    #[serde(default)]
    users: Vec<RawNs>,
    #[serde(default)]
    aliases: Vec<RawNs>,
    #[serde(default)]
    rooms: Vec<RawNs>,
}

#[derive(Debug, Deserialize)]
struct RawNs {
    #[serde(default)]
    exclusive: bool,
    regex: String,
}

/// Parse a registration document. Accepts YAML or JSON — tries YAML
/// first since that's the spec's canonical format; falls through to
/// JSON since some operators paste JSON.
pub fn parse(input: &str) -> Result<ParsedRegistration, RegistrationError> {
    let raw: RawRegistration = match serde_yaml::from_str(input) {
        Ok(v) => v,
        Err(yaml_err) => match serde_json::from_str(input) {
            Ok(v) => v,
            Err(_) => return Err(RegistrationError::Parse(yaml_err.to_string())),
        },
    };

    // Spec: id, url, as_token, hs_token, sender_localpart all required.
    // serde already errored on missing fields above; non-empty checks:
    let id = require_nonempty("id", &raw.id)?;
    let url = require_nonempty("url", &raw.url)?;
    let as_token = require_nonempty("as_token", &raw.as_token)?;
    let hs_token = require_nonempty("hs_token", &raw.hs_token)?;
    let sender_localpart = require_nonempty("sender_localpart", &raw.sender_localpart)?;

    let mut namespaces = Vec::new();
    for n in raw.namespaces.users {
        namespaces.push(check_regex(NamespaceScope::User, n)?);
    }
    for n in raw.namespaces.aliases {
        namespaces.push(check_regex(NamespaceScope::Alias, n)?);
    }
    for n in raw.namespaces.rooms {
        namespaces.push(check_regex(NamespaceScope::Room, n)?);
    }

    let appservice = AppService {
        nid: 0, // assigned at registry insert
        id: id.into(),
        config: AppServiceConfig {
            url: url.into(),
            hs_token_hash: hash_token(hs_token),
            as_token_hash: hash_token(as_token),
            sender_localpart: sender_localpart.into(),
            receive_ephemeral: raw.receive_ephemeral,
        },
        namespaces,
        enabled: true,
        owner_nid: None,
        created_at_ms: 0, // set by registry
    };

    Ok(ParsedRegistration {
        appservice,
        as_token_cleartext: as_token.to_string(),
        hs_token_cleartext: hs_token.to_string(),
    })
}

fn require_nonempty<'a>(field: &'static str, value: &'a str) -> Result<&'a str, RegistrationError> {
    let t = value.trim();
    if t.is_empty() {
        return Err(RegistrationError::MissingField(field));
    }
    Ok(t)
}

fn check_regex(scope: NamespaceScope, raw: RawNs) -> Result<Namespace, RegistrationError> {
    // Compile to validate; the matcher will recompile internally but
    // we want the operator's bad regex to fail with a clear message
    // at registration time, not later in the worker.
    if let Err(e) = regex::Regex::new(&raw.regex) {
        return Err(RegistrationError::InvalidField {
            field: "namespace regex",
            reason: format!("`{}`: {e}", raw.regex),
        });
    }
    Ok(Namespace {
        scope,
        regex: raw.regex,
        exclusive: raw.exclusive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_YAML: &str = r##"
id: "IRC Bridge"
url: "http://127.0.0.1:1234"
as_token: "as-tok-secret"
hs_token: "hs-tok-secret"
sender_localpart: "_irc_bot"
namespaces:
  users:
    - exclusive: true
      regex: "@_irc_bridge_.*"
  aliases:
    - exclusive: false
      regex: "#_irc_bridge_.*"
"##;

    #[test]
    fn parses_spec_example() {
        let p = parse(SAMPLE_YAML).unwrap();
        assert_eq!(p.appservice.id, "IRC Bridge");
        assert_eq!(p.appservice.config.url, "http://127.0.0.1:1234");
        assert_eq!(p.appservice.config.sender_localpart, "_irc_bot");
        assert_eq!(p.appservice.namespaces.len(), 2);
        // Token hashes are stored; cleartext is returned separately.
        assert!(!p.appservice.config.as_token_hash.is_empty());
        assert!(!p.appservice.config.hs_token_hash.is_empty());
        assert_eq!(p.as_token_cleartext, "as-tok-secret");
        assert_eq!(p.hs_token_cleartext, "hs-tok-secret");
    }

    #[test]
    fn rejects_empty_fields() {
        let bad = r#"
id: ""
url: "http://x"
as_token: "a"
hs_token: "h"
sender_localpart: "bot"
"#;
        assert!(matches!(
            parse(bad),
            Err(RegistrationError::MissingField("id"))
        ));
    }

    #[test]
    fn rejects_bad_regex() {
        let bad = r#"
id: "x"
url: "http://x"
as_token: "a"
hs_token: "h"
sender_localpart: "bot"
namespaces:
  users:
    - regex: "[invalid("
"#;
        assert!(matches!(
            parse(bad),
            Err(RegistrationError::InvalidField { .. })
        ));
    }

    #[test]
    fn accepts_json_too() {
        let json = r#"{
            "id": "Bot",
            "url": "http://x",
            "as_token": "a",
            "hs_token": "h",
            "sender_localpart": "bot",
            "namespaces": {
                "users": [{"regex": "^@bot_.*", "exclusive": false}]
            }
        }"#;
        let p = parse(json).unwrap();
        assert_eq!(p.appservice.id, "Bot");
    }
}
