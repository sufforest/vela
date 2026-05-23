//! `m.room.server_acl` evaluation. Shared by every federation
//! handler that mutates room state on behalf of a remote server —
//! `/send/{txn}`, `/make_join`, `/send_join`, `/make_knock`,
//! `/send_knock`, `/make_leave`, `/send_leave`, `/v2/invite`. Without
//! a single shared check, a banned server can side-door joins / knocks
//! / leaves / invites past the receive_transaction gate.

use axum::http::StatusCode;
use serde_json::{Value, json};

use crate::middleware::json::Json;
use crate::router::AppState;
use vela_store::db::Database;

/// Federation-handler convenience wrapper: 403 with `server_acl:`
/// reason when the origin is banned, `Ok(())` otherwise.
pub(crate) fn deny_if_blocked(
    state: &AppState,
    room_nid: u64,
    origin: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(reason) = check_server_acl(state, room_nid, origin) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "errcode": "M_FORBIDDEN",
                "error": format!("server_acl: {reason}"),
            })),
        ));
    }
    Ok(())
}

/// Apply the room's `m.room.server_acl` to `sender_domain`. Returns
/// `Some(reason)` when the sender should be rejected, `None` when it
/// passes (or when no ACL exists).
///
/// Spec semantics (server-server "Server Access Control Lists"):
/// - The sender domain must NOT match any pattern in `deny`.
/// - The sender domain MUST match at least one pattern in `allow`.
///   (`allow` defaults to `["*"]` when omitted; an empty list blocks
///   everyone, which is intentional per the spec.)
/// - When `allow_ip_literals` is `false`, IP-literal sender domains
///   are rejected even if the allow/deny rules would otherwise permit
///   them.
///
/// Patterns are glob-style: `*` matches any run of characters, `?`
/// matches a single character.
pub(crate) fn check_server_acl(
    state: &AppState,
    room_nid: u64,
    sender_domain: &str,
) -> Option<String> {
    check_server_acl_db(&state.db, room_nid, sender_domain)
}

/// `Database`-only variant for code paths (EDU streams) that don't
/// carry a full `AppState`. Same semantics as `check_server_acl`.
pub fn check_server_acl_db(db: &Database, room_nid: u64, sender_domain: &str) -> Option<String> {
    let acl = load_room_state_content_db(db, room_nid, "m.room.server_acl", "")?;

    let allow_ip_literals = acl
        .get("allow_ip_literals")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let allow: Vec<&str> = acl
        .get("allow")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str()).collect())
        .unwrap_or_else(|| vec!["*"]);
    let deny: Vec<&str> = acl
        .get("deny")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str()).collect())
        .unwrap_or_default();

    if !allow_ip_literals && is_ip_literal(sender_domain) {
        return Some(format!(
            "sender {sender_domain} is an IP literal but allow_ip_literals=false"
        ));
    }
    for pat in &deny {
        if glob_match(pat, sender_domain) {
            return Some(format!("sender {sender_domain} matches deny pattern {pat}"));
        }
    }
    if !allow.iter().any(|pat| glob_match(pat, sender_domain)) {
        return Some(format!("sender {sender_domain} matches no allow pattern"));
    }
    None
}

fn load_room_state_content_db(
    db: &Database,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Option<Value> {
    let type_nid = db.get_nid(event_type).ok().flatten()?;
    let sk_nid = db.get_nid(state_key).ok().flatten()?;
    let event_nid = db
        .get_state_event_nid(room_nid, type_nid, sk_nid)
        .ok()
        .flatten()?;
    let (_h, bytes) = db.get_event(event_nid).ok().flatten()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("content").cloned()
}

fn glob_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = s.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let (mut star_i, mut star_j): (Option<usize>, usize) = (None, 0);
    while j < s.len() {
        if i < p.len() && (p[i] == '?' || p[i] == s[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star_i = Some(i);
            star_j = j;
            i += 1;
        } else if let Some(si) = star_i {
            i = si + 1;
            star_j += 1;
            j = star_j;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

fn is_ip_literal(domain: &str) -> bool {
    use std::net::IpAddr;
    use std::str::FromStr;
    if let Some(rest) = domain.strip_prefix('[') {
        let host = rest.split(']').next().unwrap_or("");
        return IpAddr::from_str(host).is_ok();
    }
    let host = domain.split(':').next().unwrap_or(domain);
    IpAddr::from_str(host).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_wildcards() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*.example.com", "evil.example.com"));
        assert!(!glob_match("*.example.com", "example.com"));
        assert!(glob_match("evil.com", "evil.com"));
        assert!(!glob_match("evil.com", "evil.com.attacker.tld"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
    }

    #[test]
    fn ip_literal_detection() {
        assert!(is_ip_literal("127.0.0.1"));
        assert!(is_ip_literal("127.0.0.1:8448"));
        assert!(is_ip_literal("[::1]"));
        assert!(is_ip_literal("[::1]:8448"));
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("matrix.org:8448"));
        assert!(!is_ip_literal("1.2.3.4.example.com"));
    }
}
