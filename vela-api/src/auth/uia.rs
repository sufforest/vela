//! User-Interactive Authentication (UIA) — minimal `m.login.password` flow.
//!
//! Spec: `references/matrix-spec/content/client-server-api/_index.md` §700–960.
//!
//! A request body either lacks an `auth` field — in which case we issue a
//! 401 challenge — or includes one. We support a single one-stage flow
//! (`m.login.password`); on success the caller proceeds with the operation.
//!
//! Sessions are kept in memory. Single-stage flows don't truly need a
//! session (the second request carries everything we need to decide), but
//! we mint and return one to be spec-conformant for clients that round-trip
//! the id.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use dashmap::DashMap;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::error::ApiError;
use crate::router::AppState;

/// In-memory store of active UIA sessions. Sessions are tiny (just a
/// timestamp); we don't bother with eviction at current scale.
pub type UiaSessions = Arc<DashMap<String, UiaSession>>;

#[derive(Debug, Clone)]
pub struct UiaSession {
    #[allow(dead_code)]
    pub created_at: u64,
}

pub fn new_sessions() -> UiaSessions {
    Arc::new(DashMap::new())
}

/// Outcome of a UIA check that's not a clean success.
///
/// Both variants render to HTTP 401 with the same body shape; `Failed`
/// adds an errcode/error pair so the client knows their attempt was wrong.
#[derive(Debug)]
pub enum UiaError {
    /// First request, no auth provided.
    Challenge { session: String },
    /// Auth provided but invalid (e.g. wrong password).
    Failed {
        session: String,
        errcode: &'static str,
        error: String,
    },
}

impl From<UiaError> for ApiError {
    fn from(e: UiaError) -> Self {
        let body = match &e {
            UiaError::Challenge { session } => challenge_body(session, None),
            UiaError::Failed {
                session,
                errcode,
                error,
            } => {
                let mut body = challenge_body(session, None);
                let obj = body.as_object_mut().unwrap();
                obj.insert("errcode".to_string(), json!(errcode));
                obj.insert("error".to_string(), json!(error));
                body
            }
        };
        ApiError(VelaError::Uia {
            status: 401,
            body: body.to_string(),
        })
    }
}

fn challenge_body(session: &str, completed: Option<&[&str]>) -> Value {
    json!({
        "flows": [{"stages": ["m.login.password"]}],
        "params": {},
        "session": session,
        "completed": completed.unwrap_or(&[]),
    })
}

/// Verify the request's `auth` block presents a valid `m.login.password`
/// for *some* local user. Returns `Ok(())` when the password matches; a
/// `UiaError` otherwise (which the caller converts to an HTTP 401).
///
/// This proves the password holder is someone the server trusts, but NOT
/// that it's the authenticated caller. Every endpoint that uses UIA for
/// step-up auth (the point of which is to contain a stolen token) MUST also
/// call [`require_uia_identifier_matches`] so a stolen token + the
/// attacker's own password can't authorise an action on the victim's
/// account.
pub async fn require_password_auth(state: &AppState, body: &Value) -> Result<(), UiaError> {
    let auth = match body.get("auth") {
        Some(a) if !a.is_null() => a,
        _ => {
            return Err(UiaError::Challenge {
                session: mint_session(state),
            });
        }
    };

    let session = auth
        .get("session")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| mint_session(state));

    let auth_type = auth.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if auth_type != "m.login.password" {
        return Err(UiaError::Failed {
            session,
            errcode: "M_FORBIDDEN",
            error: format!("unsupported auth type: {auth_type}"),
        });
    }

    let user_ref = auth
        .pointer("/identifier/user")
        .and_then(|v| v.as_str())
        .or_else(|| auth.get("user").and_then(|v| v.as_str()));
    let password = auth.get("password").and_then(|v| v.as_str()).unwrap_or("");

    let user_ref = match user_ref {
        Some(u) if !u.is_empty() => u,
        _ => {
            return Err(UiaError::Failed {
                session,
                errcode: "M_FORBIDDEN",
                error: "missing user identifier".into(),
            });
        }
    };

    let user_id = if user_ref.starts_with('@') {
        user_ref.to_lowercase()
    } else {
        format!("@{}:{}", user_ref.to_lowercase(), state.config.server_name)
    };

    // Unknown user, store error and passwordless account all resolve to
    // `None`; `password::verify` then burns one argon2 run against its
    // dummy hash and fails, so every reject takes the same time and
    // surfaces the same error.
    let record = state
        .db
        .get_nid(&user_id)
        .ok()
        .flatten()
        .and_then(|nid| state.db.get_user(nid).ok().flatten());
    let stored_hash = record
        .as_ref()
        .and_then(|r| r.get("password_hash"))
        .and_then(|v| v.as_str());
    if !crate::auth::password::verify(password, stored_hash).await {
        return Err(UiaError::Failed {
            session,
            errcode: "M_FORBIDDEN",
            error: "invalid credentials".into(),
        });
    }

    Ok(())
}

/// Require the UIA `auth.identifier` to resolve to the authenticated caller.
/// 403 on mismatch — so a stolen token plus the attacker's own (valid)
/// password can't authorise a step-up action on the victim's account.
///
/// Call this BEFORE [`require_password_auth`]: checking the identifier first
/// means a mismatch is rejected without ever testing the named account's
/// password, which closes a cross-user password oracle (otherwise a wrong
/// password gives 401 and a right one gives 403, distinguishing them). When
/// no `auth` block is present this is a no-op so `require_password_auth` can
/// still issue the 401 challenge.
pub fn require_uia_identifier_matches(
    state: &AppState,
    body: &Value,
    caller_user_id: &str,
) -> Result<(), ApiError> {
    // No auth block yet → defer to require_password_auth's challenge.
    if body.get("auth").is_none_or(|a| a.is_null()) {
        return Ok(());
    }
    let auth_user = body
        .pointer("/auth/identifier/user")
        .and_then(|v| v.as_str())
        .or_else(|| body.pointer("/auth/user").and_then(|v| v.as_str()))
        .unwrap_or("");
    let auth_user_id = if auth_user.starts_with('@') {
        auth_user.to_lowercase()
    } else {
        format!("@{}:{}", auth_user.to_lowercase(), state.config.server_name)
    };
    if auth_user_id != caller_user_id {
        return Err(ApiError(VelaError::Forbidden(
            "UIA identifier does not match the caller".into(),
        )));
    }
    Ok(())
}

fn mint_session(state: &AppState) -> String {
    let bytes: [u8; 16] = rand::random();
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    state
        .uia_sessions
        .insert(id.clone(), UiaSession { created_at: now });
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    fn register(state: &AppState, user_id: &str, password: &str) {
        let hash = crate::auth::password::hash_sync(password);
        state.db.create_user(user_id, &hash).unwrap();
    }

    #[tokio::test]
    async fn empty_body_returns_challenge() {
        let (state, _tmp) = build_test_state();
        let err = require_password_auth(&state, &json!({}))
            .await
            .expect_err("challenge");
        match err {
            UiaError::Challenge { session } => assert!(!session.is_empty()),
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn wrong_password_returns_failed_with_session_echoed() {
        let (state, _tmp) = build_test_state();
        register(&state, "@alice:example.com", "right");

        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "@alice:example.com"},
                "password": "wrong",
                "session": "client_session_xyz"
            }
        });
        let err = require_password_auth(&state, &body)
            .await
            .expect_err("failed");
        match err {
            UiaError::Failed {
                session, errcode, ..
            } => {
                assert_eq!(session, "client_session_xyz");
                assert_eq!(errcode, "M_FORBIDDEN");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn right_password_succeeds() {
        let (state, _tmp) = build_test_state();
        register(&state, "@alice:example.com", "right");
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "@alice:example.com"},
                "password": "right",
            }
        });
        require_password_auth(&state, &body).await.expect("ok");
    }

    #[tokio::test]
    async fn localpart_only_is_accepted() {
        let (state, _tmp) = build_test_state();
        register(&state, "@bob:example.com", "pw");
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "bob"},
                "password": "pw",
            }
        });
        require_password_auth(&state, &body).await.expect("ok");
    }

    #[tokio::test]
    async fn unknown_user_returns_failed() {
        let (state, _tmp) = build_test_state();
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "@nobody:example.com"},
                "password": "any",
            }
        });
        let err = require_password_auth(&state, &body)
            .await
            .expect_err("failed");
        assert!(matches!(err, UiaError::Failed { .. }));
    }

    /// A passwordless (AS-minted) account must not satisfy UIA — the
    /// empty stored hash routes to the dummy verify and fails.
    #[tokio::test]
    async fn passwordless_account_cannot_pass_uia() {
        let (state, _tmp) = build_test_state();
        state.db.create_user("@asbot:example.com", "").unwrap();
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "@asbot:example.com"},
                "password": "",
            }
        });
        let err = require_password_auth(&state, &body)
            .await
            .expect_err("failed");
        assert!(matches!(err, UiaError::Failed { .. }));
    }

    #[tokio::test]
    async fn unsupported_auth_type_returns_failed() {
        let (state, _tmp) = build_test_state();
        let body = json!({
            "auth": {"type": "m.login.token", "token": "x"}
        });
        let err = require_password_auth(&state, &body)
            .await
            .expect_err("failed");
        assert!(matches!(err, UiaError::Failed { .. }));
    }

    /// The UIA must be completed AS the caller: an identifier for a DIFFERENT
    /// account (even with that account's correct password) is refused by
    /// `require_uia_identifier_matches`. Localpart and full-MXID identifiers
    /// both resolve before comparison.
    #[test]
    fn identifier_must_match_caller() {
        let (state, _tmp) = build_test_state();
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "@attacker:example.com"},
                "password": "pw",
            }
        });
        // Caller is the victim → mismatch → forbidden.
        require_uia_identifier_matches(&state, &body, "@victim:example.com")
            .expect_err("cross-account UIA must be refused");
        // Caller is the attacker (own account) → allowed.
        require_uia_identifier_matches(&state, &body, "@attacker:example.com")
            .expect("matching identifier ok");
        // Localpart identifier resolves to the full MXID before comparison.
        let local = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "bob"},
                "password": "pw",
            }
        });
        require_uia_identifier_matches(&state, &local, "@bob:example.com")
            .expect("localpart matches full mxid");
    }
}
