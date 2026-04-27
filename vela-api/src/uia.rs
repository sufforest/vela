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
/// We deliberately do *not* require the authenticated session's user to
/// match the identifier supplied in `auth.identifier` — UIA proves the
/// password holder is *someone* the server trusts. Endpoints that need
/// stronger ownership guarantees should additionally compare against
/// their `AuthenticatedUser` extractor.
pub fn require_password_auth(state: &AppState, body: &Value) -> Result<(), UiaError> {
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

    let user_nid = match state.db.get_nid(&user_id) {
        Ok(Some(n)) => n,
        _ => {
            return Err(UiaError::Failed {
                session,
                errcode: "M_FORBIDDEN",
                error: "invalid credentials".into(),
            });
        }
    };
    let record = match state.db.get_user(user_nid) {
        Ok(Some(r)) => r,
        _ => {
            return Err(UiaError::Failed {
                session,
                errcode: "M_FORBIDDEN",
                error: "invalid credentials".into(),
            });
        }
    };
    let stored_hash = record["password_hash"].as_str().unwrap_or("");
    if stored_hash.is_empty() || !verify_password(password, stored_hash) {
        return Err(UiaError::Failed {
            session,
            errcode: "M_FORBIDDEN",
            error: "invalid credentials".into(),
        });
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

fn verify_password(password: &str, stored_hash: &str) -> bool {
    use argon2::Argon2;
    use argon2::PasswordVerifier;
    use argon2::password_hash::PasswordHash;

    let parsed = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    fn register(state: &AppState, user_id: &str, password: &str) {
        use argon2::password_hash::SaltString;
        use argon2::{Argon2, PasswordHasher};
        let salt: [u8; 16] = rand::random();
        let salt_str = SaltString::encode_b64(&salt).unwrap();
        let hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt_str)
            .unwrap()
            .to_string();
        state.db.create_user(user_id, &hash).unwrap();
    }

    #[test]
    fn empty_body_returns_challenge() {
        let (state, _tmp) = build_test_state();
        let err = require_password_auth(&state, &json!({})).expect_err("challenge");
        match err {
            UiaError::Challenge { session } => assert!(!session.is_empty()),
            other => panic!("expected Challenge, got {other:?}"),
        }
    }

    #[test]
    fn wrong_password_returns_failed_with_session_echoed() {
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
        let err = require_password_auth(&state, &body).expect_err("failed");
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

    #[test]
    fn right_password_succeeds() {
        let (state, _tmp) = build_test_state();
        register(&state, "@alice:example.com", "right");
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "@alice:example.com"},
                "password": "right",
            }
        });
        require_password_auth(&state, &body).expect("ok");
    }

    #[test]
    fn localpart_only_is_accepted() {
        let (state, _tmp) = build_test_state();
        register(&state, "@bob:example.com", "pw");
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "bob"},
                "password": "pw",
            }
        });
        require_password_auth(&state, &body).expect("ok");
    }

    #[test]
    fn unknown_user_returns_failed() {
        let (state, _tmp) = build_test_state();
        let body = json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "@nobody:example.com"},
                "password": "any",
            }
        });
        let err = require_password_auth(&state, &body).expect_err("failed");
        assert!(matches!(err, UiaError::Failed { .. }));
    }

    #[test]
    fn unsupported_auth_type_returns_failed() {
        let (state, _tmp) = build_test_state();
        let body = json!({
            "auth": {"type": "m.login.token", "token": "x"}
        });
        let err = require_password_auth(&state, &body).expect_err("failed");
        assert!(matches!(err, UiaError::Failed { .. }));
    }
}
