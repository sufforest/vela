//! `POST /_matrix/client/v3/logout` and `/_matrix/client/v3/logout/all`.
//!
//! Spec: `client-server-api/#post_matrixclientv3logout`.
//!
//! `/logout` invalidates the access + refresh tokens tied to the
//! caller's device. `/logout/all` invalidates every token for the
//! caller's user account across all devices.
//!
//! The auth middleware has already validated the access token and
//! attached the `AuthenticatedUser` extractor, so we just delete the
//! tokens from storage.

use axum::Json;
use axum::extract::State;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// `POST /_matrix/client/v3/logout`
///
/// Invalidates the access + refresh tokens for the device that
/// authenticated this request and also drops the device record itself
/// — spec contract: a logged-out device MUST disappear from
/// `GET /devices`. Other devices' sessions stay live.
pub async fn logout(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    state
        .db
        .delete_device_tokens(user.user_nid, &user.device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    state
        .db
        .delete_device(user.user_nid, &user.device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({})))
}

/// `POST /_matrix/client/v3/logout/all`
///
/// Invalidates every access + refresh token for the caller's user
/// across all devices, AND removes every device record. Used for
/// "log out everywhere" buttons.
pub async fn logout_all(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    state
        .db
        .delete_user_tokens(user.user_nid, None)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let devices = state
        .db
        .list_devices(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for d in devices {
        if let Some(device_id) = d.get("device_id").and_then(|v| v.as_str()) {
            state
                .db
                .delete_device(user.user_nid, device_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        }
    }
    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    fn register(state: &AppState, user_id: &str) -> (u64, String, String) {
        let nid = state.db.create_user(user_id, "hash").unwrap();
        let device_id = "DEV1".to_string();
        state.db.create_device(nid, &device_id).unwrap();
        let token = state.db.create_token(nid, &device_id).unwrap();
        (nid, device_id, token)
    }

    #[tokio::test]
    async fn logout_invalidates_only_callers_device_tokens() {
        let (state, _tmp) = build_test_state();
        let (alice_nid, dev1, tok1) = register(&state, "@alice:example.com");

        // A second device for the same user — must survive `/logout`.
        let dev2 = "DEV2";
        state.db.create_device(alice_nid, dev2).unwrap();
        let tok2 = state.db.create_token(alice_nid, dev2).unwrap();

        let _ = logout(
            State(state.clone()),
            AuthenticatedUser {
                user_nid: alice_nid,
                user_id: "@alice:example.com".into(),
                device_id: dev1.clone(),
                is_appservice: false,
            },
        )
        .await
        .expect("logout succeeds");

        assert!(
            state.db.validate_token(&tok1).unwrap().is_none(),
            "caller's token revoked"
        );
        assert!(
            state.db.validate_token(&tok2).unwrap().is_some(),
            "other device's token survives"
        );

        let remaining: Vec<String> = state
            .db
            .list_devices(alice_nid)
            .unwrap()
            .into_iter()
            .filter_map(|d| {
                d.get("device_id")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();
        assert_eq!(remaining, vec![dev2.to_string()]);
    }

    #[tokio::test]
    async fn logout_all_invalidates_every_device_for_user() {
        let (state, _tmp) = build_test_state();
        let (alice_nid, dev1, tok1) = register(&state, "@alice:example.com");

        let dev2 = "DEV2";
        state.db.create_device(alice_nid, dev2).unwrap();
        let tok2 = state.db.create_token(alice_nid, dev2).unwrap();

        // A different user's token must be untouched.
        let bob_nid = state.db.create_user("@bob:example.com", "hash").unwrap();
        state.db.create_device(bob_nid, "BOB_DEV").unwrap();
        let bob_tok = state.db.create_token(bob_nid, "BOB_DEV").unwrap();

        let _ = logout_all(
            State(state.clone()),
            AuthenticatedUser {
                user_nid: alice_nid,
                user_id: "@alice:example.com".into(),
                device_id: dev1.clone(),
                is_appservice: false,
            },
        )
        .await
        .expect("logout_all succeeds");

        assert!(state.db.validate_token(&tok1).unwrap().is_none());
        assert!(state.db.validate_token(&tok2).unwrap().is_none());
        assert!(
            state.db.validate_token(&bob_tok).unwrap().is_some(),
            "bob's token untouched"
        );

        assert!(state.db.list_devices(alice_nid).unwrap().is_empty());
        let bob_devices: Vec<String> = state
            .db
            .list_devices(bob_nid)
            .unwrap()
            .into_iter()
            .filter_map(|d| {
                d.get("device_id")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();
        assert_eq!(bob_devices, vec!["BOB_DEV".to_string()]);
    }
}
