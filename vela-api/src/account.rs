//! Account-management handlers: `/account/password` and `/account/deactivate`.
//!
//! Spec: `client-server/password_management.yaml`, `client-server/account_deactivation.yaml`.
//!
//! UIA note: both endpoints nominally require User-Interactive Authentication.
//! Vela does not yet implement UIA (register also bypasses it). A valid access
//! token is required — proof of session ownership. Adding a full UIA flow is
//! future work.

use axum::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;
use crate::uia;

#[derive(Debug, Deserialize)]
pub struct PasswordChangeBody {
    pub new_password: String,
    #[serde(default = "default_logout_devices")]
    pub logout_devices: bool,
}

fn default_logout_devices() -> bool {
    true
}

/// POST /_matrix/client/v3/account/password
pub async fn change_password(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<PasswordChangeBody>,
) -> Result<Json<Value>, ApiError> {
    if body.new_password.is_empty() {
        return Err(VelaError::BadJson("new_password is required".into()).into());
    }

    let hash = hash_password(&body.new_password);
    state
        .db
        .update_user_password(user.user_nid, &hash)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if body.logout_devices {
        // Keep the caller's current device alive; spec: "The homeserver SHOULD
        // NOT revoke the access token provided in the request."
        state
            .db
            .delete_user_tokens(user.user_nid, Some(&user.device_id))
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    Ok(Json(json!({})))
}

/// POST /_matrix/client/v3/account/deactivate
///
/// Body is parsed as raw JSON so we can hand it to the UIA layer; we
/// inspect `auth` for UIA, optionally honour `erase` (replace
/// displayname / avatar with placeholders), and accept-but-ignore
/// `id_server` (no 3PID binding here).
///
/// Beyond marking the user deactivated, this performs the cleanup
/// hygiene a deactivated account warrants:
///
/// - revokes every access + refresh token;
/// - drops every pusher (no more push notifications);
/// - drops every E2EE artefact (device keys, OTKs, cross-signing keys);
/// - signals peer servers that all of this user's devices are now
///   `deleted=true` via `m.device_list_update`;
/// - emits an `m.room.member` `leave` for every joined / invited /
///   knocking room, with `reason: "Account deactivated"`. Local-resident
///   rooms persist immediately and federation broadcast happens in the
///   background; remote-resident rooms are leaved off the response path.
///
/// Errors from per-room leaves are logged and skipped — one stuck room
/// must not block the deactivation. Federation completion is not
/// awaited.
///
/// Idempotency: once the first deactivate succeeds, every access token
/// is revoked, so subsequent calls fail at the auth middleware with
/// `M_UNKNOWN_TOKEN` — there is no in-handler "already deactivated"
/// branch to take.
pub async fn deactivate(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    uia::require_password_auth(&state, &body)?;

    let erase = body.get("erase").and_then(|v| v.as_bool()).unwrap_or(false);

    // Snapshot the user's current devices BEFORE we drop them — we need
    // their device_ids to enqueue per-device `deleted=true`
    // `m.device_list_update`s to peer servers below.
    let devices_before: Vec<String> = state
        .db
        .list_devices(user.user_nid)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| {
            d.get("device_id")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .collect();

    state
        .db
        .deactivate_user(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Revoke every access + refresh token. `delete_user_tokens` walks
    // both `tokens` and `refresh_tokens` CFs internally.
    state
        .db
        .delete_user_tokens(user.user_nid, None)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Drop pushers — no further push notifications for this user.
    if let Err(e) = state.db.delete_user_pushers(user.user_nid) {
        tracing::warn!(error = %e, "deactivate: delete_user_pushers failed");
    }

    // Drop E2EE artefacts.
    if let Err(e) = state.db.delete_user_e2ee_keys(user.user_nid) {
        tracing::warn!(error = %e, "deactivate: delete_user_e2ee_keys failed");
    }

    // Tell peer servers their cached device lists for this user are
    // stale — every device is now `deleted=true`. We use the same
    // outbound queue as the regular device-list EDU stream; the
    // federation sender drains it in the background.
    federate_device_list_deletes(&state, &user, &devices_before);

    // Optional erasure: replace the public profile with a placeholder.
    // We only touch the local profile record; we don't try to redact
    // historical message content (the spec leaves this implementation-
    // defined, and rewriting past events is debated).
    if erase {
        let placeholder_name = format!("{} (deactivated)", user.user_id);
        if let Err(e) =
            state
                .db
                .update_user_profile(user.user_nid, Some(&placeholder_name), Some(""))
        {
            tracing::warn!(error = %e, "deactivate: erase profile failed");
        }
    }

    // Force the user out of every room. Errors per-room are logged and
    // skipped; remote-resident rooms are leaved in the background.
    crate::membership::force_leave_all_rooms_for_deactivation(&state, &user, "Account deactivated")
        .await;

    // We don't bind 3PIDs to an identity server, so nothing to unbind —
    // spec allows `success` when there are no identifiers to unbind.
    Ok(Json(json!({ "id_server_unbind_result": "success" })))
}

/// Enqueue `m.device_list_update` EDUs marking every device of the
/// (now-deactivated) user as `deleted: true`, fanned out to every
/// remote server that shares (or shared, before our forced leaves) any
/// joined room with the user. We compute the audience from the user's
/// joined rooms before the leaves land — if we waited until after the
/// leaves we'd have lost the room membership and produced no audience.
///
/// Errors are logged but not propagated; federation hygiene must not
/// block the response.
fn federate_device_list_deletes(state: &AppState, user: &AuthenticatedUser, device_ids: &[String]) {
    use std::collections::HashSet;

    if device_ids.is_empty() {
        return;
    }

    let rooms = match state.db.get_user_joined_rooms(user.user_nid) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "deactivate: get_user_joined_rooms failed");
            return;
        }
    };
    let mut destinations: HashSet<String> = HashSet::new();
    for room_nid in rooms {
        match state
            .db
            .get_remote_servers_in_room(room_nid, &state.config.server_name)
        {
            Ok(servers) => destinations.extend(servers),
            Err(e) => tracing::warn!(error = %e, "deactivate: room scan failed"),
        }
    }
    if destinations.is_empty() {
        return;
    }

    for device_id in device_ids {
        let stream_id = match state.db.bump_user_device_list_stream(user.user_nid) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "deactivate: stream bump failed");
                continue;
            }
        };
        let content = json!({
            "user_id": user.user_id,
            "device_id": device_id,
            "stream_id": stream_id,
            "deleted": true,
        });
        for dest in &destinations {
            if let Err(e) = state.db.enqueue_device_list_outbound(dest, &content) {
                tracing::warn!(target = %dest, error = %e, "deactivate: device_list enqueue failed");
                continue;
            }
            state.federation_sender.notify_destination(dest);
        }
    }
}

fn hash_password(password: &str) -> String {
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    let salt: [u8; 16] = rand::random();
    let salt_str = SaltString::encode_b64(&salt).unwrap();
    Argon2::default()
        .hash_password(password.as_bytes(), &salt_str)
        .unwrap()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::AuthenticatedUser;
    use crate::test_helpers::build_test_state;
    use axum::extract::State;

    fn register_test_user(state: &AppState, user_id: &str, password: &str) -> (u64, String) {
        let hash = hash_password(password);
        let nid = state.db.create_user(user_id, &hash).unwrap();
        let device_id = "TEST_DEV".to_string();
        state.db.create_device(nid, &device_id).unwrap();
        (nid, device_id)
    }

    fn pw_auth(user_id: &str, password: &str) -> Value {
        json!({
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": user_id},
                "password": password,
            }
        })
    }

    #[tokio::test]
    async fn change_password_updates_hash_and_revokes_other_tokens() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "old");

        // Two tokens: the caller's, and a second device's.
        let kept_token = state.db.create_token(user_nid, &device_id).unwrap();
        let other_device = "OTHER_DEV";
        state.db.create_device(user_nid, other_device).unwrap();
        let other_token = state.db.create_token(user_nid, other_device).unwrap();

        let res = change_password(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id: device_id.clone(),
            },
            Json(PasswordChangeBody {
                new_password: "new_secret".into(),
                logout_devices: true,
            }),
        )
        .await
        .expect("change succeeds");
        assert_eq!(res.0, json!({}));

        // Caller's token still valid, other's gone.
        assert!(state.db.validate_token(&kept_token).unwrap().is_some());
        assert!(state.db.validate_token(&other_token).unwrap().is_none());

        // New password hash is stored (verify by reading the user record).
        let record = state.db.get_user(user_nid).unwrap().unwrap();
        let stored = record["password_hash"].as_str().unwrap();
        assert!(
            stored.starts_with("$argon2"),
            "expected argon2 hash, got {stored}"
        );
    }

    #[tokio::test]
    async fn change_password_without_logout_keeps_all_tokens() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "old");
        let caller_tok = state.db.create_token(user_nid, &device_id).unwrap();
        state.db.create_device(user_nid, "OTHER").unwrap();
        let other_tok = state.db.create_token(user_nid, "OTHER").unwrap();

        let _ = change_password(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(PasswordChangeBody {
                new_password: "new".into(),
                logout_devices: false,
            }),
        )
        .await
        .unwrap();

        assert!(state.db.validate_token(&caller_tok).unwrap().is_some());
        assert!(state.db.validate_token(&other_tok).unwrap().is_some());
    }

    #[tokio::test]
    async fn change_password_rejects_empty() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "old");
        let err = change_password(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(PasswordChangeBody {
                new_password: String::new(),
                logout_devices: true,
            }),
        )
        .await
        .expect_err("empty rejected");
        assert!(matches!(err, ApiError(VelaError::BadJson(_))));
    }

    #[tokio::test]
    async fn deactivate_flags_user_and_revokes_all_tokens() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");
        let tok = state.db.create_token(user_nid, &device_id).unwrap();
        state.db.create_device(user_nid, "OTHER").unwrap();
        let other = state.db.create_token(user_nid, "OTHER").unwrap();

        let res = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(pw_auth("@alice:example.com", "pw")),
        )
        .await
        .expect("deactivate succeeds");
        assert_eq!(
            res.0
                .get("id_server_unbind_result")
                .and_then(|v| v.as_str()),
            Some("success")
        );

        assert!(state.db.user_is_deactivated(user_nid).unwrap());
        assert!(state.db.validate_token(&tok).unwrap().is_none());
        assert!(state.db.validate_token(&other).unwrap().is_none());
    }

    #[tokio::test]
    async fn deactivate_without_auth_returns_uia_challenge() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");

        let err = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(json!({})),
        )
        .await
        .expect_err("uia challenge");
        match err.0 {
            VelaError::Uia { status, body } => {
                assert_eq!(status, 401);
                assert!(body.contains("m.login.password"));
                assert!(body.contains("session"));
            }
            other => panic!("expected Uia, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deactivate_revokes_refresh_tokens() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");

        // Mint an access+refresh pair. Mirrors what /login + refresh-flow
        // would do.
        let (access, refresh) = state
            .db
            .create_token_pair(user_nid, &device_id, 60_000)
            .unwrap();
        // Sanity: both work pre-deactivate.
        assert!(state.db.validate_token(&access).unwrap().is_some());
        assert!(
            state
                .db
                .refresh_access_token(&refresh, 60_000)
                .unwrap()
                .is_some()
        );

        // Mint another fresh pair to actually test revocation (the first
        // refresh consumed itself above).
        let (access2, refresh2) = state
            .db
            .create_token_pair(user_nid, &device_id, 60_000)
            .unwrap();

        let _ = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(pw_auth("@alice:example.com", "pw")),
        )
        .await
        .expect("deactivate succeeds");

        // Both halves are gone.
        assert!(state.db.validate_token(&access2).unwrap().is_none());
        assert!(
            state
                .db
                .refresh_access_token(&refresh2, 60_000)
                .unwrap()
                .is_none(),
            "refresh token must be revoked on deactivate",
        );
    }

    #[tokio::test]
    async fn deactivate_drops_pushers() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");
        // Seed two pushers across two app_ids — both must vanish.
        state
            .db
            .set_pusher(
                user_nid,
                "com.example.app",
                "key-1",
                &json!({"kind": "http", "data": {"url": "https://push/notify"}}),
            )
            .unwrap();
        state
            .db
            .set_pusher(
                user_nid,
                "com.example.other",
                "key-2",
                &json!({"kind": "http", "data": {"url": "https://push/notify"}}),
            )
            .unwrap();
        assert_eq!(state.db.list_pushers(user_nid).unwrap().len(), 2);

        let _ = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(pw_auth("@alice:example.com", "pw")),
        )
        .await
        .expect("deactivate succeeds");

        assert_eq!(
            state.db.list_pushers(user_nid).unwrap().len(),
            0,
            "pushers must be cleared on deactivate",
        );
    }

    #[tokio::test]
    async fn deactivate_drops_e2ee_keys() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");
        // Seed device keys, OTKs, and a cross-signing key.
        state
            .db
            .set_device_keys(user_nid, &device_id, &json!({"keys": {"ed25519:DEV": "k"}}))
            .unwrap();
        let mut otks = serde_json::Map::new();
        otks.insert("signed_curve25519:AAAA".into(), json!({"key": "v"}));
        state
            .db
            .add_one_time_keys(user_nid, &device_id, &otks)
            .unwrap();
        state
            .db
            .set_cross_signing_keys(user_nid, "master", &json!({"keys": {"ed25519:M": "k"}}))
            .unwrap();
        assert_eq!(state.db.get_all_device_keys(user_nid).unwrap().len(), 1);
        assert_eq!(state.db.get_cross_signing_keys(user_nid).unwrap().len(), 1);

        let _ = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id: device_id.clone(),
            },
            Json(pw_auth("@alice:example.com", "pw")),
        )
        .await
        .expect("deactivate succeeds");

        assert_eq!(state.db.get_all_device_keys(user_nid).unwrap().len(), 0);
        assert_eq!(
            state
                .db
                .count_one_time_keys(user_nid, &device_id)
                .unwrap()
                .len(),
            0,
        );
        assert_eq!(state.db.get_cross_signing_keys(user_nid).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn deactivate_with_erase_replaces_profile() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");
        // Seed a profile that erasure should overwrite.
        state
            .db
            .update_user_profile(user_nid, Some("Alice"), Some("mxc://example/avatar"))
            .unwrap();

        let mut body = pw_auth("@alice:example.com", "pw");
        body.as_object_mut()
            .unwrap()
            .insert("erase".into(), json!(true));

        let _ = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(body),
        )
        .await
        .expect("deactivate succeeds");

        let user_record = state.db.get_user(user_nid).unwrap().unwrap();
        assert_eq!(
            user_record["displayname"].as_str(),
            Some("@alice:example.com (deactivated)"),
        );
        assert_eq!(user_record["avatar_url"].as_str(), Some(""));
    }

    #[tokio::test]
    async fn deactivate_without_erase_leaves_profile_intact() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");
        state
            .db
            .update_user_profile(user_nid, Some("Alice"), Some("mxc://example/avatar"))
            .unwrap();

        let _ = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(pw_auth("@alice:example.com", "pw")),
        )
        .await
        .expect("deactivate succeeds");

        let user_record = state.db.get_user(user_nid).unwrap().unwrap();
        assert_eq!(user_record["displayname"].as_str(), Some("Alice"));
        assert_eq!(
            user_record["avatar_url"].as_str(),
            Some("mxc://example/avatar")
        );
    }

    #[tokio::test]
    async fn deactivate_with_wrong_password_returns_uia_failed() {
        let (state, _tmp) = build_test_state();
        let (user_nid, device_id) = register_test_user(&state, "@alice:example.com", "pw");

        let err = deactivate(
            State(state.clone()),
            AuthenticatedUser {
                user_nid,
                user_id: "@alice:example.com".into(),
                device_id,
            },
            Json(pw_auth("@alice:example.com", "WRONG")),
        )
        .await
        .expect_err("wrong password");
        match err.0 {
            VelaError::Uia { status, body } => {
                assert_eq!(status, 401);
                assert!(body.contains("M_FORBIDDEN"));
            }
            other => panic!("expected Uia, got {other:?}"),
        }
    }
}
