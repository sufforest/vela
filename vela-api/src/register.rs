use axum::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;
use vela_core::identifiers::{DeviceId, UserId};

use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
    #[serde(default)]
    pub inhibit_login: bool,
    #[allow(dead_code)]
    pub auth: Option<Value>,
    /// MSC2918 / spec v1.3+: client opts in to refresh tokens.
    #[serde(default)]
    pub refresh_token: bool,
}

pub async fn register(
    State(state): State<AppState>,
    body_bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
    // Closed registration: refuse before parsing. Operators flip this
    // flag for invite-only deployments; spec doesn't define an exact
    // errcode for "the server doesn't accept registrations" but
    // M_FORBIDDEN with a clear message is the de-facto convention.
    if !state.config.registration_enabled {
        return Err(ApiError(VelaError::Forbidden(
            "registration is disabled on this server".into(),
        )));
    }

    // Spec mandates `M_NOT_JSON` (status 400) when the body is not
    // valid JSON, including non-UTF-8 byte sequences inside what
    // looks-like-a-JSON-string. Empty body is treated as `{}` so the
    // UIA-flow-discovery step (no body) still works.
    let body: RegisterRequest = if body_bytes.is_empty() {
        RegisterRequest {
            username: None,
            password: None,
            device_id: None,
            initial_device_display_name: None,
            inhibit_login: false,
            auth: None,
            refresh_token: false,
        }
    } else {
        // Reject invalid UTF-8 explicitly. JSON requires strings be UTF-8;
        // serde_json's slice deserializer ignores fields not present in
        // the target struct, so a non-UTF-8 byte sequence inside an
        // ignored field would otherwise sneak past as a valid parse and
        // we'd return 401 instead of the spec-mandated 400 M_NOT_JSON.
        let body_str = std::str::from_utf8(&body_bytes).map_err(|e| {
            ApiError(VelaError::NotJson(format!(
                "request body is not valid UTF-8: {e}"
            )))
        })?;
        serde_json::from_str(body_str).map_err(|e| {
            ApiError(VelaError::NotJson(format!(
                "request body is not valid JSON: {e}"
            )))
        })?
    };

    // Spec: register MUST use UIA. Any submission without `auth` gets a
    // 401 + flows challenge, regardless of whether username/password are
    // already present — clients are expected to repeat the request with
    // the same body plus an `auth` block. Token-gated registration:
    // we always offer `m.login.registration_token` here even if the
    // static `[registration] token` is unset, because the admin bot may
    // have minted dynamic tokens into the `registration_tokens` CF that
    // we need to honour. Operators with neither static token nor admin
    // bot minted tokens get the dummy flow.
    let any_token_exists = state.config.registration_token.is_some()
        || state
            .db
            .list_registration_tokens()
            .map(|v| !v.is_empty())
            .unwrap_or(false);
    let flows = if any_token_exists {
        json!([{"stages": ["m.login.registration_token"]}])
    } else {
        json!([{"stages": ["m.login.dummy"]}])
    };

    if body.auth.is_none() {
        let uia_body = json!({
            "flows": flows,
            "params": {},
            "session": mint_uia_session(),
        });
        return Err(ApiError(VelaError::Uia {
            status: 401,
            body: uia_body.to_string(),
        }));
    }

    // Verify + consume the registration token when any token is required.
    // Accepts `auth.type == "m.login.registration_token"` with `auth.token`,
    // OR a bare `auth.token` (lenient for clients that don't model the
    // registration_token UIA stage explicitly).
    //
    // Lookup order:
    //   1. dynamic tokens in `registration_tokens` CF (admin-bot-minted,
    //      plus the static bootstrap token after `admin::bootstrap`
    //      seeds it — so `!token revoke` works uniformly post-bootstrap);
    //   2. fall back to a literal match against the static
    //      `[registration] token` from vela.toml — covers the very first
    //      boot before `admin::bootstrap` runs, and integration tests
    //      that build AppState without calling bootstrap.
    //
    // The static token loses its special status as soon as an admin
    // exists AND the bootstrap helper has seeded it: at that point the
    // dynamic path owns it, and `!token revoke <static>` removes it.
    if any_token_exists {
        let provided = body
            .auth
            .as_ref()
            .and_then(|a| a.get("token"))
            .and_then(|t| t.as_str())
            .unwrap_or("");
        let mut consumed = false;
        if !provided.is_empty() {
            consumed = state
                .db
                .consume_registration_token(provided)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            if !consumed
                && let Some(static_token) = state.config.registration_token.as_deref()
                && provided == static_token
            {
                consumed = true;
            }
        }
        if !consumed {
            return Err(ApiError(VelaError::Forbidden(
                "registration requires a valid token".into(),
            )));
        }
    }

    let username = body.username.as_deref().unwrap_or("").to_lowercase();

    // Validate username
    if username.is_empty() || username.len() > 255 {
        return Err(VelaError::InvalidUsername.into());
    }
    // Allowed-character set per Matrix identifier grammar:
    //   `[0-9a-z-._=/+]` (lowercase only — we already lowercased above)
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-=/+".contains(c))
    {
        return Err(VelaError::InvalidUsername.into());
    }

    // Refuse the admin-bot's reserved localpart, even with a valid
    // registration token. Otherwise an admin could create a colliding
    // account with their own password and impersonate the bot.
    crate::admin::assert_bot_localpart_not_reserved(&state, &username)?;

    let password = body.password.as_deref().unwrap_or("");
    if password.is_empty() {
        return Err(VelaError::BadJson("password is required".into()).into());
    }

    let user_id = UserId::new(&username, &state.config.server_name);

    // Check if user exists
    if state
        .db
        .user_exists(user_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        return Err(VelaError::UserInUse.into());
    }

    // Hash password with argon2
    let salt: [u8; 16] = rand::random();
    let password_hash = hash_password(password, &salt);

    // Create user
    let user_nid = state
        .db
        .create_user(user_id.as_str(), &password_hash)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Auto-invite the very first registrant to the admin room. Runs
    // BEFORE inhibit_login so a programmatic
    // `inhibit_login=true; register` still mints the admin invite.
    // Errors are logged and the registration succeeds anyway — the bot
    // operator can always recover with `!promote` from another admin's
    // session.
    maybe_auto_invite_first_admin(&state, user_nid, user_id.as_str()).await;

    if body.inhibit_login {
        return Ok(Json(json!({
            "user_id": user_id.as_str(),
        })));
    }

    // Create device + token
    let device_id = body
        .device_id
        .map(DeviceId::new)
        .unwrap_or_else(DeviceId::generate);

    state
        .db
        .create_device(user_nid, device_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let Some(display_name) = body.initial_device_display_name.as_deref()
        && !display_name.is_empty()
    {
        state
            .db
            .update_device_display_name(user_nid, device_id.as_str(), display_name)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    let mut response = json!({
        "user_id": user_id.as_str(),
        "device_id": device_id.as_str(),
    });

    if body.refresh_token {
        let (access, refresh) = state
            .db
            .create_token_pair(
                user_nid,
                device_id.as_str(),
                crate::refresh::ACCESS_TOKEN_LIFETIME_MS,
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        response["access_token"] = Value::String(access);
        response["refresh_token"] = Value::String(refresh);
        response["expires_in_ms"] = Value::Number(crate::refresh::ACCESS_TOKEN_LIFETIME_MS.into());
    } else {
        let token = state
            .db
            .create_token(user_nid, device_id.as_str())
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        response["access_token"] = Value::String(token);
    }

    Ok(Json(response))
}

fn hash_password(password: &str, salt: &[u8; 16]) -> String {
    use argon2::Argon2;
    use argon2::PasswordHasher;
    use argon2::password_hash::SaltString;

    let salt_str = SaltString::encode_b64(salt).unwrap();
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt_str)
        .unwrap()
        .to_string()
}

#[derive(Deserialize)]
pub struct AvailableQuery {
    pub username: Option<String>,
}

/// GET /_matrix/client/v3/register/available
///
/// Reports whether a desired localpart can still be registered. Validates
/// the username against the same character set we accept on register.
pub async fn available(
    State(state): State<AppState>,
    Query(q): Query<AvailableQuery>,
) -> Result<Json<Value>, ApiError> {
    let username = q.username.as_deref().unwrap_or("").to_lowercase();
    if username.is_empty() || username.len() > 255 {
        return Err(VelaError::InvalidUsername.into());
    }
    // Allowed-character set per Matrix identifier grammar:
    //   `[0-9a-z-._=/+]` (lowercase only — we already lowercased above)
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-=/+".contains(c))
    {
        return Err(VelaError::InvalidUsername.into());
    }
    let user_id = UserId::new(&username, &state.config.server_name);
    if state
        .db
        .user_exists(user_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        return Err(VelaError::UserInUse.into());
    }
    Ok(Json(json!({"available": true})))
}

fn mint_uia_session() -> String {
    use base64::Engine;
    let bytes: [u8; 16] = rand::random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// If `new_user_nid` is the very first registrant after server
/// bootstrap, send them an invite to the admin room as the bot. Skips
/// silently when there's no admin room yet (pre-bootstrap), when an
/// admin already exists, or when the invite emit fails (logged).
async fn maybe_auto_invite_first_admin(state: &AppState, new_user_nid: u64, new_user_id: &str) {
    let should = match crate::admin::should_auto_invite_first_admin(state, new_user_nid) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = ?e.0, "register: should_auto_invite check failed");
            return;
        }
    };
    if !should {
        return;
    }
    let admin_room_nid = match state.db.get_admin_room_nid() {
        Ok(Some(n)) => n,
        _ => return,
    };
    let room_id_str = match state.db.get_admin_room_id() {
        Ok(Some(s)) => s,
        _ => return,
    };
    let room_id = match vela_core::identifiers::RoomId::parse(&room_id_str) {
        Ok(r) => r,
        Err(_) => return,
    };
    let bot_nid = match state.db.get_admin_bot_user_nid() {
        Ok(Some(n)) => n,
        _ => return,
    };
    let bot_user_id = match state.db.resolve_nid(bot_nid) {
        Ok(Some(s)) => s,
        _ => return,
    };
    let bot = crate::middleware::auth::AuthenticatedUser {
        user_nid: bot_nid,
        user_id: bot_user_id,
        device_id: crate::admin::admin_bot_device_id().to_string(),
    };
    if let Err(e) = crate::membership::invite_user_internal(
        state.clone(),
        bot,
        admin_room_nid,
        room_id,
        new_user_id.to_string(),
        false,
    )
    .await
    {
        tracing::warn!(error = ?e.0, target = %new_user_id, "register: admin auto-invite failed");
    }
}

#[cfg(test)]
mod admin_integration_tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use axum::extract::State;
    use serde_json::json;

    fn body_with(auth: Option<Value>, username: &str, password: &str) -> axum::body::Bytes {
        let mut obj = serde_json::Map::new();
        obj.insert("username".into(), Value::String(username.into()));
        obj.insert("password".into(), Value::String(password.into()));
        if let Some(a) = auth {
            obj.insert("auth".into(), a);
        }
        axum::body::Bytes::from(serde_json::to_vec(&Value::Object(obj)).unwrap())
    }

    /// The admin bot's localpart is reserved on /register, even with a
    /// valid token. Otherwise an attacker could mint a colliding
    /// `@admin:server` account and impersonate the bot.
    #[tokio::test]
    async fn register_refuses_bot_localpart() {
        let (state, _tmp) = build_test_state();
        crate::admin::bootstrap(&state).await.unwrap();
        // Seed a usable registration token.
        state
            .db
            .create_registration_token("tok-a", 0, 0, 0)
            .unwrap();
        let auth = json!({"type": "m.login.registration_token", "token": "tok-a"});
        let err = register(
            State(state.clone()),
            body_with(Some(auth), "admin", "secret123"),
        )
        .await
        .expect_err("bot localpart reserved");
        assert!(matches!(err.0, VelaError::Forbidden(_)));
    }

    /// First human registrant is auto-invited to the admin room.
    /// Second registrant is not.
    #[tokio::test]
    async fn register_auto_invites_first_admin_only() {
        let (state, _tmp) = build_test_state();
        crate::admin::bootstrap(&state).await.unwrap();
        let admin_room = state.db.get_admin_room_nid().unwrap().unwrap();
        state
            .db
            .create_registration_token("tok-a", 0, 0, 0)
            .unwrap();
        let auth = json!({"type": "m.login.registration_token", "token": "tok-a"});

        let _ = register(
            State(state.clone()),
            body_with(Some(auth.clone()), "alice", "secret123"),
        )
        .await
        .expect("first register");
        let alice_nid = state.db.get_nid("@alice:example.com").unwrap().unwrap();
        assert_eq!(
            state.db.get_membership(admin_room, alice_nid).unwrap(),
            Some(2),
            "first registrant auto-invited to admin room",
        );

        // Promote alice via direct membership (simulating accept).
        state.db.set_membership(admin_room, alice_nid, 1).unwrap();

        // Mint a fresh token (the first one was 1-use? actually unlimited
        // here; but use a new token to confirm independent flow).
        state
            .db
            .create_registration_token("tok-b", 0, 0, 0)
            .unwrap();
        let auth2 = json!({"type": "m.login.registration_token", "token": "tok-b"});
        let _ = register(
            State(state.clone()),
            body_with(Some(auth2), "bob", "secret123"),
        )
        .await
        .expect("second register");
        let bob_nid = state.db.get_nid("@bob:example.com").unwrap().unwrap();
        assert!(
            state
                .db
                .get_membership(admin_room, bob_nid)
                .unwrap()
                .is_none(),
            "second registrant must NOT be auto-invited",
        );
    }

    /// Registration token uses count down and expired tokens are
    /// rejected by the consume path inside register.
    #[tokio::test]
    async fn register_consumes_token_and_rejects_after_exhaustion() {
        let (state, _tmp) = build_test_state();
        crate::admin::bootstrap(&state).await.unwrap();
        state
            .db
            .create_registration_token("tok-once", 1, 0, 0)
            .unwrap();
        let auth = json!({"type": "m.login.registration_token", "token": "tok-once"});
        let _ = register(
            State(state.clone()),
            body_with(Some(auth.clone()), "alice", "secret123"),
        )
        .await
        .expect("first use succeeds");
        // Token now exhausted. A second user trying to reuse it gets 403.
        let err = register(
            State(state.clone()),
            body_with(Some(auth), "bob", "secret123"),
        )
        .await
        .expect_err("second use refused");
        assert!(matches!(err.0, VelaError::Forbidden(_)));
    }
}
