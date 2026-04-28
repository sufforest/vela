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
    #[allow(dead_code)]
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
        serde_json::from_slice(&body_bytes).map_err(|e| {
            ApiError(VelaError::NotJson(format!(
                "request body is not valid JSON: {e}"
            )))
        })?
    };

    // Empty body or missing both `username` and `auth` → return a UIA
    // challenge rather than 400. Spec says register MUST use UIA. We accept
    // `m.login.dummy` (no real challenge) when present, so this handler
    // serves both the discover-flows step and the actual create-user step.
    // Token-gated registration: when configured, require a UIA flow
    // that includes `m.login.registration_token` (MSC3231-style). The
    // discovery branch (empty body) advertises both flows so clients
    // know which to provide; subsequent submissions must carry the
    // matching token in `auth.token`.
    let token_required = state.config.registration_token.as_deref();
    let flows = if token_required.is_some() {
        json!([{"stages": ["m.login.registration_token"]}])
    } else {
        json!([{"stages": ["m.login.dummy"]}])
    };

    let has_username = body.username.is_some();
    let has_auth = body.auth.is_some();
    if !has_username && !has_auth {
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

    // Verify the registration token matches when one is configured.
    // Accepts `auth.type == "m.login.registration_token"` with `auth.token`,
    // OR a bare `auth.token` (lenient for clients that don't model the
    // registration_token UIA stage explicitly).
    if let Some(expected) = token_required {
        let provided = body
            .auth
            .as_ref()
            .and_then(|a| a.get("token"))
            .and_then(|t| t.as_str());
        if provided != Some(expected) {
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
