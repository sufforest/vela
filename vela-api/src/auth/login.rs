use crate::middleware::json::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;
use vela_core::identifiers::{DeviceId, UserId};

use crate::middleware::error::ApiError;
use crate::router::AppState;

/// GET /_matrix/client/v3/login — returns supported login flows.
pub async fn get_login_types() -> Json<Value> {
    Json(json!({
        "flows": [
            {"type": "m.login.password"}
        ]
    }))
}

#[derive(Deserialize)]
pub struct LoginRequest {
    #[serde(rename = "type")]
    pub login_type: String,
    pub identifier: Option<LoginIdentifier>,
    // Legacy field
    pub user: Option<String>,
    pub password: Option<String>,
    pub device_id: Option<String>,
    pub initial_device_display_name: Option<String>,
    /// MSC2918 / spec v1.3+: client opts in to refresh tokens by setting
    /// this to `true`. When unset or false we keep the legacy non-expiring
    /// access token.
    #[serde(default)]
    pub refresh_token: bool,
}

#[derive(Deserialize)]
pub struct LoginIdentifier {
    #[allow(dead_code)]
    #[serde(rename = "type")]
    pub id_type: String,
    pub user: Option<String>,
}

/// POST /_matrix/client/v3/login — authenticate and get access token.
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<Value>, ApiError> {
    if body.login_type != "m.login.password" {
        return Err(VelaError::Unknown("unsupported login type".into()).into());
    }

    let password = body
        .password
        .as_deref()
        .ok_or_else(|| ApiError(VelaError::BadJson("password required".into())))?;

    // Extract username from identifier or legacy user field
    let username = body
        .identifier
        .as_ref()
        .and_then(|id| id.user.as_deref())
        .or(body.user.as_deref())
        .ok_or_else(|| ApiError(VelaError::BadJson("user identifier required".into())))?;

    // Build full user_id if only localpart provided. Localpart is lowercased
    // to match registration, which also downcases; otherwise uppercase-login
    // would never match the stored ID.
    let user_id = if username.starts_with('@') {
        let lower = username.to_lowercase();
        UserId::parse(&lower).map_err(|e| ApiError(VelaError::BadJson(e.to_string())))?
    } else {
        UserId::new(&username.to_lowercase(), &state.config.server_name)
    };

    // Look up user
    let user_nid = state
        .db
        .get_nid(user_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or(ApiError(VelaError::Forbidden("invalid credentials".into())))?;

    let user_record = state
        .db
        .get_user(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or(ApiError(VelaError::Forbidden("invalid credentials".into())))?;

    if user_record
        .get("deactivated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Err(VelaError::UserDeactivated.into());
    }

    // Verify password
    let stored_hash = user_record["password_hash"]
        .as_str()
        .ok_or(ApiError(VelaError::Unknown("corrupt user record".into())))?;

    if !verify_password(password, stored_hash) {
        return Err(VelaError::Forbidden("invalid credentials".into()).into());
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
        "well_known": {
            "m.homeserver": {
                "base_url": format!("http://{}:{}", state.config.bind_host, state.config.bind_port)
            }
        }
    });

    if body.refresh_token {
        let (access, refresh) = state
            .db
            .create_token_pair(
                user_nid,
                device_id.as_str(),
                crate::auth::refresh::ACCESS_TOKEN_LIFETIME_MS,
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        response["access_token"] = Value::String(access);
        response["refresh_token"] = Value::String(refresh);
        response["expires_in_ms"] =
            Value::Number(crate::auth::refresh::ACCESS_TOKEN_LIFETIME_MS.into());
    } else {
        let token = state
            .db
            .create_token(user_nid, device_id.as_str())
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        response["access_token"] = Value::String(token);
    }

    Ok(Json(response))
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
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    use axum::extract::State;

    fn hash_password(password: &str) -> String {
        let salt: [u8; 16] = rand::random();
        let salt_str = SaltString::encode_b64(&salt).unwrap();
        Argon2::default()
            .hash_password(password.as_bytes(), &salt_str)
            .unwrap()
            .to_string()
    }

    /// Deactivated users get a 403 `M_USER_DEACTIVATED`, not a generic
    /// invalid-credentials path. Verifies the explicit deactivation
    /// branch in `login` is exercised before password comparison.
    #[tokio::test]
    async fn login_rejects_deactivated_user() {
        let (state, _tmp) = build_test_state();
        let hash = hash_password("pw");
        let user_nid = state.db.create_user("@alice:example.com", &hash).unwrap();
        // Mark deactivated. (`deactivate_user` also clears the password
        // hash, but the deactivation flag is the authoritative signal.)
        state.db.deactivate_user(user_nid).unwrap();

        let err = login(
            State(state.clone()),
            Json(LoginRequest {
                login_type: "m.login.password".into(),
                identifier: Some(LoginIdentifier {
                    id_type: "m.id.user".into(),
                    user: Some("@alice:example.com".into()),
                }),
                user: None,
                password: Some("pw".into()),
                device_id: None,
                initial_device_display_name: None,
                refresh_token: false,
            }),
        )
        .await
        .expect_err("deactivated user must not log in");

        assert!(matches!(err.0, VelaError::UserDeactivated));
    }

    /// Active users authenticate normally — guards against any
    /// regression where the deactivation check accidentally rejects
    /// healthy accounts.
    #[tokio::test]
    async fn login_succeeds_for_active_user() {
        let (state, _tmp) = build_test_state();
        let hash = hash_password("pw");
        state.db.create_user("@alice:example.com", &hash).unwrap();

        let res = login(
            State(state.clone()),
            Json(LoginRequest {
                login_type: "m.login.password".into(),
                identifier: Some(LoginIdentifier {
                    id_type: "m.id.user".into(),
                    user: Some("@alice:example.com".into()),
                }),
                user: None,
                password: Some("pw".into()),
                device_id: None,
                initial_device_display_name: None,
                refresh_token: false,
            }),
        )
        .await
        .expect("login succeeds");

        assert!(res.0["access_token"].as_str().is_some());
    }
}
