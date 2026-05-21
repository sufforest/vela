use crate::middleware::json::Json;
use axum::extract::State;
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;
use vela_core::identifiers::{DeviceId, UserId};

use crate::middleware::error::ApiError;
use crate::router::AppState;

/// GET /_matrix/client/v3/login — returns supported login flows.
///
/// MSC3861 Phase 2 active (introspection_endpoint configured): we
/// don't advertise `m.login.password`. Clients learn the delegated-
/// auth posture via `/auth_issuer` + `/.well-known/matrix/client`
/// and bounce to the IdP instead. Returning an empty flows array is
/// the spec-correct shape for "no legacy login available."
pub async fn get_login_types(State(state): State<AppState>) -> Json<Value> {
    if state.config.oidc.introspection_endpoint.is_some() {
        return Json(json!({ "flows": [] }));
    }
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
    // Spec v1.17 §"Server admin style permissions": servers that
    // don't implement the legacy auth API MUST refuse
    // `m.login.application_service` with M_APPSERVICE_LOGIN_UNSUPPORTED.
    // Vela never shipped legacy login — AS authentication is via
    // Bearer + ?user_id= masquerade, not /login.
    if body.login_type == "m.login.application_service" {
        return Err(ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_APPSERVICE_LOGIN_UNSUPPORTED",
            msg: "this server does not implement the legacy auth API; \
                  AS callers use Bearer + ?user_id= masquerade instead"
                .into(),
        }));
    }

    // MSC3861 Phase 2 active: legacy password login is disabled.
    // Refuse with M_UNRECOGNIZED + an issuer hint so a misbehaving
    // (non-MSC3861-aware) client can surface a clear error to the
    // operator rather than looping on 401s.
    if state.config.oidc.introspection_endpoint.is_some() {
        let issuer = &state.config.oidc.issuer;
        return Err(ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_UNRECOGNIZED",
            msg: format!(
                "this server delegates authentication to {issuer}; \
                 password login is disabled. See /_matrix/client/v1/auth_issuer."
            ),
        }));
    }

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

    // argon2 verify is CPU-bound; spawn_blocking keeps it off the
    // tokio worker so a slow login doesn't pile up other requests.
    let stored_hash = user_record["password_hash"]
        .as_str()
        .ok_or(ApiError(VelaError::Unknown("corrupt user record".into())))?
        .to_string();
    let password_owned = password.to_string();
    let ok = tokio::task::spawn_blocking(move || verify_password(&password_owned, &stored_hash))
        .await
        .map_err(|e| ApiError(VelaError::Unknown(format!("verify task: {e}"))))?;
    if !ok {
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

    /// Flip Phase 2 on by mutating the AppState's OidcConfig in place.
    /// Used by the lockdown tests below; no need to plumb a full
    /// IntrospectionState through since the lockdown checks only
    /// read the config flag.
    fn enable_phase2(state: &mut AppState) {
        use std::sync::Arc;
        let cfg = Arc::make_mut(&mut state.config);
        cfg.oidc.enabled = true;
        cfg.oidc.issuer = "https://idp.example.com".into();
        cfg.oidc.introspection_endpoint = Some("https://idp.example.com/oauth2/introspect".into());
    }

    #[tokio::test]
    async fn get_login_types_advertises_empty_flows_under_phase2() {
        let (mut state, _tmp) = build_test_state();
        enable_phase2(&mut state);
        let res = get_login_types(State(state)).await;
        let flows = res.0["flows"].as_array().expect("flows array");
        assert!(flows.is_empty(), "Phase 2 must not advertise legacy flows");
    }

    #[tokio::test]
    async fn login_password_refused_under_phase2() {
        let (mut state, _tmp) = build_test_state();
        enable_phase2(&mut state);
        // Seed a real user so we'd otherwise succeed.
        let hash = hash_password("pw");
        state.db.create_user("@alice:example.com", &hash).unwrap();
        let err = login(
            State(state),
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
        .expect_err("password login must be refused under Phase 2");
        match err.0 {
            VelaError::Custom { errcode, .. } => assert_eq!(errcode, "M_UNRECOGNIZED"),
            other => panic!("expected M_UNRECOGNIZED, got {other:?}"),
        }
    }

    /// Phase 2 off: legacy flow advertised + accepted. Guards against
    /// the lockdown leaking into the non-delegated default deployment.
    #[tokio::test]
    async fn legacy_login_still_works_with_phase2_off() {
        let (state, _tmp) = build_test_state();
        assert!(state.config.oidc.introspection_endpoint.is_none());
        let res = get_login_types(State(state)).await;
        let flows = res.0["flows"].as_array().expect("flows array");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0]["type"], "m.login.password");
    }
}
