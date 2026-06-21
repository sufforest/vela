use crate::middleware::json::Json;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;
use vela_core::identifiers::{DeviceId, UserId};

use crate::auth::client_ip::{client_ip_from_headers, hash_client_ip};
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
    /// Top-level login type. The only value vela honours here is
    /// `"m.login.application_service"`, used by AS spec §"Server admin
    /// style permissions" to create namespaced users without a
    /// password or UIA flow. Other values are ignored (the standard
    /// UIA flow runs instead).
    #[serde(rename = "type")]
    pub login_type: Option<String>,
    /// MSC2918 / spec v1.3+: client opts in to refresh tokens.
    #[serde(default)]
    pub refresh_token: bool,
}

pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    body_bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
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
            login_type: None,
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

    // Application Service register: `type: m.login.application_service`
    // + `Authorization: Bearer <as_token>` shortcuts the UIA flow,
    // creates a passwordless user inside the AS's namespace, returns
    // only `{user_id}` (no access_token because `inhibit_login` must
    // be true). Spec: AS API §"Server admin style permissions".
    //
    // This branch runs *before* the closed-registration gate: an
    // operator who closes public registration still wants their
    // bridges to mint namespaced users, otherwise bridges break on
    // every invite-only deployment.
    if body.login_type.as_deref() == Some("m.login.application_service") {
        return register_as_appservice(&state, &headers, &body).await;
    }

    // MSC3861 Phase 2 active: legacy register is disabled. AS-mode
    // register above still works (bridges aren't human users), but
    // human account creation belongs to the IdP. Surface the issuer
    // URL so the operator's account-management UX has a fighting
    // chance of guiding the user.
    if state.config.oidc.introspection_endpoint.is_some() {
        let account_url = state
            .config
            .oidc
            .account_management_url
            .clone()
            .unwrap_or_else(|| state.config.oidc.issuer.clone());
        return Err(ApiError(VelaError::Forbidden(format!(
            "this server delegates authentication to {account_url}; \
             create your account there. See /_matrix/client/v1/auth_issuer."
        ))));
    }

    // Closed registration: refuse before doing UIA work. Operators
    // flip this flag for invite-only deployments; spec doesn't define
    // an exact errcode for "the server doesn't accept registrations"
    // but M_FORBIDDEN with a clear message is the de-facto convention.
    if !state.config.registration_enabled {
        return Err(ApiError(VelaError::Forbidden(
            "registration is disabled on this server".into(),
        )));
    }

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
    // The `registration_tokens` CF is the single source of truth.
    // `admin::bootstrap` seeds the static `[registration] token` (if
    // present) into the CF on first boot when no admin exists — so the
    // operator-configured token participates in the same lifecycle as
    // tokens minted later via `!token create`. After bootstrap the
    // toml entry is decorative; `!token revoke` against that token
    // works correctly and is not bypassed by a static fallback.
    //
    // Two-phase to avoid burning a token when registration would have
    // failed anyway: validate (read-only) up front so a wrong token
    // is rejected before we hash the password, then consume (write)
    // right before user creation.
    let provided_token = if any_token_exists {
        let provided = body
            .auth
            .as_ref()
            .and_then(|a| a.get("token"))
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if provided.is_empty()
            || !state
                .db
                .validate_registration_token(&provided)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            return Err(ApiError(VelaError::Forbidden(
                "registration requires a valid token".into(),
            )));
        }
        Some(provided)
    } else {
        None
    };

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

    // M_EXCLUSIVE: a non-AS caller cannot create a user whose MXID
    // falls inside any AS's exclusive user namespace.
    let candidate_user_id = format!("@{}:{}", username, state.config.server_name);
    if let crate::appservice::exclusive::ExclusiveCheck::Refused(reason) =
        crate::appservice::exclusive::check_user(
            &state.appservice_registry,
            &candidate_user_id,
            None,
        )
    {
        return Err(ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_EXCLUSIVE",
            msg: reason,
        }));
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

    // Anti-spam: sandboxed registration-policy hook (no-op when no plugin binds
    // it). Before the expensive argon2 hash + token consume, so a blocked signup
    // wastes nothing. A block is a hard reject (we refuse to create the account).
    registration_gate(
        &state,
        &username,
        if provided_token.is_some() {
            "token"
        } else {
            "open"
        },
        &headers,
    )?;

    // Hash password with argon2
    let salt: [u8; 16] = rand::random();
    let password_hash = hash_password(password, &salt);

    // Consume the registration token atomically before creating the
    // user. If a concurrent registrant already consumed the last use
    // between our `validate_registration_token` peek and now, fail
    // here — same 403 surface as the early validation, no half-state
    // left behind.
    if let Some(token) = &provided_token
        && !state
            .db
            .consume_registration_token(token)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        return Err(ApiError(VelaError::Forbidden(
            "registration requires a valid token".into(),
        )));
    }

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

/// Application Service register handler. Mints a passwordless user
/// inside the AS's namespace and returns `{user_id}` — no UIA, no
/// password, no token, no auto-invite.
///
/// Per spec v1.17, `inhibit_login` MUST be `true`. Otherwise we
/// return `M_APPSERVICE_LOGIN_UNSUPPORTED` (vela doesn't ship the
/// legacy login API).
async fn register_as_appservice(
    state: &AppState,
    headers: &HeaderMap,
    body: &RegisterRequest,
) -> Result<Json<Value>, ApiError> {
    // Spec mandates inhibit_login=true for AS register on servers
    // that don't implement the legacy auth API.
    if !body.inhibit_login {
        return Err(ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_APPSERVICE_LOGIN_UNSUPPORTED",
            msg: "AS register requires `inhibit_login: true` on this server".into(),
        }));
    }

    // Extract Bearer as_token from the Authorization header.
    let as_token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError(VelaError::MissingToken))?;

    // Resolve to a registered AS.
    let live = crate::appservice::auth::lookup_appservice(&state.appservice_registry, as_token)
        .ok_or(ApiError(VelaError::UnknownToken))?;
    if !live.appservice.enabled {
        return Err(ApiError(VelaError::Forbidden("this AS is disabled".into())));
    }

    // Spec: AS register accepts either a localpart or a full
    // `@local:server` MXID. Synapse follows the same rule for bridges
    // that already track their virtual users as MXIDs.
    let raw = body.username.as_deref().unwrap_or("");
    let localpart = if let Some(rest) = raw.strip_prefix('@') {
        // Strip optional `:server` suffix; require it match this server.
        match rest.split_once(':') {
            Some((lp, server)) => {
                if server != state.config.server_name {
                    return Err(VelaError::InvalidUsername.into());
                }
                lp.to_string()
            }
            None => rest.to_string(),
        }
    } else {
        raw.to_string()
    };
    let username = localpart.to_lowercase();
    if username.is_empty() || username.len() > 255 {
        return Err(VelaError::InvalidUsername.into());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "._-=/+".contains(c))
    {
        return Err(VelaError::InvalidUsername.into());
    }
    crate::admin::assert_bot_localpart_not_reserved(state, &username)?;

    let user_id = UserId::new(&username, &state.config.server_name);

    // Target user_id MUST fall inside one of the AS's user namespaces.
    // Refused if it lands inside another AS's exclusive namespace.
    if let crate::appservice::exclusive::ExclusiveCheck::Refused(reason) =
        crate::appservice::exclusive::check_user(
            &state.appservice_registry,
            user_id.as_str(),
            Some(live.appservice.nid),
        )
    {
        return Err(ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_EXCLUSIVE",
            msg: reason,
        }));
    }
    if !live
        .matcher
        .matches(crate::appservice::NamespaceScope::User, user_id.as_str())
    {
        return Err(ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_EXCLUSIVE",
            msg: format!(
                "user id `{}` is outside appservice `{}`'s user namespaces",
                user_id.as_str(),
                live.appservice.id
            ),
        }));
    }

    // Refuse collision with an existing local user.
    if state
        .db
        .user_exists(user_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        return Err(VelaError::UserInUse.into());
    }

    // Create passwordless user. Empty hash makes /login refuse; AS
    // re-authenticates via Bearer + ?user_id= for every subsequent
    // call.
    state
        .db
        .create_user(user_id.as_str(), "")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    Ok(Json(json!({ "user_id": user_id.as_str() })))
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

/// Sandboxed registration-policy hook (anti-spam signup). No-op — and no work —
/// when no plugin binds `check_registration`. A block is a hard reject: we
/// refuse to create the account, surfacing the plugin's errcode/reason (403).
fn registration_gate(
    state: &AppState,
    username: &str,
    kind: &str,
    headers: &HeaderMap,
) -> Result<(), ApiError> {
    // Lock-free snapshot, like the send gate; a concurrent SIGHUP can't tear it.
    let rt = state.extensions.load();
    if !rt.binds_check_registration() {
        return Ok(());
    }
    let ip = client_ip_from_headers(headers);
    let hashed = ip
        .as_deref()
        .map(|ip| hash_client_ip(state, ip, b"vela-ext-registration-ip-key/v1"));
    let ctx = vela_extensions::RegistrationContext {
        username,
        kind,
        client_ip_full: ip.as_deref(),
        client_ip_hashed: hashed.as_deref(),
    };
    match rt.check_registration(&ctx) {
        vela_extensions::Decision::Allow => Ok(()),
        vela_extensions::Decision::Block { errcode, reason } => {
            tracing::info!(username, kind, %errcode, %reason, "extension blocked registration");
            Err(ApiError(VelaError::ExtensionBlocked { errcode, reason }))
        }
    }
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
        appservice_nid: None,
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
    use std::sync::Arc;

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
            axum::http::HeaderMap::new(),
            body_with(Some(auth), "admin", "secret123"),
        )
        .await
        .expect_err("bot localpart reserved");
        assert!(matches!(err.0, VelaError::Forbidden(_)));
    }

    /// A `check_registration` plugin can block a signup — the anti-spam point,
    /// end to end: a blocking plugin rejects `/register` with its errcode before
    /// the account is created.
    #[cfg(feature = "extensions")]
    #[tokio::test]
    async fn registration_blocked_by_extension() {
        // Gitignored fixture — run vela-extensions/tests/fixtures/build.sh first (CI does).
        const REG: &[u8] =
            include_bytes!("../../../vela-extensions/tests/fixtures/register_guest.wasm");
        let (state, _tmp) = build_test_state();
        crate::admin::bootstrap(&state).await.unwrap();
        state
            .db
            .create_registration_token("tok-a", 0, 0, 0)
            .unwrap();
        // Inject a plugin that blocks usernames containing "spam".
        let rt = vela_extensions::Runtime::new(vec![vela_extensions::PluginConfig {
            name: "reg".into(),
            wasm: REG.to_vec(),
            fail_policy: vela_extensions::FailPolicy::Closed,
            fuel: 50_000_000,
            wall_ms: 0,
            memory_pages: 256,
            event_types: None,
            points: vela_extensions::Points {
                check_event: false,
                on_event: false,
                check_registration: true,
                check_media_upload: false,
                check_profile_update: false,
                check_room_create: false,
                filter_sync_event: false,
                check_login: false,
            },
            capabilities: Default::default(),
            client_ip: Default::default(),
            config: json!({ "mode": "block_spam" }),
        }])
        .expect("register plugin loads");
        state.extensions.store(Arc::new(rt));

        let auth = json!({"type": "m.login.registration_token", "token": "tok-a"});
        // A spammy username is rejected...
        let err = register(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            body_with(Some(auth.clone()), "spammer", "secret123"),
        )
        .await
        .expect_err("registration blocked by the plugin");
        assert!(matches!(err.0, VelaError::ExtensionBlocked { .. }));

        // ...a clean username goes through.
        register(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            body_with(Some(auth), "alice", "secret123"),
        )
        .await
        .expect("clean registration allowed");
    }

    /// The `_ext_` localpart prefix is reserved for extension plugin bots — a
    /// human must not register `@_ext_*`, or their events would be silently
    /// dropped from observation (loop protection skips that prefix).
    #[tokio::test]
    async fn register_refuses_ext_prefix() {
        let (state, _tmp) = build_test_state();
        crate::admin::bootstrap(&state).await.unwrap();
        state
            .db
            .create_registration_token("tok-a", 0, 0, 0)
            .unwrap();
        let auth = json!({"type": "m.login.registration_token", "token": "tok-a"});
        let err = register(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            body_with(Some(auth), "_ext_evil", "secret123"),
        )
        .await
        .expect_err("_ext_ prefix reserved");
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
            axum::http::HeaderMap::new(),
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
            axum::http::HeaderMap::new(),
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
            axum::http::HeaderMap::new(),
            body_with(Some(auth.clone()), "alice", "secret123"),
        )
        .await
        .expect("first use succeeds");
        // Token now exhausted. A second user trying to reuse it gets 403.
        let err = register(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            body_with(Some(auth), "bob", "secret123"),
        )
        .await
        .expect_err("second use refused");
        assert!(matches!(err.0, VelaError::Forbidden(_)));
    }

    fn seed_as(
        state: &AppState,
        as_id: &str,
        regex: &str,
        cleartext_token: &str,
    ) -> crate::appservice::LiveAppService {
        use crate::appservice::namespace::{Namespace, NamespaceScope};
        use crate::appservice::{AppService, AppServiceConfig, hash_token};
        let asv = AppService {
            nid: 0,
            id: as_id.into(),
            config: AppServiceConfig {
                url: "http://localhost".into(),
                hs_token_hash: hash_token(&format!("hs-{as_id}")),
                as_token_hash: hash_token(cleartext_token),
                sender_localpart: format!("_{as_id}_bot"),
                receive_ephemeral: false,
            },
            namespaces: vec![Namespace {
                scope: NamespaceScope::User,
                regex: regex.into(),
                exclusive: true,
            }],
            enabled: true,
            owner_nid: None,
            created_at_ms: 0,
        };
        state.appservice_registry.register(asv).unwrap();
        state.appservice_registry.get_by_id(as_id).unwrap()
    }

    fn as_headers(token: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert("authorization", format!("Bearer {token}").parse().unwrap());
        h
    }

    /// AS-mode register: type=m.login.application_service + Bearer
    /// as_token + a namespaced username succeeds even when public
    /// registration is closed, returns only `{user_id}` (no access_token).
    #[tokio::test]
    async fn as_register_succeeds_inside_namespace_when_public_registration_closed() {
        let (mut state, _tmp) = build_test_state();
        // Close public registration. AS register must still work.
        Arc::make_mut(&mut state.config).registration_enabled = false;
        seed_as(&state, "irc", r"^@_irc_.*:example\.com$", "as-tok-irc");

        let body = json!({
            "type": "m.login.application_service",
            "username": "_irc_alice",
            "inhibit_login": true,
        });
        let resp = register(
            State(state.clone()),
            as_headers("as-tok-irc"),
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .expect("AS register succeeds");
        assert_eq!(resp.0["user_id"], "@_irc_alice:example.com");
        assert!(resp.0.get("access_token").is_none());
        assert!(state.db.user_exists("@_irc_alice:example.com").unwrap());
    }

    /// AS-mode register accepts a full MXID in `username` (spec: AS
    /// may send either a localpart or a full MXID).
    #[tokio::test]
    async fn as_register_accepts_full_mxid_as_username() {
        let (state, _tmp) = build_test_state();
        seed_as(&state, "irc", r"^@_irc_.*:example\.com$", "as-tok-irc");
        let body = json!({
            "type": "m.login.application_service",
            "username": "@_irc_bob:example.com",
            "inhibit_login": true,
        });
        let resp = register(
            State(state.clone()),
            as_headers("as-tok-irc"),
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .expect("AS register with full MXID succeeds");
        assert_eq!(resp.0["user_id"], "@_irc_bob:example.com");
    }

    /// AS-mode register with a username outside the AS's namespace is
    /// refused with M_EXCLUSIVE.
    #[tokio::test]
    async fn as_register_refuses_outside_own_namespace() {
        let (state, _tmp) = build_test_state();
        seed_as(&state, "irc", r"^@_irc_.*:example\.com$", "as-tok-irc");
        let body = json!({
            "type": "m.login.application_service",
            "username": "alice", // not inside @_irc_.*
            "inhibit_login": true,
        });
        let err = register(
            State(state.clone()),
            as_headers("as-tok-irc"),
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .expect_err("outside namespace refused");
        match err.0 {
            VelaError::Custom { errcode, .. } => assert_eq!(errcode, "M_EXCLUSIVE"),
            other => panic!("expected M_EXCLUSIVE, got {other:?}"),
        }
    }

    /// AS-mode register without `inhibit_login: true` is refused.
    #[tokio::test]
    async fn as_register_requires_inhibit_login() {
        let (state, _tmp) = build_test_state();
        seed_as(&state, "irc", r"^@_irc_.*:example\.com$", "as-tok-irc");
        let body = json!({
            "type": "m.login.application_service",
            "username": "_irc_alice",
            // inhibit_login not set => default false
        });
        let err = register(
            State(state.clone()),
            as_headers("as-tok-irc"),
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .expect_err("inhibit_login required");
        match err.0 {
            VelaError::Custom { errcode, .. } => {
                assert_eq!(errcode, "M_APPSERVICE_LOGIN_UNSUPPORTED")
            }
            other => panic!("expected M_APPSERVICE_LOGIN_UNSUPPORTED, got {other:?}"),
        }
    }

    /// Non-AS user trying to register inside an AS's exclusive
    /// namespace is refused with M_EXCLUSIVE — protects bridge users.
    #[tokio::test]
    async fn non_as_register_refused_in_exclusive_namespace() {
        let (state, _tmp) = build_test_state();
        crate::admin::bootstrap(&state).await.unwrap();
        seed_as(&state, "irc", r"^@_irc_.*:example\.com$", "as-tok-irc");
        state
            .db
            .create_registration_token("tok-a", 0, 0, 0)
            .unwrap();
        let auth = json!({"type": "m.login.registration_token", "token": "tok-a"});
        let err = register(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            body_with(Some(auth), "_irc_eve", "secret123"),
        )
        .await
        .expect_err("non-AS in exclusive namespace refused");
        match err.0 {
            VelaError::Custom { errcode, .. } => assert_eq!(errcode, "M_EXCLUSIVE"),
            other => panic!("expected M_EXCLUSIVE, got {other:?}"),
        }
    }

    fn enable_phase2(state: &mut AppState) {
        let cfg = Arc::make_mut(&mut state.config);
        cfg.oidc.enabled = true;
        cfg.oidc.issuer = "https://idp.example.com".into();
        cfg.oidc.introspection_endpoint = Some("https://idp.example.com/oauth2/introspect".into());
        cfg.oidc.account_management_url = Some("https://idp.example.com/account".into());
    }

    /// Phase 2 active: human /register is gone. The error message
    /// surfaces the IdP's account-management URL so a client UI can
    /// redirect the user there.
    #[tokio::test]
    async fn non_as_register_refused_under_phase2() {
        let (mut state, _tmp) = build_test_state();
        enable_phase2(&mut state);
        let auth = json!({"type": "m.login.registration_token", "token": "tok"});
        let err = register(
            State(state.clone()),
            axum::http::HeaderMap::new(),
            body_with(Some(auth), "alice", "secret123"),
        )
        .await
        .expect_err("human register must be refused under Phase 2");
        match err.0 {
            VelaError::Forbidden(msg) => {
                assert!(
                    msg.contains("idp.example.com"),
                    "error must name the IdP: {msg}",
                );
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    /// AS-mode /register MUST keep working under Phase 2 — bridges
    /// aren't human users and shouldn't be locked out when the
    /// operator delegates human auth.
    #[tokio::test]
    async fn as_register_still_works_under_phase2() {
        let (mut state, _tmp) = build_test_state();
        enable_phase2(&mut state);
        seed_as(&state, "irc", r"^@_irc_.*:example\.com$", "as-tok-irc");
        let body = json!({
            "type": "m.login.application_service",
            "username": "_irc_alice",
            "inhibit_login": true,
        });
        let resp = register(
            State(state.clone()),
            as_headers("as-tok-irc"),
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await
        .expect("AS register succeeds under Phase 2");
        assert_eq!(resp.0["user_id"], "@_irc_alice:example.com");
    }
}
