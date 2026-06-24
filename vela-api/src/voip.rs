//! VoIP — classic 1-to-1 (`/voip/turnServer`) and matrix-rtc / Element
//! Call (`MSC4143`).
//!
//! Classic path: mints time-limited HMAC credentials in coturn's
//! standard `use-auth-secret` mode. The mxid is encoded into the
//! username so the operator can correlate calls back to user accounts
//! in their TURN access logs. Empty config → 404.
//!
//! matrix-rtc path: when the operator has wired LiveKit, we mint a
//! short-lived LiveKit JWT scoped to the requested room. The
//! `.well-known/matrix/client` advertises the SFU URL so clients
//! know where to connect. Empty config → 404 on the JWT endpoint
//! and no entry in `.well-known`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use base64::Engine;
use hmac::{Hmac, Mac};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use serde_json::{Value, json};
use sha1::Sha1;
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// GET /_matrix/client/v3/voip/turnServer
///
/// Returns time-limited TURN credentials for the calling user. coturn
/// in `use-auth-secret` mode accepts any username of the form
/// `<expiry>:<user_id>` provided the password is the HMAC-SHA1 of the
/// username with the shared secret. We expose the standard shape per
/// matrix spec (`username` / `password` / `uris` / `ttl`).
///
/// 404 when the operator didn't configure TURN — clients then fall
/// back to direct WebRTC, which is fine on permissive networks.
pub async fn turn_server(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let cfg = &state.config.voip;
    if cfg.shared_secret.is_empty() || cfg.uris.is_empty() {
        return Err(ApiError(VelaError::NotFound(
            "VoIP not configured on this server".into(),
        )));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expiry = now + cfg.ttl_seconds as u64;
    let username = format!("{expiry}:{}", user.user_id);
    let password = hmac_sha1_base64(cfg.shared_secret.as_bytes(), username.as_bytes());
    Ok(Json(json!({
        "username": username,
        "password": password,
        "uris": cfg.uris,
        "ttl": cfg.ttl_seconds,
    })))
}

/// POST /_matrix/client/unstable/org.matrix.msc4143/rtc/transport
/// (and the stable name once MSC4143 lands)
///
/// Mints a LiveKit-compatible JWT scoped to a specific room. The
/// client uses the JWT to connect to the SFU advertised in
/// `.well-known/matrix/client`. We sign HS256 with the operator's
/// LiveKit secret; LiveKit verifies and grants `roomJoin` /
/// `canPublish` / `canSubscribe` for the requested room only.
pub async fn rtc_jwt(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cfg = &state.config.rtc;
    if cfg.livekit_secret.is_empty() || cfg.sfu_url.is_empty() {
        return Err(ApiError(VelaError::NotFound(
            "matrix-rtc not configured on this server".into(),
        )));
    }

    // The caller must be a current room participant (joined OR
    // invited). Without this check anyone with a token could ask us
    // to mint a JWT for any room and use it to join via the SFU
    // directly.
    let Some(room_nid) = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Err(ApiError(VelaError::NotFound("room not found".into())));
    };
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if !matches!(membership, Some(1) | Some(2)) {
        return Err(ApiError(VelaError::Forbidden(
            "not a participant in this room".into(),
        )));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let exp = now + cfg.jwt_ttl_seconds as u64;
    let claims = LiveKitClaims {
        iss: cfg.livekit_api_key.clone(),
        sub: user.user_id.clone(),
        nbf: now,
        exp,
        // LiveKit identifies participants by `sub`; we use the full
        // mxid so the SFU's logs/UI line up with Matrix identity.
        name: user.user_id.clone(),
        video: LiveKitVideoGrant {
            room: room_id.clone(),
            room_join: true,
            can_publish: true,
            can_subscribe: true,
            can_publish_data: true,
        },
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(cfg.livekit_secret.as_bytes()),
    )
    .map_err(|e| ApiError(VelaError::Unknown(format!("livekit jwt: {e}"))))?;

    Ok(Json(json!({
        "url": cfg.sfu_url,
        "jwt": token,
    })))
}

/// The matrix-rtc (MSC4143) transports this server advertises.
///
/// Single source of truth for BOTH `.well-known`'s
/// `org.matrix.msc4143.rtc_foci` block and the `GET .../rtc/transports`
/// response, so the two can't drift (the same lesson as
/// `discovery::resolve_base_url`). Empty when no SFU is configured.
pub fn rtc_foci_list(rtc: &crate::router::RtcConfig) -> Vec<Value> {
    if rtc.sfu_url.is_empty() {
        return Vec::new();
    }
    vec![json!({
        "type": "livekit",
        "livekit_service_url": rtc.sfu_url,
    })]
}

/// GET /_matrix/client/unstable/org.matrix.msc4143/rtc/transports
/// (and the `/v1/rtc/transports` path).
///
/// MSC4143 transport discovery — Element Call reads this to find the
/// LiveKit backend, mirroring the `rtc_foci` it would otherwise read
/// from `.well-known`. Authenticated (401 without a token, per spec).
/// Empty list when no SFU is configured; the client then shows no
/// group-call transport rather than erroring.
pub async fn rtc_transports(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
) -> Json<Value> {
    Json(json!({ "rtc_transports": rtc_foci_list(&state.config.rtc) }))
}

/// HMAC-SHA1 with the given key, base64-encoded — coturn's expected
/// password format under `use-auth-secret`.
fn hmac_sha1_base64(key: &[u8], data: &[u8]) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    base64::engine::general_purpose::STANDARD.encode(result)
}

/// LiveKit JWT claims. LiveKit reads `iss` (the API key), `sub`
/// (participant identity), and `video` (the grants). We don't issue
/// admin or recording grants — those would let a participant
/// override the SFU's room state.
#[derive(Serialize)]
struct LiveKitClaims {
    iss: String,
    sub: String,
    nbf: u64,
    exp: u64,
    name: String,
    video: LiveKitVideoGrant,
}

#[derive(Serialize)]
struct LiveKitVideoGrant {
    room: String,
    #[serde(rename = "roomJoin")]
    room_join: bool,
    #[serde(rename = "canPublish")]
    can_publish: bool,
    #[serde(rename = "canSubscribe")]
    can_subscribe: bool,
    #[serde(rename = "canPublishData")]
    can_publish_data: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::router::RtcConfig;

    #[test]
    fn rtc_foci_list_empty_without_sfu() {
        assert!(rtc_foci_list(&RtcConfig::default()).is_empty());
    }

    #[test]
    fn rtc_foci_list_advertises_livekit_when_configured() {
        let rtc = RtcConfig {
            sfu_url: "https://sfu.example.org/livekit/jwt".into(),
            livekit_api_key: "key".into(),
            livekit_secret: "secret".into(),
            jwt_ttl_seconds: 3600,
        };
        assert_eq!(
            rtc_foci_list(&rtc),
            vec![json!({
                "type": "livekit",
                "livekit_service_url": "https://sfu.example.org/livekit/jwt",
            })]
        );
    }
}
