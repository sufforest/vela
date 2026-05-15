use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::router::AppState;

pub async fn well_known(State(state): State<AppState>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    out.insert(
        "m.homeserver".to_string(),
        json!({
            "base_url": format!("http://{}:{}", state.config.bind_host, state.config.bind_port)
        }),
    );
    // MSC4143: advertise the matrix-rtc SFU as a "focus" clients can
    // use for group calls. Empty config → no entry; clients then
    // fall back to whatever focus another participant brings or the
    // classic m.call.* path.
    if !state.config.rtc.sfu_url.is_empty() {
        out.insert(
            "org.matrix.msc4143.rtc_foci".to_string(),
            json!([{
                "type": "livekit",
                "livekit_service_url": state.config.rtc.sfu_url,
            }]),
        );
    }
    // MSC3861 phase 1: when OIDC delegation is configured, advertise
    // the issuer here too so Element X et al. can pick it up directly
    // from `.well-known` without a second roundtrip to `/auth_issuer`.
    if state.config.oidc.enabled {
        let mut block = serde_json::Map::new();
        block.insert("issuer".to_string(), json!(state.config.oidc.issuer));
        if let Some(url) = &state.config.oidc.account_management_url {
            block.insert("account".to_string(), json!(url));
        }
        out.insert("org.matrix.msc3861".to_string(), Value::Object(block));
    }
    Json(Value::Object(out))
}

pub async fn versions(State(state): State<AppState>) -> Json<Value> {
    // We implement the v1.18 CS-API surface + sliding sync (MSC4186).
    // Advertising older versions too lets clients pinned to v1.12–v1.17
    // fall through to features they know about instead of bailing.
    let mut unstable = serde_json::Map::from_iter([
        ("org.matrix.simplified_msc3575".to_string(), json!(true)),
        ("org.matrix.msc3030".to_string(), json!(false)),
        ("org.matrix.msc4140".to_string(), json!(false)),
        ("org.matrix.msc4143".to_string(), json!(true)),
        ("org.matrix.msc4222".to_string(), json!(true)),
        ("io.element.msc4306".to_string(), json!(true)),
        ("io.element.msc4308".to_string(), json!(true)),
    ]);
    // Phase 1 capability bit: only when the operator has actually
    // wired up an OIDC issuer. A bare `true` here would mislead
    // clients into attempting an OAuth flow against a server that
    // hasn't been configured for it.
    if state.config.oidc.enabled {
        unstable.insert("org.matrix.msc3861".to_string(), json!(true));
    }
    Json(json!({
        "versions": [
            "v1.12", "v1.13", "v1.14", "v1.15", "v1.16", "v1.17", "v1.18"
        ],
        "unstable_features": unstable,
    }))
}

/// MSC3861 `GET /_matrix/client/v1/auth_issuer`. Returns the configured
/// issuer (and optional account-management URL) when delegation is on,
/// or 404 `M_NOT_FOUND` otherwise — the spec's "this homeserver runs
/// legacy auth" signal.
pub async fn auth_issuer(State(state): State<AppState>) -> axum::response::Response {
    if !state.config.oidc.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "errcode": "M_NOT_FOUND",
                "error": "this homeserver does not delegate authentication",
            })),
        )
            .into_response();
    }
    let mut body = serde_json::Map::new();
    body.insert("issuer".to_string(), json!(state.config.oidc.issuer));
    if let Some(url) = &state.config.oidc.account_management_url {
        body.insert("account".to_string(), json!(url));
    }
    Json(Value::Object(body)).into_response()
}
