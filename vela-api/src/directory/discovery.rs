use crate::middleware::json::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::router::AppState;

/// Heuristic: is this server_name a development placeholder rather
/// than a real public domain? `localhost` is unambiguous; bare IP
/// literals catch container-only setups; anything else (e.g.
/// `pwd.wiki`, `matrix.example.com`) is treated as public so that
/// well-known publishes `https://<name>` by default.
fn is_local_server_name(name: &str) -> bool {
    if name == "localhost" || name.starts_with("localhost:") {
        return true;
    }
    // Bare IPv4 literal? (4 dot-separated all-numeric components.)
    if name.split(':').next().is_some_and(|host| {
        let parts: Vec<&str> = host.split('.').collect();
        parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
    }) {
        return true;
    }
    false
}

pub async fn well_known(State(state): State<AppState>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    // Resolution order:
    //   1. operator-set [server] public_base_url (explicit override)
    //   2. https://{server_name} (the common case: API host == identity)
    //   3. http://{bind_host}:{bind_port} (dev fallback for localhost
    //      or other non-public server_name values)
    //
    // Without (2), every reverse-proxied deploy (Caddy / Cloudflare /
    // nginx — i.e. almost all real ones) saw "http://127.0.0.1:8008"
    // in well-known and Element fell to the laptop's loopback. (2)
    // covers the "API is at https://<identity-domain>" case which is
    // 95% of personal-homeserver setups; (1) is only needed when the
    // API runs at a different host (e.g. matrix.example.com proxying
    // for identity domain example.com) or non-default port.
    let base_url = if let Some(url) = &state.config.public_base_url {
        url.clone()
    } else if !is_local_server_name(&state.config.server_name) {
        format!("https://{}", state.config.server_name)
    } else {
        format!(
            "http://{}:{}",
            state.config.bind_host, state.config.bind_port
        )
    };
    out.insert("m.homeserver".to_string(), json!({"base_url": base_url}));
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
        // MSC3030 stabilised in Matrix 1.6 as `/v1/rooms/{id}/timestamp_to_event`.
        // Advertise the unstable flag too for clients that don't check
        // matrix versions — the endpoint is implemented either way.
        ("org.matrix.msc3030".to_string(), json!(true)),
        // MSC3391 (account_data deletion endpoints).
        ("org.matrix.msc3391".to_string(), json!(true)),
        // MSC3874 (filter /messages by m.relates_to.rel_type).
        ("org.matrix.msc3874".to_string(), json!(true)),
        // MSC3890 (purge device-local notification settings on logout).
        ("org.matrix.msc3890".to_string(), json!(true)),
        // MSC3930 (default push rules for poll events).
        ("org.matrix.msc3930".to_string(), json!(true)),
        // MSC3967 (idempotent cross-signing key upload).
        ("org.matrix.msc3967".to_string(), json!(true)),
        ("org.matrix.msc4140".to_string(), json!(false)),
        ("org.matrix.msc4143".to_string(), json!(true)),
        // MSC4155 (server-side invite filtering).
        ("org.matrix.msc4155".to_string(), json!(true)),
        ("org.matrix.msc4222".to_string(), json!(true)),
        ("io.element.msc4306".to_string(), json!(true)),
        ("io.element.msc4308".to_string(), json!(true)),
        // MSC3706 partial-state joins: outbound /send_join sets
        // `omit_members=true` and inbound honours the same param,
        // returning partial state when asked. Filler fills the rest
        // in the background.
        ("org.matrix.msc3706".to_string(), json!(true)),
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
