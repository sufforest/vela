use crate::middleware::json::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::router::AppState;

/// Heuristic: is this server_name a development placeholder rather
/// than a real public domain? `localhost` is unambiguous; bare IP
/// literals catch container-only setups; anything else (e.g.
/// `chat.example.org`, `matrix.example.com`) is treated as public so
/// that well-known publishes `https://<name>` by default.
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

/// Resolve the public base URL clients reach this homeserver at.
///
/// Single source of truth for that URL, used by BOTH
/// `.well-known/matrix/client` (discovery, before login) AND the
/// `well_known` block of the `/login` response (after login). The two
/// MUST agree: Element validates the post-login URL against the
/// discovered one and, on a mismatch, refuses the session with "… is
/// misconfigured … incorrect or duplicate entries". Sharing this
/// resolver is what keeps the two call sites in lockstep — they diverged
/// once (login hardcoded `http://{bind}:{port}`) and that is exactly the
/// "duplicate entries" failure this prevents.
///
/// Resolution order:
///   1. operator-set `[server] public_base_url` (explicit override)
///   2. https://{server_name} (the common case: API host == identity)
///   3. http://{bind_host}:{bind_port} (dev fallback for localhost
///      or other non-public server_name values)
///
/// Without (2), every reverse-proxied deploy (Caddy / Cloudflare /
/// nginx — i.e. almost all real ones) saw "http://127.0.0.1:8008" and
/// Element fell to the laptop's loopback. (2) covers "API host ==
/// identity domain" (95% of personal homeservers); (1) is only needed
/// when the API runs at a different host or non-default port.
pub fn resolve_base_url(config: &crate::router::ServerConfig) -> String {
    if let Some(url) = &config.public_base_url {
        url.clone()
    } else if !is_local_server_name(&config.server_name) {
        format!("https://{}", config.server_name)
    } else {
        format!("http://{}:{}", config.bind_host, config.bind_port)
    }
}

pub async fn well_known(State(state): State<AppState>) -> Json<Value> {
    let mut out = serde_json::Map::new();
    out.insert(
        "m.homeserver".to_string(),
        json!({"base_url": resolve_base_url(&state.config)}),
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

/// `GET /.well-known/matrix/support` (MSC1929 / spec v1.10).
///
/// Static admin/security contact discovery. Returns 404 when the
/// operator hasn't configured any contacts or a support page — the
/// spec lets clients treat an empty doc as "no info", but a 404 avoids
/// advertising a meaningless empty `{}`.
pub async fn well_known_support(State(state): State<AppState>) -> impl IntoResponse {
    let support = &state.config.support;
    if support.is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({}))).into_response();
    }

    let mut out = serde_json::Map::new();
    if !support.contacts.is_empty() {
        let contacts: Vec<Value> = support
            .contacts
            .iter()
            .map(|c| {
                let mut m = serde_json::Map::new();
                if let Some(v) = &c.matrix_id {
                    m.insert("matrix_id".to_string(), json!(v));
                }
                if let Some(v) = &c.email_address {
                    m.insert("email_address".to_string(), json!(v));
                }
                if let Some(v) = &c.role {
                    m.insert("role".to_string(), json!(v));
                }
                Value::Object(m)
            })
            .collect();
        out.insert("contacts".to_string(), Value::Array(contacts));
    }
    if let Some(page) = &support.support_page {
        out.insert("support_page".to_string(), json!(page));
    }
    Json(Value::Object(out)).into_response()
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
        // MSC4140 delayed events.
        ("org.matrix.msc4140".to_string(), json!(true)),
        ("org.matrix.msc4143".to_string(), json!(true)),
        // MSC4155 (server-side invite filtering).
        ("org.matrix.msc4155".to_string(), json!(true)),
        // MSC4133 (extended profile fields).
        ("uk.tcpip.msc4133".to_string(), json!(true)),
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
/// or 404 `M_UNRECOGNIZED` otherwise — the spec's "this homeserver runs
/// legacy auth" signal (CS-API v1.15).
pub async fn auth_issuer(State(state): State<AppState>) -> axum::response::Response {
    if !state.config.oidc.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                // Spec (CS-API v1.15): a server that does NOT support the
                // OAuth 2.0 API responds 404 + M_UNRECOGNIZED. Element's
                // auth_metadata probe keys on this errcode to fall back to
                // legacy password login; any other 404 errcode is treated
                // as a hard discovery error ("misconfigured").
                "errcode": "M_UNRECOGNIZED",
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

/// MSC2965 `GET /_matrix/client/v1/auth_metadata`. Returns the IdP's
/// RFC 8414 OAuth authorization-server metadata (token/authorization
/// endpoints, JWKS, supported scopes, …). vela doesn't hold those itself,
/// so it relays the issuer's `/.well-known/oauth-authorization-server`;
/// on any fetch failure it falls back to a minimal `{issuer, account}`
/// doc so clients can at least discover the issuer. 404 `M_UNRECOGNIZED`
/// when delegated auth is off (the spec's not-supported signal — clients
/// then use legacy login). The issuer is operator-configured (not user
/// input), so the outbound fetch is not an SSRF vector.
pub async fn auth_metadata(State(state): State<AppState>) -> axum::response::Response {
    if !state.config.oidc.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                // Spec (CS-API v1.15): a server that does NOT support the
                // OAuth 2.0 API responds 404 + M_UNRECOGNIZED. Element's
                // auth_metadata probe keys on this errcode to fall back to
                // legacy password login; any other 404 errcode is treated
                // as a hard discovery error ("misconfigured").
                "errcode": "M_UNRECOGNIZED",
                "error": "this homeserver does not delegate authentication",
            })),
        )
            .into_response();
    }

    let issuer = state.config.oidc.issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/oauth-authorization-server");

    if let Some(mut doc) = fetch_idp_metadata(&url).await
        && let Some(obj) = doc.as_object_mut()
    {
        obj.entry("issuer".to_string())
            .or_insert_with(|| json!(state.config.oidc.issuer));
        if let Some(acct) = &state.config.oidc.account_management_url {
            obj.entry("account_management_uri".to_string())
                .or_insert_with(|| json!(acct));
        }
        return Json(doc).into_response();
    }

    // Fallback: issuer + account only.
    let mut body = serde_json::Map::new();
    body.insert("issuer".to_string(), json!(state.config.oidc.issuer));
    if let Some(acct) = &state.config.oidc.account_management_url {
        body.insert("account_management_uri".to_string(), json!(acct));
    }
    Json(Value::Object(body)).into_response()
}

async fn fetch_idp_metadata(url: &str) -> Option<Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state_with_name;
    use std::sync::Arc;

    #[test]
    fn is_local_server_name_classifies_dev_vs_public() {
        // Dev placeholders → local (well-known falls back to bind addr).
        assert!(is_local_server_name("localhost"));
        assert!(is_local_server_name("localhost:8008"));
        assert!(is_local_server_name("127.0.0.1"));
        assert!(is_local_server_name("10.0.0.5:8448"));
        assert!(is_local_server_name("192.168.1.20"));
        // Real public names → not local (well-known publishes https://).
        assert!(!is_local_server_name("chat.example.net"));
        assert!(!is_local_server_name("matrix.example.com"));
        assert!(!is_local_server_name("example.com"));
        // Not a bare IPv4 (too many octets / out of u8 range) → a name.
        assert!(!is_local_server_name("1.2.3.4.5"));
        assert!(!is_local_server_name("999.1.1.1"));
    }

    #[tokio::test]
    async fn resolve_base_url_prefers_https_name_over_bind_addr() {
        // A real public server_name resolves to https://<name>, NOT the
        // loopback bind address — the bug that sent Element to 127.0.0.1.
        let (state, _tmp) = build_test_state_with_name("matrix.example.org");
        assert_eq!(
            resolve_base_url(&state.config),
            "https://matrix.example.org"
        );
    }

    #[tokio::test]
    async fn resolve_base_url_falls_back_to_bind_for_localhost() {
        // bind_host=127.0.0.1, bind_port=0 in the test fixture.
        let (state, _tmp) = build_test_state_with_name("localhost");
        assert_eq!(resolve_base_url(&state.config), "http://127.0.0.1:0");
    }

    #[tokio::test]
    async fn resolve_base_url_honours_explicit_public_base_url() {
        // Explicit override wins even over a public server_name.
        let (mut state, _tmp) = build_test_state_with_name("matrix.example.org");
        Arc::make_mut(&mut state.config).public_base_url =
            Some("https://api.example.org".to_string());
        assert_eq!(resolve_base_url(&state.config), "https://api.example.org");
    }
}
