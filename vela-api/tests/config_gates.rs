//! P0 config gates: federation_enabled, registration_enabled,
//! registration_token, max_upload_size.
//!
//! Each test flips one knob and verifies the surface behaviour the
//! operator expects. Defaults preserve the previous always-on
//! behaviour so the rest of the integration suite is unaffected.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{ConfigOverrides, Harness, read_json};

// --- federation_enabled ---------------------------------------------------

/// `/_matrix/federation/v1/query/directory` is in the authenticated
/// federation route set: when federation is on, an unauthenticated GET
/// should hit middleware (401); when federation is off, the route is
/// not mounted at all (404).
const FED_ROUTE: &str = "/_matrix/federation/v1/query/directory?room_alias=%23a:r.example";

#[tokio::test]
async fn federation_disabled_returns_404_on_federation_routes() {
    let harness = Harness::with_config(ConfigOverrides {
        federation_enabled: false,
        ..Default::default()
    });
    let resp = harness
        .request(Request::get(FED_ROUTE).body(Body::empty()).unwrap())
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "federation routes must 404 when disabled: {resp:?}"
    );
}

#[tokio::test]
async fn federation_enabled_serves_federation_routes() {
    // Default = enabled. Sanity check that the route IS mounted —
    // unauthenticated request hits middleware and returns 401, NOT 404.
    let harness = Harness::new();
    let resp = harness
        .request(Request::get(FED_ROUTE).body(Body::empty()).unwrap())
        .await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "federation routes must be mounted by default: {resp:?}"
    );
}

#[tokio::test]
async fn federation_disabled_short_circuits_outbound_client() {
    let harness = Harness::with_config(ConfigOverrides {
        federation_enabled: false,
        ..Default::default()
    });
    let res = harness
        .state
        .federation_client
        .signed_request(
            reqwest::Method::GET,
            "remote.example",
            "/_matrix/federation/v1/version",
            None,
        )
        .await;
    let err = res.expect_err("expected federation-disabled error");
    let msg = err.to_string();
    assert!(
        msg.contains("federation is disabled"),
        "expected disabled error, got {msg}"
    );
}

// --- registration_enabled / registration_token ----------------------------

#[tokio::test]
async fn registration_disabled_returns_403() {
    let harness = Harness::with_config(ConfigOverrides {
        registration_enabled: false,
        ..Default::default()
    });
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "alice",
                        "password": "pw",
                        "auth": {"type": "m.login.dummy"},
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = read_json(resp).await;
    assert_eq!(body["errcode"], "M_FORBIDDEN");
}

#[tokio::test]
async fn registration_token_required_and_rejects_missing() {
    let harness = Harness::with_config(ConfigOverrides {
        registration_token: Some("hunter2".into()),
        ..Default::default()
    });
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "alice",
                        "password": "pw",
                        "auth": {"type": "m.login.dummy"},
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "registration without token must be rejected when token is required"
    );
}

#[tokio::test]
async fn registration_token_required_rejects_wrong_token() {
    let harness = Harness::with_config(ConfigOverrides {
        registration_token: Some("hunter2".into()),
        ..Default::default()
    });
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "alice",
                        "password": "pw",
                        "auth": {
                            "type": "m.login.registration_token",
                            "token": "wrong_token"
                        },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn registration_token_required_accepts_correct_token() {
    let harness = Harness::with_config(ConfigOverrides {
        registration_token: Some("hunter2".into()),
        ..Default::default()
    });
    // The static fallback was removed: the [registration] token in the
    // config only matters when admin::bootstrap seeds it into the CF.
    // Tests skip bootstrap, so we seed the token here ourselves to
    // exercise the "valid token presented" path.
    harness
        .state
        .db
        .create_registration_token("hunter2", 0, 0, 0)
        .expect("seed registration_token CF for test");
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "alice",
                        "password": "pw",
                        "auth": {
                            "type": "m.login.registration_token",
                            "token": "hunter2"
                        },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "correct token must succeed: {resp:?}"
    );
    let body = read_json(resp).await;
    assert!(body["access_token"].is_string());
}

#[tokio::test]
async fn single_use_token_is_consumed_after_one_registration() {
    // Bootstrap-shaped token: uses_allowed = 1. First registrant succeeds;
    // second attempt with the same token fails because the CF row is gone.
    // Locks in the design where the static bootstrap token, once seeded
    // single-use, can't be re-used as a back-door even if the operator
    // leaves it in vela.toml.
    let harness = Harness::with_config(ConfigOverrides {
        registration_token: Some("bootstrap-once".into()),
        ..Default::default()
    });
    harness
        .state
        .db
        .create_registration_token("bootstrap-once", 1, 0, 0)
        .expect("seed single-use token");

    let register = |username: &'static str| {
        let h = &harness;
        async move {
            h.request(
                Request::post("/_matrix/client/v3/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "username": username,
                            "password": "pw",
                            "auth": {
                                "type": "m.login.registration_token",
                                "token": "bootstrap-once",
                            },
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
        }
    };

    let r1 = register("first").await;
    assert_eq!(r1.status(), StatusCode::OK, "first registrant: {r1:?}");

    let r2 = register("second").await;
    assert_eq!(
        r2.status(),
        StatusCode::FORBIDDEN,
        "second use of single-use token must be rejected: {r2:?}"
    );
}

#[tokio::test]
async fn failed_registration_does_not_consume_token() {
    // Two-phase consume: validate up front (read-only), commit-consume
    // late. A registration that fails before user creation (e.g. invalid
    // username) must leave the token usable. Otherwise a typo would burn
    // the bootstrap token and lock the operator out.
    let harness = Harness::with_config(ConfigOverrides {
        registration_token: Some("survive-typo".into()),
        ..Default::default()
    });
    harness
        .state
        .db
        .create_registration_token("survive-typo", 1, 0, 0)
        .expect("seed single-use token");

    // First attempt: invalid username (empty). Must 4xx WITHOUT consuming.
    let r1 = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "",
                        "password": "pw",
                        "auth": {
                            "type": "m.login.registration_token",
                            "token": "survive-typo",
                        },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_ne!(r1.status(), StatusCode::OK, "invalid username must fail");

    // Token should still be usable: second attempt with valid username succeeds.
    let r2 = harness
        .request(
            Request::post("/_matrix/client/v3/register")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "username": "alice",
                        "password": "pw",
                        "auth": {
                            "type": "m.login.registration_token",
                            "token": "survive-typo",
                        },
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(
        r2.status(),
        StatusCode::OK,
        "token must still be valid after failed-registration: {r2:?}"
    );
}

// --- max_upload_size ------------------------------------------------------

#[tokio::test]
async fn max_upload_size_rejects_oversized_upload() {
    let harness = Harness::with_config(ConfigOverrides {
        max_upload_size: 1024, // 1 KiB cap
        ..Default::default()
    });
    let (_, alice_tok) = harness.register("alice", "pw").await;

    // 2 KiB payload — over the 1 KiB cap.
    let payload = vec![b'a'; 2048];
    let resp = harness
        .request(
            Request::post("/_matrix/media/v3/upload")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/octet-stream")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
    // Either 413 (body limit layer) or our custom error code — both
    // are valid for "too large." Our handler currently maps it through
    // ApiError. Accept either as long as it's not 200.
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "oversized upload must NOT succeed: {resp:?}"
    );
    assert!(
        resp.status().is_client_error(),
        "oversized upload should yield 4xx, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn max_upload_size_reported_via_media_config_endpoint() {
    let harness = Harness::with_config(ConfigOverrides {
        max_upload_size: 1024 * 1024, // 1 MiB
        ..Default::default()
    });
    let (_, alice_tok) = harness.register("alice", "pw").await;
    let resp = harness
        .request(
            Request::get("/_matrix/media/v3/config")
                .header("authorization", format!("Bearer {alice_tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = read_json(resp).await;
    assert_eq!(body["m.upload.size"], 1024 * 1024);
}

// --- encrypt_by_default ----------------------------------------------------

async fn create_room_and_get_encryption(
    harness: &Harness,
    token: &str,
    body: Value,
) -> Option<String> {
    let resp = harness
        .request(
            Request::post("/_matrix/client/v3/createRoom")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v = read_json(resp).await;
    let room_id = v["room_id"].as_str().unwrap().to_string();

    // Read m.room.encryption state event for that room.
    let resp = harness
        .request(
            Request::get(format!(
                "/_matrix/client/v3/rooms/{}/state/m.room.encryption/",
                urlencoding::encode(&room_id)
            ))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    if resp.status() != StatusCode::OK {
        return None;
    }
    let v = read_json(resp).await;
    v.get("algorithm")
        .and_then(|s| s.as_str())
        .map(String::from)
}

mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.replace('!', "%21").replace(':', "%3A")
    }
}

#[tokio::test]
async fn encrypt_by_default_off_does_not_inject_encryption() {
    let harness = Harness::new(); // default: Off
    let (_, tok) = harness.register("alice", "pw").await;
    let alg =
        create_room_and_get_encryption(&harness, &tok, json!({"preset": "private_chat"})).await;
    assert!(alg.is_none(), "default policy should not inject encryption");
}

#[tokio::test]
async fn encrypt_by_default_private_only_injects_for_private_chat() {
    let harness = Harness::with_config(ConfigOverrides {
        encrypt_by_default: vela_api::router::EncryptByDefault::PrivateOnly,
        ..Default::default()
    });
    let (_, tok) = harness.register("alice", "pw").await;
    let alg =
        create_room_and_get_encryption(&harness, &tok, json!({"preset": "private_chat"})).await;
    assert_eq!(alg.as_deref(), Some("m.megolm.v1.aes-sha2"));
}

#[tokio::test]
async fn encrypt_by_default_private_only_skips_public_chat() {
    let harness = Harness::with_config(ConfigOverrides {
        encrypt_by_default: vela_api::router::EncryptByDefault::PrivateOnly,
        ..Default::default()
    });
    let (_, tok) = harness.register("alice", "pw").await;
    let alg =
        create_room_and_get_encryption(&harness, &tok, json!({"preset": "public_chat"})).await;
    assert!(
        alg.is_none(),
        "public_chat must not be auto-encrypted regardless of policy"
    );
}

#[tokio::test]
async fn explicit_initial_state_wins_over_policy() {
    // Policy says inject; client explicitly opts out via empty
    // algorithm. Client wins.
    let harness = Harness::with_config(ConfigOverrides {
        encrypt_by_default: vela_api::router::EncryptByDefault::All,
        ..Default::default()
    });
    let (_, tok) = harness.register("alice", "pw").await;
    let alg = create_room_and_get_encryption(
        &harness,
        &tok,
        json!({
            "preset": "private_chat",
            "initial_state": [{
                "type": "m.room.encryption",
                "state_key": "",
                "content": {"algorithm": "client.choose"},
            }],
        }),
    )
    .await;
    assert_eq!(
        alg.as_deref(),
        Some("client.choose"),
        "client-supplied m.room.encryption must win over server policy"
    );
}

#[tokio::test]
async fn encrypt_by_default_dm_only_requires_is_direct() {
    let harness = Harness::with_config(ConfigOverrides {
        encrypt_by_default: vela_api::router::EncryptByDefault::DmOnly,
        ..Default::default()
    });
    let (_, tok) = harness.register("alice", "pw").await;

    let alg_no_dm =
        create_room_and_get_encryption(&harness, &tok, json!({"preset": "private_chat"})).await;
    assert!(
        alg_no_dm.is_none(),
        "dm_only without is_direct: no injection"
    );

    let alg_dm = create_room_and_get_encryption(
        &harness,
        &tok,
        json!({"preset": "private_chat", "is_direct": true}),
    )
    .await;
    assert_eq!(
        alg_dm.as_deref(),
        Some("m.megolm.v1.aes-sha2"),
        "dm_only with is_direct: should inject"
    );
}

/// Regression test: axum's per-extractor body limit defaults to 2 MiB.
/// Without `DefaultBodyLimit::max(...)` on the router, ANY upload
/// over 2 MiB rejected with 413 — even though our config says 50 MiB.
/// Element's "exceeds this homeserver's size limit" error pointed at
/// this. A 4 MiB upload under the default 50 MiB cap must succeed.
#[tokio::test]
async fn upload_above_axum_default_2mb_succeeds_under_configured_cap() {
    let harness = Harness::new(); // default 50 MiB cap
    let (_, alice_tok) = harness.register("alice", "pw").await;
    let payload = vec![b'a'; 4 * 1024 * 1024]; // 4 MiB — was the broken case
    let resp = harness
        .request(
            Request::post("/_matrix/media/v3/upload")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/octet-stream")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "4 MiB upload under 50 MiB cap must succeed: {resp:?}"
    );
    let body = read_json(resp).await;
    assert!(body["content_uri"].is_string());
}

#[tokio::test]
async fn max_upload_size_accepts_under_limit() {
    let harness = Harness::with_config(ConfigOverrides {
        max_upload_size: 8192,
        ..Default::default()
    });
    let (_, alice_tok) = harness.register("alice", "pw").await;
    let payload = vec![b'a'; 4096]; // half the cap
    let resp = harness
        .request(
            Request::post("/_matrix/media/v3/upload")
                .header("authorization", format!("Bearer {alice_tok}"))
                .header("content-type", "application/octet-stream")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "under-cap upload should succeed: {resp:?}"
    );
    let body = read_json(resp).await;
    assert!(body["content_uri"].is_string());
}
