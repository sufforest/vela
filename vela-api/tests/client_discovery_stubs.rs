//! Client-facing endpoints Element probes unconditionally that must NOT
//! fall through to the catch-all `M_UNRECOGNIZED`:
//!
//! - `GET /_matrix/client/v3/thirdparty/protocols` → `200 {}` (we run no
//!   appservices, but the spec shape for "none" is an empty object).
//! - `GET .../org.matrix.msc4143/rtc/transports` → `200 {rtc_transports: …}`
//!   mirroring `.well-known`'s `rtc_foci`. Both surfaces share one
//!   resolver; the last test asserts they agree end-to-end so they can't
//!   drift (the discovery-mismatch class of bug this thread hit).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::{ConfigOverrides, Harness, read_json};

async fn get(harness: &Harness, uri: &str, token: Option<&str>) -> (StatusCode, serde_json::Value) {
    let mut req = Request::get(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = harness.request(req.body(Body::empty()).unwrap()).await;
    let s = resp.status();
    (s, read_json(resp).await)
}

#[tokio::test]
async fn thirdparty_protocols_returns_empty_object() {
    let harness = Harness::new();
    let (_uid, token) = harness.register("alice", "pw").await;
    let (status, body) = get(
        &harness,
        "/_matrix/client/v3/thirdparty/protocols",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Spec shape for "no third-party protocols" — NOT M_UNRECOGNIZED.
    assert_eq!(body, json!({}));
}

#[tokio::test]
async fn thirdparty_protocols_requires_auth() {
    let harness = Harness::new();
    let (status, _) = get(&harness, "/_matrix/client/v3/thirdparty/protocols", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rtc_transports_empty_when_no_sfu() {
    let harness = Harness::new();
    let (_uid, token) = harness.register("alice", "pw").await;
    let (status, body) = get(
        &harness,
        "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "rtc_transports": [] }));
}

#[tokio::test]
async fn rtc_transports_requires_auth() {
    let harness = Harness::new();
    let (status, _) = get(
        &harness,
        "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rtc_transports_matches_well_known_foci_when_sfu_configured() {
    // One resolver feeds both the well-known block and the endpoint;
    // assert they agree end-to-end so a future edit to one can't silently
    // diverge from the other.
    let harness = Harness::with_config(ConfigOverrides {
        rtc: vela_api::router::RtcConfig {
            sfu_url: "https://sfu.example.org/livekit/jwt".into(),
            livekit_api_key: "key".into(),
            livekit_secret: "secret".into(),
            jwt_ttl_seconds: 3600,
        },
        ..Default::default()
    });
    let (_uid, token) = harness.register("alice", "pw").await;

    let (status, transports) = get(
        &harness,
        "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports",
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let from_endpoint = &transports["rtc_transports"];

    let (wk_status, wk) = get(&harness, "/.well-known/matrix/client", None).await;
    assert_eq!(wk_status, StatusCode::OK);
    let from_well_known = &wk["org.matrix.msc4143.rtc_foci"];

    assert_eq!(from_endpoint, from_well_known);
    assert_eq!(
        from_endpoint,
        &json!([{ "type": "livekit", "livekit_service_url": "https://sfu.example.org/livekit/jwt" }])
    );
}
