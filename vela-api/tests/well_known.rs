//! `/.well-known/matrix/client` resolution-order tests.
//!
//! The handler picks the m.homeserver.base_url from:
//!   1. `[server] public_base_url` if set
//!   2. `https://{server.name}` if server.name isn't a local placeholder
//!   3. `http://{bind_host}:{bind_port}` as the dev fallback
//!
//! Without (2), every reverse-proxied deploy (the common case) saw
//! the bind:port loopback in well-known and Element fell to the
//! laptop's localhost. The bug surfaced on a real Cloudflare-fronted
//! deploy of pwd.wiki — locking it in here.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use common::{ConfigOverrides, Harness, read_json};

#[tokio::test]
async fn well_known_default_for_public_server_name_emits_https_url() {
    // server_name = "pwd.wiki" — looks like a public domain → publish
    // `https://pwd.wiki` without operator needing to configure
    // public_base_url.
    let harness = Harness::with_server_name("pwd.wiki");
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["m.homeserver"]["base_url"], "https://pwd.wiki");
}

#[tokio::test]
async fn well_known_localhost_falls_back_to_bind_port() {
    // server_name = "localhost:8008" — the dev placeholder → publish
    // the loopback URL the developer expects.
    let harness = Harness::new();
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    // Test harness binds to bind_host=127.0.0.1, bind_port=0.
    assert_eq!(body["m.homeserver"]["base_url"], "http://127.0.0.1:0");
}

#[tokio::test]
async fn well_known_explicit_public_base_url_wins() {
    // Operator deployment where the public URL differs from
    // `https://{server.name}` — e.g. identity domain `example.com` but
    // API at `https://matrix.example.com:8443`. `public_base_url`
    // overrides both other paths.
    let harness = common::Harness::with_overrides(
        "example.com",
        ConfigOverrides {
            public_base_url: Some("https://matrix.example.com:8443".to_string()),
            ..Default::default()
        },
    );
    let resp = harness
        .request(
            Request::get("/.well-known/matrix/client")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(
        body["m.homeserver"]["base_url"],
        "https://matrix.example.com:8443"
    );
}
