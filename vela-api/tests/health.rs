//! `/_health` operational endpoint. Locks in:
//! - the route is reachable without an `Authorization` header,
//! - the response is valid JSON with the documented field shape,
//! - the cargo version + on-disk schema version are reported.
//!
//! Anything richer (DB readable, federation reachable) belongs on a
//! deeper `/_health/ready` if we ever grow one — keep this test
//! focused on the contract operators script against.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use common::{Harness, read_json};

#[tokio::test]
async fn health_endpoint_unauth_returns_ok_payload() {
    let harness = Harness::new();
    let resp = harness
        .request(Request::get("/_health").body(Body::empty()).unwrap())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["schema_version"], vela_store::db::SCHEMA_VERSION);
    // uptime_secs and started_at_ms are integers; just assert they're
    // present and the right JSON type. Asserting concrete values would
    // bake in clock-dependent flakiness.
    assert!(body["uptime_secs"].is_u64(), "uptime_secs must be u64");
    assert!(body["started_at_ms"].is_u64(), "started_at_ms must be u64");
}

#[tokio::test]
async fn health_endpoint_does_not_require_matrix_path() {
    // Sanity: the route is intentionally NOT under /_matrix/* so the
    // fallback (which returns M_UNRECOGNIZED for unknown matrix paths)
    // doesn't shadow it. Verify by hitting both paths.
    let harness = Harness::new();
    let h = harness
        .request(Request::get("/_health").body(Body::empty()).unwrap())
        .await;
    assert_eq!(h.status(), StatusCode::OK);

    let nope = harness
        .request(
            Request::get("/_matrix/_health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(nope.status(), StatusCode::NOT_FOUND);
}
