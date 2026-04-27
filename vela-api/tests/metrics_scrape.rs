//! `/_vela/metrics` surfaces Prometheus text. In tests the recorder is
//! off (to avoid double-install across parallel test processes), so the
//! endpoint returns 503 — exactly the shape a production deploy would
//! see if it booted without the recorder. What we're locking in here is
//! that the route exists, is reachable, and reports its install state
//! honestly.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use common::Harness;

#[tokio::test]
async fn metrics_endpoint_reports_recorder_absent_in_tests() {
    let harness = Harness::new();
    let resp = harness
        .request(Request::get("/_vela/metrics").body(Body::empty()).unwrap())
        .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(
        std::str::from_utf8(&body)
            .unwrap()
            .contains("not installed")
    );
}
