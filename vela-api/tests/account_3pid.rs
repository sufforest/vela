//! `/account/3pid` stub: vela doesn't store email / phone associations
//! so the endpoint returns an empty `threepids` array. Without this stub
//! the 404 from a missing route surfaces in Element settings as
//! "Unable to load email addresses / phone numbers" — cosmetic but
//! confusing.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};

use common::{Harness, read_json};

#[tokio::test]
async fn get_3pid_returns_empty_threepids() {
    let harness = Harness::new();
    let (_user_id, token) = harness.register("alice", "pw").await;
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/account/3pid")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["threepids"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn get_3pid_requires_auth() {
    let harness = Harness::new();
    let resp = harness
        .request(
            Request::get("/_matrix/client/v3/account/3pid")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    // No bearer → 401 from auth middleware
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
