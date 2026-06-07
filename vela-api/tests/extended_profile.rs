//! MSC4133 extended profile fields — GET/PUT/DELETE /profile/{u}/{key}.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn put_field(
    harness: &Harness,
    token: &str,
    user: &str,
    key: &str,
    value: Value,
) -> StatusCode {
    harness
        .request(
            Request::put(format!("/_matrix/client/v3/profile/{user}/{key}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({ key: value }).to_string()))
                .unwrap(),
        )
        .await
        .status()
}

async fn get_field(harness: &Harness, user: &str, key: &str) -> (StatusCode, Value) {
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v3/profile/{user}/{key}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let s = resp.status();
    (s, read_json(resp).await)
}

#[tokio::test]
async fn put_get_delete_extended_field() {
    let harness = Harness::new();
    let (alice, atok) = harness.register("alice", "pw").await;

    assert_eq!(
        put_field(
            &harness,
            &atok,
            &alice,
            "us.cloke.msc4175.tz",
            json!("Europe/London")
        )
        .await,
        StatusCode::OK
    );

    let (s, body) = get_field(&harness, &alice, "us.cloke.msc4175.tz").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["us.cloke.msc4175.tz"], "Europe/London");

    // Full profile folds the extended field in.
    let resp = harness
        .request(
            Request::get(format!("/_matrix/client/v3/profile/{alice}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    let prof = read_json(resp).await;
    assert_eq!(prof["us.cloke.msc4175.tz"], "Europe/London");

    // Delete, then it's gone (404).
    let del = harness
        .request(
            Request::delete(format!(
                "/_matrix/client/v3/profile/{alice}/us.cloke.msc4175.tz"
            ))
            .header("authorization", format!("Bearer {atok}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(del.status(), StatusCode::OK);
    let (s, _) = get_field(&harness, &alice, "us.cloke.msc4175.tz").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cannot_set_another_users_field() {
    let harness = Harness::new();
    let (alice, _atok) = harness.register("alice", "pw").await;
    let (_bob, btok) = harness.register("bob", "pw").await;
    // bob's token, alice's profile → 403.
    assert_eq!(
        put_field(
            &harness,
            &btok,
            &alice,
            "org.example.pronouns",
            json!("they/them")
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn delete_missing_field_is_idempotent() {
    let harness = Harness::new();
    let (alice, atok) = harness.register("alice", "pw").await;
    let del = harness
        .request(
            Request::delete(format!(
                "/_matrix/client/v3/profile/{alice}/org.example.nope"
            ))
            .header("authorization", format!("Bearer {atok}"))
            .body(Body::empty())
            .unwrap(),
        )
        .await;
    assert_eq!(del.status(), StatusCode::OK);
}

#[tokio::test]
async fn displayname_still_works_via_dedicated_route() {
    // The static displayname route must still win over {keyName}.
    let harness = Harness::new();
    let (alice, atok) = harness.register("alice", "pw").await;
    let put = harness
        .request(
            Request::put(format!("/_matrix/client/v3/profile/{alice}/displayname"))
                .header("authorization", format!("Bearer {atok}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"displayname": "Alice A"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(put.status(), StatusCode::OK);
    let (s, body) = get_field(&harness, &alice, "displayname").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["displayname"], "Alice A");
}
