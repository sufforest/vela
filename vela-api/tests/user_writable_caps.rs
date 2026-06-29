//! Caps on user-writable values, so a single client can't bloat
//! server-fanned-out state: registered pushers per user (push dispatch fans
//! out over every recipient's pushers) and profile field length (displayname
//! / avatar_url propagate into a member event in every room the user is in).
//! Limits are generous — far above any real client — so legit use is unaffected.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;

use common::Harness;

async fn set_pusher(h: &Harness, tok: &str, pushkey: &str) -> StatusCode {
    h.request(
        Request::post("/_matrix/client/v3/pushers/set")
            .header("authorization", format!("Bearer {tok}"))
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "app_id": "com.example.app",
                    "pushkey": pushkey,
                    "kind": "http",
                    "app_display_name": "App",
                    "device_display_name": "Dev",
                    "lang": "en",
                    "data": {"url": "https://push.example/_matrix/push/v1/notify"},
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .status()
}

async fn set_displayname(h: &Harness, tok: &str, user_id: &str, name: &str) -> StatusCode {
    h.request(
        Request::put(format!("/_matrix/client/v3/profile/{user_id}/displayname"))
            .header("authorization", format!("Bearer {tok}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"displayname": name}).to_string()))
            .unwrap(),
    )
    .await
    .status()
}

async fn set_avatar(h: &Harness, tok: &str, user_id: &str, url: &str) -> StatusCode {
    h.request(
        Request::put(format!("/_matrix/client/v3/profile/{user_id}/avatar_url"))
            .header("authorization", format!("Bearer {tok}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"avatar_url": url}).to_string()))
            .unwrap(),
    )
    .await
    .status()
}

#[tokio::test]
async fn pusher_count_is_capped_but_updates_still_allowed() {
    let h = Harness::new();
    let (_id, tok) = h.register("alice", "pw").await;

    // Fill up to the cap (100) with distinct pushkeys.
    for i in 0..100 {
        assert_eq!(
            set_pusher(&h, &tok, &format!("key-{i}")).await,
            StatusCode::OK,
            "pusher {i} within the cap must succeed"
        );
    }
    // The next NEW pusher is refused.
    assert_eq!(
        set_pusher(&h, &tok, "key-overflow").await,
        StatusCode::BAD_REQUEST,
        "a new pusher beyond the cap must be refused"
    );
    // But re-setting (updating) an existing pusher is still allowed.
    assert_eq!(
        set_pusher(&h, &tok, "key-0").await,
        StatusCode::OK,
        "updating an existing pusher must not be blocked by the cap"
    );
}

#[tokio::test]
async fn profile_fields_are_length_capped() {
    let h = Harness::new();
    let (id, tok) = h.register("alice", "pw").await;

    // A normal value is accepted.
    assert_eq!(
        set_displayname(&h, &tok, &id, "Alice").await,
        StatusCode::OK
    );

    // An oversized displayname is refused.
    let huge = "x".repeat(4096);
    assert_eq!(
        set_displayname(&h, &tok, &id, &huge).await,
        StatusCode::BAD_REQUEST,
        "an oversized displayname must be refused"
    );

    // Avatar url: normal accepted, oversized refused.
    assert_eq!(
        set_avatar(&h, &tok, &id, "mxc://example.com/abc").await,
        StatusCode::OK
    );
    assert_eq!(
        set_avatar(&h, &tok, &id, &format!("mxc://example.com/{huge}")).await,
        StatusCode::BAD_REQUEST,
        "an oversized avatar_url must be refused"
    );
}
