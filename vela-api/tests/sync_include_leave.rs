//! `/sync` must honour the room filter's `include_leave` (spec default:
//! false). A room the user left before the sync window (and, on an initial
//! sync, any left room) is surfaced only when `include_leave` is set — but a
//! room left *within* the window is always surfaced so the client learns of
//! the leave.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync(h: &Harness, tok: &str, since: Option<&str>, filter_id: Option<&str>) -> Value {
    let mut url = "/_matrix/client/v3/sync?timeout=0".to_string();
    if let Some(s) = since {
        url.push_str(&format!("&since={s}"));
    }
    if let Some(f) = filter_id {
        url.push_str(&format!("&filter={f}"));
    }
    let resp = h
        .request(
            Request::get(&url)
                .header("authorization", format!("Bearer {tok}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await
}

async fn leave(h: &Harness, tok: &str, room: &str) {
    let resp = h
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{room}/leave"))
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "leave failed");
}

async fn store_filter(h: &Harness, user: &str, tok: &str, body: Value) -> String {
    let resp = h
        .request(
            Request::post(format!("/_matrix/client/v3/user/{user}/filter"))
                .header("authorization", format!("Bearer {tok}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    read_json(resp).await["filter_id"]
        .as_str()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn initial_sync_excludes_historical_left_rooms_unless_include_leave() {
    let h = Harness::new();
    let (alice, tok) = h.register("alice", "pw").await;
    let room = h.create_room(&tok, json!({})).await;
    leave(&h, &tok, &room).await;

    // Default filter (include_leave omitted → false): the left room is a
    // historical leave on an initial sync and must not appear.
    let s = sync(&h, &tok, None, None).await;
    assert!(
        s["rooms"]["leave"].get(&room).is_none(),
        "left room leaked on an initial sync without include_leave: {:?}",
        s["rooms"]["leave"]
    );

    // include_leave=true surfaces it.
    let fid = store_filter(&h, &alice, &tok, json!({"room": {"include_leave": true}})).await;
    let s = sync(&h, &tok, None, Some(&fid)).await;
    assert!(
        s["rooms"]["leave"].get(&room).is_some(),
        "include_leave=true must surface the historical left room: {:?}",
        s["rooms"]["leave"]
    );
}

#[tokio::test]
async fn leave_within_window_is_always_surfaced() {
    let h = Harness::new();
    let (_alice, tok) = h.register("alice", "pw").await;
    let room = h.create_room(&tok, json!({})).await;

    // Anchor a since token before the leave.
    let init = sync(&h, &tok, None, None).await;
    let since = init["next_batch"].as_str().unwrap().to_string();

    leave(&h, &tok, &room).await;

    // Incremental sync from before the leave, with the default filter: the
    // client must still learn it left, even without include_leave.
    let s = sync(&h, &tok, Some(&since), None).await;
    assert!(
        s["rooms"]["leave"].get(&room).is_some(),
        "a leave within the sync window must be surfaced regardless of include_leave: {:?}",
        s["rooms"]["leave"]
    );
}

#[tokio::test]
async fn historical_leave_not_resurfaced_on_incremental_even_with_include_leave() {
    // Complement's TestOlderLeftRoomsNotInLeaveSection: once a leave has been
    // reported, include_leave must not make it reappear on every later
    // incremental sync.
    let h = Harness::new();
    let (alice, tok) = h.register("alice", "pw").await;
    let room = h.create_room(&tok, json!({})).await;
    let fid = store_filter(&h, &alice, &tok, json!({"room": {"include_leave": true}})).await;

    let s1 = sync(&h, &tok, None, Some(&fid)).await;
    let since1 = s1["next_batch"].as_str().unwrap().to_string();

    leave(&h, &tok, &room).await;

    // The sync that spans the leave surfaces it once.
    let s2 = sync(&h, &tok, Some(&since1), Some(&fid)).await;
    assert!(
        s2["rooms"]["leave"].get(&room).is_some(),
        "the leave should appear on the incremental sync that spans it"
    );
    let since2 = s2["next_batch"].as_str().unwrap().to_string();

    // A later incremental sync (past the leave), still with include_leave, must
    // NOT re-surface the now-historical leave.
    let s3 = sync(&h, &tok, Some(&since2), Some(&fid)).await;
    assert!(
        s3["rooms"]["leave"].get(&room).is_none(),
        "a historical leave must not reappear on a later incremental sync even with \
         include_leave: {:?}",
        s3["rooms"]["leave"]
    );
}
