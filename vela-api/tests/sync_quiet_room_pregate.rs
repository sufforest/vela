//! The /sync quiet-room fast-path skips the per-room build for rooms with
//! nothing new since the caller's cursor. This pins both sides: a truly quiet
//! room is omitted (the win + busy-loop guard), and a room whose ONLY change
//! is non-timeline — a receipt, account-data, state-only, or typing change —
//! is NOT dropped (the risk the pre-gate must never hit).

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, read_json};
use serde_json::{Value, json};

async fn sync(harness: &Harness, token: &str, since: Option<&str>) -> Value {
    let path = match since {
        Some(s) => format!("/_matrix/client/v3/sync?timeout=0&since={s}"),
        None => "/_matrix/client/v3/sync?timeout=0".to_string(),
    };
    let resp = harness
        .request(
            Request::get(path)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::OK, "sync non-200");
    read_json(resp).await
}

fn room_in_join(sync: &Value, room: &str) -> bool {
    sync.pointer(&format!(
        "/rooms/join/{}",
        room.replace('~', "~0").replace('/', "~1")
    ))
    .is_some()
        || sync
            .pointer("/rooms/join")
            .and_then(|v| v.as_object())
            .is_some_and(|o| o.contains_key(room))
}

#[tokio::test]
async fn quiet_room_omitted_but_receipt_and_account_data_surface() {
    let harness = Harness::new();
    let (uid, token) = harness.register("alice", "password").await;
    let room = harness
        .create_room(&token, json!({"preset":"private_chat"}))
        .await;
    let ev = harness.send_message(&token, &room, "hello").await;

    // Initial sync → cursor.
    let s0 = sync(&harness, &token, None).await;
    let since0 = s0["next_batch"].as_str().unwrap().to_string();

    // 1. Nothing changed → the room must be OMITTED from the incremental
    //    sync (this is the fast-path win and the busy-loop guard).
    let s1 = sync(&harness, &token, Some(&since0)).await;
    assert!(
        !room_in_join(&s1, &room),
        "quiet room must be omitted from incremental sync, got {:?}",
        s1.pointer("/rooms/join")
    );
    let since1 = s1["next_batch"].as_str().unwrap().to_string();

    // 2. A read RECEIPT is the room's only change → the room MUST appear
    //    (the pre-gate must not skip a receipt-only update).
    let r = harness
        .request(
            Request::post(format!(
                "/_matrix/client/v3/rooms/{room}/receipt/m.read/{ev}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap(),
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK, "receipt post failed");
    let s2 = sync(&harness, &token, Some(&since1)).await;
    assert!(
        room_in_join(&s2, &room),
        "receipt-only change must surface the room in incremental sync"
    );
    let since2 = s2["next_batch"].as_str().unwrap().to_string();

    // 3. ACCOUNT DATA is the room's only change → the room MUST appear.
    let r = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/user/{uid}/rooms/{room}/account_data/m.fully_read"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"event_id": ev}).to_string()))
            .unwrap(),
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK, "account_data put failed");
    let s3 = sync(&harness, &token, Some(&since2)).await;
    assert!(
        room_in_join(&s3, &room),
        "account-data-only change must surface the room in incremental sync"
    );

    // 4. A new message surfaces the room too (sanity).
    let since3 = s3["next_batch"].as_str().unwrap().to_string();
    harness.send_message(&token, &room, "again").await;
    let s4 = sync(&harness, &token, Some(&since3)).await;
    assert!(
        room_in_join(&s4, &room),
        "new message must surface the room"
    );

    // 5. A STATE-only change (a topic, no message) must surface the room —
    //    a Live state event carries a timeline stream_pos, so the pre-gate's
    //    timeline check catches it.
    let since4 = s4["next_batch"].as_str().unwrap().to_string();
    let r = harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room}/state/m.room.topic"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({"topic": "a new topic"}).to_string()))
            .unwrap(),
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK, "set topic failed");
    let s5 = sync(&harness, &token, Some(&since4)).await;
    assert!(
        room_in_join(&s5, &room),
        "state-only change (topic) must surface the room"
    );

    // 6. A TYPING-only transition must surface the room (in-memory
    //    typing_change_pos check).
    let since5 = s5["next_batch"].as_str().unwrap().to_string();
    let r = harness
        .request(
            Request::put(format!("/_matrix/client/v3/rooms/{room}/typing/{uid}"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"typing": true, "timeout": 30000}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), StatusCode::OK, "typing put failed");
    let s6 = sync(&harness, &token, Some(&since5)).await;
    assert!(
        room_in_join(&s6, &room),
        "typing-only transition must surface the room"
    );
}
