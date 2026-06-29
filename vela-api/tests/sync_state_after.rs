//! Regression for the msc4140 `delayed_state_events_are_sent_on_timeout`
//! Complement failure, root-caused to the MSC4222 `state_after` computation.
//!
//! Under `use_state_after`, `state_after` is the room state at the END of the
//! returned timeline, so a state event that lands IN the timeline batch must
//! also appear in `state_after`. vela was computing the delta only up to the
//! START of the timeline (the legacy `state` semantics), so a state event
//! that was the sole new event sat in the timeline and never showed up in
//! `state_after` — and Complement's `SyncStateAfterHas` never matched.
//!
//! The delayed-event path just sends an ordinary state event from a
//! background task, so a normal `PUT /state` reproduces the bug deterministically.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn sync(harness: &Harness, token: &str, since: Option<&str>, state_after: bool) -> Value {
    let mut url = "/_matrix/client/v3/sync?timeout=0".to_string();
    if state_after {
        url.push_str("&use_state_after=true");
    }
    if let Some(s) = since {
        url.push_str(&format!("&since={s}"));
    }
    let resp = harness
        .request(
            Request::get(&url)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    read_json(resp).await
}

async fn put_state(
    harness: &Harness,
    token: &str,
    room: &str,
    etype: &str,
    key: &str,
    body: Value,
) -> StatusCode {
    harness
        .request(
            Request::put(format!(
                "/_matrix/client/v3/rooms/{room}/state/{etype}/{key}"
            ))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        )
        .await
        .status()
}

fn section_has(sync: &Value, room: &str, section: &str, etype: &str, key: &str) -> bool {
    sync.pointer(&format!("/rooms/join/{room}/{section}/events"))
        .and_then(|v| v.as_array())
        .map(|evs| {
            evs.iter().any(|e| {
                e.get("type").and_then(|t| t.as_str()) == Some(etype)
                    && e.get("state_key").and_then(|k| k.as_str()) == Some(key)
            })
        })
        .unwrap_or(false)
}

#[tokio::test]
async fn state_event_in_timeline_appears_in_state_after() {
    let h = Harness::new();
    let (_alice, tok) = h.register("alice", "pw").await;
    let room = h.create_room(&tok, json!({"preset": "public_chat"})).await;

    // Anchor a since token past room creation.
    let init = sync(&h, &tok, None, true).await;
    let since = init["next_batch"].as_str().unwrap().to_string();

    // A state event sent after `since` — exactly what a delayed event firing
    // on timeout produces.
    assert_eq!(
        put_state(
            &h,
            &tok,
            &room,
            "com.example.delayed",
            "to_send_on_timeout",
            json!({"setter": "on_timeout"})
        )
        .await,
        StatusCode::OK
    );

    let inc = sync(&h, &tok, Some(&since), true).await;
    assert!(
        section_has(
            &inc,
            &room,
            "state_after",
            "com.example.delayed",
            "to_send_on_timeout"
        ),
        "a state event in the timeline must also appear in state_after; got room: {}",
        serde_json::to_string_pretty(
            inc.pointer(&format!("/rooms/join/{room}"))
                .unwrap_or(&Value::Null)
        )
        .unwrap_or_default()
    );
}

#[tokio::test]
async fn legacy_state_field_excludes_in_timeline_event() {
    // Guard the fix doesn't leak into the legacy `state` field: per spec the
    // pre-MSC4222 `state` is the delta up to the START of the timeline, so an
    // event that's IN the timeline must NOT be duplicated into `state`.
    let h = Harness::new();
    let (_alice, tok) = h.register("alice", "pw").await;
    let room = h.create_room(&tok, json!({"preset": "public_chat"})).await;

    let init = sync(&h, &tok, None, false).await;
    let since = init["next_batch"].as_str().unwrap().to_string();

    assert_eq!(
        put_state(&h, &tok, &room, "com.example.legacy", "k", json!({"v": 1})).await,
        StatusCode::OK
    );

    let inc = sync(&h, &tok, Some(&since), false).await;
    assert!(
        section_has(&inc, &room, "timeline", "com.example.legacy", "k"),
        "the state event should be in the timeline"
    );
    assert!(
        !section_has(&inc, &room, "state", "com.example.legacy", "k"),
        "legacy `state` is the pre-timeline delta and must not duplicate the in-timeline event"
    );
}
