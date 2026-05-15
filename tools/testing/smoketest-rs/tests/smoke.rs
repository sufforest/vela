//! End-to-end smoke test: register → login → create_room → send →
//! incremental /sync. Drives ruma-client over a real TCP listener so
//! wire-shape regressions (sync field-name typos, unsigned.age missing,
//! event-id format drift) surface here rather than in Complement.
//!
//! Multi-thread flavour because the harness spawns the server task on
//! the same runtime; a single-thread runtime would deadlock when the
//! test future blocks on a request that the server task needs to
//! process.

use std::time::Duration;

use ruma::api::client::account::register::{self, RegistrationKind};
use ruma::api::client::message::send_message_event;
use ruma::api::client::room::create_room;
use ruma::api::client::sync::sync_events;
use ruma::api::client::uiaa::{AuthData, Dummy};
use ruma::events::room::message::{MessageType, RoomMessageEventContent};
use ruma::events::{AnySyncMessageLikeEvent, AnySyncTimelineEvent};
use ruma::{TransactionId, assign};
use ruma_client::Client;

use vela_smoketest_rs::spawn;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_send_sync_happy_path() {
    let harness = spawn().await;

    // ruma-client constructs typed requests and ships them over
    // reqwest; the only thing we hand it is the homeserver URL.
    let client: Client<ruma_client::http_client::Reqwest> = Client::builder()
        .homeserver_url(harness.base_url.to_string())
        .build()
        .await
        .expect("ruma client build");

    // -- register Alice ----------------------------------------------
    // m.login.dummy stage satisfies the open-registration default.
    let reg_req = assign!(register::v3::Request::new(), {
        username: Some("alice".to_owned()),
        password: Some("hunter2-correcthorse".to_owned()),
        auth: Some(AuthData::Dummy(Dummy::new())),
        kind: RegistrationKind::User,
        inhibit_login: false,
    });
    let reg = client
        .send_request(reg_req)
        .await
        .expect("register over the wire");
    let access_token = reg.access_token.expect("token from /register");
    // Wire it back into the same Client so subsequent calls carry the
    // Bearer header. ruma-client's auth state is per-instance, so we
    // rebuild rather than mutate.
    let client: Client<ruma_client::http_client::Reqwest> = Client::builder()
        .homeserver_url(harness.base_url.to_string())
        .access_token(Some(access_token.clone()))
        .build()
        .await
        .expect("ruma client (authed) build");

    // -- create a room -----------------------------------------------
    let room_id = client
        .send_request(create_room::v3::Request::new())
        .await
        .expect("createRoom over the wire")
        .room_id;

    // -- baseline sync (so we have a `since` token) ------------------
    let initial = client
        .send_request(sync_events::v3::Request::new())
        .await
        .expect("initial /sync");
    let since = initial.next_batch.clone();

    // -- send a message ----------------------------------------------
    let txn = TransactionId::new();
    let body = "hello";
    let content = RoomMessageEventContent::new(MessageType::Text(
        ruma::events::room::message::TextMessageEventContent::plain(body),
    ));
    let send_req = send_message_event::v3::Request::new(room_id.clone(), txn, &content)
        .expect("serialize event content");
    let sent_event_id = client
        .send_request(send_req)
        .await
        .expect("send over the wire")
        .event_id;

    // -- incremental sync should surface the message -----------------
    // Spin until the event appears or we time out. Vela's sync long-poll
    // wakes immediately on a write, so this typically returns on the
    // first request; the loop guards against rare scheduling lag.
    let mut found: Option<ruma::serde::Raw<AnySyncTimelineEvent>> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut since_cursor = since;
    while std::time::Instant::now() < deadline && found.is_none() {
        let req = assign!(sync_events::v3::Request::new(), {
            since: Some(since_cursor.clone()),
            timeout: Some(Duration::from_secs(1)),
        });
        let resp = client.send_request(req).await.expect("incremental /sync");
        since_cursor = resp.next_batch.clone();
        if let Some(joined) = resp.rooms.join.get(&room_id) {
            for raw in &joined.timeline.events {
                let kind = raw
                    .get_field::<String>("type")
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                if kind == "m.room.message" {
                    found = Some(raw.clone());
                    break;
                }
            }
        }
    }
    let raw_event = found.expect("expected m.room.message in joined.timeline.events");

    // -- deserialise and assert wire shape ---------------------------
    // `Raw::deserialize` roundtrips through ruma's spec types. If vela
    // emits a field with the wrong name (or drops a required one),
    // this fails loudly. That's the entire point of the suite.
    let deserialized = raw_event
        .deserialize()
        .expect("deserialize as AnySyncTimelineEvent");
    let msg = match deserialized {
        AnySyncTimelineEvent::MessageLike(AnySyncMessageLikeEvent::RoomMessage(ev)) => ev,
        other => panic!(
            "expected sync RoomMessage, got type {:?}",
            other.event_type()
        ),
    };
    let original = msg
        .as_original()
        .expect("server should not emit a redacted message here");

    // sender, content, event_id
    assert_eq!(
        original.sender.as_str().split(':').next().unwrap(),
        "@alice",
        "sender localpart should be @alice"
    );
    assert_eq!(original.event_id, sent_event_id);
    match &original.content.msgtype {
        MessageType::Text(text) => assert_eq!(text.body, body),
        other => panic!("expected m.text, got {:?}", other.msgtype()),
    }

    // unsigned.age — populated by the homeserver, not the client. A
    // missing or zero value is the canonical "did the wire shape
    // regress?" signal we want this suite to catch.
    let age = raw_event
        .get_field::<serde_json::Value>("unsigned")
        .ok()
        .flatten()
        .and_then(|u| u.get("age").cloned())
        .and_then(|v| v.as_i64());
    let age = age.expect("unsigned.age must be present on a synced event");
    assert!(age >= 0, "unsigned.age must be non-negative, got {age}");
}
