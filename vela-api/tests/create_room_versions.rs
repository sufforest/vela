//! createRoom must shape the creator's power per room version.
//!
//! Through v11 the creator is an ordinary user: the only thing that lets
//! them send the rest of the initial state is `power_levels.users[creator]
//! = 100`, and a trusted_private_chat gives invitees the same entry. v12
//! (MSC4289) forbids creators in `users` and promotes invitees to
//! `additional_creators` instead. vela used to emit the v12 shape in every
//! version — self-consistent locally, rejected by every compliant peer.

mod common;

use axum::body::Body;
use axum::http::Request;
use serde_json::{Value, json};

use common::{Harness, read_json};

async fn state(h: &Harness, token: &str, room_id: &str, ty: &str) -> Value {
    let resp = h
        .request(
            Request::get(format!("/_matrix/client/v3/rooms/{room_id}/state/{ty}/"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(resp.status().is_success(), "GET {ty}: {}", resp.status());
    read_json(resp).await
}

#[tokio::test]
async fn creator_listed_at_100_through_v11() {
    let h = Harness::new();
    let (alice, token) = h.register("alice", "pw").await;
    for version in ["6", "10", "11"] {
        let room = h
            .create_room(
                &token,
                json!({"preset": "public_chat", "room_version": version, "name": "r"}),
            )
            .await;
        let pl = state(&h, &token, &room, "m.room.power_levels").await;
        assert_eq!(pl["users"][&alice], 100, "v{version}");
        assert!(pl["events"].get("m.room.tombstone").is_none(), "v{version}");
        let create = state(&h, &token, &room, "m.room.create").await;
        assert!(create.get("additional_creators").is_none(), "v{version}");
    }
}

#[tokio::test]
async fn creator_absent_from_users_in_v12() {
    let h = Harness::new();
    let (alice, token) = h.register("alice", "pw").await;
    let room = h
        .create_room(
            &token,
            json!({"preset": "public_chat", "room_version": "12"}),
        )
        .await;
    let pl = state(&h, &token, &room, "m.room.power_levels").await;
    assert!(pl["users"].get(&alice).is_none());
    assert_eq!(pl["events"]["m.room.tombstone"], 150);
}

#[tokio::test]
async fn trusted_private_chat_invitees_get_power_per_version() {
    let h = Harness::new();
    let (_alice, token) = h.register("alice", "pw").await;
    let (bob, _) = h.register("bob", "pw").await;

    let room = h
        .create_room(
            &token,
            json!({"preset": "trusted_private_chat", "room_version": "11", "invite": [&bob]}),
        )
        .await;
    let pl = state(&h, &token, &room, "m.room.power_levels").await;
    assert_eq!(pl["users"][&bob], 100);
    let create = state(&h, &token, &room, "m.room.create").await;
    assert!(create.get("additional_creators").is_none());

    let room = h
        .create_room(
            &token,
            json!({"preset": "trusted_private_chat", "room_version": "12", "invite": [&bob]}),
        )
        .await;
    let pl = state(&h, &token, &room, "m.room.power_levels").await;
    assert!(pl["users"].get(&bob).is_none());
    let create = state(&h, &token, &room, "m.room.create").await;
    assert_eq!(create["additional_creators"], json!([&bob]));
}

/// Through v11 an override `users` map replaces ours wholesale, so one that
/// leaves the creator out is refused up front rather than producing a room
/// its creator cannot administer. v12 has no such entry to drop.
#[tokio::test]
async fn pre_v12_override_must_keep_creator() {
    let h = Harness::new();
    let (_alice, token) = h.register("alice", "pw").await;
    let (bob, _) = h.register("bob", "pw").await;
    let body = |version: &str| {
        json!({
            "room_version": version,
            "power_level_content_override": {"users": {&bob: 100}},
        })
    };
    let resp = h
        .request(
            Request::post("/_matrix/client/v3/createRoom")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body("11").to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(read_json(resp).await["errcode"], "M_BAD_JSON");

    // Same override is fine in v12: creators are implicit there.
    let room = h.create_room(&token, body("12")).await;
    let pl = state(&h, &token, &room, "m.room.power_levels").await;
    assert_eq!(pl["users"][&bob], 100);
}

/// v6–v10 create events carry `content.creator`; it is what the auth rules
/// consult when there is no power_levels event.
#[tokio::test]
async fn pre_v11_create_carries_creator_field() {
    let h = Harness::new();
    let (alice, token) = h.register("alice", "pw").await;
    let room = h.create_room(&token, json!({"room_version": "10"})).await;
    let create = state(&h, &token, &room, "m.room.create").await;
    assert_eq!(create["creator"], alice);
    assert_eq!(create["room_version"], "10");
}

/// Upgrading into a pre-v12 version must leave the upgrader able to run the
/// new room: a v12 creator has no `users` entry to copy, so the transferred
/// power_levels is raised to the highest level it demands.
#[tokio::test]
async fn upgrade_to_pre_v12_keeps_upgrader_powerful() {
    let h = Harness::new();
    let (alice, token) = h.register("alice", "pw").await;
    let old = h
        .create_room(
            &token,
            json!({"preset": "public_chat", "room_version": "12"}),
        )
        .await;
    let resp = h
        .request(
            Request::post(format!("/_matrix/client/v3/rooms/{old}/upgrade"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"new_version": "9"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), 200, "upgrade");
    let new = read_json(resp).await["replacement_room"]
        .as_str()
        .unwrap()
        .to_string();
    let pl = state(&h, &token, &new, "m.room.power_levels").await;
    // Highest level the copied event demands: the v12 default puts
    // m.room.tombstone at 150, above power_levels/history_visibility (100).
    assert_eq!(pl["users"][&alice], 150);
    let create = state(&h, &token, &new, "m.room.create").await;
    assert_eq!(create["creator"], alice);
    // And the upgrader can in fact administer it.
    let resp = h
        .request(
            Request::put(format!("/_matrix/client/v3/rooms/{new}/state/m.room.name/"))
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(json!({"name": "after"}).to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), 200, "set name in upgraded room");
}
