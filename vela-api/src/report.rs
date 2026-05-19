//! Content reports — `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`
//! and the 1.13/1.14 room and user variants.
//!
//! Spec: `client-server-api/modules/report_content.md`. As of v1.18 the
//! event endpoint takes only `{reason?}` (the legacy `score` field was
//! dropped). Per the spec's privacy note we always return 200 `{}`, even
//! when the room/event/target is missing or the reporter isn't joined —
//! a 404 leaks existence to a probing client, and timing-side-channel
//! probing is still possible but no longer trivially scriptable.
//!
//! Reports are written to the `event_reports` CF; the admin bot's
//! `!reports` command surfaces them for the operator.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;
use vela_core::identifiers::{EventId, RoomId, UserId};

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::middleware::json::Json;
use crate::router::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct ReportBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
pub async fn report_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, event_id_str)): Path<(String, String)>,
    Json(body): Json<ReportBody>,
) -> Result<Json<Value>, ApiError> {
    // Parse-or-200: per spec we return 200 even when input is structurally
    // dubious, to avoid leaking which IDs exist.
    let Ok(room_id) = RoomId::parse(&room_id_str) else {
        return Ok(empty_ok());
    };
    if EventId::parse(&event_id_str).is_err() {
        return Ok(empty_ok());
    }
    let Some(room_nid) = state.db.get_nid(room_id.as_str()).map_err(store_err)? else {
        return Ok(empty_ok());
    };
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(store_err)?;
    if membership != Some(1) {
        return Ok(empty_ok());
    }
    let event_nid = state
        .db
        .get_event_nid_by_id(&event_id_str)
        .map_err(store_err)?;

    persist_report(
        &state,
        &user,
        json!({
            "kind": "event",
            "room_id": room_id.as_str(),
            "room_nid": room_nid,
            "event_id": event_id_str,
            "event_nid": event_nid,
            "reporter_user_id": user.user_id,
            "reporter_nid": user.user_nid,
            "reason": body.reason.unwrap_or_default(),
        }),
    )?;
    Ok(empty_ok())
}

/// POST /_matrix/client/v3/rooms/{roomId}/report (v1.13+)
pub async fn report_room(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Json(body): Json<ReportBody>,
) -> Result<Json<Value>, ApiError> {
    let Ok(room_id) = RoomId::parse(&room_id_str) else {
        return Ok(empty_ok());
    };
    let Some(room_nid) = state.db.get_nid(room_id.as_str()).map_err(store_err)? else {
        return Ok(empty_ok());
    };
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(store_err)?;
    if membership != Some(1) {
        return Ok(empty_ok());
    }

    persist_report(
        &state,
        &user,
        json!({
            "kind": "room",
            "room_id": room_id.as_str(),
            "room_nid": room_nid,
            "reporter_user_id": user.user_id,
            "reporter_nid": user.user_nid,
            "reason": body.reason.unwrap_or_default(),
        }),
    )?;
    Ok(empty_ok())
}

/// POST /_matrix/client/v3/users/{userId}/report (v1.14+).
/// Reporter does not need to share a room with the target.
pub async fn report_user(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(target_user_id_str): Path<String>,
    Json(body): Json<ReportBody>,
) -> Result<Json<Value>, ApiError> {
    if UserId::parse(&target_user_id_str).is_err() {
        return Ok(empty_ok());
    }
    let target_nid = state.db.get_nid(&target_user_id_str).map_err(store_err)?;

    persist_report(
        &state,
        &user,
        json!({
            "kind": "user",
            "target_user_id": target_user_id_str,
            "target_user_nid": target_nid,
            "reporter_user_id": user.user_id,
            "reporter_nid": user.user_nid,
            "reason": body.reason.unwrap_or_default(),
        }),
    )?;
    Ok(empty_ok())
}

fn persist_report(
    state: &AppState,
    user: &AuthenticatedUser,
    value: Value,
) -> Result<(), ApiError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts_ms = now.as_millis() as u64;
    let ts_ns = now.as_nanos() as u64;
    let mut value = value;
    if let Some(m) = value.as_object_mut() {
        m.insert("ts_ms".into(), json!(ts_ms));
    }
    state
        .db
        .insert_event_report(ts_ns, user.user_nid, &value)
        .map_err(store_err)?;
    Ok(())
}

fn empty_ok() -> Json<Value> {
    Json(json!({}))
}

fn store_err(e: rocksdb::Error) -> ApiError {
    ApiError(VelaError::Store(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    fn auth(nid: u64, mxid: &str) -> AuthenticatedUser {
        AuthenticatedUser {
            user_nid: nid,
            user_id: mxid.to_string(),
            device_id: "DEVICE".to_string(),
        }
    }

    /// A joined reporter posts a report against an event: 200 `{}`,
    /// row appears in `list_recent_reports`.
    #[tokio::test]
    async fn report_event_persists_for_joined_reporter() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!room:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        db.create_room_meta(room_nid, room_id, "12").unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        let resp = report_event(
            axum::extract::State(state.clone()),
            auth(alice_nid, "@alice:example.com"),
            axum::extract::Path((room_id.into(), "$evt:example.com".into())),
            Json(ReportBody {
                reason: Some("spam".into()),
            }),
        )
        .await
        .expect("ok");
        assert_eq!(resp.0, json!({}));

        let reports = db.list_recent_reports(10).unwrap();
        assert_eq!(reports.len(), 1, "report should be persisted");
        let r = &reports[0];
        assert_eq!(r["kind"], "event");
        assert_eq!(r["room_id"], room_id);
        assert_eq!(r["event_id"], "$evt:example.com");
        assert_eq!(r["reporter_user_id"], "@alice:example.com");
        assert_eq!(r["reason"], "spam");
    }

    /// Spec privacy mode: non-joined reporter still gets 200 but no
    /// row is written. Confirms we don't leak room/event existence.
    #[tokio::test]
    async fn report_event_silent_when_not_joined() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!room:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        db.create_room_meta(room_nid, room_id, "12").unwrap();
        let bob_nid = db.get_or_create_nid("@bob:example.com").unwrap();
        // bob is NOT a member.

        let resp = report_event(
            axum::extract::State(state.clone()),
            auth(bob_nid, "@bob:example.com"),
            axum::extract::Path((room_id.into(), "$evt:example.com".into())),
            Json(ReportBody { reason: None }),
        )
        .await
        .expect("ok");
        assert_eq!(resp.0, json!({}));
        assert!(db.list_recent_reports(10).unwrap().is_empty());
    }

    /// Room and user reports round-trip through their own endpoints.
    #[tokio::test]
    async fn report_room_and_user_persist() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!room:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        db.create_room_meta(room_nid, room_id, "12").unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        report_room(
            axum::extract::State(state.clone()),
            auth(alice_nid, "@alice:example.com"),
            axum::extract::Path(room_id.into()),
            Json(ReportBody {
                reason: Some("bad vibes".into()),
            }),
        )
        .await
        .expect("ok");
        report_user(
            axum::extract::State(state.clone()),
            auth(alice_nid, "@alice:example.com"),
            axum::extract::Path("@mallory:example.com".into()),
            Json(ReportBody {
                reason: Some("harassment".into()),
            }),
        )
        .await
        .expect("ok");

        let reports = db.list_recent_reports(10).unwrap();
        assert_eq!(reports.len(), 2);
        let kinds: Vec<&str> = reports.iter().filter_map(|r| r["kind"].as_str()).collect();
        assert!(kinds.contains(&"room"));
        assert!(kinds.contains(&"user"));
    }
}
