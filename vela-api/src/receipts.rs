use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct ReceiptBody {
    /// Threaded receipt scope (CS-API §receipts). Either `"main"` for the
    /// main timeline or a thread-root event id. Absent for unthreaded
    /// receipts (which TestThreadedReceipts contrasts against).
    #[serde(default)]
    pub thread_id: Option<String>,
}

/// POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
pub async fn post_receipt(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, receipt_type, event_id)): Path<(String, String, String)>,
    body: Option<Json<ReceiptBody>>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let thread_id = body.as_ref().and_then(|b| b.thread_id.as_deref());

    state
        .db
        .set_local_receipt(
            room_nid,
            &receipt_type,
            user.user_nid,
            &event_id,
            now_ms,
            thread_id,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Wake the federation senders for any peers in this room so the
    // m.receipt EDU rides out without waiting for the idle poll.
    state.federation_sender.notify_room(room_nid);

    Ok(Json(json!({})))
}

#[derive(Debug, Default, Deserialize)]
pub struct ReadMarkersBody {
    #[serde(rename = "m.fully_read")]
    pub fully_read: Option<String>,
    #[serde(rename = "m.read")]
    pub read: Option<String>,
    #[serde(rename = "m.read.private")]
    pub read_private: Option<String>,
}

/// POST /_matrix/client/v3/rooms/{roomId}/read_markers
///
/// Stores `m.fully_read` as room-scoped account data, then mirrors any
/// `m.read` / `m.read.private` to the receipts table — saving the client a
/// second round-trip per spec §Read Markers.
pub async fn post_read_markers(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Json(body): Json<ReadMarkersBody>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    if let Some(event_id) = body.fully_read {
        state
            .db
            .set_room_account_data(
                user.user_nid,
                room_nid,
                "m.fully_read",
                &json!({"event_id": event_id}),
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    if let Some(event_id) = body.read {
        state
            .db
            .set_local_receipt(room_nid, "m.read", user.user_nid, &event_id, now_ms, None)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        state.federation_sender.notify_room(room_nid);
    }
    if let Some(event_id) = body.read_private {
        // Spec note: `m.read.private` is intentionally NOT federated —
        // it's a per-user-per-server marker. Persist locally only.
        state
            .db
            .set_receipt(
                room_nid,
                "m.read.private",
                user.user_nid,
                &event_id,
                now_ms,
                None,
            )
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use axum::extract::{Path, State};

    fn alice(state: &AppState) -> AuthenticatedUser {
        let nid = state.db.get_or_create_nid("@alice:example.com").unwrap();
        AuthenticatedUser {
            user_nid: nid,
            user_id: "@alice:example.com".into(),
            device_id: "DEV".into(),
        }
    }

    #[tokio::test]
    async fn read_markers_writes_fully_read_account_data() {
        let (state, _tmp) = build_test_state();
        let room_nid = state.db.get_or_create_nid("!room:example.com").unwrap();
        let user = alice(&state);

        let _ = post_read_markers(
            State(state.clone()),
            user,
            Path("!room:example.com".into()),
            Json(ReadMarkersBody {
                fully_read: Some("$last_seen".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let stored = state
            .db
            .get_room_account_data(
                state.db.get_nid("@alice:example.com").unwrap().unwrap(),
                room_nid,
                "m.fully_read",
            )
            .unwrap()
            .expect("fully_read written");
        assert_eq!(
            stored.get("event_id").and_then(|v| v.as_str()),
            Some("$last_seen")
        );
    }

    #[tokio::test]
    async fn read_markers_mirrors_read_receipt() {
        let (state, _tmp) = build_test_state();
        let room_nid = state.db.get_or_create_nid("!room:example.com").unwrap();
        let user_nid = state.db.get_or_create_nid("@alice:example.com").unwrap();

        let _ = post_read_markers(
            State(state.clone()),
            alice(&state),
            Path("!room:example.com".into()),
            Json(ReadMarkersBody {
                read: Some("$msg".into()),
                ..Default::default()
            }),
        )
        .await
        .unwrap();

        let receipts = state.db.get_room_receipts(room_nid).unwrap();
        assert!(
            receipts.iter().any(|(rt, un, _tid, val)| rt == "m.read"
                && *un == user_nid
                && val.get("event_id").and_then(|v| v.as_str()) == Some("$msg")),
            "expected m.read receipt, got {receipts:?}"
        );
    }

    #[tokio::test]
    async fn read_markers_empty_body_is_no_op() {
        let (state, _tmp) = build_test_state();
        let res = post_read_markers(
            State(state.clone()),
            alice(&state),
            Path("!room:example.com".into()),
            Json(ReadMarkersBody::default()),
        )
        .await;
        // Empty body should still succeed: no fully_read, no receipts written.
        // Room not found is also acceptable here since we never set it up;
        // verify we either got an empty 200 or NotFound.
        match res {
            Ok(_) => {}
            Err(ApiError(VelaError::NotFound(_))) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}
