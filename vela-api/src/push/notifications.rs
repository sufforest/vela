//! `GET /_matrix/client/v3/notifications` — paginated notification history.
//!
//! Rows are persisted by `push::dispatch_inner` whenever a push rule
//! matches for a local recipient. The `read` flag is computed at query
//! time from the user's `m.read` receipt / `m.fully_read` marker so it
//! never needs a second write path.

use std::collections::HashMap;

use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::middleware::json::Json;
use crate::router::AppState;

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;

#[derive(Debug, Default, Deserialize)]
pub struct NotificationsQuery {
    pub from: Option<String>,
    pub limit: Option<usize>,
    pub only: Option<String>,
}

/// GET /_matrix/client/v3/notifications
pub async fn get_notifications(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<NotificationsQuery>,
) -> Result<Json<Value>, ApiError> {
    let from = query
        .from
        .as_deref()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let only_highlight = query.only.as_deref() == Some("highlight");

    let (rows, next) = state
        .db
        .list_user_notifications(user.user_nid, from, limit, only_highlight)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Read-marker position cached per room across this page.
    let mut read_pos_cache: HashMap<u64, Option<u64>> = HashMap::new();
    let mut notifications = Vec::new();

    for (_pos, row) in &rows {
        let room_id = row.get("room_id").and_then(|v| v.as_str()).unwrap_or("");
        let event_id = row.get("event_id").and_then(|v| v.as_str()).unwrap_or("");
        let ts = row.get("ts").and_then(|v| v.as_u64()).unwrap_or(0);
        let actions = row
            .get("actions")
            .cloned()
            .unwrap_or_else(|| json!(["notify"]));
        let event_stream_pos = row.get("event_stream_pos").and_then(|v| v.as_u64());

        // Skip rows whose room or event no longer resolve (e.g. purged).
        let Some(room_nid) = state.db.get_nid(room_id).ok().flatten() else {
            continue;
        };
        let Some(event_nid) = state.db.get_event_nid_by_id(event_id).ok().flatten() else {
            continue;
        };
        let Some(event) = crate::room::messages::load_client_event(&state, event_nid, room_id)?
        else {
            continue;
        };

        let read_pos = *read_pos_cache
            .entry(room_nid)
            .or_insert_with(|| read_position(&state, room_nid, user.user_nid));
        let read = matches!((event_stream_pos, read_pos), (Some(ev), Some(rp)) if ev <= rp);

        notifications.push(json!({
            "actions": actions,
            "event": event,
            "read": read,
            "room_id": room_id,
            "ts": ts,
        }));
    }

    let mut resp = serde_json::Map::new();
    resp.insert("notifications".into(), Value::Array(notifications));
    // Advertise a continuation token only when the page was full (more may
    // remain); omitting it tells the client it's caught up.
    if rows.len() >= limit {
        resp.insert("next_token".into(), json!(next.to_string()));
    }
    Ok(Json(Value::Object(resp)))
}

/// The user's read position in a room: the stream position of their
/// `m.read` receipt event, or `m.fully_read` marker, whichever is higher.
/// `None` when neither is set.
fn read_position(state: &AppState, room_nid: u64, user_nid: u64) -> Option<u64> {
    let mut best: Option<u64> = None;
    if let Ok(Some(eid)) = state
        .db
        .get_user_receipt_event_id(room_nid, "m.read", user_nid)
        && let Ok(Some(p)) = state.db.event_stream_pos(room_nid, &eid)
    {
        best = Some(p);
    }
    if let Ok(Some(marker)) = state
        .db
        .get_room_account_data(user_nid, room_nid, "m.fully_read")
        && let Some(eid) = marker.get("event_id").and_then(|v| v.as_str())
        && let Ok(Some(p)) = state.db.event_stream_pos(room_nid, eid)
    {
        best = Some(best.map_or(p, |b| b.max(p)));
    }
    best
}
