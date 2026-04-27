//! `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event`
//!
//! Returns the closest event to a given timestamp in the requested
//! direction. Currently a minimal implementation — we do the
//! permission and parameter checks the spec mandates, then walk the
//! room's timeline to find the best match.
//!
//! Permission model per spec: caller MUST be a joined member of the
//! room. World-readability does NOT grant access here — the spec is
//! deliberately stricter than `/messages` to avoid leaking
//! point-in-time event ids to non-members.

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct TimestampQuery {
    /// Origin-server timestamp to search from, in milliseconds.
    pub ts: u64,
    /// `"f"` = forward (closest event ≥ ts), `"b"` = backward (≤ ts).
    /// Spec says either is valid; default is implementation-defined.
    /// We default to backward (more useful for "what was happening at
    /// time T").
    #[serde(default = "default_dir")]
    pub dir: String,
}

fn default_dir() -> String {
    "b".to_string()
}

/// GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event
pub async fn timestamp_to_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Query(q): Query<TimestampQuery>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    // Membership gate. Per spec, only joined members may query —
    // even for world-readable rooms (unlike /messages, which has
    // history-visibility semantics).
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("user not joined to room".into()).into());
    }

    // Validate dir parameter early.
    if q.dir != "f" && q.dir != "b" {
        return Err(VelaError::Forbidden("dir must be 'f' or 'b'".into()).into());
    }

    // Walk the room's timeline to find the closest event to `ts` in
    // the requested direction. We iterate the room_timeline CF
    // sequentially; for rooms with deep history this would benefit
    // from a timestamp index, but rooms here typically have a
    // bounded recent window and the linear scan is acceptable.
    let timeline = state
        .db
        .get_timeline_range(room_nid, 0, u64::MAX, 1000)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let want_forward = q.dir == "f";
    let mut best: Option<(u64, u64)> = None; // (origin_server_ts, event_nid)
    for (_stream_pos, nid) in timeline {
        let header = match state.db.get_event(nid) {
            Ok(Some((h, _))) => h,
            _ => continue,
        };
        let ots = header.origin_server_ts;
        let candidate = if want_forward {
            ots >= q.ts
        } else {
            ots <= q.ts
        };
        if !candidate {
            continue;
        }
        let better = match best {
            None => true,
            Some((current_ts, _)) => {
                let cur_dist = if want_forward {
                    current_ts.saturating_sub(q.ts)
                } else {
                    q.ts.saturating_sub(current_ts)
                };
                let new_dist = if want_forward {
                    ots.saturating_sub(q.ts)
                } else {
                    q.ts.saturating_sub(ots)
                };
                new_dist < cur_dist
            }
        };
        if better {
            best = Some((ots, nid));
        }
    }

    let (ts, nid) =
        best.ok_or_else(|| ApiError(VelaError::NotFound("no event matching timestamp".into())))?;
    let event_id = state
        .db
        .get_event_id_by_nid(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("event lookup".into())))?;

    Ok(Json(json!({
        "event_id": event_id,
        "origin_server_ts": ts,
    })))
}
