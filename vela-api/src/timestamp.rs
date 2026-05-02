//! `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event`
//!
//! MSC3030 jump-to-date. Returns the event whose `origin_server_ts`
//! is closest to the supplied `ts` in the requested direction.
//!
//! Permission model per spec: caller MUST be a joined member of the
//! room. World-readability does NOT grant access here — the spec is
//! deliberately stricter than `/messages` to avoid leaking
//! point-in-time event ids to non-members.
//!
//! Tie-break per spec: when several events share the target
//! timestamp, `dir=f` returns the topologically earliest (lowest
//! stream position) and `dir=b` the latest. A naive "closest
//! distance" implementation returns the first one in the database,
//! which fails the topological-tiebreak Complement test.

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
    /// `"f"` = forward (smallest event_ts ≥ ts),
    /// `"b"` = backward (largest event_ts ≤ ts).
    /// Spec doesn't define a default; we default to backward (more
    /// useful for "what was happening at time T").
    #[serde(default = "default_dir")]
    pub dir: String,
}

fn default_dir() -> String {
    "b".to_string()
}

/// Cap the timeline scan so a pathologically large room can't tie up
/// a single request indefinitely. With ~10k events the linear walk
/// stays under tens of milliseconds; rooms larger than that would
/// benefit from a dedicated origin_server_ts index, deferred.
const MAX_TIMESTAMP_SCAN: usize = 10_000;

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

    // Membership gate: spec restricts this endpoint to joined
    // members, even for world-readable rooms (unlike /messages,
    // which has history-visibility semantics).
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("user not joined to room".into()).into());
    }

    if q.dir != "f" && q.dir != "b" {
        return Err(VelaError::BadJson("dir must be 'f' or 'b'".into()).into());
    }

    let entries = state
        .db
        .get_timeline_range(room_nid, 0, u64::MAX, MAX_TIMESTAMP_SCAN)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Track (event_ts, stream_pos, event_nid). The lex order on
    // (event_ts, stream_pos) gives us the spec-mandated tie-break:
    // for `dir=f` we minimise the pair (lowest ts, then lowest
    // stream_pos = topologically earliest); for `dir=b` we maximise
    // the pair (highest ts, then highest stream_pos = topologically
    // latest). Stream position monotonically increases in topological
    // order for events persisted on this server.
    let want_forward = q.dir == "f";
    let mut best: Option<(u64, u64, u64)> = None;
    for (stream_pos, event_nid) in entries {
        let header = match state
            .db
            .get_event(event_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some((h, _)) => h,
            None => continue,
        };
        let event_ts = header.origin_server_ts;
        let qualifies = if want_forward {
            event_ts >= q.ts
        } else {
            event_ts <= q.ts
        };
        if !qualifies {
            continue;
        }
        let candidate = (event_ts, stream_pos, event_nid);
        best = Some(match best {
            None => candidate,
            Some(cur) => {
                let prefer_candidate = if want_forward {
                    (candidate.0, candidate.1) < (cur.0, cur.1)
                } else {
                    (candidate.0, candidate.1) > (cur.0, cur.1)
                };
                if prefer_candidate { candidate } else { cur }
            }
        });
    }

    let (event_ts, _, event_nid) =
        best.ok_or_else(|| ApiError(VelaError::NotFound("no event matches timestamp".into())))?;
    let event_id = state
        .db
        .get_event_id_by_nid(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("no event matches timestamp".into())))?;

    Ok(Json(json!({
        "event_id": event_id,
        "origin_server_ts": event_ts,
    })))
}
