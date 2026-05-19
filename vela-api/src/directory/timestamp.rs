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

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use axum::http::StatusCode;

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::middleware::federation_auth::XMatrixOrigin;
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
    // Skip state events: clients use timestamp_to_event to "jump to date"
    // in the message timeline, and state events (m.room.create,
    // m.room.member, etc.) shouldn't be selected when a client points
    // at a timestamp expecting a chat message. matters in practice
    // because v12 m.room.create uses a monotonic counter for ts (to
    // keep room_id hashes unique under concurrent createRoom from the
    // same sender) — under parallel test pressure that counter can
    // outpace wall-clock by enough that an old create event qualifies
    // for a `dir=f` query whose given_ts was meant to land between
    // create and the first message. tested by TestJumpToDateEndpoint's
    // looking_forwards sub-test.
    for (stream_pos, event_nid) in entries {
        let header = match state
            .db
            .get_event(event_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some((h, _)) => h,
            None => continue,
        };
        // state_key_nid 0 means the event has no state_key (= timeline
        // event). All state events have a non-zero state_key_nid.
        if header.state_key_nid != 0 {
            continue;
        }
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

    // Federation fallback (MSC3030): always query peers when the room
    // is federated, then pick whichever answer is closer to ts. Local
    // empty alone isn't a sufficient trigger — after send_join we have
    // some state events, so a local search returns *something*, but
    // that something can be far from ts when the timeline messages
    // we're after were sent before we joined and never reached us.
    let remote_answer =
        remote_timestamp_to_event(&state, room_nid, &room_id_str, q.ts, &q.dir).await;

    let local_answer = if let Some((event_ts, _, event_nid)) = best {
        let event_id = state
            .db
            .get_event_id_by_nid(event_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        event_id.map(|eid| (eid, event_ts))
    } else {
        None
    };

    let chosen = match (local_answer, remote_answer) {
        (Some(local), None) => local,
        (None, Some(remote_v)) => extract_remote(&remote_v)
            .ok_or_else(|| ApiError(VelaError::NotFound("no event matches timestamp".into())))?,
        (Some(local), Some(remote_v)) => {
            let remote = extract_remote(&remote_v);
            match remote {
                Some(rem) => closer_to(q.ts, local, rem),
                None => local,
            }
        }
        (None, None) => {
            return Err(ApiError(VelaError::NotFound(
                "no event matches timestamp".into(),
            )));
        }
    };

    Ok(Json(json!({
        "event_id": chosen.0,
        "origin_server_ts": chosen.1,
    })))
}

fn extract_remote(resp: &Value) -> Option<(String, u64)> {
    let event_id = resp
        .get("event_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())?;
    let ts = resp.get("origin_server_ts").and_then(|v| v.as_u64())?;
    Some((event_id, ts))
}

fn closer_to(target: u64, a: (String, u64), b: (String, u64)) -> (String, u64) {
    let da = target.abs_diff(a.1);
    let db = target.abs_diff(b.1);
    if da <= db { a } else { b }
}

/// Iterate remote members of `room_nid` asking each for their best
/// match. First peer that returns a 200 with a usable event wins; we
/// validate-and-persist the PDU so it shows up in subsequent /context
/// or /messages calls. Returns the JSON to send back, or `None` if
/// nothing usable came back from any peer.
async fn remote_timestamp_to_event(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    ts: u64,
    dir: &str,
) -> Option<Value> {
    let candidates = state
        .db
        .get_remote_servers_in_room(room_nid, &state.config.server_name)
        .ok()?;
    if candidates.is_empty() {
        return None;
    }
    for server in &candidates {
        let resp = match state
            .federation_client
            .timestamp_to_event(server, room_id, ts, dir)
            .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        let event_id = resp
            .get("event_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let origin_ts = resp.get("origin_server_ts").and_then(|v| v.as_u64());
        let (Some(event_id), Some(origin_ts)) = (event_id, origin_ts) else {
            continue;
        };

        // Backfill the event so future requests find it locally.
        // Tolerate failure: the spec answer is the event_id; a
        // persistence miss only means /context will need its own
        // fetch later.
        if state
            .db
            .get_event_nid_by_id(&event_id)
            .ok()
            .flatten()
            .is_none()
            && let Ok(pdu_value) = state
                .federation_client
                .fetch_event_pdu(server, &event_id)
                .await
        {
            let _ = crate::federation::federation_receive::persist_fetched_event(
                state,
                &pdu_value,
                server,
                crate::federation::federation_receive::new_fetch_budget(),
                crate::federation::federation_receive::FetchKind::Backfill,
            )
            .await;

            // Also pull the pivot's ancestors so /context-then-/messages
            // can return a useful chunk. Without this the test pattern
            // is /timestamp_to_event → /context (cursor at pivot) →
            // /messages dir=b: vela has the pivot but no older events,
            // so the chunk is just the pivot. attempt_backfill walks
            // the pivot's prev_events and pulls a window of historical
            // PDUs persisted with stream_pos.
            if let Some(prev_events) =
                pdu_value
                    .get("prev_events")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                && !prev_events.is_empty()
            {
                let _ = crate::federation::federation_backfill::attempt_backfill(
                    state,
                    room_nid,
                    room_id,
                    &prev_events,
                    crate::federation::federation_backfill::BACKFILL_LIMIT,
                )
                .await;
            }
        }
        return Some(json!({
            "event_id": event_id,
            "origin_server_ts": origin_ts,
        }));
    }
    None
}

/// GET /_matrix/federation/v1/timestamp_to_event/{roomId}?ts=…&dir=…
///
/// Federation companion to the C2S handler. Peers send this when
/// their own search yields nothing and they think we may have the
/// event. Same lookup logic as the C2S path, with two differences:
/// (1) authentication is X-Matrix (handled by the federation_auth
/// middleware, hence the `XMatrixOrigin` extractor) — no member
/// check, since signed peers are authoritative for their own users;
/// (2) errors are returned as bare HTTP statuses so we don't leak
/// our internal `M_*` error codes onto the federation surface.
pub async fn federation_timestamp_to_event(
    State(state): State<AppState>,
    axum::extract::Extension(_origin): axum::extract::Extension<XMatrixOrigin>,
    Path(room_id_str): Path<String>,
    Query(q): Query<TimestampQuery>,
) -> Result<Json<Value>, StatusCode> {
    if q.dir != "f" && q.dir != "b" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let room_nid = state
        .db
        .get_nid(&room_id_str)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let entries = state
        .db
        .get_timeline_range(room_nid, 0, u64::MAX, MAX_TIMESTAMP_SCAN)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let want_forward = q.dir == "f";
    let mut best: Option<(u64, u64, u64)> = None;
    // Skip state events on the federation surface too — see C2S handler
    // comment; same monotonic-create-ts vs wall-clock issue.
    for (stream_pos, event_nid) in entries {
        let header = match state
            .db
            .get_event(event_nid)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            Some((h, _)) => h,
            None => continue,
        };
        if header.state_key_nid != 0 {
            continue;
        }
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

    let (event_ts, _, event_nid) = best.ok_or(StatusCode::NOT_FOUND)?;
    let event_id = state
        .db
        .get_event_id_by_nid(event_nid)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(json!({
        "event_id": event_id,
        "origin_server_ts": event_ts,
    })))
}
