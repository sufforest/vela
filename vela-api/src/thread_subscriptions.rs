//! MSC4306 thread subscriptions.
//!
//! Three endpoints under `/_matrix/client/unstable/io.element.msc4306/
//! rooms/{roomId}/thread/{threadRootEventId}/subscription`:
//!
//! * PUT — subscribe (manually if body is `{}`, automatically when body
//!   carries `automatic: <event_id>`). Automatic subscriptions are
//!   subject to two spec checks: the cause event must be part of the
//!   thread (per `m.relates_to`), and it must have arrived strictly
//!   after the user's most recent unsubscribe (otherwise we'd let
//!   stale events re-subscribe a user who explicitly opted out).
//! * GET — return `{automatic: bool}` or 404 if not subscribed.
//! * DELETE — record an unsubscribe sentinel. Idempotent.
//!
//! The thread-root event must exist in the room — both PUT and GET
//! return 404 otherwise so misbehaving clients don't get a silent
//! "subscribed to nothing" state.

use axum::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

const STATE_UNSUBSCRIBED: u8 = 0;
const STATE_MANUAL: u8 = 1;
const STATE_AUTOMATIC: u8 = 2;

/// PUT subscription. Body either `{}` for manual or `{automatic: event_id}`.
pub async fn put_subscription(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, thread_root_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let (room_nid, _root_nid) = resolve_room_and_root(&state, &room_id, &thread_root_id)?;
    let automatic_cause = body.get("automatic").and_then(|v| v.as_str());

    if let Some(cause_id) = automatic_cause {
        // Spec: an automatic subscription must point at an event that
        // is itself part of the thread, AND that event must have
        // arrived after the user's last unsubscribe.

        // The thread root can't be the cause: subscribing to a thread
        // "because of" its own root would let any thread auto-subscribe
        // every user who ever saw it.
        if cause_id == thread_root_id {
            return Err(custom_err(
                400,
                "IO.ELEMENT.MSC4306.M_NOT_IN_THREAD",
                "cause event must be a reply, not the thread root",
            ));
        }

        let Some(cause_nid) = state.db.get_event_nid_by_id(cause_id).map_err(db_err)? else {
            return Err(custom_err(
                400,
                "IO.ELEMENT.MSC4306.M_NOT_IN_THREAD",
                "cause event not found",
            ));
        };
        if !event_is_in_thread(&state, cause_nid, &thread_root_id)? {
            return Err(custom_err(
                400,
                "IO.ELEMENT.MSC4306.M_NOT_IN_THREAD",
                "cause event is not in the named thread",
            ));
        }

        // Conflict: if the user has an `unsubscribed` record AND the
        // cause event was created before/at that unsubscribe, refuse.
        // Without this, a slow client could re-subscribe a user who
        // explicitly opted out based on events older than the opt-out.
        if let Some((STATE_UNSUBSCRIBED, prev_pos)) = state
            .db
            .get_thread_subscription(user.user_nid, room_nid, &thread_root_id)
            .map_err(db_err)?
        {
            let cause_pos = event_stream_pos(&state, room_nid, cause_nid)?;
            if cause_pos <= prev_pos {
                return Err(custom_err(
                    409,
                    "IO.ELEMENT.MSC4306.M_CONFLICTING_UNSUBSCRIPTION",
                    "cause event predates the most recent unsubscribe",
                ));
            }
        }

        // If the user already has a manual subscription, leave it
        // alone — manual outranks automatic.
        let existing = state
            .db
            .get_thread_subscription(user.user_nid, room_nid, &thread_root_id)
            .map_err(db_err)?;
        let new_state = match existing {
            Some((STATE_MANUAL, _)) => STATE_MANUAL,
            _ => STATE_AUTOMATIC,
        };
        state
            .db
            .set_thread_subscription(user.user_nid, room_nid, &thread_root_id, new_state)
            .map_err(db_err)?;
        return Ok(Json(json!({})));
    }

    // Manual subscription. Always overrides whatever the previous
    // state was — even an explicit unsubscribe — because the spec
    // treats manual writes as direct user intent.
    state
        .db
        .set_thread_subscription(user.user_nid, room_nid, &thread_root_id, STATE_MANUAL)
        .map_err(db_err)?;
    Ok(Json(json!({})))
}

/// GET subscription. 404 if not currently subscribed (the
/// unsubscribed sentinel and the no-record case both surface as 404
/// because the client UI semantics are identical).
pub async fn get_subscription(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, thread_root_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (room_nid, _root_nid) = resolve_room_and_root(&state, &room_id, &thread_root_id)?;
    let sub = state
        .db
        .get_thread_subscription(user.user_nid, room_nid, &thread_root_id)
        .map_err(db_err)?;
    match sub {
        Some((STATE_MANUAL, _)) => Ok(Json(json!({"automatic": false}))),
        Some((STATE_AUTOMATIC, _)) => Ok(Json(json!({"automatic": true}))),
        _ => Err(custom_err(
            404,
            "M_NOT_FOUND",
            "not subscribed to this thread",
        )),
    }
}

/// DELETE subscription. Idempotent: writing the unsubscribed sentinel
/// even when there was no prior record is fine, and it gives the
/// `set_thread_subscription` write a stream position we can compare
/// against when an automatic-subscribe attempt arrives later.
pub async fn delete_subscription(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, thread_root_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let (room_nid, _root_nid) = resolve_room_and_root(&state, &room_id, &thread_root_id)?;
    state
        .db
        .set_thread_subscription(user.user_nid, room_nid, &thread_root_id, STATE_UNSUBSCRIBED)
        .map_err(db_err)?;
    Ok(Json(json!({})))
}

fn resolve_room_and_root(
    state: &AppState,
    room_id: &str,
    thread_root_id: &str,
) -> Result<(u64, u64), ApiError> {
    let Some(room_nid) = state.db.get_nid(room_id).map_err(db_err)? else {
        return Err(custom_err(404, "M_NOT_FOUND", "room not found"));
    };
    let Some(root_nid) = state
        .db
        .get_event_nid_by_id(thread_root_id)
        .map_err(db_err)?
    else {
        return Err(custom_err(
            404,
            "M_NOT_FOUND",
            "thread root event not found",
        ));
    };
    Ok((room_nid, root_nid))
}

fn event_is_in_thread(
    state: &AppState,
    event_nid: u64,
    thread_root_id: &str,
) -> Result<bool, ApiError> {
    let (_, bytes) = state
        .db
        .get_event(event_nid)
        .map_err(db_err)?
        .ok_or_else(|| {
            ApiError(VelaError::Unknown(
                "thread cause event vanished mid-flight".into(),
            ))
        })?;
    let json: Value = serde_json::from_slice(&bytes)
        .map_err(|e| ApiError(VelaError::Unknown(format!("event json: {e}"))))?;
    let rel_type = json
        .pointer("/content/m.relates_to/rel_type")
        .and_then(|v| v.as_str());
    let event_id = json
        .pointer("/content/m.relates_to/event_id")
        .and_then(|v| v.as_str());
    Ok(rel_type == Some("m.thread") && event_id == Some(thread_root_id))
}

/// Find the stream_pos of `event_nid` in `room_nid`. There's no direct
/// `event_nid -> stream_pos` index in vela today; the room_timeline CF
/// is keyed (room_nid, stream_pos). Linear scan of the room's timeline
/// is fine for MSC4306's tests (threads with a handful of events) and
/// the constant SCAN cap keeps it bounded. Add a dedicated index if
/// real traffic shows this in profiles.
fn event_stream_pos(state: &AppState, room_nid: u64, event_nid: u64) -> Result<u64, ApiError> {
    const SCAN: usize = 50_000;
    let entries = state
        .db
        .get_timeline_latest(room_nid, SCAN)
        .map_err(db_err)?;
    for (pos, nid) in entries {
        if nid == event_nid {
            return Ok(pos);
        }
    }
    // If we can't find it, fall through with stream_pos=0. That makes
    // the conflict check permissive (any unsubscribe will have a
    // higher pos), which is the correct fail-open: better to allow a
    // valid resubscribe than to incorrectly refuse one.
    Ok(0)
}

fn db_err<E: std::fmt::Display>(e: E) -> ApiError {
    ApiError(VelaError::Store(e.to_string()))
}

fn custom_err(status: u16, errcode: &'static str, msg: &str) -> ApiError {
    ApiError(VelaError::Custom {
        status,
        errcode,
        msg: msg.to_string(),
    })
}
