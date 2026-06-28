use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::messages::load_client_event;
use crate::router::AppState;

/// `?format=` controls whether `state/.../{eventType}/{stateKey}` returns
/// just the event content (default `content`, omitted) or the full client
/// event (when `event`).
#[derive(Debug, Default, Deserialize)]
pub struct StateFormatQuery {
    pub format: Option<String>,
}

/// Membership-bucket constants used by `get_membership`. The encoding
/// is set in `federation_receive.rs::set_membership` and matches the
/// leave path in `membership.rs::emit_membership_event_for_target`:
///   0 = leave (or anything else / unknown)
///   1 = join
///   2 = invite
///   3 = ban
///   4 = knock
const MEMBERSHIP_LEAVE: u8 = 0;
const MEMBERSHIP_JOIN: u8 = 1;
const MEMBERSHIP_BAN: u8 = 3;

/// GET /_matrix/client/v3/rooms/{roomId}/state
///
/// Currently-joined members see the live state. Departed members
/// (membership=leave or ban) see the state as it was at their leave
/// event — spec history-visibility rule 2: "If the user's `membership`
/// was `join`, allow."
pub async fn get_all_state(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        // Unknown room and known-room-non-member both surface as 403 (the
        // membership gate below also 403s) so a 404-vs-403 difference can't
        // be used to probe which rooms exist — same posture as /messages.
        .ok_or_else(|| ApiError(VelaError::Forbidden("not a member of this room".into())))?;

    let view = pick_state_view(&state, room_nid, user.user_nid)?;
    let state_nids = view.all_state_nids(&state, room_nid)?;

    let mut events = Vec::new();
    for nid in state_nids {
        if let Some(ev) = load_client_event(&state, nid, &room_id)? {
            events.push(ev);
        }
    }

    Ok(Json(Value::Array(events)))
}

/// GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
pub async fn get_state_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(params): Path<(String, String, String)>,
    Query(q): Query<StateFormatQuery>,
) -> Result<Json<Value>, ApiError> {
    let (room_id, event_type, state_key) = params;

    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        // Unknown room and known-room-non-member both surface as 403 (the
        // membership gate below also 403s) so a 404-vs-403 difference can't
        // be used to probe which rooms exist — same posture as /messages.
        .ok_or_else(|| ApiError(VelaError::Forbidden("not a member of this room".into())))?;

    let view = pick_state_view(&state, room_nid, user.user_nid)?;

    let type_nid = state
        .db
        .get_nid(&event_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    let skey_nid = state
        .db
        .get_nid(&state_key)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    let event_nid = view
        .lookup_state_event(&state, room_nid, type_nid, skey_nid)?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    let event = load_client_event(&state, event_nid, &room_id)?
        .ok_or_else(|| ApiError(VelaError::NotFound("state event not found".into())))?;

    // ?format=event returns the full client event; default returns content only.
    if matches!(q.format.as_deref(), Some("event")) {
        Ok(Json(event))
    } else {
        let content = event.get("content").cloned().unwrap_or(json!({}));
        Ok(Json(content))
    }
}

/// GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}
/// (state_key defaults to empty string)
pub async fn get_state_event_no_key(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, event_type)): Path<(String, String)>,
    Query(q): Query<StateFormatQuery>,
) -> Result<Json<Value>, ApiError> {
    get_state_event(
        State(state),
        user,
        Path((room_id, event_type, String::new())),
        Query(q),
    )
    .await
}

/// Which slice of room state is visible to this caller. `Current` is
/// the live state; `AsOfLeave` reads the state snapshot recorded at
/// the user's most recent leave/ban member event so departed users
/// see a frozen view rather than 403.
enum StateView {
    Current,
    AsOfLeave { snapshot: Vec<u64> },
}

impl StateView {
    fn all_state_nids(&self, state: &AppState, room_nid: u64) -> Result<Vec<u64>, ApiError> {
        match self {
            StateView::Current => state
                .db
                .get_all_state_event_nids(room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string()))),
            StateView::AsOfLeave { snapshot } => Ok(snapshot.clone()),
        }
    }

    fn lookup_state_event(
        &self,
        state: &AppState,
        room_nid: u64,
        type_nid: u64,
        skey_nid: u64,
    ) -> Result<Option<u64>, ApiError> {
        match self {
            StateView::Current => state
                .db
                .get_state_event_nid(room_nid, type_nid, skey_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string()))),
            StateView::AsOfLeave { snapshot } => {
                for &nid in snapshot {
                    if let Some((header, _)) = state
                        .db
                        .get_event(nid)
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                        && header.type_nid == type_nid
                        && header.state_key_nid == skey_nid
                    {
                        return Ok(Some(nid));
                    }
                }
                Ok(None)
            }
        }
    }
}

/// Resolve which state view the caller is allowed to read. Joined
/// members get live state; users whose current membership is leave
/// or ban get the snapshot captured at their leave/ban event.
/// Anything else (no membership at all, invite, knock) is 403.
fn pick_state_view(state: &AppState, room_nid: u64, user_nid: u64) -> Result<StateView, ApiError> {
    let membership = state
        .db
        .get_membership(room_nid, user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Note: a user with no membership entry at all gets `None` (treat
    // as never-a-member, deny). A user with `Some(0)` had their
    // membership set explicitly to leave — they were once a member.
    match membership {
        Some(MEMBERSHIP_JOIN) => Ok(StateView::Current),
        Some(MEMBERSHIP_LEAVE) | Some(MEMBERSHIP_BAN) => {
            // The "current" m.room.member event for a leave/ban user
            // *is* their leave/ban event. Read the state snapshot
            // recorded after that event was applied.
            let user_id = state
                .db
                .resolve_nid(user_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .ok_or_else(|| ApiError(VelaError::Forbidden("unknown caller".into())))?;
            let type_nid = state
                .db
                .get_nid("m.room.member")
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .ok_or_else(|| {
                    ApiError(VelaError::Forbidden("not a member of this room".into()))
                })?;
            let sk_nid = state
                .db
                .get_nid(&user_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .ok_or_else(|| {
                    ApiError(VelaError::Forbidden("not a member of this room".into()))
                })?;
            let leave_event_nid = state
                .db
                .get_state_event_nid(room_nid, type_nid, sk_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .ok_or_else(|| {
                    ApiError(VelaError::Forbidden("not a member of this room".into()))
                })?;
            let snapshot = state
                .db
                .get_state_at_event(leave_event_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .ok_or_else(|| {
                    ApiError(VelaError::Forbidden(
                        "state snapshot for departed view missing".into(),
                    ))
                })?;
            Ok(StateView::AsOfLeave { snapshot })
        }
        _ => Err(VelaError::Forbidden("not a member of this room".into()).into()),
    }
}
