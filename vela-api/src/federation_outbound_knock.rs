//! Outbound federation knock flow.
//!
//! When a local user wants to knock on a remote room we don't already
//! know about, we:
//! 1. `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}?ver=12` for
//!    an unsigned template.
//! 2. Sign locally.
//! 3. `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}` with the
//!    signed event — on success the resident returns `knock_room_state`,
//!    a stripped-state bundle for client chrome while the knock waits.
//! 4. Persist the knock locally so `rooms.knock.{roomId}` surfaces in sync.
//!
//! Unlike `do_remote_join` this does NOT bootstrap full state — a knock
//! is an admission request, not a join. We only need enough state to
//! render the room in the client's "knocked" tray.

use std::sync::Arc;

use serde_json::{Map, Value, json};
use tracing::{debug, warn};

use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::sign_unsigned_template;
use vela_core::events::view::EventView;
use vela_core::identifiers::{Nid, RoomId};

use crate::middleware::error::ApiError;
use crate::router::{AppState, notify_user};

/// Try each `server_hints` entry in order until one round-trips
/// make_knock + send_knock successfully.
pub async fn do_remote_knock(
    state: &AppState,
    user_id: &str,
    user_nid: u64,
    room_id: &RoomId,
    server_hints: &[String],
    reason: Option<&str>,
) -> Result<(), ApiError> {
    if server_hints.is_empty() {
        return Err(ApiError(VelaError::NotFound(
            "remote knock requires ?server_name= hint to locate a resident server".into(),
        )));
    }

    let mut last_error: Option<String> = None;
    for server in server_hints {
        if server == &state.config.server_name {
            continue;
        }
        match try_knock_via(state, user_id, user_nid, room_id, server, reason).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(%server, error = %e, "remote knock via server failed");
                last_error = Some(e);
            }
        }
    }

    Err(ApiError(VelaError::Forbidden(format!(
        "all resident-server hints failed: {}",
        last_error.unwrap_or_else(|| "no hints tried".into())
    ))))
}

async fn try_knock_via(
    state: &AppState,
    user_id: &str,
    user_nid: u64,
    room_id: &RoomId,
    server: &str,
    reason: Option<&str>,
) -> Result<(), String> {
    debug!(%room_id, %user_id, %server, "starting remote knock via");

    // --- 1. make_knock ---
    let make_knock_resp = state
        .federation_client
        .make_knock(server, room_id.as_str(), user_id, &["12"])
        .await
        .map_err(|e| format!("make_knock failed: {e}"))?;

    let room_version = make_knock_resp
        .get("room_version")
        .and_then(|v| v.as_str())
        .ok_or("make_knock response missing room_version")?;
    if room_version != "12" {
        return Err(format!(
            "unsupported room_version {room_version} (Vela only supports v12)"
        ));
    }

    let mut template = make_knock_resp
        .get("event")
        .and_then(|v| v.as_object())
        .cloned()
        .ok_or("make_knock response missing event template")?;

    validate_template(&template, user_id, room_id.as_str())?;

    // `origin` / `origin_server_ts` are the joining server's responsibility.
    if !template.contains_key("origin_server_ts") {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        template.insert("origin_server_ts".into(), json!(now));
    }
    if !template.contains_key("origin") {
        template.insert("origin".into(), json!(state.config.server_name));
    }

    // Attach the optional reason. The template from make_knock may already
    // carry a content subtree; we only inject `reason` when the client
    // supplied one, and leave the rest intact.
    if let Some(reason) = reason
        && let Some(content) = template
            .entry("content".to_string())
            .or_insert_with(|| json!({}))
            .as_object_mut()
    {
        content.insert("reason".into(), json!(reason));
    }

    // --- 2. Sign ---
    let (signed_event, event_id) =
        sign_unsigned_template(template, &state.signing_key, &state.config.server_name);

    // --- 3. send_knock ---
    let send_resp = state
        .federation_client
        .send_knock_v1(
            server,
            room_id.as_str(),
            event_id.as_str(),
            Value::Object(signed_event.clone()),
        )
        .await
        .map_err(|e| format!("send_knock failed: {e}"))?;

    // --- 4. Persist locally: stripped state + our knock event ---
    persist_knock(
        state,
        user_id,
        user_nid,
        room_id,
        room_version,
        &signed_event,
        event_id.as_str(),
        &send_resp,
    )
    .await
    .map_err(|e| format!("persist_knock failed: {e}"))?;

    Ok(())
}

/// Spec checks on the make_knock template.
fn validate_template(
    template: &Map<String, Value>,
    user_id: &str,
    room_id: &str,
) -> Result<(), String> {
    let ev_type = template.event_type().ok_or("template missing type")?;
    if ev_type != "m.room.member" {
        return Err(format!(
            "template type is {ev_type}, expected m.room.member"
        ));
    }
    let sender = template.sender().ok_or("template missing sender")?;
    if sender != user_id {
        return Err(format!("template sender {sender} != {user_id}"));
    }
    let state_key = template.state_key().ok_or("template missing state_key")?;
    if state_key != user_id {
        return Err(format!("template state_key {state_key} != {user_id}"));
    }
    let tmpl_room = template.room_id().ok_or("template missing room_id")?;
    if tmpl_room != room_id {
        return Err(format!("template room_id {tmpl_room} != {room_id}"));
    }
    let membership = template
        .membership()
        .ok_or("template missing content.membership")?;
    if membership != "knock" {
        return Err(format!(
            "template membership is {membership}, expected knock"
        ));
    }
    Ok(())
}

async fn persist_knock(
    state: &AppState,
    user_id: &str,
    user_nid: u64,
    room_id: &RoomId,
    room_version: &str,
    signed_event: &Map<String, Value>,
    event_id: &str,
    send_resp: &Value,
) -> Result<(), String> {
    let room_nid = state
        .db
        .get_or_create_nid(room_id.as_str())
        .map_err(|e| format!("db: {e}"))?;

    // Serialize with the resident-view of the room.
    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let _ = state
        .db
        .create_room_meta(room_nid, room_id.as_str(), room_version);

    // Persist any stripped knock_room_state events as plain state events
    // so sync can render room chrome. These are NOT full PDUs — they lack
    // auth_events/prev_events — we store them only for display purposes
    // and skip signature checks accordingly. If/when the knock is
    // accepted, a real make_join flow will supersede this minimal view.
    let stripped = send_resp
        .get("knock_room_state")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for ev in stripped {
        if let Err(e) = persist_stripped_state_event(state, room_nid, &ev).await {
            debug!(error = %e, "stripped knock state skipped");
        }
    }

    // Persist our own knock event.
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| format!("db: {e}"))?;
    let sender_nid = state
        .db
        .get_or_create_nid(user_id)
        .map_err(|e| format!("db: {e}"))?;
    let depth = signed_event
        .get("depth")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    let origin_ts = signed_event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let event_nid = state.db.next_nid();
    let json_bytes = canonical_json_object(signed_event);
    state
        .db
        .persist_event(
            event_nid,
            event_id,
            room_nid,
            type_nid,
            sender_nid,
            sender_nid,
            origin_ts,
            depth,
            &json_bytes,
            &[],
            &[],
            true,
            false,
        )
        .map_err(|e| format!("persist knock: {e}"))?;

    state
        .db
        .set_membership(room_nid, user_nid, 4) // 4 = knock
        .map_err(|e| format!("set membership: {e}"))?;

    notify_user(state, user_nid);
    Ok(())
}

/// Persist a stripped state event from `knock_room_state`. These events
/// carry the top-level fields of a minimal state event (type, state_key,
/// sender, content) but no PDU plumbing (no hashes, no signatures, no
/// prev/auth). We store them with empty prev/auth lists purely for sync
/// display.
async fn persist_stripped_state_event(
    state: &AppState,
    room_nid: u64,
    event: &Value,
) -> Result<(), String> {
    let obj = event.as_object().ok_or("stripped event not an object")?;
    let etype = obj.event_type().ok_or("stripped event missing type")?;
    let state_key = obj.state_key().unwrap_or("");
    let sender = obj.sender().unwrap_or("");

    let type_nid = state
        .db
        .get_or_create_nid(etype)
        .map_err(|e| format!("db: {e}"))?;
    let state_key_nid = state
        .db
        .get_or_create_nid(state_key)
        .map_err(|e| format!("db: {e}"))?;
    let sender_nid = state
        .db
        .get_or_create_nid(sender)
        .map_err(|e| format!("db: {e}"))?;

    // Synthesize a stable event id so repeated stripped state doesn't pile
    // up duplicates in the event_id index. `knock-stripped-{type}-{skey}`
    // keys on role, not content; later knock-state updates clobber it.
    let pseudo_id = format!("$knock-stripped:{room_nid}:{etype}:{state_key}");
    if let Ok(Some(existing)) = state.db.get_event_nid_by_id(&pseudo_id) {
        // Overwrite is fine: we never reference these from a real DAG.
        let _ = existing;
    }

    let event_nid = state.db.next_nid();
    let json_bytes = canonical_json_object(obj);
    state
        .db
        .persist_event(
            event_nid,
            &pseudo_id,
            room_nid,
            type_nid,
            sender_nid,
            state_key_nid,
            0,
            0,
            &json_bytes,
            &[],
            &[],
            true,
            false,
        )
        .map_err(|e| format!("persist stripped: {e}"))?;

    Ok(())
}
