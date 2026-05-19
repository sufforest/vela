//! Inbound federation invite handler.
//!
//! Spec: `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}`.
//!
//! The inviting server sends us a signed `m.room.member` invite event for
//! one of OUR users. We validate the signature, co-sign with our key,
//! persist the event locally so the target sees an invite in /sync, and
//! return the double-signed event.
//!
//! `invite_room_state` is a stripped-state bundle we persist alongside
//! so the client can render room chrome (name, avatar) before joining.

use std::sync::Arc;

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::{Map, Value, json};
use tracing::debug;

use vela_core::canonical::canonical_json_object;
use vela_core::events::hash::{compute_content_hash, compute_event_id_for_version};
use vela_core::events::pdu::Pdu;
use vela_core::events::view::EventView;
use vela_core::federation::keys::{decode_public_key, verify_event_signature};
use vela_core::identifiers::Nid;

use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// PUT /_matrix/federation/v2/invite/{roomId}/{eventId}
pub async fn invite_v2(
    State(state): State<AppState>,
    Path((room_id, event_id)): Path<(String, String)>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
    axum::extract::Extension(VerifiedBody(body)): axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    debug!(%room_id, %event_id, origin = %origin.0, "inbound invite v2");

    let body = body.ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "empty body"))?;
    let body_obj = body
        .as_object()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "body not an object"))?;

    let room_version = body_obj
        .get("room_version")
        .and_then(|v| v.as_str())
        .unwrap_or("12");
    let event_room_version = vela_core::events::room_version::RoomVersion::parse(room_version)
        .ok_or_else(|| {
            err(
                StatusCode::BAD_REQUEST,
                "M_INCOMPATIBLE_ROOM_VERSION",
                "unsupported room_version",
            )
        })?;
    if !event_room_version.at_least(state.config.minimum_room_version) {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_INCOMPATIBLE_ROOM_VERSION",
            "room_version below operator minimum",
        ));
    }

    let mut event = body_obj
        .get("event")
        .and_then(|v| v.as_object())
        .cloned()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing event"))?;

    // Structural checks.
    if event.event_type() != Some("m.room.member") {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "type must be m.room.member",
        ));
    }
    if event.membership() != Some("invite") {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "content.membership must be invite",
        ));
    }

    let sender = event
        .sender()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing sender"))?
        .to_string();
    let state_key = event
        .state_key()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing state_key"))?
        .to_string();
    let sender_domain = sender
        .split_once(':')
        .map(|(_, d)| d)
        .unwrap_or("")
        .to_string();
    if sender_domain != origin.0 {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "sender domain does not match origin",
        ));
    }
    let target_domain = state_key
        .split_once(':')
        .map(|(_, d)| d.to_string())
        .unwrap_or_default();
    if target_domain != state.config.server_name {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "invite target is not on this server",
        ));
    }
    let claimed_room = event
        .room_id()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing room_id"))?;
    if claimed_room != room_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "event room_id doesn't match URL",
        ));
    }

    // Verify the origin's signature.
    let keys = state
        .remote_keys
        .get_or_fetch(&sender_domain)
        .await
        .map_err(|e| {
            err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                &format!("key fetch: {e}"),
            )
        })?;
    let sigs = event
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(&sender_domain))
        .and_then(|v| v.as_object())
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "no origin signature"))?;
    let mut verified = false;
    for (key_id, _) in sigs {
        let Some(pub_b64) = keys.verify_keys.get(key_id) else {
            continue;
        };
        let Ok(public_key) = decode_public_key(pub_b64) else {
            continue;
        };
        if verify_event_signature(
            &event,
            &sender_domain,
            key_id,
            &public_key,
            event_room_version,
        )
        .is_ok()
        {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "signature verification failed",
        ));
    }

    // event_id in the URL must match the computed reference hash.
    // Pre-v11 redaction shape differs from v12 — the URL-vs-hash
    // check has to use the actual room version we negotiated above.
    let computed_id = compute_event_id_for_version(&event, event_room_version);
    if computed_id.as_str() != event_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "URL event_id doesn't match reference hash",
        ));
    }

    // Hash check; redact on mismatch.
    let declared = event
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let computed_hash = compute_content_hash(&event);
    if declared != Some(computed_hash.as_str()) {
        event = vela_core::events::redact::redact_event(&event);
    }

    // Add OUR signature alongside the origin's.
    state
        .signing_key
        .sign_event(&mut event, &state.config.server_name);

    // Persist the event + stripped invite_room_state locally. The room
    // exists on the remote server; we only track enough for the target
    // user's /sync to surface the invite.
    let target_nid = state.db.get_or_create_nid(&state_key).map_err(db_err)?;
    let room_nid = state.db.get_or_create_nid(&room_id).map_err(db_err)?;

    // Room meta — idempotent.
    let _ = state.db.create_room_meta(room_nid, &room_id, room_version);

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Persist invite_room_state stripped events for client chrome.
    if let Some(arr) = body_obj.get("invite_room_state").and_then(|v| v.as_array()) {
        for stripped in arr {
            if let Err(e) = persist_stripped(&state, room_nid, stripped).await {
                debug!(error = %e, "stripped invite_room_state event skipped");
            }
        }
    }

    // Persist the invite event itself.
    let pdu = Pdu::from_json(event_id.clone(), &event)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "malformed PDU"))?;
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(db_err)?;
    let sender_nid = state.db.get_or_create_nid(&sender).map_err(db_err)?;
    let skey_nid = state.db.get_or_create_nid(&state_key).map_err(db_err)?;

    let event_nid = state.db.next_nid().map_err(db_err)?;
    let json_bytes = canonical_json_object(&event);
    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            &event_id,
            room_nid,
            type_nid,
            sender_nid,
            skey_nid,
            pdu.origin_server_ts,
            pdu.depth,
            &json_bytes,
            &[],
            &[],
            true,
            false,
        )
        .map_err(db_err)?;

    // Mark the target user as invited + wake both channels.
    crate::router::apply_membership_change(&state, room_nid, target_nid, 2, stream_pos);

    Ok(Json(json!({"event": event})))
}

/// Persist one stripped state event from `invite_room_state`. We only
/// need it for client chrome, so we synthesize a pseudo event_id and
/// skip all normal PDU plumbing. Same pattern as inbound knock.
async fn persist_stripped(state: &AppState, room_nid: u64, stripped: &Value) -> Result<(), String> {
    let obj = stripped.as_object().ok_or("stripped not an object")?;
    let etype = obj.event_type().ok_or("missing type")?;
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

    let pseudo_id = format!("$invite-stripped:{room_nid}:{etype}:{state_key}");
    if state
        .db
        .get_event_nid_by_id(&pseudo_id)
        .map_err(|e| format!("db: {e}"))?
        .is_some()
    {
        return Ok(());
    }

    let event_nid = state.db.next_nid().map_err(|e| format!("db: {e}"))?;
    let obj_map: Map<String, Value> = obj.clone();
    let bytes = canonical_json_object(&obj_map);
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
            &bytes,
            &[],
            &[],
            true,
            false,
        )
        .map_err(|e| format!("persist stripped: {e}"))?;
    Ok(())
}

fn err(code: StatusCode, errcode: &str, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({"errcode": errcode, "error": msg})))
}

fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    // Log the underlying error operator-side; respond generically to the
    // federating peer so DB internals don't leak.
    tracing::error!(error = %e, "federation invite: db error");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "M_UNKNOWN",
        "internal error",
    )
}
