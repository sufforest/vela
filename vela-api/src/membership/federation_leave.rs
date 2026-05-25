//! Inbound federation `make_leave` / `send_leave`.
//!
//! Spec:
//! - `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`
//! - `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}`
//!
//! Mirrors the shape of `federation_join.rs` but for the leave flow: the
//! origin server asks us for an unsigned leave template for one of its
//! users, signs it, and sends it back via `send_leave`.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::{Map, Value, json};
use tracing::{debug, warn};

use vela_core::auth_rules::{AuthError, check_auth};
use vela_core::events::builder::select_auth_events;
use vela_core::events::hash::compute_content_hash;
use vela_core::events::pdu::Pdu;
use vela_core::events::view::EventView;
use vela_core::federation::keys::{decode_public_key, verify_event_signature};
use vela_core::identifiers::EventId;
use vela_core::identifiers::Nid;

use crate::federation::federation_state::{ensure_create_in_state, load_pdu_by_event_id};
use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// GET /_matrix/federation/v1/make_leave/{roomId}/{userId}
pub async fn make_leave(
    State(state): State<AppState>,
    Path((room_id, user_id)): Path<(String, String)>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    debug!(%room_id, %user_id, origin = %origin.0, "make_leave");

    // Sender's domain must match the request origin.
    match user_id.split_once(':') {
        Some((_, domain)) if domain == origin.0 => {}
        _ => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "userId does not belong to origin",
            ));
        }
    }

    let room_nid = state.db.get_nid(&room_id).map_err(db_err)?.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room not known locally",
        )
    })?;

    let user_nid = state.db.get_or_create_nid(&user_id).map_err(db_err)?;
    // User must currently be in the room (joined/invited/knocked) to leave it.
    match state.db.get_membership(room_nid, user_nid).ok().flatten() {
        Some(1) | Some(2) | Some(4) => {}
        _ => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "user is not a member of this room",
            ));
        }
    }

    let room_version = state.db.get_room_version_typed(room_nid).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &format!("db: {e}"),
        )
    })?;

    let content_val = vela_core::events::content::member_content_leave();
    let auth_events = select_auth_events(
        "m.room.member",
        &user_id,
        Some(&user_id),
        Some(&content_val),
        room_version,
        &|etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            let eid = state.db.get_event_id_by_nid(en).ok()??;
            EventId::parse(&eid).ok()
        },
    );

    let extremity_nids = state.db.get_extremities(room_nid).map_err(db_err)?;
    let mut prev_event_ids: Vec<String> = Vec::new();
    let mut max_depth: u64 = 0;
    for &enid in &extremity_nids {
        if let Ok(Some(d)) = state.db.get_event_depth(enid)
            && d > max_depth
        {
            max_depth = d;
        }
        if let Ok(Some(id)) = state.db.get_event_id_by_nid(enid) {
            prev_event_ids.push(id);
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut template = Map::new();
    template.insert("type".into(), json!("m.room.member"));
    template.insert("state_key".into(), json!(user_id));
    template.insert("sender".into(), json!(user_id));
    template.insert("room_id".into(), json!(room_id));
    template.insert("content".into(), content_val);
    template.insert("origin".into(), json!(origin.0));
    template.insert("origin_server_ts".into(), json!(now));
    template.insert("depth".into(), json!(max_depth + 1));
    template.insert("prev_events".into(), json!(prev_event_ids));
    template.insert(
        "auth_events".into(),
        json!(auth_events.iter().map(|e| e.as_str()).collect::<Vec<_>>()),
    );

    Ok(Json(json!({
        "room_version": room_version.as_str(),
        "event": template,
    })))
}

/// PUT /_matrix/federation/v1/send_leave/{roomId}/{eventId}
///
/// Legacy variant. Same validation and persist logic as v2; v1's
/// success body wraps in a `[200, {...}]` array. Delegate to
/// `send_leave_v2` and reshape; errors pass through unchanged.
pub async fn send_leave_v1(
    state: State<AppState>,
    path: Path<(String, String)>,
    origin: axum::extract::Extension<XMatrixOrigin>,
    body: axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let v2 = send_leave_v2(state, path, origin, body).await?;
    Ok(Json(json!([200, v2.0])))
}

/// PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}
pub async fn send_leave_v2(
    State(state): State<AppState>,
    Path((room_id, event_id)): Path<(String, String)>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
    axum::extract::Extension(VerifiedBody(body)): axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    debug!(%room_id, %event_id, origin = %origin.0, "send_leave v2");

    let event_json = body.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "empty send_leave body",
        )
    })?;
    let event_obj = event_json
        .as_object()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "event not an object"))?;

    // Structural checks.
    if event_obj.event_type() != Some("m.room.member") {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "send_leave event must be m.room.member",
        ));
    }
    // Spec: "leave" (voluntary) is the common case; bans also route here on
    // some servers. We accept both to stay lenient.
    let membership = event_obj.membership().unwrap_or("");
    if membership != "leave" && membership != "ban" {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "send_leave membership must be leave or ban",
        ));
    }
    let sender = event_obj
        .sender()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing sender"))?;
    let state_key = event_obj
        .state_key()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing state_key"))?;
    // For voluntary leaves, send_leave is self-only — `state_key` must
    // equal `sender`. A different state_key is structurally a kick,
    // which is what `send_leave/{kicked_user}` from another endpoint
    // (or the local power-level path) handles. Returning 403 from
    // auth would be misleading; spec wants 400 here.
    // Bans are exempt: state_key is the banned user, not the banner.
    if membership == "leave" && state_key != sender {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "send_leave state_key must equal sender",
        ));
    }
    let sender_domain = sender.split_once(':').map(|(_, d)| d).unwrap_or("");
    if sender_domain != origin.0 {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "sender domain does not match origin",
        ));
    }

    // Look up room.
    let room_nid = state.db.get_nid(&room_id).map_err(db_err)?.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room not known locally",
        )
    })?;

    // Acquire the per-room lock before reading auth state, persisting,
    // promoting state, and flipping membership. Mirrors process_pdu's
    // top-of-function lock (PR #92) so a concurrent /send for this
    // room can't interleave a write between our auth_state read and
    // our promote_state_event/set_membership writes. Without the
    // lock, ban events arriving via /send_leave can be promoted just
    // after a concurrent invite/join for the same user wins state-res,
    // and the next /sync sees a torn view.
    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _room_guard = lock.lock().await;

    // Verify signature against origin's published keys.
    let keys = state
        .remote_keys
        .get_or_fetch(sender_domain)
        .await
        .map_err(|e| {
            err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                &format!("key fetch: {e}"),
            )
        })?;
    let sigs = event_obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(sender_domain))
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                &format!("no signatures from {sender_domain}"),
            )
        })?;
    let send_leave_room_version = state
        .db
        .get_room_version_typed(room_nid)
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);
    let mut verified = false;
    for (key_id, _) in sigs {
        let Some(pub_b64) = keys.verify_keys.get(key_id) else {
            continue;
        };
        let Ok(public_key) = decode_public_key(pub_b64) else {
            continue;
        };
        if verify_event_signature(
            event_obj,
            sender_domain,
            key_id,
            &public_key,
            send_leave_room_version,
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

    // Hash check — on mismatch, redact.
    let declared = event_obj
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let computed = compute_content_hash(event_obj);
    let to_persist: Map<String, Value> = match declared {
        Some(d) if d == computed => event_obj.clone(),
        _ => vela_core::events::redact::redact_event(event_obj),
    };

    let pdu = Pdu::from_json(event_id.clone(), &to_persist)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "malformed PDU"))?;

    // Run standard auth via the rule engine. Build a state view from the
    // event's auth_events + (v12) injected create.
    let mut auth_state = std::collections::HashMap::new();
    for aev in &pdu.auth_events {
        if let Some(p) = load_pdu_by_event_id(&state.db, aev)
            && let Some(sk) = p.state_key.as_deref()
        {
            auth_state.insert((p.event_type.clone(), sk.to_string()), p);
        }
    }
    ensure_create_in_state(&state.db, room_nid, &mut auth_state);
    let auth_fn = |t: &str, sk: &str| auth_state.get(&(t.to_string(), sk.to_string()));
    if let Err(AuthError::Rejected(reason)) = check_auth(&pdu, &auth_fn) {
        warn!(%event_id, %reason, "send_leave rejected");
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            &format!("auth check failed: {reason}"),
        ));
    }

    // Persist. Reuse the federation-receive path for consistency: persist the
    // event, update state snapshot, flip membership, broadcast to peers.
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(db_err)?;
    let sender_nid = state.db.get_or_create_nid(sender).map_err(db_err)?;
    let state_key_nid = state.db.get_or_create_nid(state_key).map_err(db_err)?;
    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &pdu.prev_events {
        match state.db.get_event_nid_by_id(pid) {
            Ok(Some(n)) => prev_nids.push(n),
            Ok(None) => {
                debug!(event_id = %pdu.event_id, prev_event = %pid, "send_leave: prev_event unknown locally, dropped from event_edges")
            }
            Err(e) => {
                debug!(event_id = %pdu.event_id, prev_event = %pid, error = %e, "send_leave: prev_event lookup error")
            }
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &pdu.auth_events {
        match state.db.get_event_nid_by_id(aid) {
            Ok(Some(n)) => auth_nids.push(n),
            Ok(None) => {
                debug!(event_id = %pdu.event_id, auth_event = %aid, "send_leave: auth_event unknown locally, dropped from event_auth_edges")
            }
            Err(e) => {
                debug!(event_id = %pdu.event_id, auth_event = %aid, error = %e, "send_leave: auth_event lookup error")
            }
        }
    }
    let event_nid = state.db.next_nid().map_err(db_err)?;
    let json_bytes = vela_core::canonical::canonical_json_object(&to_persist);
    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            &event_id,
            room_nid,
            type_nid,
            sender_nid,
            state_key_nid,
            pdu.origin_server_ts,
            pdu.depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            true,
            false,
        )
        .map_err(db_err)?;

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, state_key_nid)
        .map_err(db_err)?;

    // device_lists.left bookkeeping: if the leaver was a joined member,
    // fan out a peer-departure entry to every observer (other room
    // members) so their /sync surfaces this user moving out of the
    // shared device-key set. Run BEFORE apply_membership_change so
    // get_room_members still includes the observers.
    let membership_byte = if membership == "ban" { 3u8 } else { 0u8 };
    let was_joined = state.db.get_membership(room_nid, sender_nid).ok().flatten() == Some(1);
    if was_joined {
        crate::e2ee::keys::record_device_changes_on_leave(&state, sender_nid, room_nid);
    }
    // Update per-user membership index + notify local sync, then
    // broadcast to remote peers.
    crate::router::apply_membership_change(
        &state,
        room_nid,
        sender_nid,
        membership_byte,
        stream_pos,
    );
    state.federation_sender.broadcast(room_nid, event_nid);

    Ok(Json(json!({})))
}

fn err(code: StatusCode, errcode: &str, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({"errcode": errcode, "error": msg})))
}

fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    // Log the underlying error operator-side; respond generically to the
    // federating peer so DB internals don't leak.
    tracing::error!(error = %e, "federation leave: db error");
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "M_UNKNOWN",
        "internal error",
    )
}
