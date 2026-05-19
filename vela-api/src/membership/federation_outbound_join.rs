//! Outbound federation join flow.
//!
//! When a local user tries to join a room hosted by another server, we:
//! 1. Hit `/_matrix/federation/v1/make_join/{roomId}/{userId}?ver=12` to fetch
//!    an unsigned template.
//! 2. Sign the template (add hashes, signature, compute event_id).
//! 3. Hit `/_matrix/federation/v2/send_join/{roomId}/{eventId}` with the
//!    signed event.
//! 4. Bootstrap the room locally from the response: persist auth_chain as
//!    historical context, persist state as current state, persist our join
//!    event, update memberships.
//!
//! Works for public and restricted rooms: the resident server is
//! responsible for populating `join_authorised_via_users_server` in the
//! make_join template when the room is restricted; we sign the template
//! as-is and `send_join`. Auth rule 5.3.5 enforces the authoriser has
//! invite power when the event is persisted.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use tracing::{debug, warn};

use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::sign_unsigned_template;
use vela_core::events::pdu::Pdu;
use vela_core::events::room_version::RoomVersion;
use vela_core::events::view::EventView;
use vela_core::identifiers::{EventId, Nid, RoomId};

use crate::middleware::error::ApiError;
use crate::router::AppState;

/// Orchestrate a federated join. Tries each `server_hints` entry in order
/// until one successfully returns a make_join template AND accepts our
/// send_join.
pub async fn do_remote_join(
    state: &AppState,
    user_id: &str,
    user_nid: u64,
    room_id: &RoomId,
    server_hints: &[String],
) -> Result<(), ApiError> {
    if server_hints.is_empty() {
        return Err(ApiError(VelaError::NotFound(
            "remote room requires ?server_name= hint to locate a resident server".into(),
        )));
    }

    let mut last_error: Option<String> = None;
    for server in server_hints {
        // Don't try to federate with ourselves.
        if server == &state.config.server_name {
            continue;
        }
        match try_join_via(state, user_id, user_nid, room_id, server).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                warn!(%server, error = %e, "remote join via server failed");
                last_error = Some(e);
            }
        }
    }

    Err(ApiError(VelaError::Forbidden(format!(
        "all resident-server hints failed: {}",
        last_error.unwrap_or_else(|| "no hints tried".into())
    ))))
}

async fn try_join_via(
    state: &AppState,
    user_id: &str,
    user_nid: u64,
    room_id: &RoomId,
    server: &str,
) -> Result<(), String> {
    debug!(%room_id, %user_id, %server, "starting remote join via");

    // --- 1. make_join ---
    let make_join_resp = state
        .federation_client
        .make_join(
            server,
            room_id.as_str(),
            user_id,
            &["6", "7", "8", "9", "10", "11", "12"],
        )
        .await
        .map_err(|e| format!("make_join failed: {e}"))?;

    let room_version = make_join_resp
        .get("room_version")
        .and_then(|v| v.as_str())
        .ok_or("make_join response missing room_version")?;
    let room_version_typed = RoomVersion::parse(room_version)
        .ok_or_else(|| format!("unsupported room_version {room_version} (vela: v6–v12)"))?;
    if !room_version_typed.at_least(state.config.minimum_room_version) {
        return Err(format!(
            "room_version {room_version} below operator minimum {}",
            state.config.minimum_room_version.as_str()
        ));
    }

    let mut template = make_join_resp
        .get("event")
        .and_then(|v| v.as_object())
        .cloned()
        .ok_or("make_join response missing event template")?;

    validate_template(&template, user_id, room_id.as_str())?;

    // The joining server is responsible for setting origin_server_ts and
    // origin. The remote's make_join template may omit them (per spec).
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

    // --- 2. Sign the template under the room's actual version (which
    // we just parsed from make_join's response). Mismatched version =
    // mismatched canonical bytes = peer rejects our signature.
    let (signed_event, event_id) = sign_unsigned_template(
        template,
        &state.signing_key,
        &state.config.server_name,
        room_version_typed,
    );

    // --- 3. send_join ---
    let send_join_resp = state
        .federation_client
        .send_join_v2(
            server,
            room_id.as_str(),
            event_id.as_str(),
            Value::Object(signed_event.clone()),
        )
        .await
        .map_err(|e| format!("send_join failed: {e}"))?;

    // --- 4. Bootstrap the room locally ---
    bootstrap_remote_room(
        state,
        user_id,
        user_nid,
        room_id,
        room_version,
        &signed_event,
        &event_id,
        &send_join_resp,
    )
    .await
    .map_err(|e| format!("bootstrap_remote_room failed: {e}"))?;

    Ok(())
}

/// Structural checks on the make_join template: spec-mandated fields present,
/// sender/state_key match the joining user, room_id matches.
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

    let state_key = template.state_key().ok_or("template missing state_key")?;
    if state_key != user_id {
        return Err(format!(
            "template state_key {state_key} doesn't match joining user {user_id}"
        ));
    }

    let sender = template.sender().ok_or("template missing sender")?;
    if sender != user_id {
        return Err(format!(
            "template sender {sender} doesn't match joining user {user_id}"
        ));
    }

    let tmpl_room = template.room_id().ok_or("template missing room_id")?;
    if tmpl_room != room_id {
        return Err(format!(
            "template room_id {tmpl_room} doesn't match requested {room_id}"
        ));
    }

    let membership = template
        .membership()
        .ok_or("template missing content.membership")?;
    if membership != "join" {
        return Err(format!(
            "template membership is {membership}, expected join"
        ));
    }

    Ok(())
}

/// Persist everything the send_join response delivered:
/// - `auth_chain` events → historical context (suppress_current_state=true).
/// - `state` events → our local current state for this room.
/// - the signed join event itself → becomes the room's sole forward extremity.
async fn bootstrap_remote_room(
    state: &AppState,
    user_id: &str,
    user_nid: u64,
    room_id: &RoomId,
    room_version: &str,
    signed_event: &Map<String, Value>,
    event_id: &EventId,
    send_join_resp: &Value,
) -> Result<(), String> {
    let room_nid = state
        .db
        .get_or_create_nid(room_id.as_str())
        .map_err(|e| format!("db: {e}"))?;

    // Room-level lock for the duration of bootstrap.
    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Room meta — idempotent.
    let _ = state
        .db
        .create_room_meta(room_nid, room_id.as_str(), room_version);

    // --- Auth chain (historical) ---
    // Outlier: events CF only — auth chain events are ancestors, never on
    // the live timeline, never current state. Sort by depth ascending so
    // ancestors are persisted before events that reference them; otherwise
    // `auth_nids` lookups silently drop edges when an event's ancestor
    // isn't yet in the DB.
    let auth_chain = send_join_resp
        .get("auth_chain")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let auth_chain_sorted = sort_by_depth(auth_chain);
    for ev in &auth_chain_sorted {
        if let Err(e) =
            persist_remote_event(state, room_nid, ev, vela_store::db::PersistKind::Outlier).await
        {
            debug!(error = %e, "auth_chain event skipped");
        }
    }

    // --- State (current) ---
    // StateBundleOnly: state events from send_join define current state for
    // the joining server but predate the join — they update room_state so
    // /sync's state field reflects them, but DON'T enter the timeline (no
    // stream_pos) and DON'T replace forward extremities. This is critical
    // for /messages: with stream_pos these state events would surface as
    // "events" the joining user can paginate through, blocking the
    // backfill DAG-walk from the join event back through real history.
    //
    // The join event itself is persisted next as Live and becomes the
    // post-join extremity.
    let state_events = send_join_resp
        .get("state")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let state_events_sorted = sort_by_depth(state_events);
    let mut state_nids: Vec<u64> = Vec::new();
    let mut memberships_to_set: Vec<(String, u8)> = Vec::new();
    for ev in &state_events_sorted {
        // Resolve the event's nid regardless of whether persist_remote_event
        // inserted it now or found it already persisted (auth_chain items
        // are persisted earlier and can overlap with state). Without this,
        // state_nids is a subset of the true state and later snapshots miss
        // key state events — e.g. the creator's m.room.member, yielding
        // "sender is not joined" rejections for any subsequent message PDU.
        let nid_result = persist_remote_event(
            state,
            room_nid,
            ev,
            vela_store::db::PersistKind::StateBundleOnly,
        )
        .await;
        let resolved_nid: Option<u64> = match nid_result {
            Ok(Some(nid)) => Some(nid),
            Ok(None) => {
                // Already known (typically from the auth_chain pass above).
                let parsed_version = RoomVersion::parse(room_version).unwrap_or(RoomVersion::V12);
                ev.as_object()
                    .map(|obj| {
                        vela_core::events::hash::compute_event_id_for_version(obj, parsed_version)
                            .as_str()
                            .to_string()
                    })
                    .and_then(|eid| state.db.get_event_nid_by_id(&eid).ok().flatten())
            }
            Err(e) => {
                debug!(error = %e, "state event skipped");
                None
            }
        };
        if let Some(nid) = resolved_nid {
            state_nids.push(nid);
            // Track membership state events so we can populate user_rooms.
            if let Some(obj) = ev.as_object()
                && obj.event_type() == Some("m.room.member")
            {
                let sk = obj.state_key().unwrap_or("");
                let membership = obj.membership().unwrap_or("");
                let b = match membership {
                    "join" => 1,
                    "invite" => 2,
                    "ban" => 3,
                    "knock" => 4,
                    _ => 0,
                };
                if !sk.is_empty() && b != 0 {
                    memberships_to_set.push((sk.to_string(), b));
                }
            }
        }
    }

    // Promote every bootstrapped state event into `room_state`. Events
    // shared between auth_chain and the state bundle are persisted on
    // the auth_chain pass with `suppress_current_state=true` (so they
    // DON'T land in room_state). The state-pass dedup then returns
    // Ok(None), skipping the room_state update. Without this explicit
    // promote step, current state on the joiner is incomplete (e.g.
    // creator's m.room.member missing), and any inbound message PDU
    // fails the check-6 current-state auth: "sender is not joined".
    for nid in &state_nids {
        let (header, _) = match state.db.get_event(*nid).ok().flatten() {
            Some(p) => p,
            None => continue,
        };
        let _ =
            state
                .db
                .set_room_state_entry(room_nid, header.type_nid, header.state_key_nid, *nid);
    }

    // Stamp every bootstrapped state event with the full state snapshot.
    // Without this, an inbound message PDU whose `prev_events` reference
    // one of these events resolves state-at-event to empty (no snapshot
    // -> no auth view -> "sender is not joined" rejection). State_res
    // would otherwise have to reconstruct the snapshot from the auth
    // chain on every message; precomputing once keeps the receive path
    // fast and reuses the resident server's already-resolved state.
    for nid in &state_nids {
        let _ = state.db.persist_state_snapshot(room_nid, *nid, &state_nids);
    }

    // --- Apply membership bookkeeping for existing members ---
    for (member_user_id, b) in memberships_to_set {
        let member_nid = state
            .db
            .get_or_create_nid(&member_user_id)
            .map_err(|e| format!("db: {e}"))?;
        let _ = state.db.set_membership(room_nid, member_nid, b);
    }

    // --- Persist our join event ---
    let join_event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(signed_event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| format!("db: {e}"))?;
    let sender_nid = state
        .db
        .get_or_create_nid(user_id)
        .map_err(|e| format!("db: {e}"))?;
    let skey_nid = state
        .db
        .get_or_create_nid(user_id)
        .map_err(|e| format!("db: {e}"))?;

    let join_pdu = Pdu::from_json(event_id.as_str().to_string(), signed_event)
        .ok_or("signed join event malformed")?;

    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &join_pdu.prev_events {
        match state.db.get_event_nid_by_id(pid) {
            Ok(Some(n)) => prev_nids.push(n),
            Ok(None) => {
                debug!(event_id = %event_id, prev_event = %pid, "outbound_join: prev_event unknown locally, dropped from event_edges")
            }
            Err(e) => {
                debug!(event_id = %event_id, prev_event = %pid, error = %e, "outbound_join: prev_event lookup error")
            }
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &join_pdu.auth_events {
        match state.db.get_event_nid_by_id(aid) {
            Ok(Some(n)) => auth_nids.push(n),
            Ok(None) => {
                debug!(event_id = %event_id, auth_event = %aid, "outbound_join: auth_event unknown locally, dropped from event_auth_edges")
            }
            Err(e) => {
                debug!(event_id = %event_id, auth_event = %aid, error = %e, "outbound_join: auth_event lookup error")
            }
        }
    }

    state
        .db
        .persist_event(
            join_event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            sender_nid,
            skey_nid,
            join_pdu.origin_server_ts,
            join_pdu.depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            true,  // is_state
            false, // suppress_current_state: this IS our entry into current state
        )
        .map_err(|e| format!("persist join: {e}"))?;

    // Replace any existing (m.room.member, user) in state_nids with our new one.
    let mut replaced_nid: Option<u64> = None;
    state_nids.retain(|existing| match state.db.get_event(*existing) {
        Ok(Some((h, _))) if h.type_nid == type_nid && h.state_key_nid == skey_nid => {
            replaced_nid = Some(*existing);
            false
        }
        _ => true,
    });
    state_nids.push(join_event_nid);
    state
        .db
        .persist_state_snapshot(room_nid, join_event_nid, &state_nids)
        .map_err(|e| format!("state snapshot: {e}"))?;
    if let Some(prev_nid) = replaced_nid {
        let _ = state.db.record_state_replaces(join_event_nid, prev_nid);
    }

    // Set our own membership.
    state
        .db
        .set_membership(room_nid, user_nid, 1)
        .map_err(|e| format!("set own membership: {e}"))?;
    crate::router::notify_user(state, user_nid);

    // Bump for client /sync ordering.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let _ = state.db.update_room_bump(room_nid, now, join_event_nid);

    // Notify local sync listeners if we have any.
    // Stream position for the join event = current stream_counter.
    if let Some(sender_ch) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender_ch.send(state.db.current_stream_position());
    }

    Ok(())
}

/// Persist a single event received in a send_join response. Validates
/// signature + hash; skips higher-level auth checks (the resident server
/// vouches for the chain). Returns the event_nid on success, or None if
/// the event is already known (idempotent).
async fn persist_remote_event(
    state: &AppState,
    room_nid: u64,
    event_json: &Value,
    kind: vela_store::db::PersistKind,
) -> Result<Option<u64>, String> {
    use vela_core::events::hash::{compute_content_hash, compute_event_id_for_version};

    let obj = event_json.as_object().ok_or("event is not an object")?;

    // Look up the room version FIRST: event_id derivation, sig verify
    // and content-hash all redact under the version-specific shape, so
    // we have to know the version before computing the canonical bytes.
    // send_join's state + auth_chain events were minted by the SENDER
    // under that room's version. Falling back to v12 when meta is
    // missing is fine: persist_remote_event is only called after
    // create_room_meta has been written for the joined room.
    let event_room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| format!("db room_version: {e}"))?;

    let event_id = compute_event_id_for_version(obj, event_room_version)
        .as_str()
        .to_string();

    if state
        .db
        .get_event_nid_by_id(&event_id)
        .map_err(|e| format!("db: {e}"))?
        .is_some()
    {
        return Ok(None);
    }

    let pdu = Pdu::from_json(event_id.clone(), obj).ok_or("malformed event")?;

    // Signature check against sender's domain.
    let sender_domain = pdu.sender_domain().ok_or("malformed sender")?.to_string();
    let keys = state
        .remote_keys
        .get_or_fetch(&sender_domain)
        .await
        .map_err(|e| format!("fetch keys {sender_domain}: {e}"))?;
    let sigs = obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(&sender_domain))
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("no signatures from {sender_domain}"))?;
    let mut verified = false;
    let mut tried = Vec::new();
    let mut outcomes: Vec<String> = Vec::new();
    for (key_id, _) in sigs {
        tried.push(key_id.clone());
        let Some(pub_b64) = keys.verify_keys.get(key_id) else {
            outcomes.push(format!("{key_id}=no-key"));
            continue;
        };
        let Ok(public_key) = vela_core::federation::keys::decode_public_key(pub_b64) else {
            outcomes.push(format!("{key_id}=bad-pub"));
            continue;
        };
        match vela_core::federation::keys::verify_event_signature(
            obj,
            &sender_domain,
            key_id,
            &public_key,
            event_room_version,
        ) {
            Ok(()) => {
                verified = true;
                break;
            }
            Err(e) => {
                outcomes.push(format!("{key_id}=verify-fail:{e:?}"));
            }
        }
    }
    if !verified {
        // Compute event type for triage — lets us see whether failures
        // cluster on a specific event type (e.g. all m.room.create).
        let etype = obj.event_type().unwrap_or("?");
        tracing::debug!(
            %event_id,
            %sender_domain,
            event_type = %etype,
            fetched_keys = ?keys.verify_keys.keys().collect::<Vec<_>>(),
            tried_sig_keys = ?tried,
            outcomes = ?outcomes,
            "signature verification failed — tried all keys"
        );
        return Err(format!("signature verification failed for {event_id}"));
    }

    // Hash check — on mismatch, redact.
    let declared = obj
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let computed = compute_content_hash(obj);
    let to_persist: Map<String, Value> = match declared {
        Some(d) if d == computed => obj.clone(),
        _ => vela_core::events::redact::redact_event_for_version(obj, event_room_version),
    };
    let pdu = Pdu::from_json(event_id.clone(), &to_persist).ok_or("malformed after hash check")?;

    let type_nid = state
        .db
        .get_or_create_nid(&pdu.event_type)
        .map_err(|e| format!("db: {e}"))?;
    let sender_nid = state
        .db
        .get_or_create_nid(&pdu.sender)
        .map_err(|e| format!("db: {e}"))?;
    let state_key_nid = if let Some(sk) = &pdu.state_key {
        state
            .db
            .get_or_create_nid(sk)
            .map_err(|e| format!("db: {e}"))?
    } else {
        0
    };

    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &pdu.prev_events {
        match state.db.get_event_nid_by_id(pid) {
            Ok(Some(n)) => prev_nids.push(n),
            Ok(None) => {
                debug!(event_id = %event_id, prev_event = %pid, "outbound_join state: prev_event unknown locally, dropped from event_edges")
            }
            Err(e) => {
                debug!(event_id = %event_id, prev_event = %pid, error = %e, "outbound_join state: prev_event lookup error")
            }
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &pdu.auth_events {
        match state.db.get_event_nid_by_id(aid) {
            Ok(Some(n)) => auth_nids.push(n),
            Ok(None) => {
                debug!(event_id = %event_id, auth_event = %aid, "outbound_join state: auth_event unknown locally, dropped from event_auth_edges")
            }
            Err(e) => {
                debug!(event_id = %event_id, auth_event = %aid, error = %e, "outbound_join state: auth_event lookup error")
            }
        }
    }

    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&to_persist);
    state
        .db
        .persist_event_kind(
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
            pdu.state_key.is_some(),
            kind,
        )
        .map_err(|e| format!("persist_event: {e}"))?;

    Ok(Some(event_nid))
}

// --- Room version suppression (compiler: RoomVersion is imported but unused
//     directly in this file — used via sign_unsigned_template internally).

#[allow(dead_code)]
fn _suppress_unused_room_version(_: RoomVersion, _: HashMap<u64, u64>) {}

/// Sort a batch of events by `depth` ascending so ancestors come first.
/// Events without a parsable depth sort to the front.
fn sort_by_depth(mut events: Vec<Value>) -> Vec<Value> {
    events.sort_by_key(|ev| {
        ev.as_object()
            .and_then(|o| o.get("depth"))
            .and_then(|d| d.as_u64())
            .unwrap_or(0)
    });
    events
}
