//! Outbound backfill: fetching historical events from federated peers.
//!
//! Trigger: client paginates backwards via `/messages dir=b`; if our local
//! slice is shorter than the requested `limit`, we hit `/backfill` on a
//! remote server that has the room's history and persist what they return
//! as historical context (`suppress_current_state=true`).
//!
//! Scope: single-server attempt, no retry, no clever edge detection. If the
//! pick fails, backfill returns zero events and the client sees whatever we
//! already had.

use std::collections::HashSet;

use serde_json::Value;
use tracing::{debug, warn};

use vela_core::canonical::canonical_json_object;
use vela_core::events::pdu::Pdu;

use crate::router::AppState;

/// Default federation-side limit per backfill call.
pub const BACKFILL_LIMIT: usize = 50;

/// Attempt to backfill up to `limit` events before the given `from_event_ids`
/// by asking any remote server in the room. Returns the number of events
/// persisted (possibly 0).
///
/// Failure modes (cache miss, network error, destination unreachable) are
/// all treated as "returned 0"; the caller's local query result is returned
/// to the client unchanged.
pub async fn attempt_backfill(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    from_event_ids: &[String],
    limit: usize,
) -> usize {
    if from_event_ids.is_empty() {
        return 0;
    }

    // Pick any remote server in the room. Union the partial-state
    // hint: after an `omit_members=true` send_join the memberships
    // CF is empty for the resident's users, so a pure
    // `get_remote_servers_in_room` returns no candidates and
    // /messages can't backfill history from the resident.
    let mut candidate_set: std::collections::BTreeSet<String> = match state
        .db
        .get_remote_servers_in_room(room_nid, &state.config.server_name)
    {
        Ok(c) => c.into_iter().collect(),
        Err(e) => {
            debug!(error = %e, "backfill: failed to list remote servers");
            return 0;
        }
    };
    if let Ok((true, hint)) = state.db.get_partial_state_info(room_nid) {
        for s in hint {
            if s != state.config.server_name {
                candidate_set.insert(s);
            }
        }
    }
    if candidate_set.is_empty() {
        // Local-only room — nothing to backfill.
        return 0;
    }
    let candidates: Vec<String> = candidate_set.into_iter().collect();

    let ev_ids: Vec<&str> = from_event_ids.iter().map(|s| s.as_str()).collect();

    for server in &candidates {
        match state
            .federation_client
            .backfill(server, room_id, &ev_ids, limit)
            .await
        {
            Ok(resp) => {
                let pdus = resp
                    .get("pdus")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if pdus.is_empty() {
                    debug!(%server, "backfill returned zero events");
                    continue;
                }
                let accepted = persist_backfilled(state, room_nid, &pdus).await;
                debug!(%server, returned = pdus.len(), %accepted, "backfill persisted");
                return accepted;
            }
            Err(e) => {
                warn!(%server, error = %e, "backfill call failed, trying next server");
            }
        }
    }

    0
}

/// Persist backfilled events. Signature + hash checked; auth rules skipped
/// (they're historical context, same rationale as fetched auth events).
/// Sorts the batch by `depth` ascending so ancestors are persisted before
/// descendants — without this, `auth_nids`/`prev_nids` resolution in
/// `persist_event` silently drops edges when referenced events aren't yet in
/// the DB.
///
/// Returns the count actually persisted.
async fn persist_backfilled(state: &AppState, room_nid: u64, pdus: &[Value]) -> usize {
    let mut sorted: Vec<Value> = pdus.to_vec();
    sorted.sort_by_key(|ev| {
        ev.as_object()
            .and_then(|o| o.get("depth"))
            .and_then(|d| d.as_u64())
            .unwrap_or(0)
    });

    let mut accepted = 0usize;
    for ev_json in &sorted {
        match persist_one(state, room_nid, ev_json).await {
            Ok(true) => accepted += 1,
            Ok(false) => {} // already known
            Err(e) => debug!(error = %e, "backfill event skipped"),
        }
    }
    accepted
}

async fn persist_one(state: &AppState, room_nid: u64, event_json: &Value) -> Result<bool, String> {
    use vela_core::events::hash::{compute_content_hash, compute_event_id_for_version};

    let obj = event_json
        .as_object()
        .ok_or_else(|| "event is not an object".to_string())?;

    let event_room_version = state
        .db
        .get_room_version_typed(room_nid)
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);
    let event_id = compute_event_id_for_version(obj, event_room_version)
        .as_str()
        .to_string();

    if state
        .db
        .get_event_nid_by_id(&event_id)
        .map_err(|e| format!("db: {e}"))?
        .is_some()
    {
        return Ok(false);
    }

    let pdu = Pdu::from_json(event_id.clone(), obj).ok_or_else(|| "malformed".to_string())?;

    let sender_domain = pdu
        .sender_domain()
        .ok_or_else(|| "malformed sender".to_string())?
        .to_string();

    let keys = state
        .remote_keys
        .get_or_fetch(&sender_domain)
        .await
        .map_err(|e| format!("fetch keys: {e}"))?;
    let sigs = obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(&sender_domain))
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("no signatures from {sender_domain}"))?;
    // Match the room's redaction shape so canonical bytes line up
    // with the sender's signature (pre-v11 rooms strip create.creator
    // differently; mismatched shapes mean every sig verify fails).
    let event_room_version = state
        .db
        .get_room_version_typed(room_nid)
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);

    let mut verified = false;
    for (key_id, _) in sigs {
        let Some(pub_b64) = keys.verify_keys.get(key_id) else {
            continue;
        };
        let Ok(public_key) = vela_core::federation::keys::decode_public_key(pub_b64) else {
            continue;
        };
        if vela_core::federation::keys::verify_event_signature(
            obj,
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
        return Err(format!("signature verify failed for {event_id}"));
    }

    let declared = obj
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let computed = compute_content_hash(obj);
    let to_persist = match declared {
        Some(d) if d == computed => obj.clone(),
        _ => vela_core::events::redact::redact_event_for_version(obj, event_room_version),
    };
    let pdu = Pdu::from_json(event_id.clone(), &to_persist)
        .ok_or_else(|| "malformed after hash check".to_string())?;

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
                debug!(%event_id, prev_event = %pid, "backfill: prev_event unknown locally, dropping from event_edges")
            }
            Err(e) => {
                debug!(%event_id, prev_event = %pid, error = %e, "backfill: prev_event lookup error")
            }
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &pdu.auth_events {
        match state.db.get_event_nid_by_id(aid) {
            Ok(Some(n)) => auth_nids.push(n),
            Ok(None) => {
                debug!(%event_id, auth_event = %aid, "backfill: auth_event unknown locally, dropping from event_auth_edges")
            }
            Err(e) => {
                debug!(%event_id, auth_event = %aid, error = %e, "backfill: auth_event lookup error")
            }
        }
    }

    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&to_persist);

    // BackfillTimeline: events get a stream_pos so /messages can return
    // them (TestJumpToDateEndpoint paginate sub-test calls /messages
    // without a `from` token after /context, expecting backfilled
    // alice events to surface; outliers without stream_pos miss that
    // path). They're still excluded from current room_state and from
    // forward extremities so they don't disrupt live state.
    let stream_pos = state
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
            vela_store::db::PersistKind::BackfillTimeline,
        )
        .map_err(|e| format!("persist_event: {e}"))?;

    // Index m.relates_to so the parent's count + participants reflect
    // backfilled children. Recency update is suppressed — historical
    // replies must not become the "latest activity" in /threads.
    if let Some(rel) = pdu.content.get("m.relates_to")
        && let Some(parent_event_id) = rel.get("event_id").and_then(|v| v.as_str())
        && let Some(rel_type) = rel.get("rel_type").and_then(|v| v.as_str())
        && let Ok(Some(parent_nid)) = state.db.get_event_nid_by_id(parent_event_id)
        && let Ok(rel_type_nid) = state.db.get_or_create_nid(rel_type)
        && let Err(e) = state.db.record_relation(
            parent_nid,
            stream_pos,
            event_nid,
            rel_type_nid,
            type_nid,
            room_nid,
            sender_nid,
            rel_type == "m.thread",
            false,
        )
    {
        debug!(%event_id, error = %e, "backfill: failed to record relation");
    }

    // Silence unused warning; HashSet is imported for potential future use.
    let _: Option<HashSet<String>> = None;

    Ok(true)
}
