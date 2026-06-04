//! Inbound EDU dispatch.
//!
//! Called once per EDU in a federation transaction's `edus` array.
//! Routes by `edu_type` to the matching local handler, which writes to
//! local state (so our users see the effect via `/sync`) but MUST NOT
//! re-broadcast — the sending server is responsible for fanning out
//! their own users' EDUs.
//!
//! Origin-domain validation: per the server-server spec ("Receiving
//! servers should verify that the user is in the room, and is a user
//! belonging to the sending server"), each EDU is checked against the
//! verified X-Matrix origin. EDUs about users from a different domain
//! are dropped.

use serde_json::Value;
use tracing::{debug, warn};

use crate::router::AppState;

pub async fn dispatch_edu(state: &AppState, origin: &str, edu: &Value) {
    let Some(edu_type) = edu.get("edu_type").and_then(|v| v.as_str()) else {
        debug!("EDU missing edu_type, dropping");
        return;
    };

    let Some(content) = edu.get("content") else {
        debug!(%edu_type, "EDU missing content, dropping");
        return;
    };

    match edu_type {
        "m.receipt" => handle_receipt(state, origin, content).await,
        "m.presence" => handle_presence(state, origin, content).await,
        "m.typing" => handle_typing(state, origin, content).await,
        "m.direct_to_device" => handle_direct_to_device(state, origin, content).await,
        "m.device_list_update" => handle_device_list_update(state, origin, content).await,
        "m.signing_key_update" => handle_signing_key_update(state, origin, content).await,
        // Unknown types are accepted silently per spec.
        _ => debug!(%edu_type, "EDU type not handled (silently accepted)"),
    }
}

/// `m.device_list_update` EDU.
///
/// Per spec, when a remote user's device list changes we should
/// invalidate any cached device keys for them and notify our local
/// users sharing a room so their `/sync` `device_lists.changed` array
/// surfaces the change. Clients then refetch via `/keys/query`.
///
/// We don't ingest the `keys` field directly into our device_keys CF —
/// the spec recommends refetch-on-demand via `/keys/query` because
/// EDU loss leads to gaps and refetch is the canonical reconciliation
/// path. We just mark "this user changed at this stream position" so
/// /sync surfaces the change.
async fn handle_device_list_update(state: &AppState, origin: &str, content: &Value) {
    let Some(obj) = content.as_object() else {
        return;
    };
    let Some(user_id) = obj.get("user_id").and_then(|v| v.as_str()) else {
        return;
    };
    if !user_belongs_to_origin(user_id, origin) {
        debug!(%origin, %user_id, "dropping m.device_list_update: user not from sending server");
        return;
    }

    let user_nid = match state.db.get_or_create_nid(user_id) {
        Ok(n) => n,
        Err(e) => {
            warn!(%user_id, error = %e, "nid alloc failed for inbound device_list_update");
            return;
        }
    };

    // Drop redeliveries of an already-applied stream_id. Same EDU
    // arriving twice (peer restart, retry) writes a fresh
    // device_key_changes entry at a new stream_pos — which leaks the
    // change into a later /sync window for the observer. We treat
    // missing stream_id as 0 so two zero-stream_id EDUs collapse.
    if let Some(device_id) = obj.get("device_id").and_then(|v| v.as_str()) {
        let sid = obj.get("stream_id").and_then(|v| v.as_u64()).unwrap_or(0);
        match state.db.device_list_edu_advance(user_nid, device_id, sid) {
            Ok(true) => {}
            Ok(false) => {
                debug!(%user_id, %device_id, stream_id = sid, "dropping redelivered m.device_list_update");
                return;
            }
            Err(e) => warn!(error = %e, "device_list_edu_advance failed; continuing"),
        }
    }

    // Drop any cached /user/keys/query response for this user — the
    // EDU is itself the "your cache is stale" signal regardless of
    // whether the EDU carries device keys or not. Without this the
    // C2S /keys/query short-circuit in `query_keys` keeps returning
    // the pre-update keys until a membership change or restart wipes
    // the cache.
    if let Err(e) = state.db.invalidate_remote_user_keys_cache(user_nid) {
        warn!(error = %e, "invalidate_remote_user_keys_cache failed; continuing");
    }

    // Find local users sharing a room with the changed user. They
    // need to learn that the remote user's device list moved.
    let remote_user_rooms = match state.db.get_user_joined_rooms(user_nid) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut observer_nids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for room_nid in remote_user_rooms {
        let members = match state.db.get_room_members(room_nid) {
            Ok(m) => m,
            Err(_) => continue,
        };
        for m in members {
            // Filter to users on OUR server only.
            if let Ok(Some(uid)) = state.db.resolve_nid(m)
                && uid
                    .split_once(':')
                    .map(|(_, d)| d == state.config.server_name)
                    .unwrap_or(false)
            {
                observer_nids.insert(m);
            }
        }
    }

    if observer_nids.is_empty() {
        // No local observers means the user's `memberships` row hasn't
        // been set yet (typically because the partial-state bundle
        // omitted them). Buffer the EDU so the filler's post-clear
        // reconcile can re-surface the change once the user becomes
        // observable. CanReceiveDeviceListUpdateDuringPartialStateJoin
        // and Device_list_tracking_for_pre-existing_members_in_partial_
        // state_room both rely on this replay path.
        if let Err(e) = state.db.mark_pending_partial_device_list_edu(user_nid) {
            warn!(error = %e, %user_id, "mark_pending_partial_device_list_edu failed");
        }
        return;
    }

    let stream_pos = state.db.next_stream_position();
    let _stream_guard = vela_store::db::StreamApplyOnDrop::new(&state.db, stream_pos.as_u64());
    let observer_vec: Vec<u64> = observer_nids.iter().copied().collect();
    if let Err(e) = state
        .db
        .notify_device_key_change(user_nid, &observer_vec, stream_pos.as_u64())
    {
        warn!(error = %e, "notify_device_key_change (inbound device_list_update) failed");
        return;
    }
    // Wake observers' /sync long-polls so they pick up the change
    // without waiting for the 30s timeout.
    for &observer_nid in &observer_nids {
        crate::router::notify_user(state, observer_nid);
    }
}

/// `m.signing_key_update` EDU.
///
/// Per spec, sent when a remote user's cross-signing keys change.
/// Content shape:
/// ```json
/// {
///   "user_id":          "@alice:example.com",
///   "master_key":       { ... },
///   "self_signing_key": { ... }
/// }
/// ```
///
/// We persist the keys via `set_cross_signing_keys` so subsequent
/// `/keys/query` calls return the fresh values directly. Same
/// observer-notification flow as `m.device_list_update` so local
/// users sharing a room with the remote see the change in
/// `device_lists.changed` and re-query.
async fn handle_signing_key_update(state: &AppState, origin: &str, content: &Value) {
    let Some(obj) = content.as_object() else {
        return;
    };
    let Some(user_id) = obj.get("user_id").and_then(|v| v.as_str()) else {
        return;
    };
    if !user_belongs_to_origin(user_id, origin) {
        debug!(%origin, %user_id, "dropping m.signing_key_update: user not from sending server");
        return;
    }

    let user_nid = match state.db.get_or_create_nid(user_id) {
        Ok(n) => n,
        Err(e) => {
            warn!(%user_id, error = %e, "nid alloc failed for inbound signing_key_update");
            return;
        }
    };

    if let Some(master) = obj.get("master_key").filter(|v| !v.is_null())
        && let Err(e) = state
            .db
            .set_cross_signing_keys(user_nid, "master_key", master)
    {
        warn!(error = %e, "set_cross_signing_keys (master) failed");
    }
    if let Some(sk) = obj.get("self_signing_key").filter(|v| !v.is_null())
        && let Err(e) = state
            .db
            .set_cross_signing_keys(user_nid, "self_signing_key", sk)
    {
        warn!(error = %e, "set_cross_signing_keys (self_signing) failed");
    }

    // Same observer notification path as device_list_update — local
    // users sharing a room get the user surfaced in their
    // device_lists.changed so clients re-query.
    let remote_user_rooms = match state.db.get_user_joined_rooms(user_nid) {
        Ok(r) => r,
        Err(_) => return,
    };
    let mut observer_nids: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for room_nid in remote_user_rooms {
        let members = match state.db.get_room_members(room_nid) {
            Ok(m) => m,
            Err(_) => continue,
        };
        for m in members {
            if let Ok(Some(uid)) = state.db.resolve_nid(m)
                && uid
                    .split_once(':')
                    .map(|(_, d)| d == state.config.server_name)
                    .unwrap_or(false)
            {
                observer_nids.insert(m);
            }
        }
    }
    if observer_nids.is_empty() {
        return;
    }
    let stream_pos = state.db.next_stream_position();
    let _stream_guard = vela_store::db::StreamApplyOnDrop::new(&state.db, stream_pos.as_u64());
    let observer_vec: Vec<u64> = observer_nids.iter().copied().collect();
    if let Err(e) = state
        .db
        .notify_device_key_change(user_nid, &observer_vec, stream_pos.as_u64())
    {
        warn!(error = %e, "notify_device_key_change (inbound signing_key_update) failed");
        return;
    }
    for &observer_nid in &observer_nids {
        crate::router::notify_user(state, observer_nid);
    }
}

/// `m.direct_to_device` EDU.
///
/// Content shape:
/// ```json
/// {
///   "sender":     "@alice:hs1",
///   "type":       "m.room_key_request",
///   "message_id": "<unique>",
///   "messages":   {
///     "@bob:hs2": { "DEVICE_ID": <event content>, "*": <event content> }
///   }
/// }
/// ```
///
/// Per spec receivers MUST dedupe on `(origin, message_id)` because
/// the sender retries verbatim on transient failures. We persist
/// each new message via the local to-device queue so the recipient's
/// `/sync` picks it up; duplicates are dropped silently.
async fn handle_direct_to_device(state: &AppState, origin: &str, content: &Value) {
    let Some(obj) = content.as_object() else {
        return;
    };
    let Some(sender) = obj.get("sender").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(event_type) = obj.get("type").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(message_id) = obj.get("message_id").and_then(|v| v.as_str()) else {
        debug!(%origin, "m.direct_to_device missing message_id, dropping");
        return;
    };

    // Origin-domain validation: the sender must belong to the
    // sending server. Otherwise a peer could spoof messages from
    // arbitrary user_ids.
    if !user_belongs_to_origin(sender, origin) {
        debug!(%origin, %sender, "dropping m.direct_to_device: sender not from origin");
        return;
    }

    // Spec-mandated dedup. Idempotency key is (origin, message_id) —
    // the sender chooses message_id and may retry verbatim. Returns
    // true if already seen.
    match state
        .db
        .check_and_record_to_device_message_id(origin, message_id)
    {
        Ok(true) => {
            debug!(%origin, %message_id, "m.direct_to_device duplicate, dropping");
            return;
        }
        Ok(false) => {}
        Err(e) => {
            warn!(error = %e, "to-device dedup check failed");
            // Treat as not-seen and proceed; worst case is a duplicate
            // delivery, which the recipient client also handles.
        }
    }

    let Some(messages) = obj.get("messages").and_then(|v| v.as_object()) else {
        return;
    };

    for (target_user_id, per_device) in messages {
        let Some(per_device) = per_device.as_object() else {
            continue;
        };
        // Recipients are users on OUR server (peers should only
        // address their EDUs to our users). Drop entries for users
        // whose domain isn't ours.
        if !target_belongs_to_us(target_user_id, &state.config.server_name) {
            debug!(%target_user_id, "dropping to-device entry: not our user");
            continue;
        }
        let target_user_nid = match state.db.get_or_create_nid(target_user_id) {
            Ok(n) => n,
            Err(e) => {
                warn!(%target_user_id, error = %e, "nid alloc failed (inbound to-device)");
                continue;
            }
        };

        for (device_id, msg_content) in per_device {
            // Wildcard fan-out: send to all of the user's registered
            // devices. `list_devices` (the registration index) is the
            // right surface here, NOT `get_all_device_keys` — a freshly
            // logged-in client has a `devices` entry but won't have
            // uploaded E2EE keys yet, and dropping that case loses
            // legitimate non-encrypted to-device traffic (m.room_key_
            // request retries, MSC3902 test EDUs, etc.).
            if device_id == "*" {
                if let Ok(devices) = state.db.list_devices(target_user_nid) {
                    for dev in &devices {
                        let Some(did) = dev.get("device_id").and_then(|v| v.as_str()) else {
                            continue;
                        };
                        let _ = state.db.queue_to_device(
                            target_user_nid,
                            did,
                            event_type,
                            sender,
                            msg_content,
                        );
                    }
                }
            } else if let Err(e) = state.db.queue_to_device(
                target_user_nid,
                device_id,
                event_type,
                sender,
                msg_content,
            ) {
                warn!(error = %e, "queue_to_device (inbound) failed");
            }
        }
    }
}

fn target_belongs_to_us(user_id: &str, our_server: &str) -> bool {
    user_id
        .split_once(':')
        .map(|(_, d)| d == our_server)
        .unwrap_or(false)
}

/// `m.receipt` EDU.
///
/// Content shape per spec:
/// ```json
/// {
///   "<room_id>": {
///     "<receipt_type>": {
///       "<user_id>": { "event_ids": ["$..."], "data": { "ts": ... } }
///     }
///   }
/// }
/// ```
///
/// We update each entry into our local `receipts` CF — and ONLY into
/// `receipts` (not `receipts_stream`) because the sending server has
/// already federated this; we are the receiver, not the source.
async fn handle_receipt(state: &AppState, origin: &str, content: &Value) {
    let Some(rooms) = content.as_object() else {
        return;
    };

    for (room_id, types_map) in rooms {
        let Some(types) = types_map.as_object() else {
            continue;
        };
        let Ok(Some(room_nid)) = state.db.get_nid(room_id) else {
            // Room unknown to us — silently skip. Could happen for
            // rooms we've left or never knew.
            continue;
        };

        // Per-room m.room.server_acl applies to receipts. A peer
        // banned from a room must not be able to advance our local
        // users' read-marker views via a federated receipt.
        if let Some(reason) =
            crate::federation::server_acl::check_server_acl(state, room_nid, origin)
        {
            debug!(%origin, %room_id, %reason, "dropping m.receipt: server_acl deny");
            continue;
        }

        for (receipt_type, users_map) in types {
            // Spec carves out `m.read.private` as a per-user-per-server
            // marker that MUST NOT be federated. If we received one,
            // the sender is buggy or malicious — drop.
            if receipt_type == "m.read.private" {
                warn!(
                    %origin,
                    %room_id,
                    "ignoring m.read.private EDU — must not be federated"
                );
                continue;
            }

            let Some(users) = users_map.as_object() else {
                continue;
            };

            for (user_id, payload) in users {
                // Origin-domain validation: peers may only send
                // receipts about users from their own domain.
                if !user_belongs_to_origin(user_id, origin) {
                    debug!(
                        %origin,
                        %user_id,
                        "dropping m.receipt entry: user not from sending server"
                    );
                    continue;
                }

                let Some(data) = payload.as_object() else {
                    continue;
                };
                let event_ids = data
                    .get("event_ids")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let ts = data
                    .get("data")
                    .and_then(|d| d.get("ts"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                // MSC4102: inbound m.receipt EDUs from federation may carry
                // a `thread_id` under `data` to scope the receipt to a
                // thread (or "main"). Pass it through to storage so /sync
                // surfaces the threaded receipt for local users in the
                // same room.
                let thread_id = data
                    .get("data")
                    .and_then(|d| d.get("thread_id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let user_nid = match state.db.get_or_create_nid(user_id) {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(%user_id, error = %e, "nid alloc failed for inbound receipt");
                        continue;
                    }
                };

                for event_id in event_ids.iter().filter_map(|v| v.as_str()) {
                    if let Err(e) = state.db.set_receipt(
                        room_nid,
                        receipt_type,
                        user_nid,
                        event_id,
                        ts,
                        thread_id.as_deref(),
                    ) {
                        warn!(error = %e, "set_receipt (inbound) failed");
                    }
                }
            }
        }
        // Wake local /sync long-polls so members in this room see the
        // remote user's read marker move immediately. Without this the
        // m.receipt EDU is invisible to local clients until the 30s
        // long-poll fires. Matches the local-receipt wake in
        // sync/receipts.rs::post_receipt and the inbound-typing wake
        // above in handle_typing.
        if let Some(sender) = state
            .room_senders
            .get(&vela_core::identifiers::Nid(room_nid))
        {
            let _ = sender.send(state.db.current_stream_position());
        }
    }
}

/// `m.presence` EDU.
///
/// Content shape per spec:
/// ```json
/// {
///   "push": [
///     { "user_id": "...", "presence": "online", "last_active_ago": 0,
///       "currently_active": true, "status_msg": "..." }
///   ]
/// }
/// ```
///
/// We record the latest state per user against `user_presence` (so our
/// `/sync` and `/presence/.../status` reads see it). `last_active_ms`
/// is reconstructed as `now - last_active_ago` because we store
/// absolute timestamps but the wire format is relative.
async fn handle_presence(state: &AppState, origin: &str, content: &Value) {
    let Some(push) = content.get("push").and_then(|v| v.as_array()) else {
        return;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    for entry in push {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let Some(user_id) = obj.get("user_id").and_then(|v| v.as_str()) else {
            continue;
        };
        if !user_belongs_to_origin(user_id, origin) {
            debug!(
                %origin,
                %user_id,
                "dropping m.presence entry: user not from sending server"
            );
            continue;
        }
        let presence = obj
            .get("presence")
            .and_then(|v| v.as_str())
            .unwrap_or("offline");
        let last_active_ago = obj
            .get("last_active_ago")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let last_active_ms = now.saturating_sub(last_active_ago);

        let mut rec = serde_json::Map::new();
        rec.insert("presence".into(), serde_json::json!(presence));
        rec.insert("last_active_ms".into(), serde_json::json!(last_active_ms));
        if let Some(msg) = obj.get("status_msg").and_then(|v| v.as_str())
            && !msg.is_empty()
        {
            rec.insert("status_msg".into(), serde_json::json!(msg));
        }

        let user_nid = match state.db.get_or_create_nid(user_id) {
            Ok(n) => n,
            Err(e) => {
                warn!(%user_id, error = %e, "nid alloc failed for inbound presence");
                continue;
            }
        };
        if let Err(e) = state.db.set_presence(user_nid, &Value::Object(rec)) {
            warn!(error = %e, "set_presence (inbound) failed");
        }
    }
}

/// `m.typing` EDU.
///
/// Content shape per the s2s spec:
/// `{ "room_id": "!...", "user_id": "@...", "typing": true|false }`.
///
/// We update the local `typing_state` ring so our `/sync` clients see
/// the remote user typing alongside local typers. No persistence —
/// typing has 30s TTL, matching the spec's "non-persistent" framing
/// and our local handler's storage choice (DashMap, not RocksDB).
///
/// 30s expiry: the s2s spec doesn't carry a `timeout` field on EDUs
/// (clients pick it for their own server's local state). We default
/// to 30 seconds, the upper end of the c2s spec's recommended client
/// re-PUT cadence — long enough that brief network hiccups don't
/// flap the state, short enough that a missed "stopped" EDU clears
/// quickly.
async fn handle_typing(state: &AppState, origin: &str, content: &Value) {
    let Some(obj) = content.as_object() else {
        return;
    };
    let Some(room_id) = obj.get("room_id").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(user_id) = obj.get("user_id").and_then(|v| v.as_str()) else {
        return;
    };
    let typing = obj.get("typing").and_then(|v| v.as_bool()).unwrap_or(false);

    if !user_belongs_to_origin(user_id, origin) {
        debug!(%origin, %user_id, "dropping m.typing: user not from sending server");
        return;
    }

    let Ok(Some(room_nid)) = state.db.get_nid(room_id) else {
        return;
    };

    // server_acl gate: a peer banned from the room must not be able
    // to surface typing indicators on our local /sync.
    if let Some(reason) = crate::federation::server_acl::check_server_acl(state, room_nid, origin) {
        debug!(%origin, %room_id, %reason, "dropping m.typing: server_acl deny");
        return;
    }
    let user_nid = match state.db.get_or_create_nid(user_id) {
        Ok(n) => n,
        Err(e) => {
            warn!(%user_id, error = %e, "nid alloc failed for inbound typing");
            return;
        }
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    const REMOTE_TYPING_TTL_MS: u64 = 30_000;

    let was_typing;
    {
        let mut entry = state.typing_state.entry(room_nid).or_default();
        let typers = entry.value_mut();
        was_typing = typers
            .iter()
            .any(|(uid, exp)| *uid == user_nid && *exp > now_ms);
        typers.retain(|(uid, exp)| *uid != user_nid && *exp > now_ms);
        if typing {
            typers.push((user_nid, now_ms + REMOTE_TYPING_TTL_MS));
        }
    }

    // Same wake-up + transition-position bump as the local /typing
    // handler. Without these, remote-originated typing is invisible
    // to local /sync clients: the long-poll never wakes, and the
    // EDU emit gate (since < typing_change_pos) never trips.
    if was_typing != typing {
        let pos = state.db.next_stream_position().as_u64();
        let _stream_guard = vela_store::db::StreamApplyOnDrop::new(&state.db, pos);
        state.typing_change_pos.insert(room_nid, pos);
        if let Some(sender) = state
            .room_senders
            .get(&vela_core::identifiers::Nid(room_nid))
        {
            let _ = sender.send(pos);
        }
    }
}

/// Verify the user_id's domain matches the sending server.
///
/// `user_id` shape: `@localpart:domain`. We compare the part after
/// the first `:` against `origin` (case-sensitive, per Matrix's
/// canonical-server-name rules).
fn user_belongs_to_origin(user_id: &str, origin: &str) -> bool {
    let Some(idx) = user_id.find(':') else {
        return false;
    };
    let domain = &user_id[idx + 1..];
    domain == origin
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_domain_match() {
        assert!(user_belongs_to_origin(
            "@alice:peer.example",
            "peer.example"
        ));
        assert!(!user_belongs_to_origin(
            "@alice:peer.example",
            "evil.example"
        ));
        assert!(!user_belongs_to_origin("@alice:peer.example", "peer"));
        // Malformed user_id: no colon.
        assert!(!user_belongs_to_origin("alice", "peer.example"));
    }
}
