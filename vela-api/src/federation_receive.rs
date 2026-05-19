//! PDU receive pipeline for `PUT /_matrix/federation/v1/send/{txnId}`.
//!
//! Implements the 6 checks from `server-server-api.md:456-479`:
//! 1. Format — valid event per room version (we support v12 only).
//! 2. Signatures — verify the sender's server signature over the redacted event.
//! 3. Hashes — recompute content hash; on mismatch, substitute the redacted form.
//! 4. Auth rules against the event's `auth_events`.
//! 5. Auth rules against state-at-event (resolved from prev_events' snapshots).
//! 6. Auth rules against current room state — soft-fail if this alone fails.
//!
//! Checks 4–6 reuse `vela_core::auth_rules::check_auth` — the same engine that
//! gates local writes, ensuring local and federated events are validated against
//! identical rules.

use std::collections::HashMap;

use serde_json::{Map, Value};
use tracing::{debug, error, warn};

use vela_core::auth_rules::{AuthError, check_auth};
use vela_core::canonical::canonical_json_object;
use vela_core::events::hash::compute_content_hash;
use vela_core::events::pdu::Pdu;
use vela_core::federation::keys::{decode_public_key, verify_event_signature};
use vela_core::identifiers::Nid;
use vela_core::state_res::{self, StateMap};

use crate::router::AppState;

/// Constants from spec §Transactions.
pub const MAX_PDUS_PER_TRANSACTION: usize = 50;
#[allow(dead_code)] // EDU handling is 3b
pub const MAX_EDUS_PER_TRANSACTION: usize = 100;

/// Maximum events we'll fetch from the origin to fill gaps for a single
/// incoming PDU. Guards against DoS via deeply-chained missing dependencies.
pub const MAX_MISSING_FETCH_PER_PDU: usize = 100;

/// Outcome of processing a single PDU. Maps to the per-PDU response entry.
#[derive(Debug)]
pub enum PduOutcome {
    /// Accepted and persisted. Response: `{}`.
    Accepted,
    /// Accepted but soft-failed (check 6 failed). Response: `{}`.
    /// Soft-failed PDUs get a successful response entry per spec — they're
    /// stored, they're just not relayed to clients and don't become extremities.
    SoftFailed,
    /// Rejected. Response: `{"error": "<reason>"}`.
    Rejected(String),
}

impl PduOutcome {
    pub fn to_json(&self) -> Value {
        match self {
            PduOutcome::Accepted | PduOutcome::SoftFailed => serde_json::json!({}),
            PduOutcome::Rejected(reason) => serde_json::json!({ "error": reason }),
        }
    }
}

/// Process one PDU through the 6-check pipeline. Returns the outcome to
/// report back to the sender.
///
/// On Accepted / SoftFailed the event has been persisted. On Rejected it has not.
pub async fn process_pdu(state: &AppState, pdu_json: &Value) -> (String, PduOutcome) {
    // --- Check 1: format ---
    let obj = match pdu_json.as_object() {
        Some(o) => o,
        None => {
            return (
                "unknown".into(),
                PduOutcome::Rejected("PDU is not a JSON object".into()),
            );
        }
    };

    // v3+ event format derives event_ids from the reference hash. The
    // hash is version-aware (different redaction shapes produce
    // different bytes), so we have to know the room version before
    // computing event_id. Look up via room_id (which is in the event
    // JSON) → room_nid → meta. Falls back to v12 if the room is
    // unknown locally — that's harmless: we'll re-evaluate per-event
    // once the room is bootstrapped.
    let room_version_for_event_id = obj
        .get("room_id")
        .and_then(|v| v.as_str())
        .and_then(|rid| state.db.get_nid(rid).ok().flatten())
        .and_then(|nid| state.db.get_room_version_typed(nid).ok())
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);
    let tentative_event_id =
        vela_core::events::hash::compute_event_id_for_version(obj, room_version_for_event_id)
            .as_str()
            .to_string();

    let pdu = match Pdu::from_json(tentative_event_id.clone(), obj) {
        Some(p) => p,
        None => {
            return (
                tentative_event_id,
                PduOutcome::Rejected("PDU missing required fields".into()),
            );
        }
    };

    // Sprint 3a does not process m.room.create events via /send. A room's
    // create event is normally seen via send_join (Sprint 3b) when we join a
    // remote room; receiving one as a free-floating transaction PDU is out of
    // scope. Reject with a clear message so operators can tell this apart
    // from a genuinely malformed event.
    if pdu.event_type == "m.room.create" {
        return (
            pdu.event_id,
            PduOutcome::Rejected(
                "m.room.create is not acceptable via /_matrix/federation/v1/send in 3a".into(),
            ),
        );
    }

    // v12 requires room_id on all non-create events.
    if pdu.room_id.is_empty() {
        return (
            pdu.event_id,
            PduOutcome::Rejected("PDU missing room_id".into()),
        );
    }

    // Idempotency: ignore PDUs we already accepted. The /send fan-out
    // (federation_sender::broadcast) re-echoes accepted events to
    // every remote in the room, including the origin server, so a
    // peer's transaction can come back at us under a different
    // round-trip. Re-persisting would clobber event_ids → nid and
    // re-fire device-list/membership side effects.
    if let Ok(Some(_)) = state.db.get_event_nid_by_id(&pdu.event_id) {
        return (pdu.event_id, PduOutcome::Accepted);
    }

    // Spec limits on array sizes.
    if pdu.auth_events.len() > 10 {
        return (
            pdu.event_id,
            PduOutcome::Rejected("too many auth_events".into()),
        );
    }
    if pdu.prev_events.len() > 20 {
        return (
            pdu.event_id,
            PduOutcome::Rejected("too many prev_events".into()),
        );
    }

    // Room must be known locally. Sprint 3a only accepts PDUs for rooms we're in.
    let room_nid = match state.db.get_nid(&pdu.room_id) {
        Ok(Some(n)) => n,
        Ok(None) => {
            return (pdu.event_id, PduOutcome::Rejected("unknown room".into()));
        }
        Err(e) => {
            // Log the actual error operator-side; don't leak DB internals
            // to the federating peer.
            error!(event_id = %pdu.event_id, error = %e, "db error resolving room_id");
            return (pdu.event_id, PduOutcome::Rejected("internal error".into()));
        }
    };

    // --- Check 2: signatures ---
    let sender_domain = match pdu.sender_domain() {
        Some(d) => d.to_string(),
        None => {
            return (
                pdu.event_id,
                PduOutcome::Rejected("malformed sender".into()),
            );
        }
    };

    // m.room.server_acl gate: reject events from servers the room owner has
    // banned. The ACL state event itself is exempt — otherwise a server could
    // be locked out of fixing its own ACL. See server-server spec §"Server
    // Access Control Lists".
    if pdu.event_type != "m.room.server_acl"
        && let Some(reason) = check_server_acl(state, room_nid, &sender_domain)
    {
        return (
            pdu.event_id,
            PduOutcome::Rejected(format!("server_acl: {reason}")),
        );
    }

    let sender_keys = match state.remote_keys.get_or_fetch(&sender_domain).await {
        Ok(k) => k,
        Err(e) => {
            warn!(domain = %sender_domain, error = %e, "failed to fetch sender keys");
            return (
                pdu.event_id,
                PduOutcome::Rejected("cannot fetch sender keys".into()),
            );
        }
    };

    // Find at least one signature from the sender's server that verifies.
    let sig_root = obj.get("signatures").and_then(|v| v.as_object());
    let sender_sigs = sig_root
        .and_then(|s| s.get(&sender_domain))
        .and_then(|v| v.as_object());
    let sender_sigs = match sender_sigs {
        Some(s) if !s.is_empty() => s,
        _ => {
            return (
                pdu.event_id,
                PduOutcome::Rejected(format!("no signature from {sender_domain}")),
            );
        }
    };

    // Look up the room version so redaction matches the SENDER's
    // shape — a v10 room's create event needs v10-redacted canonical
    // bytes for sig verify, not v12's "preserve all content" rule.
    let event_room_version = state
        .db
        .get_room_version_typed(room_nid)
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);

    let mut verified = false;
    for (key_id, _) in sender_sigs {
        let Some(pub_b64) = sender_keys.verify_keys.get(key_id) else {
            continue;
        };
        let Ok(public_key) = decode_public_key(pub_b64) else {
            continue;
        };
        if verify_event_signature(obj, &sender_domain, key_id, &public_key, event_room_version)
            .is_ok()
        {
            verified = true;
            break;
        }
    }
    if !verified {
        return (
            pdu.event_id,
            PduOutcome::Rejected("signature verification failed".into()),
        );
    }

    // --- Check 3: hashes ---
    // Recompute the content hash and compare against hashes.sha256.
    // Per spec: on mismatch, treat the event as redacted.
    let declared_hash = obj
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let computed_hash = compute_content_hash(obj);
    let use_redacted = match declared_hash {
        Some(d) => d != computed_hash,
        None => true,
    };

    let effective_event_json: Map<String, Value> = if use_redacted {
        warn!(event_id = %pdu.event_id, "content hash mismatch, using redacted form");
        vela_core::events::redact::redact_event_for_version(obj, event_room_version)
    } else {
        obj.clone()
    };
    let effective_pdu = match Pdu::from_json(pdu.event_id.clone(), &effective_event_json) {
        Some(p) => p,
        None => {
            return (
                pdu.event_id,
                PduOutcome::Rejected("event malformed after redaction".into()),
            );
        }
    };

    // Invite-rescind path. When a remote sends a leave/ban for a
    // *locally-invited* user, the receiving server can't run normal
    // state-at-event auth (it has only the invite event, no
    // power_levels or create). Spec-correct gate: ONLY the original
    // inviter can rescind. We handle both branches here:
    //   - sender matches the invite's sender → accept directly
    //     (mirrors federation_invite's "persist + flip" pattern).
    //   - sender doesn't match → reject. Falling through to the
    //     normal pipeline would let auth-chain fetching pull in
    //     enough state to authorise a room-admin kick that the spec
    //     forbids over federation, since the receiving server can't
    //     verify the kick's full authorisation context.
    if effective_pdu.event_type == "m.room.member"
        && matches!(effective_pdu.membership(), Some("leave") | Some("ban"))
        && let Some(target_user_id) = effective_pdu.state_key.as_deref()
        && target_user_id
            .split_once(':')
            .map(|(_, d)| d == state.config.server_name)
            .unwrap_or(false)
        && let Ok(target_nid) = state.db.get_or_create_nid(target_user_id)
        && state.db.get_membership(room_nid, target_nid).ok().flatten() == Some(2)
    {
        let inviter_match = state
            .db
            .get_nid("m.room.member")
            .ok()
            .flatten()
            .and_then(|type_nid| {
                state
                    .db
                    .get_state_event_nid(room_nid, type_nid, target_nid)
                    .ok()
                    .flatten()
            })
            .and_then(|invite_nid| state.db.get_event(invite_nid).ok().flatten())
            .and_then(|(_, bytes)| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|v| v.get("sender").and_then(|s| s.as_str().map(String::from)))
            .map(|s| s == effective_pdu.sender)
            .unwrap_or(false);
        if inviter_match {
            return (
                effective_pdu.event_id.clone(),
                apply_invite_rescind(state, room_nid, &effective_pdu, &effective_event_json).await,
            );
        }
        return (
            effective_pdu.event_id.clone(),
            PduOutcome::Rejected(
                "only the original inviter can rescind an invite over federation".into(),
            ),
        );
    }

    // --- Check 4: auth rules against auth_events ---
    // Build a state view from the event's auth_events. On a missing auth event,
    // attempt a bounded fetch from the sender's server via /event_auth.
    //
    // Rejection cascade (regression test for synapse#9595): if any
    // declared auth_event is on our `rejected_events` list, the
    // current event MUST be rejected too — irrespective of what
    // auth_events it actually selected. The wrapper at the txn
    // result layer marks `event_id` as rejected on every Rejected
    // outcome, so we don't repeat that here on each early return.
    for aev_id in &effective_pdu.auth_events {
        if state.db.is_event_rejected(aev_id).unwrap_or(false) {
            return (
                effective_pdu.event_id.clone(),
                PduOutcome::Rejected(format!("auth_event {aev_id} is rejected")),
            );
        }
    }
    let mut auth_state: HashMap<(String, String), Pdu> = HashMap::new();
    let fetch_budget = new_fetch_budget();
    for aev_id in &effective_pdu.auth_events {
        let pdu_opt = load_pdu_by_event_id(state, aev_id).or({
            // Not found locally — will fetch below.
            None
        });
        let p = match pdu_opt {
            Some(p) => p,
            None => {
                // Spec: `/event_auth/{room}/{event}` returns the auth
                // chain *for the named event*. Key the fetch on the
                // event we're validating (the trigger), not on each
                // missing aev — synapse / dendrite do the same, and
                // Complement (TestInboundFederationRejectsEventsWith
                // RejectedAuthEvents) actively forbids a per-aev call
                // because it lets a malicious peer probe the auth
                // graph one node at a time, bypassing rejection.
                let _ = fetch_auth_chain(
                    state,
                    &sender_domain,
                    &effective_pdu.room_id,
                    &effective_pdu.event_id,
                    fetch_budget.clone(),
                )
                .await;
                if state.db.is_event_rejected(aev_id).unwrap_or(false) {
                    return (
                        effective_pdu.event_id.clone(),
                        PduOutcome::Rejected(format!("auth_event {aev_id} is rejected")),
                    );
                }
                match load_pdu_by_event_id(state, aev_id) {
                    Some(p) => p,
                    None => {
                        return (
                            effective_pdu.event_id.clone(),
                            PduOutcome::Rejected(format!(
                                "auth event {aev_id} not provided in /event_auth chain"
                            )),
                        );
                    }
                }
            }
        };
        if let Some(sk) = p.state_key.as_deref() {
            auth_state.insert((p.event_type.clone(), sk.to_string()), p);
        }
    }
    // v12 (MSC4291): m.room.create is absent from auth_events.
    crate::federation_state::ensure_create_in_state(&state.db, room_nid, &mut auth_state);
    let auth_fn = |t: &str, sk: &str| auth_state.get(&(t.to_string(), sk.to_string()));
    if let Err(AuthError::Rejected(reason)) = check_auth(&effective_pdu, &auth_fn) {
        return (
            effective_pdu.event_id.clone(),
            PduOutcome::Rejected(format!("auth_events check failed: {reason}")),
        );
    }

    // If any prev_event is missing locally, attempt to fill the gap by
    // calling /get_missing_events on the sender's server. This lets us
    // accept events whose ancestors we haven't seen yet — without this,
    // the very next federated message after a missed transaction is
    // permanently unrootable.
    let mut missing_prev = false;
    for pid in &effective_pdu.prev_events {
        if state.db.get_event_nid_by_id(pid).ok().flatten().is_none()
            && !state.db.is_event_rejected(pid).unwrap_or(false)
        {
            // Genuinely missing — try to fill the gap. A prev that's
            // marked rejected isn't "missing" in the sense that warrants
            // a /get_missing_events probe; the upstream server already
            // told us about it (it just didn't pass auth). Calling
            // /get_missing_events for a known-rejected ancestor confuses
            // peers and trips Complement's UnexpectedRequestsAreErrors
            // (TestInboundFederationRejectsEventsWithRejectedAuthEvents).
            missing_prev = true;
            break;
        }
    }
    if missing_prev {
        let earliest_ids = get_room_extremity_ids(state, room_nid).unwrap_or_default();
        if let Err(e) = fetch_missing_events(
            state,
            &sender_domain,
            &effective_pdu.room_id,
            &effective_pdu.event_id,
            &earliest_ids,
            fetch_budget.clone(),
        )
        .await
        {
            // Don't reject yet — let check 5 surface a clearer per-event
            // error if any prev is still missing. Some remotes return an
            // empty list and we still succeed if events arrived via other
            // paths.
            debug!(error = %e, "fetch_missing_events failed");
        }
        // Mark the room as having had a gap fill at the current stream
        // position. /sync uses this to flag the next batch as `limited`
        // for users whose `since` predates the fill — per spec, when
        // the homeserver had to gap-fill, the timeline events alone are
        // inadequate and limited=true signals that to the client.
        state
            .last_gap_fill_pos
            .insert(room_nid, state.db.current_stream_position());
    }

    // --- Check 5: state-at-event ---
    // Resolve state from each prev_event's state_snapshot via state_res v2.
    match compute_state_at_event(state, &effective_pdu, &sender_domain).await {
        Ok(Some(mut state_at_event)) => {
            // v12 (MSC4291): m.room.create isn't a state event in the
            // post-state snapshot, so it's absent from the resolved
            // state_at_event map. The auth-check rules read the create
            // event for the creator identity; without injection, every
            // federated PDU would fail Check 5 with "no m.room.create
            // in state" — which is exactly what TestSyncTimelineGap hit.
            crate::federation_state::ensure_create_in_state(
                &state.db,
                room_nid,
                &mut state_at_event,
            );
            let sf = |t: &str, sk: &str| state_at_event.get(&(t.to_string(), sk.to_string()));
            if let Err(AuthError::Rejected(reason)) = check_auth(&effective_pdu, &sf) {
                let keys: Vec<String> = state_at_event
                    .keys()
                    .map(|(t, sk)| format!("{t}/{sk}"))
                    .collect();
                warn!(
                    event_id = %effective_pdu.event_id,
                    sender = %effective_pdu.sender,
                    prev_events = ?effective_pdu.prev_events,
                    state_at_event_keys = ?keys,
                    %reason,
                    "state-at-event check failed"
                );
                return (
                    effective_pdu.event_id.clone(),
                    PduOutcome::Rejected(format!("state-at-event check failed: {reason}")),
                );
            }
        }
        Ok(None) => {
            if effective_pdu.prev_events.is_empty() {
                // No prev_events at all — only valid for m.room.create,
                // which we don't accept over federation anyway.
                return (
                    effective_pdu.event_id.clone(),
                    PduOutcome::Rejected("no prev_events".into()),
                );
            }
            // Every prev_event is rejected/missing — skip the
            // state-at-event check. Check 4 already validated the
            // event against its declared auth_events, which is the
            // only authoritative anchor we have. Mirrors Synapse's
            // outlier path: accept the event so it can show up in
            // /sync timelines without contributing to current state.
        }
        Err(reason) => {
            // Log the detailed reason (may include internal DB error text or
            // NID values) operator-side; don't ship it to the federating peer.
            error!(
                event_id = %effective_pdu.event_id,
                error = %reason,
                "state-at-event resolution failed"
            );
            return (
                effective_pdu.event_id.clone(),
                PduOutcome::Rejected("state-at-event resolution failed".into()),
            );
        }
    }

    // --- Check 6: current state → soft-fail on failure ---
    let current_state = match build_current_state(state, room_nid) {
        Ok(s) => s,
        Err(e) => {
            error!(
                event_id = %effective_pdu.event_id,
                error = %e,
                "db error reading current state"
            );
            return (
                effective_pdu.event_id.clone(),
                PduOutcome::Rejected("internal error".into()),
            );
        }
    };
    let cs_fn = |t: &str, sk: &str| current_state.get(&(t.to_string(), sk.to_string()));
    let cs_outcome = check_auth(&effective_pdu, &cs_fn);
    let soft_failed = cs_outcome.is_err();
    if soft_failed {
        let reason = match &cs_outcome {
            Err(AuthError::Rejected(r)) => r.clone(),
            _ => "unknown".to_string(),
        };
        let keys: Vec<String> = current_state
            .keys()
            .map(|(t, sk)| format!("{t}/{sk}"))
            .collect();
        warn!(
            event_id = %effective_pdu.event_id,
            sender = %effective_pdu.sender,
            current_state_keys = ?keys,
            %reason,
            "event soft-failed"
        );
    }

    // --- Persist ---
    match persist_received_pdu(
        state,
        room_nid,
        &effective_pdu,
        &effective_event_json,
        soft_failed,
    )
    .await
    {
        Ok(()) => {
            if soft_failed {
                (effective_pdu.event_id, PduOutcome::SoftFailed)
            } else {
                (effective_pdu.event_id, PduOutcome::Accepted)
            }
        }
        Err(e) => (
            effective_pdu.event_id,
            PduOutcome::Rejected(format!("persist failed: {e}")),
        ),
    }
}

/// Resolve state-before-event by unioning each prev_event's state_snapshot via
/// state resolution v2. Returns Ok(None) if the event has no prev_events (only
/// valid for m.room.create, which we don't accept over federation).
async fn compute_state_at_event(
    state: &AppState,
    event: &Pdu,
    origin: &str,
) -> Result<Option<HashMap<(String, String), Pdu>>, String> {
    if event.prev_events.is_empty() {
        return Ok(None);
    }

    // Load each prev_event's state_snapshot (the state map AFTER that event
    // was applied, i.e. the state before this event would see it). Skip
    // prev_events that are rejected or missing — their snapshots aren't
    // meaningful, but at least one usable prev keeps state-at-event sane.
    // If every prev is rejected/missing, return Ok(None) so process_pdu can
    // fall back to auth_events-derived state (Check 4 already validated
    // those). Synapse's outlier path makes the same call.
    let mut state_sets: Vec<StateMap> = Vec::new();
    for prev_id in &event.prev_events {
        let prev_nid = match state
            .db
            .get_event_nid_by_id(prev_id)
            .map_err(|e| format!("db: {e}"))?
        {
            Some(n) => n,
            None => {
                if state.db.is_event_rejected(prev_id).unwrap_or(false) {
                    continue;
                }
                return Err(format!("unknown prev_event {prev_id}"));
            }
        };

        // Load snapshot for this prev_event.
        let snapshot_nids = state
            .db
            .get_state_at_event(prev_nid)
            .map_err(|e| format!("db: {e}"))?
            .unwrap_or_default();

        // Build StateMap (type, state_key) → event_id_string.
        // On missing referenced events we return an error rather than silently
        // dropping — a snapshot that points to a vanished event indicates DB
        // corruption, and silently continuing would run auth checks against a
        // degraded state view (e.g. missing m.room.power_levels → defaults apply,
        // which could mask improper authorisation).
        let mut sm: StateMap = StateMap::new();
        for snid in &snapshot_nids {
            let eid = state
                .db
                .get_event_id_by_nid(*snid)
                .map_err(|e| format!("db: {e}"))?
                .ok_or_else(|| {
                    format!("state snapshot references unknown event_nid {snid} (DB corruption)")
                })?;
            let (header, _) = state
                .db
                .get_event(*snid)
                .map_err(|e| format!("db: {e}"))?
                .ok_or_else(|| {
                    format!("state snapshot references unknown event_nid {snid} (DB corruption)")
                })?;
            let et = state
                .db
                .resolve_nid(header.type_nid)
                .map_err(|e| format!("db: {e}"))?
                .ok_or_else(|| format!("unknown type_nid {}", header.type_nid))?;
            let sk = state
                .db
                .resolve_nid(header.state_key_nid)
                .map_err(|e| format!("db: {e}"))?
                .unwrap_or_default();
            sm.insert((et, sk), eid);
        }
        state_sets.push(sm);
    }

    // Every prev_event was rejected/skipped — no usable state to resolve
    // against. Signal "skip Check 5" by returning Ok(None); the caller
    // distinguishes this from "no prev_events at all" by inspecting
    // event.prev_events itself.
    if state_sets.is_empty() {
        return Ok(None);
    }

    // /state_ids fallback. When prev_events are known locally but their
    // event_state inheritance is broken (e.g. fetched gap-fill events
    // whose oldest ancestor's prev wasn't a snapshot we have), each
    // prev's snapshot_nids comes back empty and state_res would
    // resolve to the empty set — Check 5 then rejects every federated
    // event with "sender is not joined". Ask the sending peer for the
    // canonical state at this event, fetch any missing PDUs as
    // outliers, and seed state_sets with that snapshot. Spec'd shape:
    // `/state_ids` returns `{auth_chain_ids, pdu_ids}`. We use only
    // pdu_ids (current state) — auth_chain validation already ran in
    // Check 4.
    if state_sets.iter().all(|sm| sm.is_empty())
        && let Ok(state_resp) = state
            .federation_client
            .state_ids(origin, &event.room_id, &event.event_id)
            .await
    {
        // Don't set last_gap_fill_pos here. /state_ids only fetches state
        // events (persisted as outliers, no stream_pos), so they don't
        // affect /sync timeline rendering. Setting the gap marker on
        // every state-only fallback wedges the /sync gap filter for any
        // user whose since predated the fallback — bob's hs2 hits
        // /state_ids routinely when state can't be anchored, and the
        // resulting filter drops post-fallback live events that the
        // user does need to see.
        let pdu_ids = state_resp
            .get("pdu_ids")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let mut sm: StateMap = StateMap::new();
        let budget = new_fetch_budget();
        for v in pdu_ids {
            let Some(eid) = v.as_str() else { continue };
            if state.db.get_event_nid_by_id(eid).ok().flatten().is_none()
                && let Ok(pdu_value) = state.federation_client.fetch_event_pdu(origin, eid).await
            {
                let _ = persist_fetched_event(
                    state,
                    &pdu_value,
                    origin,
                    budget.clone(),
                    FetchKind::AuthChain,
                )
                .await;
            }
            let nid = match state.db.get_event_nid_by_id(eid).ok().flatten() {
                Some(n) => n,
                None => continue,
            };
            let Ok(Some((header, _))) = state.db.get_event(nid) else {
                continue;
            };
            let et = match state.db.resolve_nid(header.type_nid).ok().flatten() {
                Some(s) => s,
                None => continue,
            };
            let sk = state
                .db
                .resolve_nid(header.state_key_nid)
                .ok()
                .flatten()
                .unwrap_or_default();
            sm.insert((et, sk), eid.to_string());
        }
        if !sm.is_empty() {
            state_sets = vec![sm];
        }
    }

    // Event + auth chain lookup closures for state_res.
    // Spawn on blocking pool: state_res is CPU-bound.
    let state_sets_clone = state_sets.clone();
    let db = state.db.clone();
    let resolved = tokio::task::spawn_blocking(move || {
        let event_fn = |id: &str| -> Option<Pdu> {
            let nid = db.get_event_nid_by_id(id).ok().flatten()?;
            let (_header, json_bytes) = db.get_event(nid).ok().flatten()?;
            let json: Map<String, Value> = serde_json::from_slice::<Value>(&json_bytes)
                .ok()?
                .as_object()?
                .clone();
            Pdu::from_json(id.to_string(), &json)
        };
        let auth_chain_fn = |id: &str| -> std::collections::HashSet<String> {
            // BFS through auth_events.
            let mut out = std::collections::HashSet::new();
            let mut queue = std::collections::VecDeque::new();
            queue.push_back(id.to_string());
            while let Some(n) = queue.pop_front() {
                let Some(pdu) = event_fn(&n) else { continue };
                for a in pdu.auth_events {
                    if out.insert(a.clone()) {
                        queue.push_back(a);
                    }
                }
            }
            out
        };
        state_res::resolve(&state_sets_clone, &event_fn, &auth_chain_fn)
    })
    .await
    .map_err(|e| format!("state_res task failed: {e}"))?;

    // Materialise the resolved StateMap into a (type,sk) → Pdu map for auth_rules.
    let mut out: HashMap<(String, String), Pdu> = HashMap::new();
    for (key, event_id) in &resolved {
        if let Some(pdu) = load_pdu_by_event_id(state, event_id) {
            out.insert(key.clone(), pdu);
        }
    }
    Ok(Some(out))
}

/// Build a (type, state_key) → Pdu map of the room's current state.
fn build_current_state(
    state: &AppState,
    room_nid: u64,
) -> Result<HashMap<(String, String), Pdu>, rocksdb::Error> {
    let state_nids = state.db.get_all_state_event_nids(room_nid)?;
    let mut out = HashMap::new();
    for snid in state_nids {
        let Some((header, json_bytes)) = state.db.get_event(snid)? else {
            continue;
        };
        let Some(event_id) = state.db.get_event_id_by_nid(snid)? else {
            continue;
        };
        let json: Map<String, Value> = match serde_json::from_slice::<Value>(&json_bytes) {
            Ok(v) => match v.as_object() {
                Some(o) => o.clone(),
                None => continue,
            },
            Err(_) => continue,
        };
        let Some(pdu) = Pdu::from_json(event_id, &json) else {
            continue;
        };
        let event_type = match state.db.resolve_nid(header.type_nid)? {
            Some(t) => t,
            None => continue,
        };
        let state_key = state
            .db
            .resolve_nid(header.state_key_nid)?
            .unwrap_or_default();
        out.insert((event_type, state_key), pdu);
    }
    Ok(out)
}

fn load_pdu_by_event_id(state: &AppState, event_id: &str) -> Option<Pdu> {
    let event_nid = state.db.get_event_nid_by_id(event_id).ok().flatten()?;
    let (_header, json_bytes) = state.db.get_event(event_nid).ok().flatten()?;
    let json: Map<String, Value> = serde_json::from_slice::<Value>(&json_bytes)
        .ok()?
        .as_object()?
        .clone();
    Pdu::from_json(event_id.to_string(), &json)
}

/// Persist an accepted PDU. Handles events CF write, state updates,
/// soft-fail marker, and extremity updates (only if NOT soft-failed).
async fn persist_received_pdu(
    state: &AppState,
    room_nid: u64,
    pdu: &Pdu,
    event_json: &Map<String, Value>,
    soft_failed: bool,
) -> Result<(), String> {
    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Resolve type/sender/state_key NIDs.
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

    // Resolve prev_events and auth_events to NIDs. Unknown ids drop
    // out of the cached edge arrays — paginate_dag's backfill chain
    // re-resolves prev_events from the event JSON, so a chain break
    // here is recoverable. We trace the drops because they're load-
    // bearing for any "why didn't backfill find X?" debugging.
    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &pdu.prev_events {
        match state.db.get_event_nid_by_id(pid) {
            Ok(Some(n)) => prev_nids.push(n),
            Ok(None) => {
                debug!(event_id = %pdu.event_id, prev_event = %pid, "persist_received: prev_event unknown locally, dropped from event_edges")
            }
            Err(e) => {
                debug!(event_id = %pdu.event_id, prev_event = %pid, error = %e, "persist_received: prev_event lookup error")
            }
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &pdu.auth_events {
        match state.db.get_event_nid_by_id(aid) {
            Ok(Some(n)) => auth_nids.push(n),
            Ok(None) => {
                debug!(event_id = %pdu.event_id, auth_event = %aid, "persist_received: auth_event unknown locally, dropped from event_auth_edges")
            }
            Err(e) => {
                debug!(event_id = %pdu.event_id, auth_event = %aid, error = %e, "persist_received: auth_event lookup error")
            }
        }
    }

    let event_nid = state.db.next_nid().map_err(|e| format!("db: {e}"))?;
    let json_bytes = canonical_json_object(event_json);
    let is_state = pdu.state_key.is_some();

    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            &pdu.event_id,
            room_nid,
            type_nid,
            sender_nid,
            state_key_nid,
            pdu.origin_server_ts,
            pdu.depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            is_state,
            soft_failed,
        )
        .map_err(|e| format!("persist_event: {e}"))?;

    // Promote to current state iff accepted (not soft-failed). Soft-failed
    // state events still exist in storage but MUST NOT affect current state
    // (per spec §Soft failure).
    if is_state && !soft_failed {
        state
            .db
            .promote_state_event(room_nid, event_nid, type_nid, state_key_nid)
            .map_err(|e| format!("db: {e}"))?;

        // Mirror m.room.member transitions into user_rooms so /sync's
        // get_user_left_rooms / get_user_joined_rooms reflect the
        // change. Without this, a user banned by a federated power
        // user keeps appearing in their `/sync` rooms.join section
        // and the room never moves to `rooms.leave`.
        if pdu.event_type == "m.room.member" {
            // Read membership from CURRENT state, not from the just-received
            // PDU. Persistence may have rejected the PDU's room_state
            // overwrite under the state-res tiebreak (older origin_ts loses
            // to a newer existing entry), in which case the existing entry
            // — not this PDU — defines the user's current membership.
            // Without this, an out-of-order older state event (e.g.
            // unban=leave arriving after invite in TestUnbanViaInvite)
            // would still call set_membership and stomp on the newer
            // invite that won state res.
            let current_member_nid = state
                .db
                .get_state_event_nid(room_nid, type_nid, state_key_nid)
                .ok()
                .flatten();
            let current_membership_str = current_member_nid
                .and_then(|nid| state.db.get_event(nid).ok().flatten())
                .and_then(|(_, json)| serde_json::from_slice::<Value>(&json).ok())
                .as_ref()
                .and_then(|v| v.pointer("/content/membership"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let membership_byte = match current_membership_str.as_deref() {
                Some("join") => 1u8,
                Some("invite") => 2u8,
                Some("ban") => 3u8,
                Some("knock") => 4u8,
                _ => 0u8, // leave or anything else
            };
            // For join → leave/ban transitions of federated users,
            // surface the departure to local observers via
            // device_list_left so /sync's `device_lists.left` reflects
            // the new "no longer shared" relationship. Run BEFORE the
            // membership update so `get_room_members` still includes
            // the observer set.
            let was_joined = state
                .db
                .get_membership(room_nid, state_key_nid)
                .ok()
                .flatten()
                == Some(1);
            if was_joined && (membership_byte == 0 || membership_byte == 3) {
                crate::keys::record_device_changes_on_leave(state, state_key_nid, room_nid);
            }
            if let Err(e) = state
                .db
                .set_membership(room_nid, state_key_nid, membership_byte)
            {
                tracing::warn!(error = %e, "set_membership (federated member event) failed");
            }
            // Wake the affected user so their /sync sees the move.
            crate::router::notify_user(state, state_key_nid);
        }
    }

    // Soft-fail marker (persisted regardless of state/non-state).
    if soft_failed {
        state
            .db
            .mark_soft_failed(event_nid)
            .map_err(|e| format!("db: {e}"))?;
    } else {
        // If this is a redaction and the target is on-disk, apply a marker
        // when the sender is actually allowed to redact it. Missing-target
        // case is logged and skipped; back-filling later is future work.
        if pdu.event_type == "m.room.redaction" {
            try_apply_redaction_marker(state, room_nid, pdu, event_nid);
        }

        // Index any m.relates_to so /relations sees federated children too.
        try_record_relation(state, pdu, event_nid, stream_pos, type_nid);

        // Notify local sync listeners only for non-soft-failed events.
        if let Some(sender_ch) = state.room_senders.get(&Nid(room_nid)) {
            let _ = sender_ch.send(stream_pos);
        }

        // Relay to other resident remotes. The peer that sent us this
        // PDU only knows about the destinations IT could reach. We're
        // a hub for the room's other peers; without this fan-out a
        // three-way room A→B→C never sees B's events arrive at C
        // unless B itself federates to C (and B doesn't always know
        // who's in the room beyond its own peer list).
        state.federation_sender.broadcast(room_nid, event_nid);
    }

    Ok(())
}

/// Apply an invite-rescind shortcut. Persist the leave/ban PDU,
/// promote it into current state, flip membership, wake observers.
/// Bypasses the normal auth/state-at-event/current-state checks
/// because the receiving server only has the invite event in store
/// and would otherwise reject the rescind for state-resolution
/// reasons it can't fix without first joining the room. Caller has
/// already validated signature, hash, and the inviter-sender match.
async fn apply_invite_rescind(
    state: &AppState,
    room_nid: u64,
    pdu: &Pdu,
    effective_event_json: &Map<String, Value>,
) -> PduOutcome {
    use vela_core::canonical::canonical_json_object;

    let target_user_id = match pdu.state_key.as_deref() {
        Some(s) => s,
        None => return PduOutcome::Rejected("rescind missing state_key".into()),
    };
    let type_nid = match state.db.get_or_create_nid("m.room.member") {
        Ok(n) => n,
        Err(e) => return PduOutcome::Rejected(format!("nid alloc: {e}")),
    };
    let sender_nid = match state.db.get_or_create_nid(&pdu.sender) {
        Ok(n) => n,
        Err(e) => return PduOutcome::Rejected(format!("nid alloc: {e}")),
    };
    let target_nid = match state.db.get_or_create_nid(target_user_id) {
        Ok(n) => n,
        Err(e) => return PduOutcome::Rejected(format!("nid alloc: {e}")),
    };

    let event_nid = match state.db.next_nid() {
        Ok(n) => n,
        Err(e) => return PduOutcome::Rejected(format!("nid alloc: {e}")),
    };
    let json_bytes = canonical_json_object(effective_event_json);

    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &pdu.prev_events {
        if let Ok(Some(n)) = state.db.get_event_nid_by_id(pid) {
            prev_nids.push(n);
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &pdu.auth_events {
        if let Ok(Some(n)) = state.db.get_event_nid_by_id(aid) {
            auth_nids.push(n);
        }
    }

    let stream_pos = match state.db.persist_event(
        event_nid,
        &pdu.event_id,
        room_nid,
        type_nid,
        sender_nid,
        target_nid,
        pdu.origin_server_ts,
        pdu.depth,
        &json_bytes,
        &prev_nids,
        &auth_nids,
        true,
        false,
    ) {
        Ok(pos) => pos,
        Err(e) => return PduOutcome::Rejected(format!("persist: {e}")),
    };
    if let Err(e) = state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, target_nid)
    {
        return PduOutcome::Rejected(format!("promote: {e}"));
    }
    let new_membership: u8 = if pdu.membership() == Some("ban") {
        3
    } else {
        0
    };
    if let Err(e) = state
        .db
        .set_membership(room_nid, target_nid, new_membership)
    {
        return PduOutcome::Rejected(format!("set_membership: {e}"));
    }
    crate::router::notify_user(state, target_nid);
    if let Some(sender_ch) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender_ch.send(stream_pos);
    }
    PduOutcome::Accepted
}

/// Record an `m.relates_to` index entry for an inbound event, mirroring
/// the local-send path. Skips silently if the parent isn't on disk yet —
/// the relation will be missing until back-fill brings it in.
fn try_record_relation(
    state: &AppState,
    pdu: &Pdu,
    event_nid: u64,
    stream_pos: u64,
    type_nid: u64,
) {
    let Some(rel) = pdu.content.get("m.relates_to") else {
        return;
    };
    let Some(parent_event_id) = rel.get("event_id").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(rel_type) = rel.get("rel_type").and_then(|v| v.as_str()) else {
        return;
    };
    let Ok(Some(parent_nid)) = state.db.get_event_nid_by_id(parent_event_id) else {
        return;
    };
    let Ok(rel_type_nid) = state.db.get_or_create_nid(rel_type) else {
        return;
    };
    if let Err(e) =
        state
            .db
            .record_relation(parent_nid, stream_pos, event_nid, rel_type_nid, type_nid)
    {
        warn!(parent = %parent_event_id, error = %e, "failed to record federated relation");
    }
}

/// For an accepted `m.room.redaction` event, apply the redaction marker if
/// (a) the target is present locally and (b) the sender passes the v3-handling
/// apply check. If either condition fails we silently skip — the redaction
/// event itself is still persisted and federated. Missing targets may be
/// back-filled in a future pass; insufficient-power redactions from remote
/// servers are simply no-ops per spec.
fn try_apply_redaction_marker(state: &AppState, room_nid: u64, pdu: &Pdu, redactor_nid: u64) {
    // v11+: redacts lives in content.redacts.
    let target_id = match pdu.content.get("redacts").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return,
    };

    let target_nid = match state.db.get_event_nid_by_id(target_id) {
        Ok(Some(n)) => n,
        _ => return,
    };
    let target_pdu = match load_pdu_by_event_id(state, target_id) {
        Some(p) if p.room_id == pdu.room_id => p,
        _ => return,
    };

    let create_pdu = match load_current_state_pdu(state, room_nid, "m.room.create", "") {
        Some(p) => p,
        None => return,
    };
    let pl_pdu = load_current_state_pdu(state, room_nid, "m.room.power_levels", "");
    let state_fn = |t: &str, sk: &str| -> Option<&Pdu> {
        match (t, sk) {
            ("m.room.create", "") => Some(&create_pdu),
            ("m.room.power_levels", "") => pl_pdu.as_ref(),
            _ => None,
        }
    };

    if !vela_core::auth_rules::can_apply_redaction(
        &pdu.sender,
        &target_pdu.sender,
        &state_fn,
        &create_pdu,
    ) {
        debug!(
            sender = %pdu.sender,
            target = %target_id,
            "redaction not applied: sender lacks power and differs in server"
        );
        return;
    }

    if let Err(e) = state.db.mark_redacted_by(target_nid, redactor_nid) {
        warn!(target = %target_id, error = %e, "failed to record redaction marker");
    }
}

fn load_current_state_pdu(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Option<Pdu> {
    let type_nid = state.db.get_nid(event_type).ok().flatten()?;
    let skey_nid = state.db.get_nid(state_key).ok().flatten()?;
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .ok()
        .flatten()?;
    let event_id = state.db.get_event_id_by_nid(event_nid).ok().flatten()?;
    let (_h, bytes) = state.db.get_event(event_nid).ok().flatten()?;
    let obj = serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()?
        .clone();
    Pdu::from_json(event_id, &obj)
}

/// Shared fetch budget for recursive missing-event ingestion.
///
/// Decremented once per event accepted from a fetch response. Protects
/// against pathological cases where filling a gap would require traversing
/// arbitrarily-deep ancestor chains.
pub type FetchBudget = std::sync::Arc<std::sync::atomic::AtomicUsize>;

pub(crate) fn new_fetch_budget() -> FetchBudget {
    std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(
        MAX_MISSING_FETCH_PER_PDU,
    ))
}

fn budget_exhausted(budget: &FetchBudget) -> bool {
    budget.load(std::sync::atomic::Ordering::Relaxed) == 0
}

fn consume_budget(budget: &FetchBudget) -> bool {
    // Compare-and-swap loop: return true iff we successfully decremented.
    loop {
        let current = budget.load(std::sync::atomic::Ordering::Relaxed);
        if current == 0 {
            return false;
        }
        if budget
            .compare_exchange(
                current,
                current - 1,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
        {
            return true;
        }
    }
}

/// Fetch a missing auth event (and its auth chain) from `origin` via
/// `/event_auth/{roomId}/{eventId}`. Each returned event is fully validated
/// and persisted; events with their own missing dependencies recursively
/// trigger further fetches, bounded by the shared `budget`.
fn fetch_auth_chain<'a>(
    state: &'a AppState,
    origin: &'a str,
    room_id: &'a str,
    target_event_id: &'a str,
    budget: FetchBudget,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(async move {
        if budget_exhausted(&budget) {
            return Err("fetch budget exhausted".into());
        }

        let path = format!("/_matrix/federation/v1/event_auth/{room_id}/{target_event_id}");
        let resp = state
            .federation_client
            .signed_request(reqwest::Method::GET, origin, &path, None)
            .await
            .map_err(|e| format!("/event_auth call failed: {e}"))?;

        let chain = resp
            .get("auth_chain")
            .and_then(|v| v.as_array())
            .ok_or("response missing auth_chain")?;

        // Sort by depth ascending so ancestors are persisted before
        // descendants. Remote servers don't guarantee topological order.
        let mut sorted_chain: Vec<Value> = chain.clone();
        sorted_chain.sort_by_key(|ev| {
            ev.as_object()
                .and_then(|o| o.get("depth"))
                .and_then(|d| d.as_u64())
                .unwrap_or(0)
        });

        let mut accepted = 0usize;
        for ev_json in &sorted_chain {
            if !consume_budget(&budget) {
                warn!("budget exhausted during auth_chain ingestion");
                break;
            }
            if let Err(e) =
                persist_fetched_event(state, ev_json, origin, budget.clone(), FetchKind::AuthChain)
                    .await
            {
                debug!(error = %e, "skipping fetched event");
                continue;
            }
            accepted += 1;
        }
        debug!(accepted, target_event_id, "auth chain fetched");

        Ok(())
    })
}

/// Look up the room's current forward extremities and resolve them to event
/// IDs. Used as `earliest_events` when calling /get_missing_events so the
/// remote knows where to stop walking back.
fn get_room_extremity_ids(state: &AppState, room_nid: u64) -> Result<Vec<String>, rocksdb::Error> {
    let nids = state.db.get_extremities(room_nid)?;
    let mut ids = Vec::with_capacity(nids.len());
    for n in nids {
        if let Some(eid) = state.db.get_event_id_by_nid(n)? {
            ids.push(eid);
        }
    }
    Ok(ids)
}

/// Fetch the chain of events between `latest_event_id` and the room's known
/// extremities (`earliest_event_ids`) via /get_missing_events. Returned
/// events are validated and persisted via `persist_fetched_event`, sharing
/// the caller's `budget` so a malicious or buggy remote can't drag us into
/// an unbounded fetch.
async fn fetch_missing_events(
    state: &AppState,
    origin: &str,
    room_id: &str,
    latest_event_id: &str,
    earliest_event_ids: &[String],
    budget: FetchBudget,
) -> Result<(), String> {
    if budget_exhausted(&budget) {
        return Err("fetch budget exhausted".into());
    }

    let path = format!("/_matrix/federation/v1/get_missing_events/{room_id}");
    // Spec default is 10 but it's far too small to cover real gaps:
    // a slow inbound transaction commonly skips 30+ events. Synapse uses 20
    // and Conduwuit uses 50 — we match the higher bound so a single
    // /get_missing_events round-trip walks far enough that the
    // /sync timeline truncation (typically 20) drops events from before
    // the gap, preserving the spec's "limited batch contains only post-gap
    // events" expectation without an explicit pre/post-gap split.
    let body = serde_json::json!({
        "earliest_events": earliest_event_ids,
        "latest_events": [latest_event_id],
        "limit": 50,
    });
    let resp = state
        .federation_client
        .signed_request(reqwest::Method::POST, origin, &path, Some(body))
        .await
        .map_err(|e| format!("/get_missing_events call failed: {e}"))?;

    let events = resp
        .get("events")
        .and_then(|v| v.as_array())
        .ok_or("response missing events")?;

    // Sort by depth ascending so ancestors are persisted before descendants.
    let mut sorted: Vec<Value> = events.clone();
    sorted.sort_by_key(|ev| {
        ev.as_object()
            .and_then(|o| o.get("depth"))
            .and_then(|d| d.as_u64())
            .unwrap_or(0)
    });

    let mut accepted = 0usize;
    for ev_json in &sorted {
        if !consume_budget(&budget) {
            warn!("budget exhausted during get_missing_events ingestion");
            break;
        }
        if let Err(e) = persist_fetched_event(
            state,
            ev_json,
            origin,
            budget.clone(),
            FetchKind::MissingTimeline,
        )
        .await
        {
            debug!(error = %e, "skipping fetched missing event");
            continue;
        }
        accepted += 1;
    }
    debug!(accepted, latest_event_id, "missing events fetched");
    Ok(())
}

/// Where the fetched event is being ingested from. The two paths fetch
/// different shapes of "missing" event and persist them differently.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FetchKind {
    /// `/event_auth` auth-chain ingestion. The events here predate live
    /// state and exist only as auth context for validating a downstream
    /// event. They MUST NOT join the timeline (no stream_pos), become a
    /// forward extremity, or update current state.
    AuthChain,
    /// `/get_missing_events` gap-fill ingestion. The events DO belong on
    /// the timeline — they're the messages between our last extremity
    /// and the trigger event we're processing. They get a stream_pos
    /// and surface in /sync. They momentarily become forward
    /// extremities, then the trigger event supersedes them via its own
    /// prev_events chain.
    MissingTimeline,
    /// One-shot historical fetch (e.g. /timestamp_to_event followed by
    /// /event/{event_id}). The event needs a stream_pos so /context
    /// returns a stream cursor and /messages dir=b can include it,
    /// but it must NOT update current room state or become a forward
    /// extremity — it's not part of the live DAG, just a pinpoint
    /// historical reference. Maps to PersistKind::BackfillTimeline.
    Backfill,
}

/// Validate and persist a single fetched event.
///
/// Full validation: signature, hash, and check 4 (auth rules against the
/// event's own `auth_events`). If any declared `auth_events` are missing
/// locally, recursively fetches them via `fetch_auth_chain` sharing the
/// same budget — this closes the single-level-fetch limitation from 3b.
///
/// State-at-event (check 5) and current-state (check 6) are intentionally
/// NOT run on fetched events: they're historical context for auth validation,
/// not new live events. Running check 5 would require resolving state from
/// ancestors that may themselves be missing, multiplying the fetch cost.
pub(crate) fn persist_fetched_event<'a>(
    state: &'a AppState,
    event_json: &'a Value,
    origin: &'a str,
    budget: FetchBudget,
    kind: FetchKind,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>> {
    Box::pin(persist_fetched_event_inner(
        state, event_json, origin, budget, kind,
    ))
}

async fn persist_fetched_event_inner(
    state: &AppState,
    event_json: &Value,
    origin: &str,
    budget: FetchBudget,
    kind: FetchKind,
) -> Result<(), String> {
    use vela_core::canonical::canonical_json_object;
    use vela_core::events::hash::{compute_content_hash, compute_event_id_for_version};

    let obj = event_json
        .as_object()
        .ok_or_else(|| "fetched event is not an object".to_string())?;

    // event_id derivation must use the sender's redaction shape; look
    // up via room_id → room_nid → version, fall back to v12 for
    // unknown rooms (which is the typical bootstrap path — fetched
    // events arrive before we've persisted the room locally).
    let event_id_room_version = obj
        .get("room_id")
        .and_then(|v| v.as_str())
        .and_then(|rid| state.db.get_nid(rid).ok().flatten())
        .and_then(|nid| state.db.get_room_version_typed(nid).ok())
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);
    let event_id = compute_event_id_for_version(obj, event_id_room_version)
        .as_str()
        .to_string();

    // Idempotent: if already known, skip.
    if state
        .db
        .get_event_nid_by_id(&event_id)
        .map_err(|e| format!("db: {e}"))?
        .is_some()
    {
        return Ok(());
    }

    let pdu = Pdu::from_json(event_id.clone(), obj)
        .ok_or_else(|| "fetched event malformed".to_string())?;

    // Look up the room version from local meta. Pre-v11 events have a
    // different redaction shape (m.room.create keeps only `creator`,
    // m.room.member keeps only `membership`) and using the wrong shape
    // makes our canonical bytes disagree with the sender's, breaking
    // sig verify. Fall back to v12 if the room isn't yet registered
    // locally — fetched events arriving for an unknown room go down
    // that path during outbound-join bootstrapping.
    let event_room_version = state
        .db
        .get_nid(&pdu.room_id)
        .ok()
        .flatten()
        .and_then(|n| state.db.get_room_version_typed(n).ok())
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);

    // Signature: at least one signature from sender's domain must verify.
    let sender_domain = pdu
        .sender_domain()
        .ok_or_else(|| "fetched event has malformed sender".to_string())?
        .to_string();
    let keys = state
        .remote_keys
        .get_or_fetch(&sender_domain)
        .await
        .map_err(|e| format!("cannot fetch keys for {sender_domain}: {e}"))?;
    let sigs = obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(&sender_domain))
        .and_then(|v| v.as_object())
        .ok_or_else(|| format!("no signatures from {sender_domain}"))?;
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
        return Err(format!("signature verification failed for {event_id}"));
    }

    // Hash: on mismatch, redact (per spec).
    let computed_hash = compute_content_hash(obj);
    let declared_hash = obj
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let event_obj_to_persist: Map<String, Value> = match declared_hash {
        Some(d) if d == computed_hash => obj.clone(),
        _ => vela_core::events::redact::redact_event_for_version(obj, event_room_version),
    };

    let target_pdu = Pdu::from_json(event_id.clone(), &event_obj_to_persist)
        .ok_or_else(|| "fetched event malformed after hash check".to_string())?;

    // Locate the room. If unknown locally, skip — fetched events for unknown
    // rooms shouldn't be persisted (they belong to a join state we don't have).
    let room_nid = state
        .db
        .get_nid(&target_pdu.room_id)
        .map_err(|e| format!("db: {e}"))?
        .ok_or_else(|| {
            format!(
                "fetched event references unknown room {}",
                target_pdu.room_id
            )
        })?;

    let type_nid = state
        .db
        .get_or_create_nid(&target_pdu.event_type)
        .map_err(|e| format!("db: {e}"))?;
    let sender_nid = state
        .db
        .get_or_create_nid(&target_pdu.sender)
        .map_err(|e| format!("db: {e}"))?;
    let state_key_nid = if let Some(sk) = &target_pdu.state_key {
        state
            .db
            .get_or_create_nid(sk)
            .map_err(|e| format!("db: {e}"))?
    } else {
        0
    };

    // Cascade rejection: bail before any work if the fetched event
    // declares a previously-rejected auth_event. Same logic as the
    // top-level process_pdu path.
    for aev_id in &target_pdu.auth_events {
        if state.db.is_event_rejected(aev_id).unwrap_or(false) {
            let reason = format!("auth_event {aev_id} is rejected");
            let _ = state.db.mark_event_rejected(&target_pdu.event_id, &reason);
            return Err(reason);
        }
    }

    // Check 4 (auth rules against the event's own auth_events). If any
    // referenced auth event is missing from our DB, recursively fetch it.
    // This is what closes the 3b single-level-fetch gap: a fetched event
    // whose ancestors are also missing triggers further fetches, bounded
    // by the shared budget.
    let mut auth_state: HashMap<(String, String), Pdu> = HashMap::new();
    for aev_id in &target_pdu.auth_events {
        let auth_pdu = match load_pdu_by_event_id(state, aev_id) {
            Some(p) => p,
            None => {
                // Missing — recursively fetch. If the recursion fails (budget
                // exhausted, remote error), we drop this fetched event.
                if let Err(e) =
                    fetch_auth_chain(state, origin, &target_pdu.room_id, aev_id, budget.clone())
                        .await
                {
                    let reason = format!("recursive fetch of auth {aev_id} failed: {e}");
                    let _ = state.db.mark_event_rejected(&target_pdu.event_id, &reason);
                    return Err(reason);
                }
                match load_pdu_by_event_id(state, aev_id) {
                    Some(p) => p,
                    None => {
                        // Same cascade as the top-level path: a
                        // recursive fetch can land an auth chain
                        // including a rejected event, leaving
                        // `aev_id` unloadable but recorded as
                        // rejected. Reflect that in our reason
                        // string and propagate.
                        let reason = if state.db.is_event_rejected(aev_id).unwrap_or(false) {
                            format!("auth_event {aev_id} is rejected")
                        } else {
                            format!("auth event {aev_id} still missing after recursive fetch")
                        };
                        let _ = state.db.mark_event_rejected(&target_pdu.event_id, &reason);
                        return Err(reason);
                    }
                }
            }
        };
        if let Some(sk) = auth_pdu.state_key.as_deref() {
            auth_state.insert((auth_pdu.event_type.clone(), sk.to_string()), auth_pdu);
        }
    }
    // v12 (MSC4291): m.room.create is absent from auth_events.
    crate::federation_state::ensure_create_in_state(&state.db, room_nid, &mut auth_state);
    let auth_fn = |t: &str, sk: &str| auth_state.get(&(t.to_string(), sk.to_string()));
    if let Err(vela_core::auth_rules::AuthError::Rejected(reason)) =
        vela_core::auth_rules::check_auth(&target_pdu, &auth_fn)
    {
        let full = format!(
            "fetched event {} failed check 4: {reason}",
            target_pdu.event_id
        );
        let _ = state.db.mark_event_rejected(&target_pdu.event_id, &full);
        return Err(full);
    }

    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &target_pdu.prev_events {
        if let Ok(Some(n)) = state.db.get_event_nid_by_id(pid) {
            prev_nids.push(n);
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &target_pdu.auth_events {
        if let Ok(Some(n)) = state.db.get_event_nid_by_id(aid) {
            auth_nids.push(n);
        }
    }

    let event_nid = state.db.next_nid().map_err(|e| format!("db: {e}"))?;
    let json_bytes = canonical_json_object(&event_obj_to_persist);

    // PersistKind by FetchKind:
    //   AuthChain       → Outlier            (historical auth context, no stream_pos)
    //   MissingTimeline → Live               (gap-fill on the live timeline)
    //   Backfill        → BackfillTimeline   (stream_pos, but no current state, no extremity)
    let persist_kind = match kind {
        FetchKind::AuthChain => vela_store::db::PersistKind::Outlier,
        FetchKind::MissingTimeline => vela_store::db::PersistKind::Live,
        FetchKind::Backfill => vela_store::db::PersistKind::BackfillTimeline,
    };

    state
        .db
        .persist_event_kind(
            event_nid,
            &target_pdu.event_id,
            room_nid,
            type_nid,
            sender_nid,
            state_key_nid,
            target_pdu.origin_server_ts,
            target_pdu.depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            target_pdu.state_key.is_some(),
            persist_kind,
        )
        .map_err(|e| format!("persist_event: {e}"))?;

    Ok(())
}

/// Persist a federated join event accepted via `PUT /send_join`. Unlike
/// `persist_received_pdu`, this is called under the caller's room lock and
/// skips the general check 5/6 machinery — send_join's authorisation is
/// governed by the auth_events the event itself references, verified by the
/// caller before invocation.
pub async fn persist_join_event(
    state: &AppState,
    room_nid: u64,
    pdu: &Pdu,
    event_json: &Map<String, Value>,
) -> Result<(), String> {
    use vela_core::canonical::canonical_json_object;

    let type_nid = state
        .db
        .get_or_create_nid(&pdu.event_type)
        .map_err(|e| format!("db: {e}"))?;
    let sender_nid = state
        .db
        .get_or_create_nid(&pdu.sender)
        .map_err(|e| format!("db: {e}"))?;
    let state_key = pdu
        .state_key
        .as_deref()
        .ok_or_else(|| "join event has no state_key".to_string())?;
    let state_key_nid = state
        .db
        .get_or_create_nid(state_key)
        .map_err(|e| format!("db: {e}"))?;

    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &pdu.prev_events {
        match state.db.get_event_nid_by_id(pid) {
            Ok(Some(n)) => prev_nids.push(n),
            Ok(None) => {
                debug!(event_id = %pdu.event_id, prev_event = %pid, "persist_join: prev_event unknown locally, dropped from event_edges")
            }
            Err(e) => {
                debug!(event_id = %pdu.event_id, prev_event = %pid, error = %e, "persist_join: prev_event lookup error")
            }
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &pdu.auth_events {
        match state.db.get_event_nid_by_id(aid) {
            Ok(Some(n)) => auth_nids.push(n),
            Ok(None) => {
                debug!(event_id = %pdu.event_id, auth_event = %aid, "persist_join: auth_event unknown locally, dropped from event_auth_edges")
            }
            Err(e) => {
                debug!(event_id = %pdu.event_id, auth_event = %aid, error = %e, "persist_join: auth_event lookup error")
            }
        }
    }

    let event_nid = state.db.next_nid().map_err(|e| format!("db: {e}"))?;
    let json_bytes = canonical_json_object(event_json);

    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            &pdu.event_id,
            room_nid,
            type_nid,
            sender_nid,
            state_key_nid,
            pdu.origin_server_ts,
            pdu.depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            true,  // is_state
            false, // not soft-failed
        )
        .map_err(|e| format!("persist_event: {e}"))?;

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, state_key_nid)
        .map_err(|e| format!("db: {e}"))?;

    // Update membership tracking.
    state
        .db
        .set_membership(room_nid, state_key_nid, 1)
        .map_err(|e| format!("db: {e}"))?;
    crate::router::notify_user(state, state_key_nid);

    // Notify local sync listeners.
    if let Some(sender_ch) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender_ch.send(stream_pos);
    }

    // Fan-out to other resident remotes. Without this, the just-joined
    // server is the only peer that knows about itself — bob@hs2 looking
    // up "who's in this room" for federation will miss charlie@hs3 and
    // skip delivery, breaking three-server rooms (TestACLs sentinel).
    state.federation_sender.broadcast(room_nid, event_nid);

    Ok(())
}

/// Apply the room's `m.room.server_acl` to `sender_domain`. Returns
/// `Some(reason)` when the sender should be rejected, `None` when it
/// passes (or when no ACL exists).
///
/// Spec semantics (server-server "Server Access Control Lists"):
/// - The sender domain must NOT match any pattern in `deny`.
/// - The sender domain MUST match at least one pattern in `allow`.
///   (`allow` defaults to `["*"]` when omitted; an empty list blocks
///   everyone, which is intentional per the spec.)
/// - When `allow_ip_literals` is `false`, IP-literal sender domains
///   are rejected even if the allow/deny rules would otherwise permit
///   them.
///
/// Patterns are glob-style: `*` matches any run of characters, `?`
/// matches a single character.
fn check_server_acl(state: &AppState, room_nid: u64, sender_domain: &str) -> Option<String> {
    let acl = load_room_state_content(state, room_nid, "m.room.server_acl", "")?;

    let allow_ip_literals = acl
        .get("allow_ip_literals")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let allow: Vec<&str> = acl
        .get("allow")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str()).collect())
        .unwrap_or_else(|| vec!["*"]);
    let deny: Vec<&str> = acl
        .get("deny")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|e| e.as_str()).collect())
        .unwrap_or_default();

    if !allow_ip_literals && is_ip_literal(sender_domain) {
        return Some(format!(
            "sender {sender_domain} is an IP literal but allow_ip_literals=false"
        ));
    }
    for pat in &deny {
        if glob_match(pat, sender_domain) {
            return Some(format!("sender {sender_domain} matches deny pattern {pat}"));
        }
    }
    if !allow.iter().any(|pat| glob_match(pat, sender_domain)) {
        return Some(format!("sender {sender_domain} matches no allow pattern"));
    }
    None
}

/// Read the `content` of a current state event for the room, or
/// `None` if the state event is absent or unreadable.
fn load_room_state_content(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Option<Value> {
    let type_nid = state.db.get_nid(event_type).ok().flatten()?;
    let sk_nid = state.db.get_nid(state_key).ok().flatten()?;
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, sk_nid)
        .ok()
        .flatten()?;
    let (_h, bytes) = state.db.get_event(event_nid).ok().flatten()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("content").cloned()
}

/// Glob match with `*` (any run) and `?` (single char). Linear-time
/// non-backtracking is sufficient for ACL patterns: real-world entries
/// are short ("*.example.com", "evil.com", IP literals).
fn glob_match(pattern: &str, s: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = s.chars().collect();
    let (mut i, mut j) = (0usize, 0usize);
    let (mut star_i, mut star_j): (Option<usize>, usize) = (None, 0);
    while j < s.len() {
        if i < p.len() && (p[i] == '?' || p[i] == s[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == '*' {
            star_i = Some(i);
            star_j = j;
            i += 1;
        } else if let Some(si) = star_i {
            i = si + 1;
            star_j += 1;
            j = star_j;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == '*' {
        i += 1;
    }
    i == p.len()
}

/// True if `domain` is an IP literal (IPv4 dotted, or IPv6 in brackets).
/// Optional `:port` suffix is permitted on both — that's how Matrix
/// server names carry an IP literal.
fn is_ip_literal(domain: &str) -> bool {
    use std::net::IpAddr;
    use std::str::FromStr;
    // IPv6 in brackets: `[::1]:8448` or `[::1]`.
    if let Some(rest) = domain.strip_prefix('[') {
        let host = rest.split(']').next().unwrap_or("");
        return IpAddr::from_str(host).is_ok();
    }
    // IPv4 with optional port.
    let host = domain.split(':').next().unwrap_or(domain);
    IpAddr::from_str(host).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use serde_json::json;

    #[tokio::test]
    async fn reject_non_object_pdu() {
        let (state, _tmp) = build_test_state();
        let (_, outcome) = process_pdu(&state, &json!([1, 2, 3])).await;
        assert!(matches!(outcome, PduOutcome::Rejected(ref r) if r.contains("not a JSON object")));
    }

    #[test]
    fn glob_match_wildcards() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*.example.com", "evil.example.com"));
        assert!(!glob_match("*.example.com", "example.com")); // no leftmost label
        assert!(glob_match("evil.com", "evil.com"));
        assert!(!glob_match("evil.com", "evil.com.attacker.tld"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
    }

    #[test]
    fn ip_literal_detection() {
        assert!(is_ip_literal("127.0.0.1"));
        assert!(is_ip_literal("127.0.0.1:8448"));
        assert!(is_ip_literal("[::1]"));
        assert!(is_ip_literal("[::1]:8448"));
        assert!(!is_ip_literal("example.com"));
        assert!(!is_ip_literal("matrix.org:8448"));
        // Borderline: "1.2.3.4.example.com" is NOT an IP literal —
        // the first colon-split host fails IpAddr parse.
        assert!(!is_ip_literal("1.2.3.4.example.com"));
    }

    #[tokio::test]
    async fn reject_missing_room_id() {
        let (state, _tmp) = build_test_state();
        let pdu = json!({
            "type": "m.room.message",
            "sender": "@alice:remote.example",
            "origin_server_ts": 1_700_000_000_000u64,
            "content": {"msgtype": "m.text", "body": "hi"},
            "depth": 5,
            "prev_events": [],
            "auth_events": [],
        });
        let (_, outcome) = process_pdu(&state, &pdu).await;
        assert!(matches!(outcome, PduOutcome::Rejected(ref r) if r.contains("room_id")));
    }

    #[tokio::test]
    async fn reject_unknown_room() {
        let (state, _tmp) = build_test_state();
        let pdu = json!({
            "type": "m.room.message",
            "sender": "@alice:remote.example",
            "room_id": "!never-seen-this-room",
            "origin_server_ts": 1_700_000_000_000u64,
            "content": {"msgtype": "m.text", "body": "hi"},
            "depth": 5,
            "prev_events": ["$some_prev"],
            "auth_events": ["$some_auth"],
        });
        let (_, outcome) = process_pdu(&state, &pdu).await;
        assert!(matches!(outcome, PduOutcome::Rejected(ref r) if r.contains("unknown room")));
    }

    #[tokio::test]
    async fn reject_m_room_create_over_send() {
        let (state, _tmp) = build_test_state();
        // m.room.create has no room_id in v12, but should be rejected with a
        // dedicated message (not the generic "missing room_id").
        let pdu = json!({
            "type": "m.room.create",
            "sender": "@alice:remote.example",
            "origin_server_ts": 1_700_000_000_000u64,
            "content": {"room_version": "12"},
            "depth": 0,
            "prev_events": [],
            "auth_events": [],
        });
        let (_, outcome) = process_pdu(&state, &pdu).await;
        match outcome {
            PduOutcome::Rejected(r) => assert!(
                r.contains("m.room.create"),
                "expected dedicated m.room.create rejection, got {r:?}"
            ),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn reject_too_many_auth_events() {
        let (state, _tmp) = build_test_state();
        let auth_events: Vec<String> = (0..15).map(|i| format!("$a{i}")).collect();
        let pdu = json!({
            "type": "m.room.message",
            "sender": "@alice:remote.example",
            "room_id": "!room",
            "origin_server_ts": 1_700_000_000_000u64,
            "content": {"msgtype": "m.text", "body": "hi"},
            "depth": 5,
            "prev_events": [],
            "auth_events": auth_events,
        });
        let (_, outcome) = process_pdu(&state, &pdu).await;
        assert!(matches!(outcome, PduOutcome::Rejected(ref r) if r.contains("auth_events")));
    }

    #[test]
    fn fetch_budget_consume_and_exhaust() {
        // Budget decrements correctly and returns false once exhausted.
        let b = super::new_fetch_budget();
        // Default is MAX_MISSING_FETCH_PER_PDU. Consume all.
        let max = super::MAX_MISSING_FETCH_PER_PDU;
        for i in 0..max {
            assert!(super::consume_budget(&b), "should succeed at {i}");
        }
        assert!(super::budget_exhausted(&b));
        assert!(!super::consume_budget(&b), "should fail when exhausted");
    }

    #[test]
    fn outcome_to_json_shapes() {
        assert_eq!(PduOutcome::Accepted.to_json(), json!({}));
        assert_eq!(PduOutcome::SoftFailed.to_json(), json!({}));
        assert_eq!(
            PduOutcome::Rejected("boom".into()).to_json(),
            json!({"error": "boom"})
        );
    }

    /// /get_missing_events fetcher sends the spec body shape: earliest_events,
    /// latest_events, limit. An empty events array is handled without error.
    #[tokio::test]
    async fn fetch_missing_events_request_shape() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let (state, _tmp) = build_test_state();
        let remote = MockServer::start().await;
        let server_name = "remote.example";
        state
            .federation_client
            .set_base_url_override(server_name, &remote.uri());

        Mock::given(method("POST"))
            .and(path_regex(r"^/_matrix/federation/v1/get_missing_events/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": []})))
            .expect(1)
            .mount(&remote)
            .await;

        let budget = super::new_fetch_budget();
        let res = super::fetch_missing_events(
            &state,
            server_name,
            "!room:remote.example",
            "$latest",
            &["$ext-1".into(), "$ext-2".into()],
            budget,
        )
        .await;
        assert!(res.is_ok(), "expected Ok on empty events, got {res:?}");

        // Inspect the captured request body.
        let received = remote.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(body["latest_events"], json!(["$latest"]));
        assert_eq!(body["earliest_events"], json!(["$ext-1", "$ext-2"]));
        assert_eq!(body["limit"], json!(50));
    }

    /// Budget exhaustion short-circuits before the HTTP request — no call made.
    #[tokio::test]
    async fn fetch_missing_events_respects_exhausted_budget() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let (state, _tmp) = build_test_state();
        let remote = MockServer::start().await;
        let server_name = "remote.example";
        state
            .federation_client
            .set_base_url_override(server_name, &remote.uri());

        // No expected calls — must not be hit.
        Mock::given(method("POST"))
            .and(path_regex(r"^/_matrix/federation/v1/get_missing_events/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"events": []})))
            .expect(0)
            .mount(&remote)
            .await;

        let budget = super::new_fetch_budget();
        for _ in 0..super::MAX_MISSING_FETCH_PER_PDU {
            super::consume_budget(&budget);
        }
        let res = super::fetch_missing_events(
            &state,
            server_name,
            "!room:remote.example",
            "$latest",
            &[],
            budget,
        )
        .await;
        assert!(res.is_err(), "expected Err on exhausted budget");
    }
}
