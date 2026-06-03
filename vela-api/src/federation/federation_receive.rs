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

use std::collections::{HashMap, HashSet};

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
/// `origin` is the transaction's X-Matrix origin — the peer that just
/// delivered this PDU to us. Threaded down to the relay broadcast so we
/// don't echo the event back to them; safe to pass an empty string if
/// the caller doesn't have an origin (e.g. internal callers / tests).
///
/// On Accepted / SoftFailed the event has been persisted. On Rejected it has not.
pub async fn process_pdu(state: &AppState, pdu_json: &Value, origin: &str) -> (String, PduOutcome) {
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

    // --- Check 1b: numeric ranges ---
    // Without this gate a peer can send `{"x": 1.5}` — the canonical
    // encoder substitutes "0" while the stored JSON keeps 1.5, so
    // signature verify passes on bytes that differ from what
    // downstream consumers see. Reject up front.
    if let Some(bad_path) = vela_core::canonical::find_invalid_number_path(pdu_json) {
        return (
            "unknown".into(),
            PduOutcome::Rejected(format!(
                "PDU contains disallowed numeric value at `{bad_path}` (must be integer in safe range)"
            )),
        );
    }

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

    // Take the per-room lock NOW (before the auth check), not when we
    // finally call `persist_received_pdu`. The lock used to be acquired
    // inside `persist_received_pdu`, leaving the auth-chain fetch +
    // check-4 + invite-rescind side path running with no exclusion
    // against a concurrent `outbound_join` bootstrap, `persist_join_
    // event` send_join handler, or another federation_receive on the
    // same room. The race produced repeated "fetched event $X failed
    // check 4: no m.room.create in state" + cascade rejection patterns
    // that PR #88 and PR #90 patched symptom-by-symptom. Holding the
    // lock here covers `apply_invite_rescind`, every call into
    // `fetch_auth_chain` / `persist_fetched_event`, and
    // `persist_received_pdu` (which no longer takes its own lock). The
    // lock IS held across HTTP roundtrips of the auth chain fetch —
    // federation per-room throughput naturally serialises (events
    // arrive depth-ordered from the sender), so the additional wait
    // is bounded and predictable.
    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _room_guard = lock.lock().await;

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
        && let Some(reason) =
            crate::federation::server_acl::check_server_acl(state, room_nid, &sender_domain)
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
                // /state_ids + /event fallback. Some peers (notably
                // Complement's mock servers in TestCorruptedAuthChain,
                // and any homeserver that uses synapse's
                // resolution strategy) don't register `/event_auth`
                // at all; the state-at-event view gives us the same
                // auth chain via `auth_chain_ids` + per-event /event
                // fetches. Spec permits any of these endpoints to
                // serve the same purpose.
                //
                // The target for /state_ids is the deepest unknown
                // prev_event we can walk to from the trigger. Calling
                // on the trigger itself works for some peers but not
                // for synapse (which only registers a handler for the
                // specific boundary event); finding the boundary makes
                // the fallback robust across both styles.
                if load_pdu_by_event_id(state, aev_id).is_none() {
                    let boundary = find_state_ids_boundary(state, &effective_pdu);
                    let _ = fetch_auth_via_state_ids(
                        state,
                        &sender_domain,
                        &effective_pdu.room_id,
                        &boundary,
                        fetch_budget.clone(),
                    )
                    .await;
                }
                match load_pdu_by_event_id(state, aev_id) {
                    Some(p) => p,
                    None => {
                        return (
                            effective_pdu.event_id.clone(),
                            PduOutcome::Rejected(format!(
                                "auth event {aev_id} not provided in /event_auth or /state_ids chain"
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
    crate::federation::federation_state::ensure_create_in_state(
        &state.db,
        room_nid,
        &mut auth_state,
    );
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
    match compute_state_at_event(state, &effective_pdu, &sender_domain, fetch_budget.clone()).await
    {
        Ok(Some(mut state_at_event)) => {
            // v12 (MSC4291): m.room.create isn't a state event in the
            // post-state snapshot, so it's absent from the resolved
            // state_at_event map. The auth-check rules read the create
            // event for the creator identity; without injection, every
            // federated PDU would fail Check 5 with "no m.room.create
            // in state" — which is exactly what TestSyncTimelineGap hit.
            crate::federation::federation_state::ensure_create_in_state(
                &state.db,
                room_nid,
                &mut state_at_event,
            );
            // MSC3706 partial-state safety: if the room is still
            // filling and state-at-event lacks the sender's
            // m.room.member, fall back to their auth_events
            // copy. Spec mandates auth_events contains the
            // sender's membership for every non-state PDU, so
            // this is a known-good substitute. No-op when state
            // already has it.
            crate::federation::federation_state::ensure_sender_member_in_state(
                &state.db,
                &effective_pdu.sender,
                &effective_pdu.auth_events,
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
            // Partial-state rooms hit "unknown prev_event" frequently
            // while the filler is catching up — those events are
            // legitimate (the resident vouches via Check 4 against
            // declared auth_events) and rejecting them on the
            // resolution-failed path means a mid-resync ban / kick /
            // join never lands. MSC3902 expects the homeserver to
            // accept these and resolve once the resync completes.
            let is_partial_state = state
                .db
                .get_partial_state_info(room_nid)
                .map(|(p, _)| p)
                .unwrap_or(false);
            if is_partial_state {
                debug!(
                    event_id = %effective_pdu.event_id,
                    reason = %reason,
                    "state-at-event resolution failed in partial-state room — accepting via declared auth_events"
                );
            } else {
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
    // Partial-state rooms hold an incomplete `current_state` while the
    // filler is catching up — the resident has a power_levels event or
    // member event our local map doesn't yet have. Soft-failing on that
    // basis blocks legitimate state changes (a remote ban during resync
    // never reaches /sync). Treat partial-state Check 6 failures as
    // accepts; full state reconciliation happens at filler completion.
    let cs_failed = cs_outcome.is_err();
    let is_partial_state = state
        .db
        .get_partial_state_info(room_nid)
        .map(|(p, _)| p)
        .unwrap_or(false);
    let soft_failed = cs_failed && !is_partial_state;
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
        origin,
    )
    .await
    {
        Ok(()) => {
            if !soft_failed {
                // MSC3902 lazy-loading visibility: during partial state,
                // a remote user can author a timeline event whose
                // m.room.member isn't in our local current state (the
                // filler hasn't merged it). The event itself carries
                // their member event in `auth_events`, so promote it
                // into `room_state` now — without this, lazy /sync's
                // member-event filter (timeline senders only) drops
                // the membership and clients can't render the message
                // with the right display name.
                promote_sender_member_during_partial_state(state, room_nid, &effective_pdu);
                (effective_pdu.event_id, PduOutcome::Accepted)
            } else {
                (effective_pdu.event_id, PduOutcome::SoftFailed)
            }
        }
        Err(e) => (
            effective_pdu.event_id,
            PduOutcome::Rejected(format!("persist failed: {e}")),
        ),
    }
}

/// MSC3902: when an inbound timeline PDU lands during partial state and
/// the sender's `m.room.member` isn't already in current room state,
/// fish it out of the PDU's `auth_events` and promote it. The spec
/// requires `auth_events` to list the sender's membership for every
/// non-state PDU, so it's a known-good substitute for the missing
/// state entry. No-op when the room isn't partial or the member entry
/// is already present.
fn promote_sender_member_during_partial_state(state: &AppState, room_nid: u64, pdu: &Pdu) {
    if pdu.state_key.is_some() {
        // The inbound event is itself a state event — its own
        // persist path already updates room_state for its own
        // (type, state_key). Nothing extra to do here.
        return;
    }
    let (is_partial, _) = state
        .db
        .get_partial_state_info(room_nid)
        .unwrap_or((false, Vec::new()));
    if !is_partial {
        return;
    }
    let Ok(Some(type_member_nid)) = state.db.get_nid("m.room.member") else {
        return;
    };
    let Ok(Some(sender_skey_nid)) = state.db.get_nid(&pdu.sender) else {
        return;
    };
    if let Ok(Some(_)) = state
        .db
        .get_state_event_nid(room_nid, type_member_nid, sender_skey_nid)
    {
        return;
    }
    // Find the sender's member event among auth_events. The spec
    // mandates that every non-state PDU's auth_events include the
    // sender's membership, so this should always succeed for a
    // well-formed accepted event.
    for aid in &pdu.auth_events {
        let Some(json) =
            crate::federation::federation_state::load_event_json_by_event_id(&state.db, aid)
        else {
            continue;
        };
        let Some(obj) = json.as_object() else {
            continue;
        };
        let ty = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let sk = obj.get("state_key").and_then(|v| v.as_str()).unwrap_or("");
        if ty != "m.room.member" || sk != pdu.sender {
            continue;
        }
        let Ok(Some(member_nid)) = state.db.get_event_nid_by_id(aid) else {
            continue;
        };
        if let Err(e) =
            state
                .db
                .set_room_state_entry(room_nid, type_member_nid, sender_skey_nid, member_nid)
        {
            warn!(
                event_id = %pdu.event_id,
                sender = %pdu.sender,
                error = %e,
                "MSC3902: promote sender member failed"
            );
        }
        return;
    }
}

/// Resolve state-before-event by unioning each prev_event's state_snapshot via
/// state resolution v2. Returns Ok(None) if the event has no prev_events (only
/// valid for m.room.create, which we don't accept over federation).
async fn compute_state_at_event(
    state: &AppState,
    event: &Pdu,
    origin: &str,
    fetch_budget: FetchBudget,
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
                // Last-resort fetch: under 3-server topologies the prev_event
                // can arrive at this server AFTER the event that references
                // it. /get_missing_events earlier in process_pdu may have
                // returned empty if the gap walks past the sender's own
                // earliest-known position. Try /event/{prev_id} directly
                // against the origin so we can compute state-at-event
                // instead of rejecting and waiting for re-delivery.
                // TestACLsForEDUs reproduces this race ~33% under CI load.
                if let Ok(pdu_value) = state
                    .federation_client
                    .fetch_event_pdu(origin, prev_id)
                    .await
                    && persist_fetched_event(
                        state,
                        &pdu_value,
                        origin,
                        fetch_budget.clone(),
                        FetchKind::MissingTimeline,
                    )
                    .await
                    .is_ok()
                    && let Some(n) = state
                        .db
                        .get_event_nid_by_id(prev_id)
                        .map_err(|e| format!("db: {e}"))?
                {
                    // Fetch succeeded — proceed with this prev_nid.
                    let nid_after_fetch = n;
                    let snapshot_nids = state
                        .db
                        .get_state_at_event(nid_after_fetch)
                        .map_err(|e| format!("db: {e}"))?
                        .unwrap_or_default();
                    if snapshot_nids.is_empty() {
                        // No snapshot yet — skip this prev, others may suffice.
                        continue;
                    }
                    let mut sm: StateMap = StateMap::new();
                    for snid in &snapshot_nids {
                        let Some(eid) = state
                            .db
                            .get_event_id_by_nid(*snid)
                            .map_err(|e| format!("db: {e}"))?
                        else {
                            continue;
                        };
                        let Some((header, _)) =
                            state.db.get_event(*snid).map_err(|e| format!("db: {e}"))?
                        else {
                            continue;
                        };
                        let Some(et) = state
                            .db
                            .resolve_nid(header.type_nid)
                            .map_err(|e| format!("db: {e}"))?
                        else {
                            continue;
                        };
                        let sk = state
                            .db
                            .resolve_nid(header.state_key_nid)
                            .map_err(|e| format!("db: {e}"))?
                            .unwrap_or_default();
                        sm.insert((et, sk), eid);
                    }
                    state_sets.push(sm);
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
///
/// REQUIRES: caller holds `state.room_locks[Nid(room_nid)]`. The
/// caller in `process_pdu` takes the lock at the top so the auth-
/// chain fetch + check-4 + persist + side-effects all serialise on
/// the same lock as `outbound_join`'s state bootstrap.
async fn persist_received_pdu(
    state: &AppState,
    room_nid: u64,
    pdu: &Pdu,
    event_json: &Map<String, Value>,
    soft_failed: bool,
    origin: &str,
) -> Result<(), String> {
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
            let prior_membership = state
                .db
                .get_membership(room_nid, state_key_nid)
                .ok()
                .flatten();
            let was_joined = prior_membership == Some(1);
            if was_joined && (membership_byte == 0 || membership_byte == 3) {
                crate::e2ee::keys::record_device_changes_on_leave(state, state_key_nid, room_nid);
            }
            if let Err(e) = state
                .db
                .set_membership(room_nid, state_key_nid, membership_byte)
            {
                tracing::warn!(error = %e, "set_membership (federated member event) failed");
            }
            // MSC3902 partial-state: when a federated peer joins a
            // room we're still resyncing, fire device_list_changed
            // for local observers immediately. The filler's
            // reconcile_device_lists pass runs only at completion;
            // without this hook, /sync.device_lists.changed misses
            // the new peer until the resync ends (sometimes minutes
            // later). Outside partial-state the joining server's
            // own m.device_list_update EDU covers this signal, so
            // we don't fire here to avoid double-counting.
            let became_joined = !was_joined && membership_byte == 1;
            if became_joined {
                let room_is_partial = state
                    .db
                    .get_partial_state_info(room_nid)
                    .map(|(p, _)| p)
                    .unwrap_or(false);
                if room_is_partial {
                    crate::e2ee::keys::record_device_changes_on_join(
                        state,
                        state_key_nid,
                        room_nid,
                    );
                }
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
        try_record_relation(
            state, pdu, event_nid, stream_pos, type_nid, room_nid, sender_nid,
        );

        // Notify local sync listeners only for non-soft-failed events.
        if let Some(sender_ch) = state.room_senders.get(&Nid(room_nid)) {
            let _ = sender_ch.send(stream_pos);
        }

        // Relay to other resident remotes. The peer that sent us this
        // PDU only knows about the destinations IT could reach. We're
        // a hub for the room's other peers; without this fan-out a
        // three-way room A→B→C never sees B's events arrive at C
        // unless B itself federates to C (and B doesn't always know
        // who's in the room beyond its own peer list). Skip the
        // transaction origin too — they just told us, no point echoing.
        state
            .federation_sender
            .broadcast_excluding(room_nid, event_nid, Some(origin));

        // Push dispatch. The local-send path in send.rs does the same
        // — without this call, mobile clients get no notifications for
        // any message in a federated room whose sender is remote.
        // dispatch_for_event already skips the sender and silently
        // no-ops for users without local pushers, so the federated
        // members in the joined set cost nothing.
        crate::push::dispatch_for_event(
            state,
            room_nid,
            pdu.room_id.clone(),
            pdu.event_id.clone(),
            event_nid,
            sender_nid,
        );

        // AS interest filter — every registered AS whose namespaces
        // cover this event gets one transaction. No-op if none.
        {
            use crate::appservice::interest::{InterestEvent, matching};
            let evt = InterestEvent {
                room_id: &pdu.room_id,
                sender: &pdu.sender,
                state_key: pdu.state_key.as_deref(),
            };
            for live in matching(&state.appservice_registry, &evt) {
                if let Err(e) = state.appservice_outbox.enqueue(
                    live.appservice.nid,
                    vec![event_nid],
                    vec![pdu.room_id.clone()],
                ) {
                    tracing::warn!(
                        appservice = %live.appservice.id,
                        error = %e,
                        "AS outbox enqueue (federated) failed"
                    );
                }
            }
        }
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
    // Read membership from CURRENT state, not from the rescind PDU.
    // promote_state_event applies the state-res tiebreak — if a newer
    // invite already won (e.g. a parallel invite_v2 promoted the new
    // invite into current state before this rescind arrived), this
    // rescind event loses tiebreak and the state pointer stays at the
    // invite. Forcing membership = leave/ban from the rescind PDU
    // would clobber user_rooms to leave when state-res says invite.
    // Bites TestUnbanViaInvite when the unban arrives after the new
    // invite has already been promoted.
    let current_member_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, target_nid)
        .ok()
        .flatten();
    let current_membership_str = current_member_nid
        .and_then(|nid| state.db.get_event(nid).ok().flatten())
        .and_then(|(_, json)| serde_json::from_slice::<Value>(&json).ok())
        .as_ref()
        .and_then(|v| v.pointer("/content/membership"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let new_membership: u8 = match current_membership_str.as_deref() {
        Some("join") => 1,
        Some("invite") => 2,
        Some("ban") => 3,
        Some("knock") => 4,
        _ => 0,
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

/// Record a relations index entry for an inbound event, mirroring the
/// local-send path. Accepts both `content.m.relates_to` (MSC2675) and
/// `content.m.relationship` (MSC2836) — Complement's MSC2836 tests use
/// the unstable shape. Skips silently if the parent isn't on disk yet —
/// the relation will be missing until back-fill brings it in.
fn try_record_relation(
    state: &AppState,
    pdu: &Pdu,
    event_nid: u64,
    stream_pos: u64,
    type_nid: u64,
    room_nid: u64,
    sender_nid: u64,
) {
    let rel_opt = pdu
        .content
        .get("m.relates_to")
        .or_else(|| pdu.content.get("m.relationship"));
    let Some(rel) = rel_opt else {
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
    if let Err(e) = state.db.record_relation(
        parent_nid,
        stream_pos,
        event_nid,
        rel_type_nid,
        type_nid,
        room_nid,
        sender_nid,
        rel_type == "m.thread",
        true,
    ) {
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

    let already_redacted = state
        .db
        .get_redacted_by(target_nid)
        .ok()
        .flatten()
        .is_some();
    if let Err(e) = state.db.mark_redacted_by(target_nid, redactor_nid) {
        warn!(target = %target_id, error = %e, "failed to record redaction marker");
    }
    // Decrement the (parent, rel_type) counter only on the FIRST
    // redaction of this target — same idempotency story as the
    // local redaction path.
    if !already_redacted
        && let Some(rel) = target_pdu.content.get("m.relates_to")
        && let Some(parent_event_id) = rel.get("event_id").and_then(|v| v.as_str())
        && let Some(rel_type) = rel.get("rel_type").and_then(|v| v.as_str())
        && let Ok(Some(parent_nid)) = state.db.get_event_nid_by_id(parent_event_id)
        && let Ok(Some(rel_type_nid)) = state.db.get_nid(rel_type)
    {
        let _ = state.db.relation_redacted(parent_nid, rel_type_nid);
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
        // MSC3706: when the event's room is partial-state, the
        // sender's server may not have the missing auth events (we
        // joined via a third-party resident that filtered members).
        // Build a fallback list of servers to try from
        // `servers_in_room`. Order: origin first (most likely to know
        // recent events), then the resident hints.
        let mut servers: Vec<String> = vec![origin.to_string()];
        if let Ok(Some(room_nid)) = state.db.get_nid(room_id) {
            let (partial, hints) = state
                .db
                .get_partial_state_info(room_nid)
                .unwrap_or((false, Vec::new()));
            if partial {
                for s in hints {
                    if s != origin {
                        servers.push(s);
                    }
                }
            }
        }
        let mut last_err = String::new();
        let resp = {
            let mut out: Result<Value, String> = Err("no servers".into());
            for s in &servers {
                match state
                    .federation_client
                    .signed_request(reqwest::Method::GET, s, &path, None)
                    .await
                {
                    Ok(v) => {
                        out = Ok(v);
                        break;
                    }
                    Err(e) => {
                        last_err = format!("/event_auth via {s}: {e}");
                        continue;
                    }
                }
            }
            out
        }
        .map_err(|_| format!("/event_auth call failed: {last_err}"))?;

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

/// BFS back through known events' `prev_events` to find the
/// deepest event_id we don't have locally. Used as the target for
/// the `/state_ids` fallback — synapse-style peers serve a state
/// snapshot at the missing boundary, not at the trigger event
/// itself. Capped at 32 hops so a degenerate chain can't drive
/// unbounded reads.
///
/// The trigger PDU isn't yet on disk (we're mid-process_pdu), so
/// callers pass it in directly rather than relying on
/// `load_pdu_by_event_id` for the seed.
fn find_state_ids_boundary(state: &AppState, start: &Pdu) -> String {
    use std::collections::VecDeque;
    let mut visited: HashSet<String> = HashSet::new();
    let mut frontier: VecDeque<String> = VecDeque::new();
    for pid in &start.prev_events {
        frontier.push_back(pid.clone());
    }
    visited.insert(start.event_id.clone());

    // `last_known` tracks the deepest event_id we've successfully
    // loaded. If we hit the hop cap without finding a genuinely
    // missing event, falling back to `start.event_id` would call
    // `/state_ids` on the trigger — which the peer may not be
    // willing to serve (synapse's mock in TestCorruptedAuthChain
    // only registers a handler at the specific boundary event).
    // Using the deepest known event instead at least points at
    // somewhere along the actual prev chain.
    let mut last_known = start.event_id.clone();

    for _ in 0..32 {
        let current = match frontier.pop_front() {
            Some(c) => c,
            None => return last_known,
        };
        if !visited.insert(current.clone()) {
            continue;
        }
        match load_pdu_by_event_id(state, &current) {
            Some(p) => {
                last_known = current;
                for pid in &p.prev_events {
                    if !visited.contains(pid) {
                        frontier.push_back(pid.clone());
                    }
                }
            }
            None => return current,
        }
    }
    // Hop cap exhausted without finding an unknown event. Return the
    // first unvisited frontier entry — it's deeper than `start` and
    // more likely to be a meaningful boundary than the trigger
    // itself.
    while let Some(c) = frontier.pop_front() {
        if !visited.contains(&c) {
            return c;
        }
    }
    last_known
}

/// Fallback to `/state_ids` + per-event `/event` when `/event_auth`
/// returns nothing usable. Some peers (Complement's mock used in
/// TestCorruptedAuthChain, and synapse's own resolution path)
/// don't serve `/event_auth` at all — they expose the auth chain
/// indirectly through `/state_ids[event_id=…]`'s `auth_chain_ids`,
/// and clients walk those one by one via `/event/{eventId}`.
/// Persists results under `FetchKind::AuthChain` so they appear
/// only as auth context, not in the timeline.
async fn fetch_auth_via_state_ids(
    state: &AppState,
    origin: &str,
    room_id: &str,
    target_event_id: &str,
    budget: FetchBudget,
) -> Result<(), String> {
    // Deliberately NO entry-time `budget_exhausted` guard. The
    // budget is shared with the earlier `/event_auth` attempt; by
    // the time we get here it may already be drained. The
    // `consume_budget` call inside the loop is the real gate — at
    // worst the loop short-circuits on the first iteration, which
    // is identical to the previous "return early" behaviour but
    // preserves the `/state_ids` request itself so the peer can
    // still serve auth events that happen to already be on disk
    // (the loop's `get_event_nid_by_id` short-circuit costs zero
    // budget).
    let resp = state
        .federation_client
        .state_ids(origin, room_id, target_event_id)
        .await
        .map_err(|e| format!("/state_ids: {e}"))?;
    let mut ids: Vec<String> = Vec::new();
    for key in ["auth_chain_ids", "pdu_ids"] {
        if let Some(arr) = resp.get(key).and_then(|v| v.as_array()) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    ids.push(s.to_string());
                }
            }
        }
    }
    let mut accepted = 0usize;
    for eid in &ids {
        if !consume_budget(&budget) {
            warn!("budget exhausted during /state_ids ingestion");
            break;
        }
        if state.db.get_event_nid_by_id(eid).ok().flatten().is_some() {
            continue;
        }
        match state.federation_client.fetch_event_pdu(origin, eid).await {
            Ok(ev_json) => {
                // Use the lightweight outlier persistence path —
                // `persist_fetched_event` recursively fetches each
                // event's missing auth_events via /event_auth, which
                // burns through the shared FetchBudget on a chain
                // this deep. We just need the bytes on disk so the
                // outer Check 4 can complete; downstream live events
                // get their full Check 4 via the normal receive path.
                let room_id = ev_json
                    .get("room_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or(room_id);
                let Ok(Some(room_nid)) = state.db.get_nid(room_id) else {
                    continue;
                };
                match crate::membership::federation_outbound_join::persist_remote_event(
                    state,
                    room_nid,
                    &ev_json,
                    vela_store::db::PersistKind::Outlier,
                )
                .await
                {
                    Ok(Some(_)) => accepted += 1,
                    Ok(None) => {} // already had this event
                    Err(e) => {
                        debug!(event_id = %eid, error = %e, "/state_ids: persist failed");
                    }
                }
            }
            Err(e) => {
                debug!(event_id = %eid, error = %e, "/state_ids: fetch event failed");
            }
        }
    }
    debug!(
        accepted,
        target_event_id, "auth chain fetched via /state_ids"
    );
    Ok(())
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
                        let is_rejected = state.db.is_event_rejected(aev_id).unwrap_or(false);
                        let reason = if is_rejected {
                            format!("auth_event {aev_id} is rejected")
                        } else {
                            format!("auth event {aev_id} still missing after recursive fetch")
                        };
                        // "still missing after recursive fetch" is a
                        // transient local-state hole — the auth event
                        // will arrive on a later transaction or a
                        // backfill, and the next re-send of the
                        // target event will revalidate cleanly. Same
                        // shape as the "no m.room.create in state"
                        // deferral below. Marking rejected here
                        // permanently strands every downstream event
                        // that lists target_pdu as auth_event, which
                        // is the TFRI residual flake on
                        // Non-invitee_user_cannot_rescind.
                        if is_rejected {
                            let _ = state.db.mark_event_rejected(&target_pdu.event_id, &reason);
                        }
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
    crate::federation::federation_state::ensure_create_in_state(
        &state.db,
        room_nid,
        &mut auth_state,
    );
    let auth_fn = |t: &str, sk: &str| auth_state.get(&(t.to_string(), sk.to_string()));
    if let Err(vela_core::auth_rules::AuthError::Rejected(reason)) =
        vela_core::auth_rules::check_auth(&target_pdu, &auth_fn)
    {
        let full = format!(
            "fetched event {} failed check 4: {reason}",
            target_pdu.event_id
        );
        // "no m.room.create in state" is a transient local-state hole,
        // not a real auth violation — it fires when a federation
        // transaction's auth-chain backfill races our send_join state
        // persistence on the same room. Marking the event rejected
        // here turns a temporary gap into a permanent cascade: the
        // ban PDU that triggered the fetch sees its auth_event on
        // the rejected list and gets rejected too, even after our
        // state is fully populated (TestUnbanViaInvite). Defer
        // rejection for this case so a later retransmission (or a
        // re-fetch via /event_auth) revalidates against the
        // populated state.
        if !reason.contains("no m.room.create in state") {
            let _ = state.db.mark_event_rejected(&target_pdu.event_id, &full);
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use serde_json::json;

    #[tokio::test]
    async fn reject_non_object_pdu() {
        let (state, _tmp) = build_test_state();
        let (_, outcome) = process_pdu(&state, &json!([1, 2, 3]), "test.example").await;
        assert!(matches!(outcome, PduOutcome::Rejected(ref r) if r.contains("not a JSON object")));
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
        let (_, outcome) = process_pdu(&state, &pdu, "test.example").await;
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
        let (_, outcome) = process_pdu(&state, &pdu, "test.example").await;
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
        let (_, outcome) = process_pdu(&state, &pdu, "test.example").await;
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
        let (_, outcome) = process_pdu(&state, &pdu, "test.example").await;
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

    /// The partial-state branch in Check 5 (state-at-event resolution
    /// failed) is gated on `get_partial_state_info`. Verify the DB
    /// helper returns the expected `(partial, servers)` tuple so the
    /// receive path's gate behaves correctly under various states.
    #[tokio::test]
    async fn partial_state_info_gates_check_5_fallback() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!partial:example.com").unwrap();

        // Default: not partial-state.
        let (partial, servers) = db.get_partial_state_info(room_nid).unwrap();
        assert!(!partial);
        assert!(servers.is_empty());

        // Set partial-state with the resident server.
        db.set_partial_state_join(room_nid, &["resident.example".into()], 0)
            .unwrap();
        let (partial, servers) = db.get_partial_state_info(room_nid).unwrap();
        assert!(partial);
        assert_eq!(servers, vec!["resident.example".to_string()]);

        // Clear flips back; the Check 5 path would now go through the
        // strict rejection.
        db.clear_partial_state(room_nid, 0).unwrap();
        let (partial, _) = db.get_partial_state_info(room_nid).unwrap();
        assert!(!partial);
    }

    /// Membership transitions (`set_membership` byte 0/1/2/3/4) must
    /// round-trip through `get_membership` for both sync and
    /// federation/receive to read back the right state — this is the
    /// substrate the partial-state ban / leave paths rely on.
    #[tokio::test]
    async fn membership_byte_round_trip_covers_all_states() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!mb:example.com").unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();

        // Initial: no record → None.
        assert_eq!(db.get_membership(room_nid, alice_nid).unwrap(), None);

        for byte in [0u8, 1, 2, 3, 4] {
            db.set_membership(room_nid, alice_nid, byte).unwrap();
            assert_eq!(
                db.get_membership(room_nid, alice_nid).unwrap(),
                Some(byte),
                "byte {byte} round-trip"
            );
        }
    }

    /// Banned (3) and left (0) users both appear in
    /// `get_user_left_rooms` — this is what makes /sync's rooms.leave
    /// section surface a remote-ban event after the partial-state
    /// soft-fail relaxation accepts it.
    #[tokio::test]
    async fn left_rooms_index_includes_banned_users() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let room_left = db.get_or_create_nid("!left:example.com").unwrap();
        let room_banned = db.get_or_create_nid("!banned:example.com").unwrap();
        let room_joined = db.get_or_create_nid("!joined:example.com").unwrap();

        db.set_membership(room_left, alice_nid, 0).unwrap();
        db.set_membership(room_banned, alice_nid, 3).unwrap();
        db.set_membership(room_joined, alice_nid, 1).unwrap();

        let mut left = db.get_user_left_rooms(alice_nid).unwrap();
        left.sort();
        let mut expected = vec![room_left, room_banned];
        expected.sort();
        assert_eq!(left, expected);

        let joined = db.get_user_joined_rooms(alice_nid).unwrap();
        assert_eq!(joined, vec![room_joined]);
    }
}
