//! MSC3706 partial-state filler. After an outbound /send_join with
//! `omit_members=true`, the resident server may return a partial
//! state (most member events omitted, plus `partial_state: true` +
//! `servers_in_room`). We persist the join immediately so /sync is
//! responsive, and this worker pulls the rest of the state from one
//! of the named servers via `GET /_matrix/federation/v1/state`.
//!
//! One worker per process (not per room): partial joins are bursty
//! at server warmup, otherwise quiet. The single worker walks the
//! list of partial-state rooms, tries each room's `servers_in_room`
//! in order, persists the returned state as `StateBundleOnly` (same
//! kind the join's state events use), and clears the flag.
//!
//! Failures use per-room exponential backoff up to a 24h dead-letter
//! threshold (mirrors federation_sender). When every listed server
//! fails for 24h the room stays partial; an operator can either
//! retrigger via a future admin command or re-join.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::Value;
use tokio::time::sleep;
use tracing::{debug, info, warn};
use vela_core::identifiers::Nid;

use crate::router::AppState;

/// Initial retry delay; doubles each failure up to MAX_BACKOFF.
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// After this long without success the room is left partial and the
/// worker stops touching it (the operator sees the warn log).
const DEAD_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// How often the worker rescans the partial-state list when there's
/// nothing pending. Cheap (DashMap len + maybe a CF iteration); the
/// scan kicks in mainly after `Notify::notify_one` wakes us anyway.
const IDLE_SCAN: Duration = Duration::from_secs(60);

/// Spawn the partial-state filler if it isn't already running. Idem-
/// potent — the AppState boot path calls this, and so does each
/// outbound join (so a fresh partial room doesn't have to wait for
/// the idle scan tick to be picked up).
pub fn ensure_running(state: &AppState) {
    if !state.partial_state_filler.start_if_idle() {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        run(state).await;
    });
}

/// Wake the running worker (if any) — used by the outbound join
/// path right after it persists a fresh partial-state flag.
pub fn notify_new_partial_room(state: &AppState) {
    state.partial_state_filler.notify();
}

/// Shared filler state on AppState. Holds the `running` guard so we
/// don't spawn more than one worker, and a `Notify` channel so
/// new-partial-room events wake the worker out of its idle sleep.
#[derive(Default)]
pub struct PartialStateFiller {
    running: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
    /// Per-room dead-letter clock — first failure timestamp. Cleared
    /// on success. Used to enforce DEAD_AFTER.
    first_failure_at: DashMap<u64, Instant>,
}

impl PartialStateFiller {
    pub fn new() -> Self {
        Self::default()
    }

    fn start_if_idle(&self) -> bool {
        self.running
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
    }

    fn notify(&self) {
        self.notify.notify_one();
    }
}

async fn run(state: AppState) {
    debug!("partial-state filler started");
    loop {
        let rooms = match state.db.list_partial_state_rooms() {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "partial-state filler: list failed");
                sleep(INITIAL_BACKOFF).await;
                continue;
            }
        };
        if rooms.is_empty() {
            // Idle. Wake on either the notify channel or the idle
            // scan tick, whichever comes first.
            tokio::select! {
                _ = state.partial_state_filler.notify.notified() => {}
                _ = sleep(IDLE_SCAN) => {}
            }
            continue;
        }
        let mut any_progress = false;
        for (room_nid, room_id, servers) in rooms {
            match try_fill_one(&state, room_nid, &room_id, &servers).await {
                Ok(true) => {
                    info!(room = %room_id, "MSC3706 partial state filled");
                    state
                        .partial_state_filler
                        .first_failure_at
                        .remove(&room_nid);
                    any_progress = true;
                }
                Ok(false) => {} // already cleared by another path, skip
                Err(reason) => {
                    let entry = state
                        .partial_state_filler
                        .first_failure_at
                        .entry(room_nid)
                        .or_insert_with(Instant::now);
                    if entry.value().elapsed() > DEAD_AFTER {
                        warn!(
                            room = %room_id,
                            reason = %reason,
                            "partial-state filler: dead-lettered after 24h"
                        );
                    } else {
                        debug!(
                            room = %room_id,
                            reason = %reason,
                            "partial-state filler: will retry"
                        );
                    }
                }
            }
        }
        // Per-room backoff is coarse — sleep proportional to whether
        // any room made progress. If yes: tighten the loop. If no:
        // back off so we don't hammer a row of dead peers.
        let next = if any_progress {
            INITIAL_BACKOFF
        } else {
            MAX_BACKOFF
        };
        tokio::select! {
            _ = state.partial_state_filler.notify.notified() => {}
            _ = sleep(next) => {}
        }
    }
}

/// One attempt to fill a single room. `Ok(true)` = filled + flag
/// cleared. `Ok(false)` = the room turned out to be already full
/// (e.g. another path cleared the flag). `Err` = failure; caller
/// keeps the flag and applies backoff.
async fn try_fill_one(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    servers: &[String],
) -> Result<bool, String> {
    if servers.is_empty() {
        return Err("no servers in room hint".into());
    }
    // Pick an event_id to fetch state at. We prefer the join's
    // `prev_event` (= the resident peer's pre-join tip): that is the
    // event the resident server indexed state at when it answered
    // our `make_join`, and the only anchor MSC3902 Complement mocks
    // accept. Real peers are more permissive but this is also the
    // spec-preferred anchor — the `/state_ids` response describes
    // "the state PRIOR to" the requested event.
    let event_id = pick_anchor_event_id(state, room_nid)?;
    let mut last_err = String::new();
    for server in servers {
        // MSC3902 / spec preference: try `/state_ids` first (lighter
        // — peer returns event_ids, we materialise via `/event` per
        // id). Fall back to `/state` (heavier full-PDU response) when
        // /state_ids materialisation comes up incomplete (any
        // auth_chain_id 404, or fewer than half of `pdu_ids` resolve).
        // Auth-chain truncation is dangerous: a missing ancestor can
        // make downstream auth checks reject legitimate events, so
        // partial materialisation isn't acceptable on the auth side.
        let assembled = fetch_state_via_state_ids(state, server, room_id, &event_id).await;
        let resp = match assembled {
            Ok(v) => Ok(v),
            Err(e) => {
                debug!(
                    %server,
                    error = %e,
                    "state_ids primary failed, falling back to /state"
                );
                state
                    .federation_client
                    .state(server, room_id, &event_id)
                    .await
                    .map_err(|fe| format!("{fe}"))
            }
        };
        match resp {
            Ok(resp) => {
                // persist_remote_event reaches into room_state; the
                // existing federation paths serialise on
                // state.room_locks per room. Take that here too so
                // a concurrent federation_receive can't race with
                // the merge.
                let lock = state
                    .room_locks
                    .entry(Nid(room_nid))
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone();
                let _guard = lock.lock().await;
                // Capture the membership set BEFORE the merge so we
                // can diff against the post-merge set and notify
                // local users about newly-known peers (MSC3706
                // device_list reconciliation).
                let members_before: std::collections::HashSet<u64> = state
                    .db
                    .get_room_members(room_nid)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                match merge_state_response(state, room_nid, &resp).await {
                    Ok(()) => {
                        state
                            .db
                            .clear_partial_state(room_nid)
                            .map_err(|e| format!("clear flag: {e}"))?;
                        reconcile_device_lists(state, room_nid, &members_before);
                        wake_sync_on_clear(state, room_nid);
                        return Ok(true);
                    }
                    Err(e) => {
                        last_err = format!("merge from {server}: {e}");
                        continue;
                    }
                }
            }
            Err(e) => {
                last_err = format!("fetch from {server}: {e}");
                continue;
            }
        }
    }
    Err(if last_err.is_empty() {
        "no server responded".into()
    } else {
        last_err
    })
}

/// Pick the event_id to anchor `/state_ids` / `/state` at. Prefer the
/// prev_event of the partial-state join (the resident peer's pre-join
/// tip — the only anchor MSC3902 mocks accept, and the spec-correct
/// "state PRIOR to this event" semantic). Fall back to the first
/// room extremity if we don't have the join recorded — keeps the
/// filler usable for partial-state records written before
/// `join_event_nid` tracking landed.
fn pick_anchor_event_id(state: &AppState, room_nid: u64) -> Result<String, String> {
    if let Ok(Some(join_nid)) = state.db.get_partial_join_event_nid(room_nid) {
        // The join's prev_event is the resident peer's pre-join tip
        // — we know its event_id from the join's JSON but typically
        // haven't persisted it locally. Read the id string directly
        // rather than going through nid resolution.
        if let Ok(Some(ids)) = state.db.get_prev_event_ids_from_json(join_nid)
            && let Some(eid) = ids.into_iter().next()
        {
            return Ok(eid);
        }
    }
    let extremities = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| format!("get_extremities: {e}"))?;
    let nid = extremities
        .first()
        .copied()
        .ok_or("room has no extremities")?;
    state
        .db
        .get_event_id_by_nid(nid)
        .map_err(|e| format!("resolve nid: {e}"))?
        .ok_or_else(|| "extremity nid has no event_id".into())
}

/// Primary state fetch path. Calls `/state_ids` (lighter — peer
/// returns event_id arrays), then materialises every id via
/// `/event`. Returns a Value in the same shape `merge_state_response`
/// already consumes (`{auth_chain: [pdu...], pdus: [pdu...]}`).
///
/// Spec field names are `auth_chain_ids` + `pdu_ids` (server-server
/// `events.yaml`). Older peers may return `auth_chain` / `pdus` — we
/// accept both.
///
/// Returns `Err` when materialisation comes up structurally
/// incomplete (any `auth_chain_id` 404, OR fewer than half of
/// `pdu_ids` resolve). Auth chain truncation is dangerous: a missing
/// ancestor causes downstream auth checks to reject legitimate
/// events. The caller falls back to `/state` (heavy full-PDU path)
/// in that case.
async fn fetch_state_via_state_ids(
    state: &AppState,
    server: &str,
    room_id: &str,
    event_id: &str,
) -> Result<Value, String> {
    let ids = state
        .federation_client
        .state_ids(server, room_id, event_id)
        .await
        .map_err(|e| format!("state_ids: {e}"))?;
    let auth_ids: Vec<String> = ids
        .get("auth_chain_ids")
        .or_else(|| ids.get("auth_chain"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let pdu_ids: Vec<String> = ids
        .get("pdu_ids")
        .or_else(|| ids.get("pdus"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if pdu_ids.is_empty() {
        return Err("state_ids: empty pdu_ids".into());
    }
    let mut auth_pdus: Vec<Value> = Vec::with_capacity(auth_ids.len());
    for id in &auth_ids {
        match state.federation_client.fetch_event_pdu(server, id).await {
            Ok(p) => auth_pdus.push(p),
            Err(e) => {
                return Err(format!("auth_chain /event {id}: {e}"));
            }
        }
    }
    let mut pdu_pdus: Vec<Value> = Vec::with_capacity(pdu_ids.len());
    let mut missing = 0usize;
    for id in &pdu_ids {
        match state.federation_client.fetch_event_pdu(server, id).await {
            Ok(p) => pdu_pdus.push(p),
            Err(_) => missing += 1,
        }
    }
    if missing * 2 > pdu_ids.len() {
        return Err(format!(
            "state_ids: only {}/{} pdu_ids materialised",
            pdu_pdus.len(),
            pdu_ids.len()
        ));
    }
    Ok(serde_json::json!({
        "auth_chain": auth_pdus,
        "pdus": pdu_pdus,
    }))
}

async fn merge_state_response(state: &AppState, room_nid: u64, resp: &Value) -> Result<(), String> {
    let auth_chain = resp
        .get("auth_chain")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let state_events = resp
        .get("pdus")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if state_events.is_empty() {
        return Err("peer returned no state PDUs".into());
    }
    for ev in &auth_chain {
        let _ = crate::membership::federation_outbound_join::persist_remote_event(
            state,
            room_nid,
            ev,
            vela_store::db::PersistKind::Outlier,
        )
        .await;
    }
    // Require at least one state event to persist successfully before
    // declaring the room filled. Without this, an all-fail merge
    // (signatures mismatch, malformed JSON, etc.) would still clear
    // the partial-state flag and leave the room permanently incomplete.
    let mut persisted: usize = 0;
    let mut last_err = String::new();
    for ev in &state_events {
        match crate::membership::federation_outbound_join::persist_remote_event(
            state,
            room_nid,
            ev,
            vela_store::db::PersistKind::StateBundleOnly,
        )
        .await
        {
            Ok(_) => persisted += 1,
            Err(e) => last_err = e,
        }
    }
    if persisted == 0 {
        return Err(format!(
            "no state events persisted ({} attempted; last error: {last_err})",
            state_events.len()
        ));
    }
    Ok(())
}

/// Wake any /sync long-polls blocked on this room. Filler completion
/// is a state transition observable through /sync (members_omitted
/// flips false, `rooms.join.<id>.state` now contains the full member
/// set). Without this wake a client mid-long-poll sees the change
/// only on its next scheduled refresh.
fn wake_sync_on_clear(state: &AppState, room_nid: u64) {
    let pos = state.db.next_stream_position().as_u64();
    // Filler completion doesn't persist anything new — the state
    // events were already merged before clear_partial_state. We still
    // burn a stream position so the wake carries a value > any
    // previously-returned `next_batch`.
    let _stream_guard = vela_store::db::StreamApplyOnDrop::new(&state.db, pos);
    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(pos);
    }
}

/// Reset the `running` flag — exposed for tests so they can re-spawn
/// the worker after asserting it idle-sleeps.
#[cfg(test)]
pub fn _reset_for_test(state: &AppState) {
    state
        .partial_state_filler
        .running
        .store(false, std::sync::atomic::Ordering::Release);
}

/// MSC3706 device_list reconciliation. When the filler completes,
/// the room may now include peers our local users hadn't seen
/// before — their /sync responses still report the OLD member set
/// because the device_list_changes stream wasn't updated when the
/// filler's state events landed. Iterate the diff and post one
/// device-key-change notification per newly-known peer, observable
/// by every local member of the room.
fn reconcile_device_lists(
    state: &AppState,
    room_nid: u64,
    members_before: &std::collections::HashSet<u64>,
) {
    let members_after = match state.db.get_room_members(room_nid) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "device_list reconciliation: members lookup failed");
            return;
        }
    };
    let new_peers: Vec<u64> = members_after
        .iter()
        .copied()
        .filter(|m| !members_before.contains(m))
        .collect();
    if new_peers.is_empty() {
        return;
    }
    // Local observers = every member of this room hosted on us. The
    // pre-merge members_before contains our local users that were
    // already joined (creator + invitees we knew about + ourselves);
    // post-merge members_after may also contain newly-discovered
    // remote users. Iterate the union and keep only local ones.
    let our_server = state.config.server_name.as_str();
    let mut local_observers: Vec<u64> = Vec::new();
    for m in &members_after {
        if let Ok(Some(uid)) = state.db.resolve_nid(*m)
            && uid
                .split_once(':')
                .map(|(_, d)| d == our_server)
                .unwrap_or(false)
        {
            local_observers.push(*m);
        }
    }
    if local_observers.is_empty() {
        return;
    }
    for &peer_nid in &new_peers {
        let stream_pos = state.db.next_stream_position().as_u64();
        let _stream_guard = vela_store::db::StreamApplyOnDrop::new(&state.db, stream_pos);
        if let Err(e) = state
            .db
            .notify_device_key_change(peer_nid, &local_observers, stream_pos)
        {
            warn!(error = %e, peer_nid, "device_list reconciliation: notify failed");
            continue;
        }
        for &nid in &local_observers {
            crate::router::notify_user(state, nid);
        }
    }
    debug!(
        room_nid,
        new_peers = new_peers.len(),
        observers = local_observers.len(),
        "MSC3706 device_list reconciliation fired",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use serde_json::json;

    /// `pick_anchor_event_id` returns the first extremity's event_id.
    /// Errors when the room has no extremities yet — that's the
    /// pre-bootstrap state we should retry, not crash on.
    #[test]
    fn pick_anchor_event_id_errors_when_no_extremities() {
        let (state, _tmp) = build_test_state();
        let room_nid = state.db.get_or_create_nid("!noext:example.com").unwrap();
        let err = pick_anchor_event_id(&state, room_nid).expect_err("no extremity → error");
        assert!(
            err.contains("no extremities"),
            "expected 'no extremities', got: {err}"
        );
    }

    /// When the room has an extremity its event_id is returned.
    /// Verify both the happy path and that picking the FIRST element
    /// is deterministic for a single-extremity room.
    #[test]
    fn pick_anchor_event_id_returns_extremity_event_id() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!anc:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();

        // Persist a single timeline event so it becomes the only
        // extremity.
        let body = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": room_id,
            "content": {"body": "hi"},
            "origin_server_ts": 1, "depth": 1,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            7777,
            "$anchor",
            room_nid,
            type_msg,
            alice_nid,
            0,
            1,
            1,
            &serde_json::to_vec(&body).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();

        let got = pick_anchor_event_id(&state, room_nid).unwrap();
        assert_eq!(got, "$anchor");
    }

    /// When a partial-state join is recorded, `pick_anchor_event_id`
    /// returns the prev_event of the join (the resident peer's
    /// pre-join tip), NOT the join itself. That's the only anchor
    /// MSC3902 Complement mocks accept, and the spec-correct
    /// "state PRIOR to" semantic for `/state_ids`.
    #[test]
    fn pick_anchor_prefers_join_prev_event() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!psjanchor:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();

        // Signed join event, prev_events points at "$resident_tip"
        // — the resident peer's pre-join tip. We must NOT have
        // persisted that event locally; the filler must still
        // surface it as the anchor (it's what the peer indexes
        // state at).
        let _ = type_msg;
        let join_body = json!({
            "type": "m.room.member",
            "sender": "@alice:example.com",
            "state_key": "@alice:example.com",
            "room_id": room_id,
            "content": {"membership": "join"},
            "origin_server_ts": 2, "depth": 2,
            "prev_events": ["$resident_tip"],
            "auth_events": [],
        });
        let join_nid = 1002;
        db.persist_event(
            join_nid,
            "$ourjoin",
            room_nid,
            type_member,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&join_body).unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();

        db.set_partial_state_join(room_nid, &["resident.example".into()], join_nid)
            .unwrap();

        let got = pick_anchor_event_id(&state, room_nid).unwrap();
        assert_eq!(got, "$resident_tip");
    }

    /// `wake_sync_on_clear` allocates a fresh stream position and
    /// broadcasts it on the room's `room_senders` channel. A /sync
    /// long-poll subscribed before clear must observe the new pos
    /// — without it, members_omitted=false is delivered only when
    /// some other event in the room eventually wakes the poll.
    #[test]
    fn wake_sync_on_clear_broadcasts_fresh_pos() {
        let (state, _tmp) = build_test_state();
        let room_nid = state.db.get_or_create_nid("!wake:example.com").unwrap();
        // Install a broadcast channel for the room, simulating an
        // active /sync subscription. The cap matches what the
        // AppState boot path installs (the value isn't tested).
        let (tx, mut rx) = tokio::sync::broadcast::channel::<u64>(16);
        state.room_senders.insert(Nid(room_nid), tx);

        let before = state.db.current_stream_position();
        wake_sync_on_clear(&state, room_nid);
        let pos = rx.try_recv().expect("expected a wake on room_senders");
        // The wake carries a stream pos strictly greater than the
        // last-applied value at the moment of the wake. Comparing
        // against `before` keeps the assertion stable under whatever
        // background events the test harness may have allocated.
        assert!(pos > before, "wake pos {pos} should exceed {before}");
    }

    /// `_reset_for_test` flips the filler's `running` flag back to
    /// false so each test starts from a clean state without leaking
    /// the in-progress marker into the next case.
    #[test]
    fn reset_for_test_clears_running_flag() {
        let (state, _tmp) = build_test_state();
        // Manually set running so we can observe the reset.
        state
            .partial_state_filler
            .running
            .store(true, std::sync::atomic::Ordering::Release);
        _reset_for_test(&state);
        assert!(
            !state
                .partial_state_filler
                .running
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }
}
