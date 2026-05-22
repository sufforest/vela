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
    // Pick an event_id to fetch state at: any extremity works (peers
    // accept any anchor we know). The freshly-persisted join event
    // is in there; if extremities advanced since the join the peer's
    // state response will reflect that — also fine.
    let event_id = pick_anchor_event_id(state, room_nid)?;
    let mut last_err = String::new();
    for server in servers {
        match state
            .federation_client
            .state(server, room_id, &event_id)
            .await
        {
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

fn pick_anchor_event_id(state: &AppState, room_nid: u64) -> Result<String, String> {
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
