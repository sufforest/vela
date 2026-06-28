//! Periodic retention pruner for the device-list change CFs
//! (`device_key_changes`, `device_list_left`), which would otherwise grow
//! for the life of the server — one row per device-key change (or peer
//! departure) per observer.
//!
//! Unlike the short-lived dedup caches (see [`super::dedup_pruner`]), these
//! drive E2EE device tracking: a client learns which users' device lists
//! changed while it was away from the `device_lists.changed` / `.left`
//! arrays of an incremental `/sync` (or `/keys/changes`). Pruning therefore
//! can't be a blind TTL — a client whose `since` token predates the pruned
//! window would silently get an incomplete change list and keep stale
//! device keys. So the store's [`prune_device_lists`] advances a *horizon*,
//! and the `/sync` + `/keys/changes` read paths over-report all shared-room
//! users (forcing a full `/keys/query`) for any caller that falls below it
//! — see `crate::e2ee::keys::device_list_changed_nids`.
//!
//! The window is generous (30 days) so only a client offline longer than
//! that pays the full-resync cost.
//!
//! [`prune_device_lists`]: vela_store::db::Database::prune_device_lists

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time;

use crate::router::AppState;

/// How often the pruner runs. Daily — entries age out over weeks, so an
/// hourly scan would be wasted work.
const PRUNE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Device-list entries older than this are removed. 30 days is the window
/// in which an offline client can still catch up via an incremental sync;
/// past it, it full-resyncs via the horizon guard.
const DEVICE_LIST_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Spawn the pruner as a long-lived background task. Returns immediately;
/// the task runs until the process exits.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(PRUNE_INTERVAL);
        // First tick fires immediately; skip it so we don't scan at boot.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let st = state.clone();
            match tokio::task::spawn_blocking(move || prune_once(&st)).await {
                Ok(Ok((removed, horizon))) => {
                    if removed > 0 {
                        tracing::info!(
                            removed,
                            horizon,
                            "device-list pruner removed expired entries"
                        );
                    }
                }
                Ok(Err(e)) => tracing::warn!(error = %e, "device-list pruner tick failed"),
                Err(e) => tracing::warn!(error = %e, "device-list pruner task panicked"),
            }
        }
    })
}

/// One prune pass over both device-list CFs. Returns `(entries_removed,
/// horizon)`. Public so tests can drive it without a timer.
pub fn prune_once(state: &AppState) -> Result<(usize, u64), String> {
    let cutoff = now_ms().saturating_sub(DEVICE_LIST_TTL_MS);
    state
        .db
        .prune_device_lists(cutoff)
        .map_err(|e| format!("prune_device_lists: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    /// A freshly-recorded device-key change is well within the TTL, so a
    /// prune pass must not touch it or advance the horizon — guards against
    /// an over-aggressive cutoff and confirms the task reaches the store.
    #[test]
    fn prune_once_keeps_recent_entries() {
        let (state, _tmp) = build_test_state();
        state.db.record_device_key_change(1).unwrap();

        let (removed, horizon) = prune_once(&state).unwrap();
        assert_eq!(
            (removed, horizon),
            (0, 0),
            "recent entries must not be pruned"
        );
    }
}
