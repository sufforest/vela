//! Periodic pruner for the federation/client **dedup caches** that
//! would otherwise grow for the life of the server.
//!
//! Two column families only need to remember an entry for a short
//! retry window, then never again:
//!   - `transactions` — client request idempotency
//!     (`(user, device, scope, txn_id) → event_id`), one row per
//!     client transaction.
//!   - `to_device_seen_message_ids` — inbound `m.direct_to_device`
//!     EDU dedup (`(origin, message_id)`), one row per to-device EDU.
//!
//! Re-processing a dropped entry is idempotent (events are
//! content-addressed; the to-device path dedupes again downstream), so
//! pruning is safe — the only cost of an over-aggressive cutoff is a
//! little rework. We keep a generous TTL so a real client/server retry
//! (seconds to minutes) always still hits the cache.
//!
//! Mirrors `presence::presence_sweeper`: a long-lived ticker task that
//! calls the testable [`prune_once`] each interval. The store-level
//! prune is a full CF scan (keys aren't time-ordered) run inside
//! `spawn_blocking` so it never stalls the async runtime; if it ever
//! becomes hot the upgrade is a time-ordered index CF.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::time;

use crate::router::AppState;

/// How often the pruner runs.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Entries older than this are removed. 24h matches Synapse's
/// `received_transactions` cleanup and is far longer than any real
/// client/server retry window.
const DEDUP_TTL_MS: u64 = 24 * 60 * 60 * 1000;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Spawn the pruner as a long-lived background task. Returns
/// immediately; the task runs until the process exits.
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = time::interval(PRUNE_INTERVAL);
        // First tick fires immediately; skip it so we don't scan the
        // moment the server boots.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let st = state.clone();
            match tokio::task::spawn_blocking(move || prune_once(&st)).await {
                Ok(Ok((txns, to_device))) => {
                    if txns + to_device > 0 {
                        tracing::info!(
                            transactions = txns,
                            to_device = to_device,
                            "dedup pruner removed expired entries"
                        );
                    }
                }
                Ok(Err(e)) => tracing::warn!(error = %e, "dedup pruner tick failed"),
                Err(e) => tracing::warn!(error = %e, "dedup pruner task panicked"),
            }
        }
    })
}

/// One prune pass over both dedup CFs. Returns `(transactions_removed,
/// to_device_removed)`. Public so tests can drive it without a timer.
pub fn prune_once(state: &AppState) -> Result<(usize, usize), String> {
    let cutoff = now_ms().saturating_sub(DEDUP_TTL_MS);
    let txns = state
        .db
        .prune_transactions(cutoff)
        .map_err(|e| format!("prune_transactions: {e}"))?;
    let to_device = state
        .db
        .prune_to_device_seen(cutoff)
        .map_err(|e| format!("prune_to_device_seen: {e}"))?;
    Ok((txns, to_device))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    /// A freshly-written transaction is well within the TTL, so a prune
    /// pass must not touch it — guards against an over-aggressive cutoff
    /// and confirms the task wires through to the store correctly.
    #[test]
    fn prune_once_keeps_recent_entries() {
        let (state, _tmp) = build_test_state();
        state
            .db
            .set_transaction(1, "DEV", "send", "txn1", "$e1")
            .unwrap();

        let (txns, to_device) = prune_once(&state).unwrap();
        assert_eq!(
            (txns, to_device),
            (0, 0),
            "recent entries must not be pruned"
        );
        assert_eq!(
            state
                .db
                .get_transaction(1, "DEV", "send", "txn1")
                .unwrap()
                .as_deref(),
            Some("$e1")
        );
    }
}
