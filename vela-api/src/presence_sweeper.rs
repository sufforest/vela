//! Background sweeper that applies presence auto-decay transitions
//! and broadcasts the federation EDU when a user's effective presence
//! changes due to inactivity.
//!
//! The on-disk `user_presence` record only updates when a client
//! explicitly does something — PUT /presence, or a /sync (which
//! `touch_presence` ticks `last_active_ms`). When a user goes idle and
//! stops sync'ing entirely, nothing on the API surface triggers a
//! write, so federation peers never learn the user transitioned away
//! from "online".
//!
//! This sweeper runs on `cfg.sweep_interval_ms` (default 60s). Every
//! tick: scan every `user_presence` record, compute the effective
//! state, and if it differs from the stored state, persist the
//! transition and notify federation. Local /sync responses already
//! see the right answer via `format_status` — the sweeper is purely
//! for federation correctness and to keep the stored CF aligned with
//! what gets served on the wire.
//!
//! Cost: O(local-user count) per tick, all in-process. For pwd.wiki-
//! sized deploys (single digits of users) the whole scan completes
//! in microseconds. Scaling concerns are far below the rest of the
//! homeserver's hot path.

use std::time::Duration;

use serde_json::json;
use tokio::time;

use crate::router::AppState;

/// Spawn the sweeper as a long-lived background task. Returns
/// immediately. The task runs until the process exits or its handle
/// is dropped (the returned handle is held by AppState's lifetime).
pub fn spawn(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval_ms = state.config.presence.sweep_interval_ms.max(1_000);
        let mut ticker = time::interval(Duration::from_millis(interval_ms));
        // First tick fires immediately; skip it so the sweeper waits
        // one full interval after startup before doing work. This
        // matters mostly to avoid log noise on a freshly-booted DB
        // with no presence records yet.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) = sweep_once(&state).await {
                tracing::warn!(error = %e, "presence sweeper tick failed");
            }
        }
    })
}

/// One sweep pass. Public so integration tests can drive a tick
/// deterministically without spawning a real timer.
pub async fn sweep_once(state: &AppState) -> Result<SweepStats, String> {
    let now = now_ms();
    let cfg = state.config.presence;
    let records = state
        .db
        .list_presence_records()
        .map_err(|e| format!("list_presence_records: {e}"))?;

    let mut stats = SweepStats::default();
    for (user_nid, mut rec) in records {
        stats.scanned += 1;
        let stored = rec
            .get("presence")
            .and_then(|v| v.as_str())
            .unwrap_or("offline")
            .to_string();
        let last_active_ms = rec.get("last_active_ms").and_then(|v| v.as_u64());
        let effective = crate::presence::effective_presence(&stored, last_active_ms, &cfg, now);

        if effective == stored {
            continue;
        }

        // Stored value drifted from effective. Persist the new value
        // and broadcast.
        if let Some(obj) = rec.as_object_mut() {
            obj.insert("presence".into(), json!(effective));
        }
        // `set_local_presence` writes user_presence + advances
        // presence_stream so the federation sender picks it up.
        if let Err(e) = state.db.set_local_presence(user_nid, &rec) {
            tracing::warn!(user_nid, error = %e, "sweeper: set_local_presence failed");
            continue;
        }
        state.federation_sender.notify_user_subscribers(user_nid);
        stats.transitioned += 1;
        tracing::debug!(
            user_nid,
            from = %stored,
            to = effective,
            "presence sweeper transition"
        );
    }

    if stats.transitioned > 0 {
        tracing::debug!(
            scanned = stats.scanned,
            transitioned = stats.transitioned,
            "presence sweeper tick"
        );
    }
    Ok(stats)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SweepStats {
    pub scanned: u64,
    pub transitioned: u64,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
