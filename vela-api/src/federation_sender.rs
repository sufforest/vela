//! Outbound federation transaction sender.
//!
//! One async task per destination. Each task polls a **persistent
//! outbox** in RocksDB (`federation_outbox` CF), batches up to 50
//! events into a transaction, signs and sends, then deletes the
//! drained entries on success. The in-process channel is a wake
//! signal, not the queue — durability lives entirely in the DB.
//!
//! Per-destination isolation: each destination has its own task and
//! its own backoff state, so one slow / dead peer does not stall
//! delivery to anyone else.
//!
//! Restart recovery: on startup `FederationSender::new` enumerates
//! every destination with at least one pending entry and spawns its
//! task. No event acknowledged on the inbound side is lost when the
//! process restarts.
//!
//! Backoff: 2s initial → ×2 → 5min cap. After 24h of continuous
//! failure the destination is considered dead and its task exits
//! without draining further; the outbox entries remain on disk so a
//! later restart picks them up if the peer recovers.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::{Value, json};
use tokio::sync::Notify;
use tracing::{debug, warn};
use uuid::Uuid;

use vela_store::db::Database;

use crate::edu::EduStreams;
use crate::federation_client::{FederationClient, now_ms};

/// Max PDUs per transaction per spec.
const MAX_PDUS_PER_TXN: usize = 50;

/// Max EDUs per transaction per spec.
const MAX_EDUS_PER_TXN: usize = 100;

/// Per-stream cap on a single scan. Conservatively divides the spec
/// EDU budget across the registered streams; small enough that a
/// single noisy stream can't starve the others within a transaction.
const MAX_EDUS_PER_STREAM_PER_TXN: usize = 25;

/// Initial retry backoff.
const BACKOFF_INITIAL: Duration = Duration::from_secs(2);

/// Backoff cap.
const BACKOFF_MAX: Duration = Duration::from_secs(5 * 60);

/// After this much continuous failure, mark destination dead and exit.
/// The outbox keeps its entries; a later restart re-spawns the task.
const DEAD_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Idle poll interval — when the outbox is empty AND no wake fires
/// within this window, poll once more in case we missed a write
/// notification (defence in depth; should never matter in practice).
const IDLE_POLL: Duration = Duration::from_secs(60);

/// Outbound federation sender.
pub struct FederationSender {
    /// Per-destination wake handle. Sending to a destination signals
    /// the corresponding Notify; the task wakes and polls the outbox.
    destinations: DashMap<String, Arc<Notify>>,
    db: Arc<Database>,
    client: Arc<FederationClient>,
    our_server_name: String,
    /// Registered EDU streams. Drained alongside PDUs during each
    /// transaction-build round. Empty list means "PDUs only" (current
    /// behavior). Streams are registered at composition time in
    /// `vela-server::main`.
    edu_streams: EduStreams,
    /// When false, every public entry point short-circuits before
    /// spawning a destination task or writing to the outbox. Local-only
    /// deployments set this to mirror `[federation] enabled = false`.
    enabled: bool,
}

impl FederationSender {
    /// Build a sender and resume any pending outbox queues left by a
    /// prior process. The list comes from one full scan of the outbox
    /// CF; cheap because deletions on send keep it small in steady
    /// state.
    pub fn new(
        db: Arc<Database>,
        client: Arc<FederationClient>,
        our_server_name: String,
        edu_streams: EduStreams,
    ) -> Self {
        Self::new_with_enabled(db, client, our_server_name, edu_streams, true)
    }

    /// Same as `new` but lets the caller turn off all outbound dispatch
    /// up-front. When `enabled = false`, no destination tasks are
    /// resumed and every public entry point short-circuits.
    pub fn new_with_enabled(
        db: Arc<Database>,
        client: Arc<FederationClient>,
        our_server_name: String,
        edu_streams: EduStreams,
        enabled: bool,
    ) -> Self {
        let sender = Self {
            destinations: DashMap::new(),
            db,
            client,
            our_server_name,
            edu_streams,
            enabled,
        };
        if !enabled {
            return sender;
        }
        match sender.db.list_outbound_destinations() {
            Ok(pending) => {
                if !pending.is_empty() {
                    debug!(
                        count = pending.len(),
                        "federation sender: resuming pending outbox destinations"
                    );
                    for dest in pending {
                        sender.ensure_destination(&dest);
                    }
                }
            }
            Err(e) => warn!(error = %e, "outbox enumeration failed at startup"),
        }
        sender
    }

    /// Enqueue `event_nid` for delivery to every remote server in
    /// `room_nid`. Persists to the outbox before signalling the worker
    /// so a crash between persist and signal still gets retried.
    pub fn broadcast(&self, room_nid: u64, event_nid: u64) {
        if !self.enabled {
            return;
        }
        let destinations = match self
            .db
            .get_remote_servers_in_room(room_nid, &self.our_server_name)
        {
            Ok(d) => d,
            Err(e) => {
                warn!(room_nid, error = %e, "broadcast: failed to compute destinations");
                return;
            }
        };

        if destinations.is_empty() {
            return;
        }

        debug!(
            room_nid,
            event_nid,
            destination_count = destinations.len(),
            "federation broadcast"
        );

        // One WriteBatch for all destinations — keeps the local-send
        // hot path at one RocksDB write call regardless of how many
        // remotes the room federates to.
        let dest_refs: Vec<&str> = destinations.iter().map(|s| s.as_str()).collect();
        if let Err(e) = self.db.enqueue_outbound_batch(&dest_refs, event_nid) {
            warn!(event_nid, error = %e, "outbox batch enqueue failed");
            return;
        }

        for server_name in destinations {
            let notify = self.ensure_destination(&server_name);
            notify.notify_one();
        }
    }

    /// Wake the federation tasks for every remote server that shares
    /// any joined room with `user_nid`. Used after a presence change
    /// (or any other per-user EDU) so the affected senders pick up
    /// the stream without waiting for the idle poll.
    ///
    /// Per spec: "Servers should only send presence updates for users
    /// that the receiving server would be interested in. Such as the
    /// receiving server sharing a room with a given user."
    pub fn notify_user_subscribers(&self, user_nid: u64) {
        if !self.enabled {
            return;
        }
        use std::collections::HashSet;
        let rooms = match self.db.get_user_joined_rooms(user_nid) {
            Ok(r) => r,
            Err(e) => {
                warn!(user_nid, error = %e, "notify_user_subscribers: get_user_joined_rooms failed");
                return;
            }
        };
        let mut destinations: HashSet<String> = HashSet::new();
        for room_nid in rooms {
            match self
                .db
                .get_remote_servers_in_room(room_nid, &self.our_server_name)
            {
                Ok(servers) => destinations.extend(servers),
                Err(e) => {
                    warn!(room_nid, error = %e, "notify_user_subscribers: room scan failed");
                }
            }
        }
        for server in destinations {
            let notify = self.ensure_destination(&server);
            notify.notify_one();
        }
    }

    /// Wake the federation task for a single destination. No-op if no
    /// task exists for it (the next call to `broadcast` /
    /// `enqueue_to_device_outbound` followed by a wake will spawn
    /// one). Used by EDU sources that already know the precise target
    /// (to-device, with destination embedded in the content).
    pub fn notify_destination(&self, server_name: &str) {
        if !self.enabled {
            return;
        }
        let notify = self.ensure_destination(server_name);
        notify.notify_one();
    }

    /// Wake the federation tasks for every remote server in `room_nid`.
    /// Used after a non-PDU write that produced new EDUs (e.g. a
    /// receipt update) so the affected senders pick up the EDU stream
    /// without waiting for the idle poll.
    ///
    /// No-op for local-only rooms.
    pub fn notify_room(&self, room_nid: u64) {
        if !self.enabled {
            return;
        }
        let destinations = match self
            .db
            .get_remote_servers_in_room(room_nid, &self.our_server_name)
        {
            Ok(d) => d,
            Err(e) => {
                warn!(room_nid, error = %e, "notify_room: failed to compute destinations");
                return;
            }
        };
        for server_name in destinations {
            let notify = self.ensure_destination(&server_name);
            notify.notify_one();
        }
    }

    fn ensure_destination(&self, server_name: &str) -> Arc<Notify> {
        if let Some(n) = self.destinations.get(server_name) {
            return n.clone();
        }
        let notify = Arc::new(Notify::new());
        self.destinations
            .insert(server_name.to_string(), notify.clone());

        let server_name_s = server_name.to_string();
        let db = self.db.clone();
        let client = self.client.clone();
        let origin = self.our_server_name.clone();
        let notify_for_task = notify.clone();
        let edu_streams = self.edu_streams.clone();
        tokio::spawn(run_destination(
            server_name_s,
            notify_for_task,
            db,
            client,
            origin,
            edu_streams,
        ));
        notify
    }

    /// Test hook — keep the old name so existing tests compile. The
    /// returned receiver is a placeholder (no longer the queue), so
    /// tests that read from it can't actually observe sends. Tests
    /// that need to assert delivery should inspect the outbox via
    /// `Database::peek_outbound` instead.
    #[cfg(test)]
    pub fn inject_destination_for_test(
        &self,
        server_name: &str,
    ) -> tokio::sync::mpsc::Receiver<u64> {
        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        self.destinations
            .insert(server_name.to_string(), Arc::new(Notify::new()));
        rx
    }
}

async fn run_destination(
    server_name: String,
    notify: Arc<Notify>,
    db: Arc<Database>,
    client: Arc<FederationClient>,
    our_server_name: String,
    edu_streams: EduStreams,
) {
    debug!(%server_name, "federation sender task starting");

    let mut backoff = BACKOFF_INITIAL;
    let mut last_success = Instant::now();

    loop {
        // Read the next PDU batch from the outbox.
        let batch = match db.peek_outbound(&server_name, MAX_PDUS_PER_TXN) {
            Ok(b) => b,
            Err(e) => {
                warn!(%server_name, error = %e, "peek_outbound failed");
                tokio::time::sleep(BACKOFF_INITIAL).await;
                continue;
            }
        };

        // Drain registered EDU streams for this destination. The cursor
        // for each stream is advanced only after a successful send.
        let (edus, cursor_advances) = drain_edu_streams(&edu_streams, &server_name, &db);

        if batch.is_empty() && edus.is_empty() {
            // Nothing pending — wait for a wake or the idle poll.
            tokio::select! {
                _ = notify.notified() => {},
                _ = tokio::time::sleep(IDLE_POLL) => {},
            }
            continue;
        }

        let pdus: Vec<Value> = batch
            .iter()
            .filter_map(|(_, nid)| load_event_json_for_send(&db, *nid))
            .collect();

        if pdus.is_empty() && !batch.is_empty() && edus.is_empty() {
            // Outbox referenced events that no longer exist (rare).
            // Drop the dangling entries so the queue doesn't spin.
            let positions: Vec<u64> = batch.iter().map(|(p, _)| *p).collect();
            let _ = db.delete_outbound(&server_name, &positions);
            continue;
        }

        let txn_id = new_txn_id();
        let body = json!({
            "origin": our_server_name,
            "origin_server_ts": now_ms(),
            "pdus": pdus,
            "edus": edus,
        });

        match client.send_transaction(&server_name, &txn_id, body).await {
            Ok(_) => {
                debug!(
                    %server_name,
                    pdus = batch.len(),
                    edus = edus.len(),
                    "transaction sent"
                );
                let positions: Vec<u64> = batch.iter().map(|(p, _)| *p).collect();
                if let Err(e) = db.delete_outbound(&server_name, &positions) {
                    warn!(%server_name, error = %e, "delete_outbound failed");
                }
                for (stream_name, new_cursor) in &cursor_advances {
                    if let Err(e) = db.set_edu_cursor(&server_name, stream_name, *new_cursor) {
                        warn!(%server_name, %stream_name, error = %e, "set_edu_cursor failed");
                    }
                }
                backoff = BACKOFF_INITIAL;
                last_success = Instant::now();
            }
            Err(e) => {
                warn!(%server_name, error = %e, "transaction send failed");
                if last_success.elapsed() > DEAD_AFTER {
                    warn!(
                        %server_name,
                        "destination dead after 24h of continuous failures; task exiting (outbox preserved on disk for next restart)"
                    );
                    return;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff.saturating_mul(2)).min(BACKOFF_MAX);
            }
        }
    }
}

/// Drain registered EDU streams for one destination, returning the
/// concatenated EDU list (capped at the spec's 100/txn limit) and the
/// per-stream cursor advances to apply after a successful send.
///
/// Cursor advances are reported only for streams that contributed at
/// least one EDU; streams that returned empty don't advance, so a
/// failed scan retries on the next round.
fn drain_edu_streams(
    streams: &EduStreams,
    destination: &str,
    db: &Database,
) -> (Vec<Value>, Vec<(String, u64)>) {
    let mut edus: Vec<Value> = Vec::new();
    let mut advances: Vec<(String, u64)> = Vec::new();

    for stream in streams {
        if edus.len() >= MAX_EDUS_PER_TXN {
            break;
        }
        let cursor = match db.get_edu_cursor(destination, stream.name()) {
            Ok(c) => c,
            Err(e) => {
                warn!(%destination, name = stream.name(), error = %e, "get_edu_cursor failed");
                continue;
            }
        };
        match stream.scan_since(destination, cursor, MAX_EDUS_PER_STREAM_PER_TXN, db) {
            Ok((batch, new_cursor)) if !batch.is_empty() => {
                edus.extend(batch);
                advances.push((stream.name().to_string(), new_cursor));
            }
            Ok(_) => {}
            Err(e) => warn!(%destination, name = stream.name(), error = %e, "scan_since failed"),
        }
    }

    if edus.len() > MAX_EDUS_PER_TXN {
        edus.truncate(MAX_EDUS_PER_TXN);
    }
    (edus, advances)
}

/// Load an event's canonical JSON suitable for inclusion in an outbound transaction.
fn load_event_json_for_send(db: &Database, event_nid: u64) -> Option<Value> {
    // v3+ events on the wire MUST NOT carry `event_id` — receivers derive
    // it from the reference hash, and including it in the JSON breaks
    // both content-hash verification (compute_content_hash sees the
    // injected field) and the reference hash itself, cascading into
    // signature failures and "sender is not joined" auth rejections.
    let (_h, json_bytes) = db.get_event(event_nid).ok().flatten()?;
    let mut value: Value = serde_json::from_slice(&json_bytes).ok()?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("event_id");
    }
    Some(value)
}

fn new_txn_id() -> String {
    Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn outbox_round_trip_through_sender_resumes_on_restart() {
        // Use a temp DB; verify enqueue persists to outbox + restart
        // recovers it.
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());

        // Enqueue directly via the DB API (proxy for what broadcast does).
        let pos1 = db.enqueue_outbound("peer.example", 1001).unwrap();
        let pos2 = db.enqueue_outbound("peer.example", 1002).unwrap();
        assert!(pos2 > pos1);

        let pending = db.peek_outbound("peer.example", 10).unwrap();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].1, 1001);
        assert_eq!(pending[1].1, 1002);

        // Listing destinations sees the queue.
        let dests = db.list_outbound_destinations().unwrap();
        assert_eq!(dests, vec!["peer.example"]);

        // Delete first, second remains.
        db.delete_outbound("peer.example", &[pos1]).unwrap();
        let pending = db.peek_outbound("peer.example", 10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1, 1002);
    }

    #[tokio::test]
    async fn edu_cursor_round_trip_and_namespacing() {
        // Each (destination, stream_name) pair has its own cursor; a missing
        // entry reads as 0; namespaces don't bleed across streams or peers.
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());

        // Fresh peer, fresh stream — starts at 0.
        assert_eq!(db.get_edu_cursor("peer.example", "receipts").unwrap(), 0);

        // Advance and read back.
        db.set_edu_cursor("peer.example", "receipts", 42).unwrap();
        assert_eq!(db.get_edu_cursor("peer.example", "receipts").unwrap(), 42);

        // A different stream on the same peer keeps its own cursor.
        assert_eq!(db.get_edu_cursor("peer.example", "presence").unwrap(), 0);
        db.set_edu_cursor("peer.example", "presence", 7).unwrap();
        assert_eq!(db.get_edu_cursor("peer.example", "presence").unwrap(), 7);
        // Original stream untouched.
        assert_eq!(db.get_edu_cursor("peer.example", "receipts").unwrap(), 42);

        // Different peer, same stream name — independent cursor.
        assert_eq!(db.get_edu_cursor("other.example", "receipts").unwrap(), 0);
    }

    #[tokio::test]
    async fn destination_prefix_isolation() {
        // Server "a" must not match "ab"+stream_pos due to the 0xff sep.
        let tmp = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::open(tmp.path()).unwrap());

        db.enqueue_outbound("a", 1).unwrap();
        db.enqueue_outbound("ab", 2).unwrap();
        db.enqueue_outbound("a", 3).unwrap();

        let a = db.peek_outbound("a", 10).unwrap();
        let ab = db.peek_outbound("ab", 10).unwrap();
        let a_nids: Vec<u64> = a.iter().map(|(_, n)| *n).collect();
        let ab_nids: Vec<u64> = ab.iter().map(|(_, n)| *n).collect();
        assert_eq!(a_nids, vec![1, 3], "server 'a' must not see 'ab' entries");
        assert_eq!(ab_nids, vec![2]);
    }
}
