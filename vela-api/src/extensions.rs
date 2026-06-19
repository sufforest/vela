//! Async observation path for WASM extensions.
//!
//! The `check_event` decision hook runs inline on the request path (see
//! [`crate::room::send`]); the `on_event` observation hook does not. Once a
//! locally-sent event is persisted, it's pushed onto a durable queue
//! (`wasm_observe_queue`) and a single background worker drains it off the
//! request path, running every `on_event`-bound plugin under the same sandbox
//! bounds. An observer returns no verdict and can't block.
//!
//! Delivery is best-effort with a few deliberate properties:
//! - **At-least-once for queued entries.** An entry is popped only after the
//!   plugins have run, so a crash in between re-runs it on restart. Observers
//!   must therefore be idempotent.
//! - **The enqueue itself is not atomic with persist.** A crash in the narrow
//!   window between persisting an event and queuing it drops that one
//!   observation — acceptable for observation (it isn't moderation; that's the
//!   inline decision path).
//! - **Bounded.** The queue is capped ([`MAX_DEPTH`]); if the worker stalls or
//!   falls far behind, the oldest entries are shed (and logged) so a stuck
//!   observer can't grow the on-disk queue without limit.
//! - **No single entry can wedge it.** A plugin trap, a host-side panic, and a
//!   malformed entry are each absorbed and the entry is popped regardless.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::sync::Notify;
use tracing::{debug, warn};

use vela_extensions::{EventContext, Origin, Runtime};
use vela_store::db::Database;

/// Cap on queued-but-undrained observations. Reaching it means the worker is
/// stalled or hopelessly behind; past it, the oldest entries are shed so the
/// on-disk queue stays bounded. Generous — it only trips in a genuine wedge or
/// sustained overload, where observations are already stale.
const MAX_DEPTH: u64 = 100_000;

/// One queued observation — enough to rebuild an [`EventContext`] at drain
/// time. Origin is always `Local`: only locally-sent events are observed today.
#[derive(Serialize, Deserialize)]
struct ObserveEntry {
    event: Value,
    room_id: String,
    sender: String,
    event_type: String,
}

/// Handle to the observation queue: a global sequence counter, an approximate
/// depth gauge for the backpressure cap, and a worker wake. Cheap to clone
/// (Arcs); held in `AppState` so the send path can enqueue, and cloned into the
/// background worker at startup.
#[derive(Clone)]
pub struct ObserveQueue {
    next_seq: Arc<AtomicU64>,
    depth: Arc<AtomicU64>,
    notify: Arc<Notify>,
}

impl ObserveQueue {
    /// Build the handle, priming the sequence counter past any entries a
    /// previous run left on disk (so ids are never reused) and the depth gauge
    /// to the number of those entries (so the cap accounts for them).
    pub fn new(db: &Database) -> Self {
        let (max, count) = db.observe_queue_bounds().unwrap_or((None, 0));
        Self {
            next_seq: Arc::new(AtomicU64::new(max.unwrap_or(0) + 1)),
            depth: Arc::new(AtomicU64::new(count)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Persist one observed event and wake the worker. Called from the send
    /// path after persist, only when some plugin binds `on_event`.
    ///
    /// Best-effort: the event is already persisted and federated, so a failure
    /// to enqueue is logged and swallowed — it must never fail the client's
    /// send. The cost paid here is one RocksDB put; running the plugins happens
    /// off the request path in the worker.
    pub fn enqueue(
        &self,
        db: &Database,
        event: &Map<String, Value>,
        room_id: &str,
        sender: &str,
        event_type: &str,
    ) {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let entry = ObserveEntry {
            event: Value::Object(event.clone()),
            room_id: room_id.to_string(),
            sender: sender.to_string(),
            event_type: event_type.to_string(),
        };
        let value = serde_json::to_value(&entry).unwrap_or(json!(null));
        if let Err(e) = db.push_observe_queue(seq, &value) {
            warn!(error = %e, room_id, "extensions: failed to enqueue observation; on_event skipped for this event");
            return;
        }
        let depth = self.depth.fetch_add(1, Ordering::Relaxed) + 1;
        self.notify.notify_one();
        // Backpressure: a healthy worker keeps depth near zero, so this only
        // fires when it's stalled or badly behind. Shed the oldest so the
        // on-disk queue can't grow without bound.
        if depth > MAX_DEPTH {
            self.shed_oldest(db, depth - MAX_DEPTH);
        }
    }

    /// Drop the `n` oldest entries to bring the queue back under the cap.
    /// Approximate (it races the worker's own pops, which is harmless — pops
    /// are idempotent and the depth gauge saturates), and logged once so a
    /// shedding queue is never silent.
    fn shed_oldest(&self, db: &Database, n: u64) {
        let mut dropped = 0u64;
        for _ in 0..n {
            match db.peek_observe_queue() {
                Ok(Some((seq, _))) => {
                    let _ = db.pop_observe_queue(seq);
                    self.dec_depth();
                    dropped += 1;
                }
                _ => break,
            }
        }
        if dropped > 0 {
            warn!(
                dropped,
                cap = MAX_DEPTH,
                "extensions: observation queue over cap (worker stalled or behind); shed oldest observations"
            );
        }
    }

    /// Decrement the depth gauge without underflowing (the shed path and the
    /// worker can both decrement for an entry under a race).
    fn dec_depth(&self) {
        let _ = self
            .depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |d| {
                Some(d.saturating_sub(1))
            });
    }

    /// Drain one queued observation: peek the oldest entry, run every
    /// `on_event`-bound plugin under `runtime`, then pop it. Returns `Ok(true)`
    /// if it processed an entry and `Ok(false)` if the queue was empty.
    ///
    /// No single entry can wedge the queue: a plugin **trap** is absorbed inside
    /// [`Runtime::on_event`], a host-side **panic** is caught here, and a
    /// **malformed** entry is logged — in every case the entry is still popped.
    /// Synchronous (runs wasm); callers run it off the async runtime via
    /// `spawn_blocking`.
    pub fn drain_one(&self, db: &Database, runtime: &Runtime) -> Result<bool, rocksdb::Error> {
        let Some((seq, value)) = db.peek_observe_queue()? else {
            return Ok(false);
        };
        match serde_json::from_value::<ObserveEntry>(value) {
            Ok(entry) => {
                let ctx = EventContext {
                    event: &entry.event,
                    room_id: &entry.room_id,
                    sender: &entry.sender,
                    event_type: &entry.event_type,
                    origin: Origin::Local,
                };
                // A trap is already absorbed in on_event; catch a host-layer
                // panic too so a deterministically-panicking entry drops rather
                // than wedging the queue (it's popped below regardless).
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.on_event(&ctx)))
                    .is_err()
                {
                    warn!(
                        seq,
                        "extensions: observation host call panicked; dropping this entry"
                    );
                }
            }
            Err(e) => warn!(seq, error = %e, "extensions: observation entry malformed; dropping"),
        }
        db.pop_observe_queue(seq)?;
        self.dec_depth();
        Ok(true)
    }

    /// Spawn the long-lived worker that drains the queue and runs `on_event`
    /// plugins. Reads the current plugin set from `extensions` per drain, so a
    /// SIGHUP reload is picked up immediately. The worker is always running
    /// (cheap when idle) so a reload that *adds* an `on_event` plugin starts
    /// being observed without a restart.
    pub fn spawn_worker(
        &self,
        db: Arc<Database>,
        extensions: Arc<arc_swap::ArcSwap<Runtime>>,
    ) -> tokio::task::JoinHandle<()> {
        let queue = self.clone();
        tokio::spawn(async move { run_worker(queue, db, extensions).await })
    }
}

async fn run_worker(
    queue: ObserveQueue,
    db: Arc<Database>,
    extensions: Arc<arc_swap::ArcSwap<Runtime>>,
) {
    debug!("extension observation worker started");
    let notify = queue.notify.clone();
    loop {
        // Snapshot the live plugin set for this drain; wasm runs on a blocking
        // thread so it never ties up an async worker for its wall-clock budget.
        let runtime = extensions.load_full();
        let db2 = db.clone();
        let q = queue.clone();
        match tokio::task::spawn_blocking(move || q.drain_one(&db2, &runtime)).await {
            Ok(Ok(true)) => continue, // more may be queued — keep draining
            Ok(Ok(false)) => notify.notified().await,
            Ok(Err(e)) => {
                // A drain (peek/pop) error means the DB is unhealthy; back off
                // rather than busy-loop. drain_one catches plugin traps and
                // panics itself, so this arm is only reached for store errors.
                warn!(error = %e, "extensions: observation drain failed; retrying shortly");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                // spawn_blocking itself failed (e.g. runtime shutting down).
                warn!(error = %e, "extensions: observation drain task failed to join; retrying shortly");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(all(test, feature = "extensions"))]
mod tests {
    use super::*;
    use vela_extensions::{FailPolicy, PluginConfig, Points};

    const SPAM_FIXTURE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vela-extensions/tests/fixtures/spam_guest.wasm"
    ));

    fn observer_runtime(mode: &str) -> Runtime {
        Runtime::new(vec![PluginConfig {
            name: "obs".into(),
            wasm: SPAM_FIXTURE.to_vec(),
            fail_policy: FailPolicy::Open,
            fuel: 5_000_000,
            wall_ms: 0,
            memory_pages: 256,
            event_types: None,
            points: Points {
                check_event: false,
                on_event: true,
            },
            config: json!({ "mode": mode }),
        }])
        .expect("observer runtime loads")
    }

    fn temp_db() -> (Arc<Database>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let db = Arc::new(Database::open(tmp.path()).expect("db open"));
        (db, tmp)
    }

    fn message(body: &str) -> Map<String, Value> {
        json!({ "type": "m.room.message", "content": { "msgtype": "m.text", "body": body } })
            .as_object()
            .unwrap()
            .clone()
    }

    fn enq(q: &ObserveQueue, db: &Database, body: &str) {
        q.enqueue(
            db,
            &message(body),
            "!r:example.org",
            "@a:example.org",
            "m.room.message",
        );
    }

    #[test]
    fn enqueue_then_drain_runs_in_order_and_clears() {
        let (db, _tmp) = temp_db();
        let rt = observer_runtime("allow");
        let q = ObserveQueue::new(&db);

        enq(&q, &db, "first");
        enq(&q, &db, "second");

        // FIFO: the oldest entry surfaces first; draining runs the observer.
        let (seq1, _) = db.peek_observe_queue().unwrap().expect("first queued");
        assert!(q.drain_one(&db, &rt).unwrap());
        let (seq2, _) = db
            .peek_observe_queue()
            .unwrap()
            .expect("second still queued");
        assert!(seq2 > seq1, "second event must sort after the first");
        assert!(q.drain_one(&db, &rt).unwrap());

        // Drained dry.
        assert!(db.peek_observe_queue().unwrap().is_none());
        assert!(
            !q.drain_one(&db, &rt).unwrap(),
            "empty queue drains to false"
        );
    }

    #[test]
    fn a_trapping_observer_does_not_wedge_the_queue() {
        // An observer that burns all its fuel (infinite loop) traps. Because an
        // observer can't block, the trap is absorbed and the entry is popped
        // anyway — a malicious or buggy plugin can't stall the queue behind it.
        let (db, _tmp) = temp_db();
        let rt = observer_runtime("loop");
        let q = ObserveQueue::new(&db);
        enq(&q, &db, "hi");

        assert!(q.drain_one(&db, &rt).unwrap());
        assert!(
            db.peek_observe_queue().unwrap().is_none(),
            "a trapped observer must not wedge the queue"
        );
    }

    #[test]
    fn malformed_entry_is_dropped_not_wedged() {
        // A JSON-but-wrong-shape entry (e.g. left by an older/newer encoding)
        // must be logged and popped, never re-peeked forever.
        let (db, _tmp) = temp_db();
        let rt = observer_runtime("allow");
        let q = ObserveQueue::new(&db);
        db.push_observe_queue(1, &json!({ "not": "an observe entry" }))
            .unwrap();

        assert!(q.drain_one(&db, &rt).unwrap(), "a bad entry still drains");
        assert!(
            db.peek_observe_queue().unwrap().is_none(),
            "malformed entry must be popped, not wedge the queue"
        );
    }

    #[test]
    fn queue_is_bounded_when_the_worker_never_drains() {
        // Simulate a wedged worker: enqueue past the cap without draining. The
        // on-disk queue must stay bounded — the oldest are shed.
        let (db, _tmp) = temp_db();
        let q = ObserveQueue::new(&db);
        for i in 0..(MAX_DEPTH + 200) {
            enq(&q, &db, &format!("event {i}"));
        }
        let (_, count) = db.observe_queue_bounds().unwrap();
        assert!(
            count <= MAX_DEPTH,
            "queue must stay bounded by the cap, got {count}"
        );
    }

    #[test]
    fn restart_does_not_reuse_an_undrained_seq() {
        // A fresh handle over a db with a queued-but-undrained entry must prime
        // its counter past it, so a crash-and-restart never collides seqs.
        let (db, _tmp) = temp_db();
        let q1 = ObserveQueue::new(&db);
        enq(&q1, &db, "before restart");
        let (seq1, _) = db.peek_observe_queue().unwrap().expect("one queued");

        let q2 = ObserveQueue::new(&db); // simulates a restart
        enq(&q2, &db, "after restart");
        db.pop_observe_queue(seq1).unwrap();

        let (seq2, _) = db
            .peek_observe_queue()
            .unwrap()
            .expect("post-restart entry");
        assert!(seq2 > seq1, "restart must not reuse an undrained seq");
    }
}
