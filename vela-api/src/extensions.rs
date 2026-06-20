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
//! - **Bounded.** The queue is capped (`MAX_DEPTH`); if the worker stalls or
//!   falls far behind, the oldest entries are shed (and logged) so a stuck
//!   observer can't grow the on-disk queue without limit.
//! - **No single entry can wedge it.** A plugin trap, a host-side panic, and a
//!   malformed entry are each absorbed and the entry is popped regardless.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tracing::{debug, warn};
use vela_core::error::VelaError;

use vela_extensions::{
    EmitError, EmitRequest, EventContext, EventEmitter, KvError, KvStore, Origin, Runtime,
};
use vela_store::db::Database;

use crate::router::AppState;

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

/// vela-api's implementation of the extension `emit-event` capability. Resolves
/// a plugin's `@_ext_<name>` bot user (creating it on first use) and emits
/// through the shared `crate::admin::emit_event_as` path, so emitted events go
/// through normal room authorization — the bot must be joined with power level.
///
/// The trait method is synchronous (it's called from the sandbox's blocking
/// observation-worker thread), so it drives the async emit via `block_on` on a
/// captured runtime handle — legal because the caller is a blocking-pool thread,
/// not an async worker.
///
/// `AppState` is filled in via [`set_state`](Self::set_state) *after*
/// construction: the runtime holds this emitter and `AppState` holds the
/// runtime, so the emitter is built first (empty) and wired once `AppState`
/// exists.
pub struct ApiEventEmitter {
    state: OnceLock<AppState>,
    handle: Handle,
}

impl ApiEventEmitter {
    /// Build an emitter bound to the current tokio runtime. Call from async
    /// context (e.g. server startup) so `Handle::current()` is valid.
    pub fn new() -> Arc<Self> {
        Arc::new(ApiEventEmitter {
            state: OnceLock::new(),
            handle: Handle::current(),
        })
    }

    /// Provide the `AppState` once it's been constructed.
    pub fn set_state(&self, state: AppState) {
        let _ = self.state.set(state);
    }
}

impl EventEmitter for ApiEventEmitter {
    fn emit(&self, plugin: &str, req: EmitRequest) -> Result<String, EmitError> {
        let Some(state) = self.state.get() else {
            warn!("extensions: emit called before AppState was wired");
            return Err(EmitError::Internal);
        };
        let state = state.clone();
        let plugin = plugin.to_string();
        self.handle
            .block_on(async move { emit_for_plugin(&state, &plugin, req).await })
    }
}

async fn emit_for_plugin(
    state: &AppState,
    plugin: &str,
    req: EmitRequest,
) -> Result<String, EmitError> {
    let bot_user_id = format!("@_ext_{plugin}:{}", state.config.server_name);
    let bot_nid = ensure_plugin_bot(state, &bot_user_id).map_err(|e| {
        warn!(plugin, error = %e, "extensions: failed to provision plugin bot");
        EmitError::Internal
    })?;

    // Resolve the target room. An unknown room → not-permitted (nothing to join).
    let room_nid = match state.db.get_nid(&req.room_id) {
        Ok(Some(n)) => n,
        _ => {
            return Err(EmitError::NotPermitted(format!(
                "unknown room {}",
                req.room_id
            )));
        }
    };

    match crate::admin::emit_event_as(
        state,
        room_nid,
        bot_nid,
        &bot_user_id,
        &req.event_type,
        req.content,
        req.state_key.as_deref(),
    )
    .await
    {
        Ok(event_id) => Ok(event_id.as_str().to_string()),
        // A room-auth rejection (bot not joined / lacks power level) is the
        // expected, operator-fixable case; everything else is internal.
        Err(e) => match e.0 {
            VelaError::Forbidden(reason) => {
                debug!(plugin, %reason, "extensions: emit unauthorized");
                Err(EmitError::Unauthorized)
            }
            other => {
                warn!(plugin, error = %other, "extensions: emit failed");
                Err(EmitError::Internal)
            }
        },
    }
}

/// Resolve a plugin bot's `user_nid`, creating the (passwordless, never-logs-in)
/// bot user on first use. Idempotent. Serialized in practice by the single
/// observation worker, so no create race.
fn ensure_plugin_bot(state: &AppState, bot_user_id: &str) -> Result<u64, rocksdb::Error> {
    let nid = state.db.get_or_create_nid(bot_user_id)?;
    // `get_or_create_nid` just created the nid mapping, so check the users-CF
    // record itself (keyed by nid) to decide whether to provision — mirrors the
    // admin-bot bootstrap. (Checking `user_exists`, which tests the nid mapping,
    // would always be true here and never create the record.)
    if state.db.get_user(nid)?.is_none() {
        state.db.create_user(bot_user_id, "")?;
        debug!(bot = bot_user_id, "extensions: provisioned plugin bot user");
    }
    Ok(nid)
}

/// Per-plugin byte budget for the `kv` capability — the reject-on-full backstop
/// (TTL is the routine space manager). Generous for counter/flag workloads;
/// bounded so N granted plugins can't surprise an operator on disk.
const KV_QUOTA_BYTES: u64 = 4 * 1024 * 1024;

/// vela-api's implementation of the extension `kv` capability. A thin layer over
/// the `wasm_kv` store: resolves the plugin's namespace nid, converts a relative
/// TTL to an absolute deadline against the wall clock, and serializes writes
/// per plugin (the store's quota read-modify-write isn't internally locked).
/// Synchronous — kv has no async, so no `block_on` and no `AppState` needed.
pub struct ApiKvStore {
    db: Arc<Database>,
    /// plugin name → its `wasm_kv` namespace nid (cache; the nid is stable).
    nids: dashmap::DashMap<String, u64>,
    /// Per-plugin write lock, keyed by namespace nid.
    locks: dashmap::DashMap<u64, Arc<std::sync::Mutex<()>>>,
}

impl ApiKvStore {
    pub fn new(db: Arc<Database>) -> Arc<Self> {
        Arc::new(ApiKvStore {
            db,
            nids: dashmap::DashMap::new(),
            locks: dashmap::DashMap::new(),
        })
    }

    /// Stable namespace nid for a plugin (cached). Derived from a synthetic id so
    /// it never collides with a real user/room nid.
    fn nid(&self, plugin: &str) -> Result<u64, KvError> {
        if let Some(n) = self.nids.get(plugin) {
            return Ok(*n);
        }
        let n = self
            .db
            .get_or_create_nid(&format!("ext_kv:{plugin}"))
            .map_err(|_| KvError::Internal)?;
        self.nids.insert(plugin.to_string(), n);
        Ok(n)
    }

    fn lock(&self, nid: u64) -> Arc<std::sync::Mutex<()>> {
        self.locks
            .entry(nid)
            .or_insert_with(|| Arc::new(std::sync::Mutex::new(())))
            .clone()
    }

    /// The TTL sweep: reap expired entries and heal the quota gauge, one plugin
    /// at a time, **each under that plugin's write lock** so the gauge rewrite
    /// can't race a concurrent `set`/`delete`. Run periodically off the async
    /// runtime (it does blocking scans). Returns the total reaped.
    pub fn sweep(&self) -> u64 {
        let now = now_ms();
        let plugins = match self.db.kv_quota_plugins() {
            Ok(p) => p,
            Err(_) => return 0,
        };
        let mut total = 0;
        for nid in plugins {
            let lock = self.lock(nid);
            let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
            total += self.db.kv_sweep_plugin(nid, now).unwrap_or(0);
        }
        total
    }
}

impl KvStore for ApiKvStore {
    fn get(&self, plugin: &str, key: &[u8]) -> Result<Option<Vec<u8>>, KvError> {
        let nid = self.nid(plugin)?;
        self.db
            .kv_get(nid, key, now_ms())
            .map_err(|_| KvError::Internal)
    }

    fn set(
        &self,
        plugin: &str,
        key: &[u8],
        value: &[u8],
        ttl_ms: Option<u64>,
    ) -> Result<(), KvError> {
        let nid = self.nid(plugin)?;
        let expiry = match ttl_ms {
            Some(t) if t > 0 => now_ms().saturating_add(t),
            _ => 0,
        };
        let lock = self.lock(nid);
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
        match self.db.kv_set(nid, key, value, expiry, KV_QUOTA_BYTES) {
            Ok(true) => Ok(()),
            Ok(false) => Err(KvError::QuotaExceeded),
            Err(_) => Err(KvError::Internal),
        }
    }

    fn delete(&self, plugin: &str, key: &[u8]) -> Result<(), KvError> {
        let nid = self.nid(plugin)?;
        let lock = self.lock(nid);
        let _g = lock.lock().unwrap_or_else(|e| e.into_inner());
        self.db.kv_delete(nid, key).map_err(|_| KvError::Internal)
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
                check_registration: false,
            },
            capabilities: vela_extensions::Capabilities::default(),
            client_ip: vela_extensions::ClientIpTier::default(),
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

    #[test]
    fn api_kv_store_roundtrips_and_isolates_plugins() {
        let (db, _tmp) = temp_db();
        let kv = ApiKvStore::new(db);

        // Round-trip through the real store (exercises nid resolution + lock).
        kv.set("p", b"k", b"hello", None).unwrap();
        assert_eq!(kv.get("p", b"k").unwrap().as_deref(), Some(&b"hello"[..]));
        kv.delete("p", b"k").unwrap();
        assert_eq!(kv.get("p", b"k").unwrap(), None);

        // Two plugins, same key — each resolves to its own namespace nid.
        kv.set("a", b"k", b"1", None).unwrap();
        kv.set("b", b"k", b"2", None).unwrap();
        assert_eq!(kv.get("a", b"k").unwrap().as_deref(), Some(&b"1"[..]));
        assert_eq!(kv.get("b", b"k").unwrap().as_deref(), Some(&b"2"[..]));

        // A TTL'd write is readable immediately (deterministic expiry is covered
        // by the vela-store tests, which control the clock).
        kv.set("p", b"t", b"v", Some(60_000)).unwrap();
        assert_eq!(kv.get("p", b"t").unwrap().as_deref(), Some(&b"v"[..]));
    }
}
