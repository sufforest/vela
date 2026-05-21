//! Per-AS outbound delivery. One Tokio task per registered AS
//! drains a persistent RocksDB queue, calls `client::deliver`, and
//! applies exponential backoff on retryable failures.
//!
//! Architecture mirrors `federation_sender`: per-destination task,
//! persistent CF, `tokio::sync::Notify` wake on new work, 24h dead
//! threshold. The wire-level layer differs (Bearer auth + JSON
//! transaction body for AS vs. X-Matrix-signed transactions for
//! federation), so it's a separate implementation — but the retry
//! semantics are identical and not worth reinventing.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde_json::json;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use vela_store::db::Database;

use crate::appservice::Transaction;
use crate::appservice::client::{DeliveryError, deliver};
use crate::appservice::registry::AsRegistry;

const INITIAL_BACKOFF: Duration = Duration::from_secs(2);
const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
const DEAD_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// Scheduler owns per-AS worker tasks. Cheap to clone (Arcs);
/// callers hand a reference to AppState so the interest filter can
/// enqueue from the request path.
#[derive(Clone)]
pub struct AsOutbox {
    db: Arc<Database>,
    registry: Arc<AsRegistry>,
    inner: Arc<Inner>,
    /// Map of `appservice_nid → cleartext hs_token`. Populated by
    /// the registration handler at register-time (cleartext is
    /// otherwise gone — we only store hashes). Persists for the
    /// life of the process; on restart the operator must
    /// re-paste-and-register to restore.
    hs_tokens: Arc<DashMap<u64, String>>,
    http: reqwest::Client,
}

struct Inner {
    notifies: DashMap<u64, Arc<Notify>>,
    next_seq: DashMap<u64, AtomicU64>,
    workers: DashMap<u64, JoinHandle<()>>,
}

impl AsOutbox {
    pub fn new(db: Arc<Database>, registry: Arc<AsRegistry>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .build()
            .expect("reqwest client");
        Self {
            db,
            registry,
            inner: Arc::new(Inner {
                notifies: DashMap::new(),
                next_seq: DashMap::new(),
                workers: DashMap::new(),
            }),
            hs_tokens: Arc::new(DashMap::new()),
            http,
        }
    }

    /// Make the cleartext `hs_token` available to this AS's worker.
    /// Called at registration time + each time the operator restores
    /// the token (e.g. via `!as set-hs-token`).
    pub fn set_hs_token(&self, appservice_nid: u64, cleartext: String) {
        self.hs_tokens.insert(appservice_nid, cleartext);
    }

    /// Cleartext hs_token for this AS, if known. Used by HS→AS
    /// query callers to sign their GET requests.
    pub fn hs_token(&self, appservice_nid: u64) -> Option<String> {
        self.hs_tokens
            .get(&appservice_nid)
            .map(|r| r.value().clone())
    }

    /// Shared HTTP client. Reused for HS→AS queries so we don't spin
    /// up a fresh connection pool per call.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http
    }

    pub fn start_all(&self) {
        for live in self.registry.list() {
            self.start_worker(live.appservice.nid);
        }
    }

    pub fn start_worker(&self, appservice_nid: u64) {
        if self.inner.workers.contains_key(&appservice_nid) {
            return;
        }
        let primed = self
            .db
            .max_appservice_outbox_seq(appservice_nid)
            .unwrap_or(None)
            .unwrap_or(0)
            + 1;
        self.inner
            .next_seq
            .entry(appservice_nid)
            .or_insert_with(|| AtomicU64::new(primed));
        let notify = self
            .inner
            .notifies
            .entry(appservice_nid)
            .or_insert_with(|| Arc::new(Notify::new()))
            .clone();
        let db = self.db.clone();
        let registry = self.registry.clone();
        let hs_tokens = self.hs_tokens.clone();
        let http = self.http.clone();
        let handle = tokio::spawn(async move {
            run_worker(db, registry, hs_tokens, http, appservice_nid, notify).await;
        });
        self.inner.workers.insert(appservice_nid, handle);
    }

    /// Enqueue one transaction onto the AS's outbox. Allocates a
    /// fresh seq, persists, wakes the worker. Caller (interest
    /// filter) supplies the events + room_ids to deliver.
    pub fn enqueue(
        &self,
        appservice_nid: u64,
        event_nids: Vec<u64>,
        room_ids: Vec<String>,
    ) -> Result<(), rocksdb::Error> {
        self.enqueue_inner(appservice_nid, event_nids, room_ids, vec![])
    }

    /// Enqueue an ephemeral-only transaction (typing / receipt / etc).
    /// Each EDU is a JSON object with `type` + `room_id` + `content`,
    /// per the AS transaction spec's `ephemeral` array.
    pub fn enqueue_ephemeral(
        &self,
        appservice_nid: u64,
        ephemeral: Vec<serde_json::Value>,
    ) -> Result<(), rocksdb::Error> {
        if ephemeral.is_empty() {
            return Ok(());
        }
        self.enqueue_inner(appservice_nid, vec![], vec![], ephemeral)
    }

    fn enqueue_inner(
        &self,
        appservice_nid: u64,
        event_nids: Vec<u64>,
        room_ids: Vec<String>,
        ephemeral: Vec<serde_json::Value>,
    ) -> Result<(), rocksdb::Error> {
        let seq = self
            .inner
            .next_seq
            .entry(appservice_nid)
            .or_insert_with(|| AtomicU64::new(1))
            .fetch_add(1, Ordering::Relaxed);
        let txn = Transaction {
            txn_id: format!("vela-{appservice_nid}-{seq}"),
            event_nids,
            room_ids,
            ephemeral,
        };
        let value = serde_json::to_value(&txn).unwrap_or(json!(null));
        self.db
            .push_appservice_outbox(appservice_nid, seq, &value)?;
        if let Some(n) = self.inner.notifies.get(&appservice_nid) {
            n.notify_one();
        }
        Ok(())
    }
}

async fn run_worker(
    db: Arc<Database>,
    registry: Arc<AsRegistry>,
    hs_tokens: Arc<DashMap<u64, String>>,
    http: reqwest::Client,
    appservice_nid: u64,
    notify: Arc<Notify>,
) {
    debug!(appservice_nid, "AS outbox worker started");
    let mut backoff = INITIAL_BACKOFF;
    let mut dead_since: Option<Instant> = None;

    loop {
        let live = match registry.get(appservice_nid) {
            Some(l) => l,
            None => {
                info!(appservice_nid, "AS unregistered; worker exiting");
                return;
            }
        };
        if !live.appservice.enabled {
            notify.notified().await;
            continue;
        }

        let pending = db.peek_appservice_outbox(appservice_nid).unwrap_or(None);
        let Some((seq, value)) = pending else {
            dead_since = None;
            backoff = INITIAL_BACKOFF;
            notify.notified().await;
            continue;
        };

        let txn: Transaction = match serde_json::from_value(value) {
            Ok(t) => t,
            Err(e) => {
                warn!(appservice_nid, seq, error = %e, "outbox entry malformed; dropping");
                let _ = db.pop_appservice_outbox(appservice_nid, seq);
                continue;
            }
        };

        let cleartext = hs_tokens.get(&appservice_nid).map(|r| r.value().clone());
        let result = deliver(&http, &db, &live.appservice, cleartext.as_deref(), &txn).await;
        match result {
            Ok(()) => {
                let _ = db.pop_appservice_outbox(appservice_nid, seq);
                backoff = INITIAL_BACKOFF;
                dead_since = None;
            }
            Err(DeliveryError::Permanent(reason)) => {
                warn!(
                    appservice_nid,
                    seq, reason, "permanent AS delivery failure; dropping"
                );
                let _ = db.pop_appservice_outbox(appservice_nid, seq);
                backoff = INITIAL_BACKOFF;
            }
            Err(DeliveryError::Retryable(reason)) => {
                debug!(
                    appservice_nid,
                    seq,
                    reason,
                    ?backoff,
                    "retryable; backing off"
                );
                let started = dead_since.get_or_insert_with(Instant::now);
                if started.elapsed() > DEAD_AFTER {
                    warn!(
                        appservice_nid,
                        "AS unresponsive for >{DEAD_AFTER:?}; worker exiting (outbox preserved)"
                    );
                    return;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}
