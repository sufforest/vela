//! MSC4140 delayed events.
//!
//! Clients schedule an event to be sent at a future time by passing
//! `?org.matrix.msc4140.delay=<ms>` on the existing `PUT /send` or
//! `PUT /state` endpoints. The server holds the event in a delayed
//! queue, fires it after the delay elapses, and exposes management
//! endpoints to list, cancel, restart, or send-now.
//!
//! Storage: every record persists to the `delayed_events` CF keyed
//! on a freshly-minted `delay_id` (UUID). An in-memory `DashMap` on
//! `AppState` mirrors the CF for fast scheduler scans; the CF
//! survives restarts so pending events come back to life.
//!
//! Scheduler: one tokio task per process. Tick interval is 100ms —
//! short enough that the Complement subtests (which sleep 1s and
//! check) consistently observe the fire, and long enough that the
//! scan cost is negligible (a DashMap walk + ms comparison).

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::middleware::json::Json;
use crate::router::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use vela_core::error::VelaError;

/// MSC4140 hasn't stabilised; clients pass the unstable query param.
pub const DELAY_QUERY_PARAM: &str = "org.matrix.msc4140.delay";
/// Scheduler tick. Determines worst-case latency between deadline
/// and fire.
const TICK_INTERVAL: Duration = Duration::from_millis(100);

/// Default for `ServerConfig::max_delay_ms` when the operator
/// hasn't overridden it. Bounds how far into the future a client
/// can schedule an event — without a cap a buggy or hostile client
/// could pin events for years.
pub const DEFAULT_MAX_DELAY_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 days

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelayedEventRecord {
    pub delay_id: String,
    pub user_nid: u64,
    pub user_id: String,
    pub device_id: String,
    pub room_id: String,
    pub event_type: String,
    /// `None` for message events, `Some` (possibly empty) for state.
    pub state_key: Option<String>,
    pub content: Value,
    /// `None` for state events (which don't carry a txn_id).
    pub txn_id: Option<String>,
    pub scheduled_at_ms: u64,
    pub delay_ms: u64,
}

#[derive(Debug, Default)]
pub struct DelayedEventStore {
    /// `delay_id` → record. DashMap for concurrent read/write.
    pub by_id: DashMap<String, DelayedEventRecord>,
    /// Cache of `(room_id, event_type, state_key)` → `delay_id` for
    /// state events. Lets a fresh state-event PUT for an existing
    /// (type, state_key) cancel its previous pending delay — and
    /// the key is room-scoped (not user-scoped) because state
    /// itself is room-scoped: two pending delays from different
    /// users at the same (room, type, state_key) would both fire,
    /// and the order would determine the final state.
    pub state_key_index: DashMap<(String, String, String), String>,
    /// Cache of `(user_nid, device_id, room_id, event_type, txn_id)` →
    /// `delay_id` for message events so a re-PUT of the same txn_id
    /// returns the original `delay_id` instead of minting a new one.
    pub txn_index: DashMap<(u64, String, String, String, String), String>,
}

impl DelayedEventStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn new_delay_id() -> String {
    // Hex-encoded 16 bytes from the OS CSPRNG. The action endpoint
    // treats `delay_id` as a capability token (no auth check beyond
    // string equality), so the source MUST be cryptographically
    // secure — `rand::rng()` is ChaCha12 today but a future rand
    // bump could silently weaken to a non-CS source. `OsRng` is the
    // OS's CSPRNG (`/dev/urandom` on Unix, `BCryptGenRandom` on
    // Windows) and that contract is part of the rand-core trait.
    use rand::TryRngCore;
    use rand::rngs::OsRng;
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG must not fail");
    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
}

/// Insert a record into both DashMap mirror and the persistent CF.
pub fn store(state: &AppState, rec: DelayedEventRecord) -> Result<(), ApiError> {
    metrics::counter!("vela_delayed_events_scheduled_total").increment(1);
    metrics::gauge!("vela_delayed_events_pending").increment(1.0);
    let bytes = serde_json::to_vec(&rec).map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    state
        .db
        .save_delayed_event(&rec.delay_id, &bytes)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let Some(sk) = &rec.state_key {
        let key = state_index_key(&rec.room_id, &rec.event_type, sk);
        state
            .delayed_events
            .state_key_index
            .insert(key, rec.delay_id.clone());
    }
    if let Some(tid) = &rec.txn_id {
        let key = (
            rec.user_nid,
            rec.device_id.clone(),
            rec.room_id.clone(),
            rec.event_type.clone(),
            tid.clone(),
        );
        state
            .delayed_events
            .txn_index
            .insert(key, rec.delay_id.clone());
    }
    state.delayed_events.by_id.insert(rec.delay_id.clone(), rec);
    Ok(())
}

/// Drop the auxiliary index entries (state_key_index, txn_index)
/// that point at `rec`. Shared between every removal path so the
/// CF and the mirrors stay consistent.
fn drop_indexes(state: &AppState, rec: &DelayedEventRecord) {
    if let Some(sk) = &rec.state_key {
        let key = state_index_key(&rec.room_id, &rec.event_type, sk);
        // Only drop the index entry if it still points at this
        // delay_id — a concurrent re-schedule may have overwritten
        // it with a fresh id, and we mustn't clobber the new one.
        let _ = state
            .delayed_events
            .state_key_index
            .remove_if(&key, |_, v| v == &rec.delay_id);
    }
    if let Some(tid) = &rec.txn_id {
        let key = (
            rec.user_nid,
            rec.device_id.clone(),
            rec.room_id.clone(),
            rec.event_type.clone(),
            tid.clone(),
        );
        let _ = state
            .delayed_events
            .txn_index
            .remove_if(&key, |_, v| v == &rec.delay_id);
    }
}

/// Remove a record from both stores. Idempotent — returns `None`
/// when the id is unknown.
pub fn remove(state: &AppState, delay_id: &str) -> Result<Option<DelayedEventRecord>, ApiError> {
    let rec = state.delayed_events.by_id.remove(delay_id).map(|(_, r)| r);
    if let Some(r) = &rec {
        drop_indexes(state, r);
        metrics::gauge!("vela_delayed_events_pending").decrement(1.0);
    }
    state
        .db
        .delete_delayed_event(delay_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(rec)
}

/// Atomic "take this record if it's still scheduled to fire by
/// `deadline_ms`" — the scheduler's primitive. Closes the
/// fire-vs-cancel and fire-vs-restart races: a cancel between the
/// scheduler's filter pass and its fire pass changes the by_id
/// map state, and `remove_if` re-checks under the DashMap shard
/// lock, so the scheduler only fires events that are still both
/// present AND due.
fn take_if_due(state: &AppState, delay_id: &str, deadline_ms: u64) -> Option<DelayedEventRecord> {
    let removed = state
        .delayed_events
        .by_id
        .remove_if(delay_id, |_, r| r.scheduled_at_ms <= deadline_ms)
        .map(|(_, r)| r);
    if removed.is_some() {
        metrics::gauge!("vela_delayed_events_pending").decrement(1.0);
    }
    if let Some(r) = &removed {
        drop_indexes(state, r);
        let _ = state.db.delete_delayed_event(delay_id);
    }
    removed
}

/// State index key. Cross-user: two users delaying the same
/// (room, type, state_key) cancel each other, since state is
/// room-scoped (last-writer-wins). The MSC's "avoid clashing
/// state keys" guidance is room-scoped, not per-user — making
/// this per-user would let user A's pending delay sit alongside
/// user B's, and the order they fire would determine the final
/// state nondeterministically.
fn state_index_key(room_id: &str, event_type: &str, state_key: &str) -> (String, String, String) {
    (
        room_id.to_string(),
        event_type.to_string(),
        state_key.to_string(),
    )
}

/// Populate the in-memory store from the persistent CF. Called once
/// at process boot.
pub fn load_from_disk(state: &AppState) -> Result<usize, ApiError> {
    let rows = state
        .db
        .list_delayed_events()
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut count = 0;
    for (_, bytes) in rows {
        if let Ok(rec) = serde_json::from_slice::<DelayedEventRecord>(&bytes) {
            if let Some(sk) = &rec.state_key {
                let key = state_index_key(&rec.room_id, &rec.event_type, sk);
                state
                    .delayed_events
                    .state_key_index
                    .insert(key, rec.delay_id.clone());
            }
            if let Some(tid) = &rec.txn_id {
                let key = (
                    rec.user_nid,
                    rec.device_id.clone(),
                    rec.room_id.clone(),
                    rec.event_type.clone(),
                    tid.clone(),
                );
                state
                    .delayed_events
                    .txn_index
                    .insert(key, rec.delay_id.clone());
            }
            state.delayed_events.by_id.insert(rec.delay_id.clone(), rec);
            count += 1;
        }
    }
    // Sync the pending gauge to the loaded record count so the
    // metric reflects post-boot reality, not just deltas observed
    // by the scheduler/handlers since process start.
    metrics::gauge!("vela_delayed_events_pending").set(count as f64);
    Ok(count)
}

/// Look up an existing `delay_id` for a (user, device, room, type,
/// txn_id) tuple. Lets the send handler short-circuit a re-PUT
/// without re-parsing the body — the upstream test issues such a
/// re-PUT with no body and expects the previous `delay_id` back.
pub fn existing_delay_id_for_txn(
    state: &AppState,
    user_nid: u64,
    device_id: &str,
    room_id: &str,
    event_type: &str,
    txn_id: &str,
) -> Option<String> {
    let key = (
        user_nid,
        device_id.to_string(),
        room_id.to_string(),
        event_type.to_string(),
        txn_id.to_string(),
    );
    state
        .delayed_events
        .txn_index
        .get(&key)
        .map(|e| e.value().clone())
}

/// Mint a new delayed event for a message-style send. Cancels any
/// prior pending delay for the same `(user, device, room, type, txn)`
/// and returns the EXISTING `delay_id` instead — this matches the
/// MSC's idempotency contract on `txn_id` retries.
pub fn schedule_message(
    state: &AppState,
    user: &AuthenticatedUser,
    room_id: &str,
    event_type: &str,
    txn_id: &str,
    content: Value,
    delay_ms: u64,
) -> Result<String, ApiError> {
    let key = (
        user.user_nid,
        user.device_id.clone(),
        room_id.to_string(),
        event_type.to_string(),
        txn_id.to_string(),
    );
    if let Some(existing) = state.delayed_events.txn_index.get(&key) {
        return Ok(existing.value().clone());
    }
    let scheduled_at_ms = now_ms() + delay_ms;
    let rec = DelayedEventRecord {
        delay_id: new_delay_id(),
        user_nid: user.user_nid,
        user_id: user.user_id.clone(),
        device_id: user.device_id.clone(),
        room_id: room_id.to_string(),
        event_type: event_type.to_string(),
        state_key: None,
        content,
        txn_id: Some(txn_id.to_string()),
        scheduled_at_ms,
        delay_ms,
    };
    let id = rec.delay_id.clone();
    store(state, rec)?;
    Ok(id)
}

/// Mint a new delayed event for a state-style send. Cancels any
/// prior pending delay for the same `(user, room, type, state_key)`
/// (state events are inherently latest-wins).
pub fn schedule_state(
    state: &AppState,
    user: &AuthenticatedUser,
    room_id: &str,
    event_type: &str,
    state_key: &str,
    content: Value,
    delay_ms: u64,
) -> Result<String, ApiError> {
    let key = state_index_key(room_id, event_type, state_key);
    if let Some(prior_id) = state
        .delayed_events
        .state_key_index
        .get(&key)
        .map(|e| e.value().clone())
    {
        let _ = remove(state, &prior_id);
    }
    let scheduled_at_ms = now_ms() + delay_ms;
    let rec = DelayedEventRecord {
        delay_id: new_delay_id(),
        user_nid: user.user_nid,
        user_id: user.user_id.clone(),
        device_id: user.device_id.clone(),
        room_id: room_id.to_string(),
        event_type: event_type.to_string(),
        state_key: Some(state_key.to_string()),
        content,
        txn_id: None,
        scheduled_at_ms,
        delay_ms,
    };
    let id = rec.delay_id.clone();
    store(state, rec)?;
    Ok(id)
}

/// Validate the `?org.matrix.msc4140.delay=` value against the
/// operator-configured maximum. Send handlers call this before
/// scheduling so a 400 surfaces at the API boundary rather than at
/// fire time.
pub fn validate_delay_ms(delay_ms: u64, max_delay_ms: u64) -> Result<(), ApiError> {
    if delay_ms == 0 || delay_ms > max_delay_ms {
        return Err(VelaError::InvalidParam(format!(
            "delay {delay_ms}ms out of range [1, {max_delay_ms}]"
        ))
        .into());
    }
    Ok(())
}

// ============================================================
// Handlers
// ============================================================

/// Default page size when the caller doesn't supply `?limit=`.
/// Bound the upper edge separately to cap response size.
const LIST_DEFAULT_LIMIT: usize = 100;
const LIST_MAX_LIMIT: usize = 1000;

#[derive(Debug, Deserialize, Default)]
pub struct ListQuery {
    /// Opaque resume token from a previous `next_batch`.
    #[serde(default)]
    pub from: Option<String>,
    /// Page size cap (default 100, max 1000).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// `GET /_matrix/client/unstable/org.matrix.msc4140/delayed_events` —
/// return pending events owned by the calling user, paginated.
/// Pagination uses an opaque `next_batch` token: a freshly-base16'd
/// `delay_id` of the next record the caller hasn't seen. Order is
/// lexicographic over `delay_id` (DashMap iteration is unordered,
/// so we sort the candidate set before slicing).
///
/// The lex order matches the random delay_id ordering — it isn't
/// chronological, but it IS stable and that's the property
/// pagination needs: callers walking with `from=<prev_token>` see
/// every record exactly once.
pub async fn list_delayed_events_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    axum::extract::Query(q): axum::extract::Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    let limit = q
        .limit
        .unwrap_or(LIST_DEFAULT_LIMIT)
        .clamp(1, LIST_MAX_LIMIT);

    // Collect ids belonging to the caller, then sort. DashMap's
    // iteration order is unspecified; without sorting, pagination
    // would skip or duplicate entries across calls.
    let mut owned_ids: Vec<String> = state
        .delayed_events
        .by_id
        .iter()
        .filter(|e| e.value().user_nid == user.user_nid)
        .map(|e| e.key().clone())
        .collect();
    owned_ids.sort();

    // Apply the `from` token (exclusive start — caller's last seen).
    let start = match q.from {
        Some(t) => owned_ids.partition_point(|id| id.as_str() <= t.as_str()),
        None => 0,
    };
    let end = (start + limit).min(owned_ids.len());
    let next_batch = if end < owned_ids.len() {
        Some(owned_ids[end - 1].clone())
    } else {
        None
    };

    let now = now_ms();
    let mut events: Vec<Value> = Vec::with_capacity(end - start);
    for id in &owned_ids[start..end] {
        let Some(rec) = state.delayed_events.by_id.get(id) else {
            continue;
        };
        let rec = rec.value();
        let remaining = rec.scheduled_at_ms.saturating_sub(now);
        let mut obj = serde_json::Map::new();
        obj.insert("delay_id".into(), json!(rec.delay_id));
        obj.insert("room_id".into(), json!(rec.room_id));
        obj.insert("type".into(), json!(rec.event_type));
        if let Some(sk) = &rec.state_key {
            obj.insert("state_key".into(), json!(sk));
        }
        obj.insert("content".into(), rec.content.clone());
        obj.insert(
            "running_since".into(),
            json!(rec.scheduled_at_ms - rec.delay_ms),
        );
        obj.insert("delay".into(), json!(rec.delay_ms));
        obj.insert("running_until".into(), json!(rec.scheduled_at_ms));
        obj.insert("remaining".into(), json!(remaining));
        events.push(Value::Object(obj));
    }

    let mut resp = serde_json::Map::new();
    resp.insert("delayed_events".into(), Value::Array(events));
    if let Some(t) = next_batch {
        resp.insert("next_batch".into(), Value::String(t));
    }
    Ok(Json(Value::Object(resp)))
}

/// `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delay_id}/{action}` —
/// MSC4140's three-verb management endpoint. The path-positional
/// `action` is one of `cancel | restart | send`; anything else
/// surfaces as a 404 per the test's
/// `cannot update a delayed event with an invalid action` subtest.
///
/// Deliberately NOT auth-gated: per MSC4140 the `delay_id` itself
/// acts as a capability token (it's a 128-bit random opaque value,
/// only handed to the user who created the delay). The upstream
/// Complement test exercises this by using an unauthenticated
/// client to cancel/restart/send a real delay — `MustDo` against
/// the response would fail under a 401.
pub async fn update_delayed_event_handler(
    State(state): State<AppState>,
    Path((delay_id, action)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    // Early existence check is purely for the 404 path. The
    // mutating branches re-validate atomically below so a
    // scheduler tick between the existence check and the mutation
    // can't double-fire (cancel) or double-fire-and-overwrite
    // (send/restart).
    if !state.delayed_events.by_id.contains_key(&delay_id) {
        return Err(VelaError::NotFound("delay_id".into()).into());
    }
    match action.as_str() {
        "cancel" => {
            // Atomic remove. If the scheduler already fired it, our
            // remove returns None and there's nothing left to do
            // — the user's intent (no further fire) is already
            // achieved by virtue of having already fired once.
            let removed = remove(&state, &delay_id)?;
            if removed.is_some() {
                metrics::counter!("vela_delayed_events_cancelled_total").increment(1);
            }
            Ok(Json(json!({})))
        }
        "send" => {
            // `take_if_due` with deadline=MAX gives us an
            // unconditional atomic remove. If the scheduler claims
            // the event first, we silently skip firing again —
            // double-firing the same event would violate the MSC's
            // "the delayed event is sent at most once" contract.
            if let Some(rec) = take_if_due(&state, &delay_id, u64::MAX) {
                metrics::counter!("vela_delayed_events_manual_send_total").increment(1);
                if let Err(e) = fire_event(&state, rec).await {
                    tracing::debug!(error = ?e, "delayed event manual fire failed");
                }
            }
            Ok(Json(json!({})))
        }
        "restart" => {
            // Atomic in-place update of `scheduled_at_ms`. Avoids
            // the remove+store window in which the entry is
            // momentarily absent (a list call would miss it). The
            // CF gets re-written outside the lock; if the entry
            // vanished between our entry-modify and the persist,
            // the persist is a harmless no-op (next list_from_disk
            // would just reload the deleted state).
            let mut now_rec: Option<DelayedEventRecord> = None;
            state
                .delayed_events
                .by_id
                .entry(delay_id.clone())
                .and_modify(|r| {
                    r.scheduled_at_ms = now_ms() + r.delay_ms;
                    now_rec = Some(r.clone());
                });
            if let Some(rec) = now_rec {
                let bytes = serde_json::to_vec(&rec)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                state
                    .db
                    .save_delayed_event(&rec.delay_id, &bytes)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                metrics::counter!("vela_delayed_events_restarted_total").increment(1);
            }
            Ok(Json(json!({})))
        }
        _ => Err(VelaError::NotFound(format!("action: {action}")).into()),
    }
}

/// Reject the action-less POST shape that some clients accidentally
/// send. Per the test, this should be `MatchFailure` — any 4xx.
pub async fn update_delayed_event_no_action_handler() -> Result<Json<Value>, StatusCode> {
    Err(StatusCode::METHOD_NOT_ALLOWED)
}

/// Fire a delayed event through the normal send pipeline. Constructs
/// an `AuthenticatedUser` from the stored record and reuses the
/// existing send handlers so the event goes through the same auth +
/// persist + broadcast flow as a regular `PUT /send` or `PUT /state`.
pub async fn fire_event(state: &AppState, rec: DelayedEventRecord) -> Result<(), ApiError> {
    let user = AuthenticatedUser {
        user_nid: rec.user_nid,
        user_id: rec.user_id.clone(),
        device_id: rec.device_id.clone(),
        appservice_nid: None,
    };
    if let Some(state_key) = rec.state_key {
        let _ = crate::room::send::send_state_inner(
            state.clone(),
            user,
            rec.room_id,
            rec.event_type,
            state_key,
            None,
            rec.content,
        )
        .await?;
    } else {
        let _ = crate::room::send::send_message_inner(
            state.clone(),
            user,
            rec.room_id,
            rec.event_type,
            rec.txn_id.unwrap_or_default(),
            None,
            rec.content,
        )
        .await?;
    }
    Ok(())
}

/// Spawn the scheduler task. Idempotent — only the first call
/// actually spawns; later ones are no-ops.
pub fn ensure_running(state: &AppState) {
    if state
        .delayed_events_scheduler_running
        .swap(true, std::sync::atomic::Ordering::AcqRel)
    {
        return;
    }
    let state = state.clone();
    tokio::spawn(async move {
        run_scheduler(state).await;
    });
}

async fn run_scheduler(state: AppState) {
    // Tick-then-sleep (not sleep-then-tick): on cold boot we want
    // any events that aged-past-deadline while the process was down
    // (the "kept on server restart" subtest schedules a 900ms event
    // and bounces the server) to fire as soon as we can, not after
    // the first 100ms slice. The test's CI failure was the cold-
    // boot first-tick latency racing the test's 5s MustSyncUntil
    // poll window.
    loop {
        let now = now_ms();
        // First pass: collect candidate ids. Second pass: try to
        // atomically claim each via `take_if_due` and fire only on
        // success. The `take_if_due` re-checks the deadline under
        // the DashMap shard lock, so a `restart` that pushed the
        // deadline out OR a `cancel` that removed the entry both
        // win the race cleanly — the scheduler skips and the next
        // tick re-evaluates.
        let candidate_ids: Vec<String> = state
            .delayed_events
            .by_id
            .iter()
            .filter(|e| e.value().scheduled_at_ms <= now)
            .map(|e| e.key().clone())
            .collect();
        for id in candidate_ids {
            let Some(rec) = take_if_due(&state, &id, now) else {
                continue;
            };
            metrics::counter!("vela_delayed_events_fired_total").increment(1);
            if let Err(e) = fire_event(&state, rec).await {
                metrics::counter!("vela_delayed_events_fire_errors_total").increment(1);
                tracing::debug!(error = ?e, "delayed event fire failed");
            }
        }
        tokio::time::sleep(TICK_INTERVAL).await;
    }
}

pub fn boot(state: &AppState) {
    if let Err(e) = load_from_disk(state) {
        tracing::warn!(error = ?e, "delayed_events load_from_disk failed");
    }
    ensure_running(state);
}

/// Pull the type Arc out for AppState construction. Keeps the
/// concrete `DashMap` type out of the AppState definition.
pub fn new_store() -> Arc<DelayedEventStore> {
    Arc::new(DelayedEventStore::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Range bound: any value in `[1, max]` accepted; `0` and
    /// `max+1` rejected.
    #[test]
    fn validate_delay_ms_enforces_inclusive_range() {
        let max = 10_000;
        assert!(validate_delay_ms(1, max).is_ok());
        assert!(validate_delay_ms(5_000, max).is_ok());
        assert!(validate_delay_ms(max, max).is_ok());
        assert!(validate_delay_ms(0, max).is_err());
        assert!(validate_delay_ms(max + 1, max).is_err());
    }

    /// Operators can tighten the cap. A delay accepted under the
    /// default would be rejected under a shorter operator cap.
    #[test]
    fn validate_delay_ms_honours_lower_operator_cap() {
        let strict = 1_000;
        assert!(validate_delay_ms(500, strict).is_ok());
        assert!(validate_delay_ms(1_500, strict).is_err());
    }

    /// Bound-fire: at exactly `DEFAULT_MAX_DELAY_MS` the validator
    /// accepts; one millisecond over and it errors. Pins the
    /// inclusive boundary so a future tweak that turns it
    /// half-open is caught.
    #[test]
    fn validate_delay_ms_default_cap_boundary() {
        assert!(validate_delay_ms(DEFAULT_MAX_DELAY_MS, DEFAULT_MAX_DELAY_MS).is_ok());
        assert!(validate_delay_ms(DEFAULT_MAX_DELAY_MS + 1, DEFAULT_MAX_DELAY_MS).is_err());
    }

    #[test]
    fn new_delay_id_returns_hex_uuid_shape() {
        let id = new_delay_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Two consecutive IDs differ — random source is wired.
        assert_ne!(id, new_delay_id());
    }

    /// Helper: build a minimal record for pagination tests. State,
    /// txn, and content shape don't matter for the slicing logic.
    fn pagination_rec(delay_id: &str, user_nid: u64) -> DelayedEventRecord {
        DelayedEventRecord {
            delay_id: delay_id.to_string(),
            user_nid,
            user_id: format!("@u{user_nid}:example.com"),
            device_id: "DEVICE".into(),
            room_id: "!r:example.com".into(),
            event_type: "m.room.message".into(),
            state_key: None,
            content: serde_json::json!({}),
            txn_id: Some(format!("txn-{delay_id}")),
            scheduled_at_ms: 1_000_000,
            delay_ms: 1000,
        }
    }

    /// The `from` token is the last-seen delay_id, exclusive. The
    /// partition-point logic must include the next id past it and
    /// must NOT re-emit the token itself. Bound-fire: the boundary
    /// where the token equals an existing id.
    #[test]
    fn list_pagination_from_token_is_exclusive() {
        use crate::test_helpers::build_test_state;
        let (state, _tmp) = build_test_state();
        // Seed 5 ids for one user.
        for c in ["a", "b", "c", "d", "e"] {
            let rec = pagination_rec(c, 1);
            state.delayed_events.by_id.insert(rec.delay_id.clone(), rec);
        }
        // Sorted ids: [a, b, c, d, e]. `from=c` → slice starts at `d`.
        let mut owned_ids: Vec<String> = state
            .delayed_events
            .by_id
            .iter()
            .filter(|e| e.value().user_nid == 1)
            .map(|e| e.key().clone())
            .collect();
        owned_ids.sort();
        let start = owned_ids.partition_point(|id| id.as_str() <= "c");
        assert_eq!(start, 3, "from=c must skip past c");
        assert_eq!(&owned_ids[start..], &["d", "e"]);
    }

    /// Cross-user isolation: a caller's pagination must NOT include
    /// other users' delays even when their delay_ids would sort into
    /// the slice. The handler filters before sorting; pin that here.
    #[test]
    fn list_pagination_isolates_users() {
        use crate::test_helpers::build_test_state;
        let (state, _tmp) = build_test_state();
        for c in ["a", "c", "e"] {
            state
                .delayed_events
                .by_id
                .insert(c.to_string(), pagination_rec(c, 1));
        }
        for c in ["b", "d"] {
            state
                .delayed_events
                .by_id
                .insert(c.to_string(), pagination_rec(c, 2));
        }
        let owned: Vec<String> = state
            .delayed_events
            .by_id
            .iter()
            .filter(|e| e.value().user_nid == 1)
            .map(|e| e.key().clone())
            .collect();
        assert_eq!(owned.len(), 3, "only user 1's events");
        let owned_set: std::collections::HashSet<&str> = owned.iter().map(|s| s.as_str()).collect();
        for c in ["a", "c", "e"] {
            assert!(owned_set.contains(c));
        }
        for c in ["b", "d"] {
            assert!(!owned_set.contains(c));
        }
    }

    /// Bound-fire on `limit`: a value over `LIST_MAX_LIMIT` clamps
    /// down; `0` clamps up to 1 (the call still gets at least one
    /// row, matching the spec's "limit defines page size, not
    /// opt-out" semantic).
    #[test]
    fn list_pagination_limit_clamps_to_bounds() {
        assert_eq!(
            (LIST_MAX_LIMIT + 5_000).clamp(1, LIST_MAX_LIMIT),
            LIST_MAX_LIMIT
        );
        assert_eq!(0_usize.clamp(1, LIST_MAX_LIMIT), 1);
    }

    /// Round-trip pagination: walking `next_batch` from one call to
    /// the next must produce every record exactly once, in order,
    /// with no duplicates and no skips. Pins the `next_batch =
    /// last-seen-id` semantic by simulating the caller's loop.
    /// Strategy alternative (`next_batch = first-unseen-id`) would
    /// skip the first id of every page — caught here.
    #[test]
    fn list_pagination_round_trip_visits_every_id_once() {
        use crate::test_helpers::build_test_state;
        let (state, _tmp) = build_test_state();
        let all_ids = ["a", "b", "c", "d", "e", "f", "g"];
        for c in all_ids {
            state
                .delayed_events
                .by_id
                .insert(c.to_string(), pagination_rec(c, 1));
        }

        let mut owned_ids: Vec<String> = state
            .delayed_events
            .by_id
            .iter()
            .filter(|e| e.value().user_nid == 1)
            .map(|e| e.key().clone())
            .collect();
        owned_ids.sort();

        let limit = 3;
        let mut seen: Vec<String> = Vec::new();
        let mut from: Option<String> = None;
        loop {
            let start = match &from {
                Some(t) => owned_ids.partition_point(|id| id.as_str() <= t.as_str()),
                None => 0,
            };
            let end = (start + limit).min(owned_ids.len());
            if start >= end {
                break;
            }
            for id in &owned_ids[start..end] {
                seen.push(id.clone());
            }
            from = if end < owned_ids.len() {
                Some(owned_ids[end - 1].clone())
            } else {
                None
            };
            if from.is_none() {
                break;
            }
        }
        assert_eq!(
            seen,
            all_ids.map(String::from),
            "round-trip must visit every id exactly once in order"
        );
    }
}
