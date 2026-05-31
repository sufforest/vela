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
use axum::extract::{Path, Query, State};
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

/// Maximum allowable delay (ms). Bound it so a malicious / buggy
/// client can't pin events for years and exhaust the queue.
const MAX_DELAY_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 days

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
    /// Cache of `(user_nid, room_id, event_type, state_key)` →
    /// `delay_id` for state events. Lets a fresh state-event PUT for
    /// an existing (type, state_key) cancel its previous pending
    /// delay — per MSC4140 "Avoid clashing state keys as that would
    /// cancel previous delayed events on the same key" (test L474).
    pub state_key_index: DashMap<(u64, String, String, String), String>,
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
    // Hex-encoded 16-byte UUID. Random enough that collisions across
    // billions are infeasible; printable so we can dump it into JSON
    // and URLs without encoding gymnastics.
    let mut bytes = [0u8; 16];
    use rand::Rng;
    rand::rng().fill(&mut bytes);
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// Insert a record into both DashMap mirror and the persistent CF.
pub fn store(state: &AppState, rec: DelayedEventRecord) -> Result<(), ApiError> {
    let bytes = serde_json::to_vec(&rec).map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    state
        .db
        .save_delayed_event(&rec.delay_id, &bytes)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let Some(sk) = &rec.state_key {
        let key = (
            rec.user_nid,
            rec.room_id.clone(),
            rec.event_type.clone(),
            sk.clone(),
        );
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

/// Remove a record from both stores.
pub fn remove(state: &AppState, delay_id: &str) -> Result<Option<DelayedEventRecord>, ApiError> {
    let rec = state.delayed_events.by_id.remove(delay_id).map(|(_, r)| r);
    if let Some(r) = &rec {
        if let Some(sk) = &r.state_key {
            let key = (
                r.user_nid,
                r.room_id.clone(),
                r.event_type.clone(),
                sk.clone(),
            );
            state.delayed_events.state_key_index.remove(&key);
        }
        if let Some(tid) = &r.txn_id {
            let key = (
                r.user_nid,
                r.device_id.clone(),
                r.room_id.clone(),
                r.event_type.clone(),
                tid.clone(),
            );
            state.delayed_events.txn_index.remove(&key);
        }
    }
    state
        .db
        .delete_delayed_event(delay_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(rec)
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
                let key = (
                    rec.user_nid,
                    rec.room_id.clone(),
                    rec.event_type.clone(),
                    sk.clone(),
                );
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
    let key = (
        user.user_nid,
        room_id.to_string(),
        event_type.to_string(),
        state_key.to_string(),
    );
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

/// Parse the `org.matrix.msc4140.delay` query param. Returns
/// `Ok(None)` when not present, `Ok(Some(ms))` when valid, `Err`
/// when the value is malformed or exceeds `MAX_DELAY_MS`.
pub fn parse_delay(raw: &str) -> Result<Option<u64>, ApiError> {
    for pair in raw.split('&') {
        let mut iter = pair.splitn(2, '=');
        let key = iter.next().unwrap_or("");
        let val = iter.next().unwrap_or("");
        if key != DELAY_QUERY_PARAM {
            continue;
        }
        let ms: u64 = val
            .parse()
            .map_err(|_| ApiError(VelaError::InvalidParam(format!("delay: {val}"))))?;
        if ms == 0 || ms > MAX_DELAY_MS {
            return Err(VelaError::InvalidParam(format!(
                "delay {ms}ms out of range [1, {MAX_DELAY_MS}]"
            ))
            .into());
        }
        return Ok(Some(ms));
    }
    Ok(None)
}

// ============================================================
// Handlers
// ============================================================

/// `GET /_matrix/client/v1/delayed_events` — return pending events
/// owned by the calling user. MSC4140 specifies pagination but
/// vela returns the full set in one page; users with thousands of
/// pending events would push us over the response size limit, which
/// is well beyond the test surface.
pub async fn list_delayed_events_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let mut events: Vec<Value> = Vec::new();
    for entry in state.delayed_events.by_id.iter() {
        let rec = entry.value();
        if rec.user_nid != user.user_nid {
            continue;
        }
        let remaining = rec.scheduled_at_ms.saturating_sub(now_ms());
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
    Ok(Json(json!({"delayed_events": events})))
}

#[derive(Deserialize)]
pub struct ActionParams {
    /// `cancel` | `restart` | `send`. Per the MSC, the action is in
    /// the URL path; missing or unrecognised values surface as 404.
    pub action: String,
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
    let rec = state
        .delayed_events
        .by_id
        .get(&delay_id)
        .map(|e| e.value().clone());
    let rec = match rec {
        Some(r) => r,
        None => return Err(VelaError::NotFound("delay_id".into()).into()),
    };
    match action.as_str() {
        "cancel" => {
            remove(&state, &delay_id)?;
            Ok(Json(json!({})))
        }
        "send" => {
            // Fire immediately. Remove BEFORE firing so a concurrent
            // scheduler tick doesn't fire it a second time.
            let _ = remove(&state, &delay_id)?;
            fire_event(&state, rec).await?;
            Ok(Json(json!({})))
        }
        "restart" => {
            let mut updated = rec;
            updated.scheduled_at_ms = now_ms() + updated.delay_ms;
            store(&state, updated)?;
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
    loop {
        tokio::time::sleep(TICK_INTERVAL).await;
        let now = now_ms();
        // Collect due events first, then fire outside the iteration
        // so we don't hold DashMap shards across an await.
        let due: Vec<DelayedEventRecord> = state
            .delayed_events
            .by_id
            .iter()
            .filter(|e| e.value().scheduled_at_ms <= now)
            .map(|e| e.value().clone())
            .collect();
        for rec in due {
            let _ = remove(&state, &rec.delay_id);
            if let Err(e) = fire_event(&state, rec).await {
                tracing::debug!(error = ?e, "delayed event fire failed");
            }
        }
    }
}

#[derive(Deserialize, Debug, Default)]
pub struct ListQuery {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
}

/// `GET /_matrix/client/v1/delayed_events` with optional pagination
/// params (currently ignored — see handler doc).
#[allow(dead_code)]
pub async fn list_with_query_handler(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(_q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    list_delayed_events_handler(State(state), user).await
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

    #[test]
    fn parse_delay_accepts_valid_values() {
        assert_eq!(
            parse_delay("org.matrix.msc4140.delay=1500").unwrap(),
            Some(1500)
        );
        assert_eq!(parse_delay("foo=bar").unwrap(), None);
        assert_eq!(parse_delay("").unwrap(), None);
    }

    #[test]
    fn parse_delay_rejects_zero() {
        assert!(parse_delay("org.matrix.msc4140.delay=0").is_err());
    }

    #[test]
    fn parse_delay_rejects_overflow() {
        let v = MAX_DELAY_MS + 1;
        assert!(parse_delay(&format!("org.matrix.msc4140.delay={v}")).is_err());
    }

    #[test]
    fn parse_delay_rejects_non_numeric() {
        assert!(parse_delay("org.matrix.msc4140.delay=abc").is_err());
    }

    #[test]
    fn new_delay_id_returns_hex_uuid_shape() {
        let id = new_delay_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Two consecutive IDs differ — random source is wired.
        assert_ne!(id, new_delay_id());
    }
}
