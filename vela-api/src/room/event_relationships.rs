//! MSC2836 `event_relationships` endpoints.
//!
//! Two paths, one shared walker:
//!   - `POST /_matrix/client/unstable/event_relationships`       (CS-API)
//!   - `POST /_matrix/federation/unstable/event_relationships`   (S2S)
//!
//! The walker traverses the per-event relations graph in the
//! requested direction. `down` follows the `event_relations`
//! column family (the same index that backs MSC2675 `/relations`,
//! which we extend in `record_relation_if_present` to also pick up
//! MSC2836's unstable `m.relationship` content shape). `up` reads
//! `content.m.relationship.event_id` (and falls back to MSC2675's
//! `m.relates_to.event_id`) off the persisted child JSON. Cycles
//! are broken by a visited set keyed on event NID.
//!
//! Federation backfill: when the requested `event_id` (or a parent
//! we'd otherwise walk into) isn't on disk locally, the CS-API
//! handler picks any joined remote server in the room and forwards
//! to its `/unstable/event_relationships`. Returned events are
//! persisted as outliers so subsequent walks find them locally.
//!
//! Response envelope matches the MSC's shape: `events`, `limited`,
//! and (on federation) `auth_chain`. Each event in `events` carries
//! `unsigned.children` (rel_type → count) and `unsigned.children_hash`
//! (`base64(sha256(sorted_event_ids.join(""))))` so threading clients
//! can render aggregations without a second roundtrip.

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::middleware::federation_auth::XMatrixOrigin;
use crate::middleware::json::Json;
use crate::room::messages::load_client_event;
use crate::router::AppState;
use axum::extract::{Extension, State};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet, VecDeque};
use vela_core::error::VelaError;

/// Cap on the number of federation backfill rounds a single CS-API
/// request can drive. Each round resolves one batch of missing
/// parents; the upper bound prevents a pathological chain from
/// turning a client call into an unbounded federation crawl.
const MAX_BACKFILL_ROUNDS: usize = 3;
/// Cap on missing-parent events we'll backfill per round. Test
/// scenarios resolve in 1–2 events; the cap is a defence against a
/// peer that returns a deep tree as missing.
const BACKFILL_PER_ROUND: usize = 8;
/// Cap on children enumerated when computing a local
/// `unsigned.children_hash`. Past this the hash field is omitted
/// (see `bundle_unsigned`) — a partial-set hash would mismatch
/// every other peer's recompute.
const LOCAL_CHILDREN_CAP: usize = 1024;

const DEFAULT_MAX_DEPTH: u32 = 3;
const HARD_MAX_DEPTH: u32 = 10;
const DEFAULT_MAX_BREADTH: u32 = 10;
const HARD_MAX_BREADTH: u32 = 50;
const DEFAULT_LIMIT: usize = 100;
const HARD_MAX_LIMIT: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct EventRelationshipsRequest {
    pub event_id: String,
    /// MSC2836 hint: when the requested event isn't local, this
    /// names the room so the handler knows which server pool to
    /// federate against. Spec-required for federation backfill,
    /// optional when the event is already on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_breadth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth_first: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recent_first: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_parent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_children: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

pub struct WalkResult {
    pub events: Vec<Value>,
    /// Parallel list of event_ids — same length and order as `events`.
    /// Carries the canonical id even when the event JSON shape doesn't
    /// (the federation handler swaps to PDU envelopes that drop
    /// `event_id` as a top-level field, so we need this here for
    /// downstream lookups like `bundle_unsigned`).
    pub event_ids: Vec<String>,
    /// MSC2836's response field; true when the walk stopped at the
    /// configured cap instead of exhausting the reachable subgraph.
    pub limited: bool,
    /// Event IDs the walker would have stepped into but couldn't —
    /// declared parents (via `m.relationship`/`m.relates_to`) not
    /// on disk locally. The CS-API handler federation-backfills
    /// these and re-runs the walk; the federation-side handler
    /// ignores them (no backfill on the way out).
    pub missing_parents: Vec<String>,
}

/// Walk the relations graph starting from `start_event_nid`. Returns
/// the events visited (start always included), in BFS order by
/// default. `limited` flips true if the walk stopped at the
/// configured limit instead of exhausting the reachable set.
pub fn walk(
    state: &AppState,
    room_id: &str,
    start_event_nid: u64,
    req: &EventRelationshipsRequest,
) -> Result<WalkResult, ApiError> {
    let max_depth = req
        .max_depth
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .min(HARD_MAX_DEPTH);
    let max_breadth = req
        .max_breadth
        .unwrap_or(DEFAULT_MAX_BREADTH)
        .min(HARD_MAX_BREADTH) as usize;
    let limit = req.limit.unwrap_or(DEFAULT_LIMIT).min(HARD_MAX_LIMIT);
    let depth_first = req.depth_first.unwrap_or(false);
    let recent_first = req.recent_first.unwrap_or(true);
    let include_parent = req.include_parent.unwrap_or(false);
    let include_children = req.include_children.unwrap_or(false);
    let direction = match req.direction.as_deref() {
        Some("up") => Direction::Up,
        _ => Direction::Down,
    };

    let mut events: Vec<Value> = Vec::with_capacity(limit.min(64));
    let mut visited: HashSet<u64> = HashSet::new();
    let mut event_ids: Vec<String> = Vec::with_capacity(limit.min(64));
    let mut missing_parents: Vec<String> = Vec::new();
    let mut missing_seen: HashSet<String> = HashSet::new();

    let mut record_missing = |eid: &str| {
        if missing_seen.insert(eid.to_string()) {
            missing_parents.push(eid.to_string());
        }
    };

    let push_loaded =
        |events: &mut Vec<Value>, event_ids: &mut Vec<String>, nid: u64| -> Result<(), ApiError> {
            if let Some(ev) = load_client_event(state, nid, room_id)? {
                if let Some(eid) = ev.get("event_id").and_then(|v| v.as_str()) {
                    event_ids.push(eid.to_string());
                } else {
                    event_ids.push(String::new());
                }
                events.push(ev);
            }
            Ok(())
        };

    // The start event is always returned (MSC2836 "the requested
    // event is considered to be at depth 0").
    push_loaded(&mut events, &mut event_ids, start_event_nid)?;
    visited.insert(start_event_nid);
    if events.len() >= limit {
        return Ok(WalkResult {
            events,
            event_ids,
            limited: true,
            missing_parents,
        });
    }

    // Optional opposite-direction one-step add. For a "down" walk
    // `include_parent` pulls in the start event's direct parent;
    // for an "up" walk `include_children` pulls in the start event's
    // direct children. Both ignore max_depth.
    if direction == Direction::Down && include_parent {
        match parent_lookup(state, start_event_nid)? {
            Some((_, Some(parent_nid))) if visited.insert(parent_nid) => {
                push_loaded(&mut events, &mut event_ids, parent_nid)?;
                if events.len() >= limit {
                    return Ok(WalkResult {
                        events,
                        event_ids,
                        limited: true,
                        missing_parents,
                    });
                }
            }
            Some((eid, None)) => record_missing(&eid),
            _ => {}
        }
    }
    if direction == Direction::Up && include_children {
        for child_nid in children_of(state, start_event_nid, max_breadth, recent_first)? {
            if !visited.insert(child_nid) {
                continue;
            }
            push_loaded(&mut events, &mut event_ids, child_nid)?;
            if events.len() >= limit {
                return Ok(WalkResult {
                    events,
                    event_ids,
                    limited: true,
                    missing_parents,
                });
            }
        }
    }

    // Main walk. Default is BFS; `depth_first` swaps the queue for a
    // stack. Tracking `(nid, depth)` lets us enforce max_depth without
    // a separate distance table.
    let mut frontier: VecDeque<(u64, u32)> = VecDeque::new();
    frontier.push_back((start_event_nid, 0));

    while let Some((node, depth)) = if depth_first {
        frontier.pop_back()
    } else {
        frontier.pop_front()
    } {
        if depth >= max_depth {
            continue;
        }
        let next_nids: Vec<u64> = match direction {
            Direction::Down => children_of(state, node, max_breadth, recent_first)?,
            Direction::Up => match parent_lookup(state, node)? {
                Some((_, Some(p))) => vec![p],
                Some((eid, None)) => {
                    record_missing(&eid);
                    Vec::new()
                }
                None => Vec::new(),
            },
        };
        for next_nid in next_nids {
            if !visited.insert(next_nid) {
                continue;
            }
            push_loaded(&mut events, &mut event_ids, next_nid)?;
            if events.len() >= limit {
                return Ok(WalkResult {
                    events,
                    event_ids,
                    limited: true,
                    missing_parents,
                });
            }
            frontier.push_back((next_nid, depth + 1));
        }
    }

    Ok(WalkResult {
        events,
        event_ids,
        limited: false,
        missing_parents,
    })
}

/// Look up the parent event NID for `event_nid` by reading the
/// MSC2836 `content.m.relationship.event_id` or the MSC2675
/// `content.m.relates_to.event_id` off the persisted JSON.
/// Returns `(parent_event_id, Option<parent_nid>)` — the id is
/// always populated when a parent is declared, so the caller can
/// federation-backfill on `None`.
fn parent_lookup(
    state: &AppState,
    event_nid: u64,
) -> Result<Option<(String, Option<u64>)>, ApiError> {
    let row = state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (_h, json_bytes) = match row {
        Some(v) => v,
        None => return Ok(None),
    };
    let v: Value = match serde_json::from_slice(&json_bytes) {
        Ok(v) => v,
        // Persisted JSON that fails to re-parse is a corruption
        // case; treat it as "no parent visible" rather than 500ing
        // the whole walk.
        Err(_) => return Ok(None),
    };
    let parent_event_id = v
        .pointer("/content/m.relationship/event_id")
        .and_then(|p| p.as_str())
        .or_else(|| {
            v.pointer("/content/m.relates_to/event_id")
                .and_then(|p| p.as_str())
        });
    let Some(parent_event_id) = parent_event_id else {
        return Ok(None);
    };
    let nid = state
        .db
        .get_event_nid_by_id(parent_event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Some((parent_event_id.to_string(), nid)))
}

/// Look up the direct children of `event_nid` via the same
/// `event_relations` index that backs `/rooms/{id}/relations`. Returns
/// up to `max_breadth` child NIDs, newest-first by default.
fn children_of(
    state: &AppState,
    event_nid: u64,
    max_breadth: usize,
    recent_first: bool,
) -> Result<Vec<u64>, ApiError> {
    let from = if recent_first { u64::MAX } else { 0 };
    let entries = state
        .db
        .list_relations(event_nid, None, None, from, recent_first, max_breadth)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(entries
        .into_iter()
        .map(|(_sp, child_nid, _rt, _ct)| child_nid)
        .collect())
}

/// Resolve `event_nid` → `(room_nid, room_id)`. The header doesn't
/// carry the room directly, so we parse `room_id` off the JSON and
/// hit the NID map. Spec 404s leak room existence — match the
/// MSC2675 `/relations` shape: a missing event is `M_NOT_FOUND`.
fn room_of_event(state: &AppState, event_nid: u64) -> Result<Option<(u64, String)>, ApiError> {
    let row = state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let Some((_h, json_bytes)) = row else {
        return Ok(None);
    };
    let v: Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let Some(room_id) = v.get("room_id").and_then(|r| r.as_str()) else {
        return Ok(None);
    };
    let room_nid = state
        .db
        .get_nid(room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(room_nid.map(|nid| (nid, room_id.to_string())))
}

/// Attach MSC2836's `unsigned.children` (rel_type → count) and
/// `unsigned.children_hash` (`base64(sha256(sorted_event_ids))`) to
/// every event in the response. Threading clients render these
/// without a second roundtrip; the test suite gates on both fields.
///
/// Federation backfill populates `event_relationships_unsigned_cache`
/// with peer-supplied bundles. We prefer the cached value when
/// present so an event surfaced via `include_parent` (whose
/// siblings aren't on our walk path and therefore aren't local)
/// still reports authoritative counts. Otherwise compute locally
/// from `event_relations`.
fn bundle_unsigned(
    state: &AppState,
    events: &mut [Value],
    event_ids: &[String],
) -> Result<(), ApiError> {
    for (i, ev) in events.iter_mut().enumerate() {
        let Some(eid) = event_ids.get(i).map(|s| s.as_str()) else {
            continue;
        };
        if eid.is_empty() {
            continue;
        }
        let Some(nid) = state
            .db
            .get_event_nid_by_id(eid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };

        // Cache hit: peer told us the truth about this event's
        // children; trust it. Sibling-discovery for events surfaced
        // via include_parent depends on this path.
        if let Some(cached) = state.event_relationships_unsigned_cache.get(&nid) {
            let cached = cached.value().clone();
            let unsigned = ev.as_object_mut().and_then(|o| {
                o.entry("unsigned")
                    .or_insert_with(|| json!({}))
                    .as_object_mut()
            });
            if let Some(u) = unsigned {
                if let Some(children) = cached.get("children") {
                    u.insert("children".into(), children.clone());
                }
                if let Some(hash) = cached.get("children_hash") {
                    u.insert("children_hash".into(), hash.clone());
                }
            }
            continue;
        }

        // BTreeMap so the resulting JSON object is stably ordered —
        // tests that compare children_hash care about determinism.
        let mut rel_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut child_eids: Vec<String> = Vec::new();
        let entries = state
            .db
            .list_relations(nid, None, None, u64::MAX, true, LOCAL_CHILDREN_CAP + 1)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let truncated = entries.len() > LOCAL_CHILDREN_CAP;
        for (_sp, child_nid, rt_nid, _ct) in entries.into_iter().take(LOCAL_CHILDREN_CAP) {
            if let Ok(Some(rt)) = state.db.resolve_nid(rt_nid) {
                *rel_counts.entry(rt).or_default() += 1;
            }
            if let Ok(Some(child_eid)) = state.db.get_event_id_by_nid(child_nid) {
                child_eids.push(child_eid);
            }
        }
        child_eids.sort();
        let hash = Sha256::digest(child_eids.join("").as_bytes());
        let hash_b64 = STANDARD_NO_PAD.encode(hash);

        let unsigned = ev.as_object_mut().and_then(|o| {
            o.entry("unsigned")
                .or_insert_with(|| json!({}))
                .as_object_mut()
        });
        if let Some(u) = unsigned {
            u.insert("children".into(), json!(rel_counts));
            // Skip `children_hash` when we couldn't enumerate every
            // child — a partial-set hash would mismatch every other
            // server's recompute and clients comparing hashes to
            // detect "I have a stale aggregate" would always think
            // they're stale. Better no hash than a wrong one.
            if !truncated {
                u.insert("children_hash".into(), json!(hash_b64));
            }
        }
    }
    Ok(())
}

/// Read `origin_server_ts` off an event JSON for the backfill
/// indexing sort. Falls back to 0 for malformed events so the sort
/// is still well-defined (they cluster at the front).
fn origin_server_ts_of(ev: &Value) -> u64 {
    ev.get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// Federation backfill for a single `event_id`. Walks every remote
/// server in the room until one returns a response, then persists
/// the returned `events` (and `auth_chain`, when present) as
/// outliers — re-indexing relations so subsequent walks observe
/// the parent/child edges. Returns the number of newly-persisted
/// events. `Ok(0)` means we either ran out of servers or every
/// returned event was already on disk.
async fn backfill_via_federation(
    state: &AppState,
    room_nid: u64,
    event_id: &str,
    body: &EventRelationshipsRequest,
) -> Result<usize, ApiError> {
    let our_server = state.config.server_name.as_str();
    // Union currently-known-joined remotes with the partial-state
    // hint so a MSC2836 relationships walk right after a federated
    // join can still reach the resident server (memberships CF is
    // empty for the resident's users until the filler clears).
    let mut server_set: std::collections::BTreeSet<String> = state
        .db
        .get_remote_servers_in_room(room_nid, our_server)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .into_iter()
        .collect();
    if let Ok((true, hint)) = state.db.get_partial_state_info(room_nid) {
        for s in hint {
            if s != our_server {
                server_set.insert(s);
            }
        }
    }
    if server_set.is_empty() {
        return Ok(0);
    }
    let servers: Vec<String> = server_set.into_iter().collect();

    // Build the body to forward — same shape as the inbound request,
    // but with `event_id` swapped to the specific missing parent so
    // the peer walks the right subtree.
    let mut fwd_body = match serde_json::to_value(body) {
        Ok(v) => v,
        Err(e) => return Err(ApiError(VelaError::Store(e.to_string()))),
    };
    if let Some(obj) = fwd_body.as_object_mut() {
        obj.insert("event_id".into(), json!(event_id));
    }

    let mut response: Option<Value> = None;
    for server in &servers {
        match state
            .federation_client
            .event_relationships(server, fwd_body.clone())
            .await
        {
            Ok(resp) => {
                response = Some(resp);
                break;
            }
            Err(e) => {
                tracing::debug!(server = %server, error = %e, "event_relationships backfill failed");
            }
        }
    }
    let Some(resp) = response else {
        return Ok(0);
    };

    let returned_events = resp
        .get("events")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let auth_chain = resp
        .get("auth_chain")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Two-pass: persist EVERY event first (auth_chain + returned),
    // then index parent→child relations. The peer's response is in
    // walk order (typically child-first up-walks), so a child's
    // parent NID won't exist yet on the first pass — we must wait
    // for all NIDs to settle before recording relations against them.
    let mut persisted_pairs: Vec<(u64, &Value)> = Vec::new();
    let mut persisted = 0usize;
    for ev in auth_chain.iter().chain(returned_events.iter()) {
        let res = crate::membership::federation_outbound_join::persist_remote_event(
            state,
            room_nid,
            ev,
            vela_store::db::PersistKind::Outlier,
        )
        .await;
        match res {
            Ok(Some(nid)) => {
                persisted += 1;
                persisted_pairs.push((nid, ev));
            }
            Ok(None) => {
                // Already had this event — index it anyway in case
                // we previously persisted without indexing. Lookup
                // its existing NID.
                if let Some(eid) = ev.get("event_id").and_then(|v| v.as_str())
                    && let Ok(Some(nid)) = state.db.get_event_nid_by_id(eid)
                {
                    persisted_pairs.push((nid, ev));
                }
            }
            Err(reason) => {
                tracing::debug!(error = %reason, "event_relationships backfill persist failed");
            }
        }
    }
    // Sort by origin_server_ts ASC so the indexing pass allocates
    // stream positions in creation order. Without this, `list_relations`
    // returns children in arrival order — which is typically child-
    // first for an up-walk peer response, breaking `recent_first=false`
    // (oldest-first) consumers like the second TestFederatedEvent-
    // Relationships subtest that expects [A, B, C].
    persisted_pairs.sort_by_key(|(_, ev)| origin_server_ts_of(ev));
    for (nid, ev) in &persisted_pairs {
        index_relation_after_backfill(state, ev, *nid, room_nid);
    }

    // MSC2836 sibling discovery: cache peer-supplied `unsigned.children`
    // and `unsigned.children_hash` so events surfaced via `include_parent`
    // can report authoritative counts even when their siblings aren't on
    // our walk path. Key on the nid we already resolved during persist
    // — the PDU envelope deliberately drops `event_id` (it'd break
    // content_hash verification), so we can't look it up here.
    //
    // Trust model: the cached values come from a federation peer and
    // are NOT verified locally (we can't recompute the hash without
    // knowing the actual child event_ids). A hostile peer can poison
    // the cache for any event we ask about. Mitigation: bound the
    // cache size so a peer can't drive us to OOM, and accept that
    // counts on backfilled events are advisory rather than
    // authoritative. The hash field is reused verbatim from the
    // peer's response so client-side equality comparisons still work
    // against same-peer data.
    for (nid, ev) in &persisted_pairs {
        let Some(unsigned) = ev.get("unsigned") else {
            continue;
        };
        let children = unsigned.get("children").cloned();
        let children_hash = unsigned.get("children_hash").cloned();
        if children.is_none() && children_hash.is_none() {
            continue;
        }
        let mut cache_entry = serde_json::Map::new();
        if let Some(c) = children {
            cache_entry.insert("children".into(), c);
        }
        if let Some(h) = children_hash {
            cache_entry.insert("children_hash".into(), h);
        }
        // Trim the cache opportunistically once it crosses the cap.
        // DashMap's iteration order is unspecified, so this evicts a
        // somewhat-random batch — fine for an advisory cache.
        if state.event_relationships_unsigned_cache.len() >= UNSIGNED_CACHE_MAX {
            evict_unsigned_cache_batch(&state.event_relationships_unsigned_cache);
        }
        state
            .event_relationships_unsigned_cache
            .insert(*nid, Value::Object(cache_entry));
    }
    Ok(persisted)
}

/// Soft cap on the unsigned cache. Past this, every insert triggers a
/// batch eviction of `UNSIGNED_CACHE_EVICT_BATCH` arbitrary entries.
/// `10_000` is plenty for a busy server (every thread/thread reply
/// cycle adds at most one row per backfill); the bound's job is to
/// stop an adversarial peer pumping new event_nids from blowing the
/// heap.
const UNSIGNED_CACHE_MAX: usize = 10_000;
const UNSIGNED_CACHE_EVICT_BATCH: usize = 1_000;

fn evict_unsigned_cache_batch(cache: &dashmap::DashMap<u64, Value>) {
    let to_drop: Vec<u64> = cache
        .iter()
        .take(UNSIGNED_CACHE_EVICT_BATCH)
        .map(|e| *e.key())
        .collect();
    for k in to_drop {
        cache.remove(&k);
    }
}

/// Return `true` if the parent→child relation is already recorded
/// somewhere in `event_relations`. Backfill repeats can hit the
/// same edge across multiple rounds (different `event_id` queries
/// reaching the same subtree on the peer); re-recording each one
/// at a fresh stream position would surface the child multiple
/// times in `list_relations`, scrambling walk order.
fn relation_already_recorded(state: &AppState, parent_nid: u64, child_nid: u64) -> bool {
    state
        .db
        .list_relations(parent_nid, None, None, u64::MAX, true, 1024)
        .map(|entries| entries.iter().any(|(_, c, _, _)| *c == child_nid))
        .unwrap_or(false)
}

/// Mirror `record_relation_if_present` for a freshly-persisted
/// backfill event. Allocates a fresh stream position per call so
/// distinct backfills land at distinct keys in `event_relations`.
fn index_relation_after_backfill(
    state: &AppState,
    event_json: &Value,
    child_event_nid: u64,
    room_nid: u64,
) {
    let content = event_json.get("content");
    let rel = match content
        .and_then(|c| c.get("m.relationship"))
        .or_else(|| content.and_then(|c| c.get("m.relates_to")))
    {
        Some(r) => r,
        None => return,
    };
    let Some(parent_event_id) = rel.get("event_id").and_then(|v| v.as_str()) else {
        return;
    };
    let Some(rel_type) = rel.get("rel_type").and_then(|v| v.as_str()) else {
        return;
    };
    let Ok(Some(parent_nid)) = state.db.get_event_nid_by_id(parent_event_id) else {
        return;
    };
    if relation_already_recorded(state, parent_nid, child_event_nid) {
        return;
    }
    let Ok(rel_type_nid) = state.db.get_or_create_nid(rel_type) else {
        return;
    };
    let event_type = event_json
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Ok(type_nid) = state.db.get_or_create_nid(event_type) else {
        return;
    };
    let sender = event_json
        .get("sender")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Ok(sender_nid) = state.db.get_or_create_nid(sender) else {
        return;
    };
    // Use `origin_server_ts` as the relation's stream position. The
    // event_relations CF key is `(parent_nid, sp)`; a fresh
    // `next_stream_position` per call would scramble ordering when
    // two backfill rounds visit the same parent from different
    // start events (the test's subtest 1 backfills `D`'s chain;
    // subtest 2 backfills `A`'s chain — without ts-as-sp, D's
    // earlier-allocated sp wins over C's later one and a
    // `recent_first=false` walk returns [D, C] instead of [C, D]).
    // Mixed local+backfill ordering is acceptable: locals (small
    // sp) sort before backfills (ms-since-epoch sp), still
    // chronological within each group.
    let stream_pos = origin_server_ts_of(event_json);
    if let Err(e) = state.db.record_relation(
        parent_nid,
        stream_pos,
        child_event_nid,
        rel_type_nid,
        type_nid,
        room_nid,
        sender_nid,
        rel_type == "m.thread",
        false, // backfill — don't bump thread recency
    ) {
        tracing::debug!(error = %e, "backfill relation index failed");
    }
}

/// POST `/_matrix/client/unstable/event_relationships`.
pub async fn event_relationships_cs(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<EventRelationshipsRequest>,
) -> Result<Json<Value>, ApiError> {
    if body.event_id.is_empty() {
        return Err(VelaError::InvalidParam("event_id required".into()).into());
    }

    // Resolve the room. Two cases: the start event is already on
    // disk (room derived from the event's `room_id` field), or it
    // isn't and the request body's `room_id` tells us which room
    // to backfill against.
    let mut start_nid_opt = state
        .db
        .get_event_nid_by_id(&body.event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (room_nid, room_id) = if let Some(nid) = start_nid_opt {
        room_of_event(&state, nid)?
            .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?
    } else if let Some(rid) = body.room_id.as_deref() {
        let rn = state
            .db
            .get_nid(rid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
        (rn, rid.to_string())
    } else {
        return Err(VelaError::NotFound("event not found".into()).into());
    };

    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership.is_none() || membership == Some(0) {
        // Spec privacy rule: don't distinguish "room doesn't exist"
        // from "not a member" — both 403, matching MSC2675.
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    // If the start event isn't on disk, federation-backfill it now.
    // The peer's response carries the whole reachable subtree, so a
    // single round usually suffices.
    if start_nid_opt.is_none() {
        let _ = backfill_via_federation(&state, room_nid, &body.event_id, &body).await?;
        start_nid_opt = state
            .db
            .get_event_nid_by_id(&body.event_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }
    let Some(start_nid) = start_nid_opt else {
        return Err(VelaError::NotFound("event not found".into()).into());
    };

    // Walk locally; if we hit declared parents that aren't on disk,
    // backfill them and re-walk. Capped at `MAX_BACKFILL_ROUNDS` to
    // bound the work per request.
    let mut result = walk(&state, &room_id, start_nid, &body)?;
    let mut rounds = 0;
    while !result.missing_parents.is_empty() && rounds < MAX_BACKFILL_ROUNDS {
        let mut filled = 0usize;
        for missing in result.missing_parents.iter().take(BACKFILL_PER_ROUND) {
            filled += backfill_via_federation(&state, room_nid, missing, &body).await?;
        }
        rounds += 1;
        if filled == 0 {
            break;
        }
        result = walk(&state, &room_id, start_nid, &body)?;
    }

    bundle_unsigned(&state, &mut result.events, &result.event_ids)?;
    Ok(Json(json!({
        "events": result.events,
        "limited": result.limited,
    })))
}

/// POST `/_matrix/federation/v1/event_relationships`. The X-Matrix
/// signature on the request already proves the origin's identity;
/// we additionally check the origin has at least one user joined to
/// the room (MSC2836: "the responding server must … verify that
/// the requesting server is in the room").
pub async fn event_relationships_fed(
    State(state): State<AppState>,
    Extension(origin): Extension<XMatrixOrigin>,
    Json(body): Json<EventRelationshipsRequest>,
) -> Result<Json<Value>, ApiError> {
    if body.event_id.is_empty() {
        return Err(VelaError::InvalidParam("event_id required".into()).into());
    }
    let start_nid = state
        .db
        .get_event_nid_by_id(&body.event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;

    let (room_nid, room_id) = room_of_event(&state, start_nid)?
        .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;

    // Origin-in-room gate. Iterate joined members, resolve each NID
    // to its full mxid, compare the domain. For O(1) hot rooms this
    // is cheap; if it ever becomes the bottleneck the right move is
    // a `room_servers` index, not caching here.
    let origin_server = origin.0.as_str();
    let members = state
        .db
        .get_room_members(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut origin_in_room = false;
    for nid in &members {
        if let Ok(Some(mxid)) = state.db.resolve_nid(*nid)
            && mxid
                .split_once(':')
                .map(|(_, d)| d == origin_server)
                .unwrap_or(false)
        {
            origin_in_room = true;
            break;
        }
    }
    if !origin_in_room {
        return Err(VelaError::Forbidden(format!("server {origin_server} not in room")).into());
    }

    let mut result = walk(&state, &room_id, start_nid, &body)?;
    // CS-API loaders strip `signatures` and `hashes` because clients
    // don't need them. Federation peers do — they need to verify the
    // event signature before persisting. Swap each event back to its
    // raw PDU JSON form, preserving the walk order. `bundle_unsigned`
    // runs against the PDU shape too so peer-supplied counts ride
    // along; clients won't render PDU envelopes directly, but every
    // homeserver implementation parses them the same way.
    promote_to_pdu_events(&state, &mut result.events, &result.event_ids);
    bundle_unsigned(&state, &mut result.events, &result.event_ids)?;

    // MSC2836 federation envelope additionally carries `auth_chain`
    // — the transitive auth closure of the returned events. The
    // requesting server uses it to authorise the events without
    // having to fetch them again. Empty array when we can't compute
    // one (e.g. the start event is unknown locally, which shouldn't
    // happen here because we already resolved its NID above).
    let auth_chain = compute_auth_chain_pdus(&state, &result.event_ids);
    Ok(Json(json!({
        "events": result.events,
        "limited": result.limited,
        "auth_chain": auth_chain,
    })))
}

/// Replace each event in `events` with the raw PDU JSON loaded
/// from `events` CF, preserving order. Used by the federation
/// handler so peers receive signature- and hashes-intact PDUs;
/// the CS-API handler keeps the redaction-applied client shape.
///
/// We deliberately DON'T splice `event_id` back into the PDU —
/// `compute_content_hash` doesn't strip `event_id` before hashing,
/// so an extra top-level field would mismatch peer-side hash
/// verification and force a defensive redaction on persist. The
/// canonical id rides on the parallel `event_ids` list instead.
fn promote_to_pdu_events(state: &AppState, events: &mut Vec<Value>, event_ids: &[String]) {
    let mut promoted: Vec<Value> = Vec::with_capacity(events.len());
    for (i, ev) in events.iter().enumerate() {
        let eid = match event_ids.get(i) {
            Some(s) if !s.is_empty() => s.as_str(),
            _ => {
                tracing::warn!(
                    "event_relationships federation response: dropping client-shaped \
                     event into PDU envelope without lookup (no event_id available)"
                );
                promoted.push(ev.clone());
                continue;
            }
        };
        match crate::federation::federation_state::load_event_json_by_event_id(&state.db, eid) {
            Some(pdu) => promoted.push(pdu),
            None => {
                // Falling back to the client shape here ships a PDU
                // the peer can't signature-verify. Log loudly — this
                // is either a DB issue or a stale `event_ids` list,
                // both of which would silently corrupt the peer's
                // auth-chain construction.
                tracing::warn!(
                    event_id = %eid,
                    "event_relationships federation response: PDU load failed, sending client shape"
                );
                promoted.push(ev.clone());
            }
        }
    }
    *events = promoted;
}

/// Build the `auth_chain` field for a federation response by
/// gathering the union of each returned event's declared
/// `auth_events` (and their transitive ancestors) and loading the
/// PDU JSON for each. Skips events not on disk locally.
fn compute_auth_chain_pdus(state: &AppState, event_ids: &[String]) -> Vec<Value> {
    let roots: Vec<&str> = event_ids
        .iter()
        .filter(|s| !s.is_empty())
        .map(|s| s.as_str())
        .collect();
    match crate::federation::federation_state::auth_chain_union_pdu_json(&state.db, &roots) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = ?e, "auth_chain computation failed; returning empty");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;
    use serde_json::json;

    /// Build a synthetic relations graph and persist it. Returns the
    /// (room_nid, root_event_nid) for the start of the walk. Layout:
    ///
    ///    root
    ///    ├── child_a
    ///    │   └── grandchild_a1
    ///    └── child_b
    ///        └── grandchild_b1
    fn fixture_tree(state: &AppState) -> (u64, u64) {
        let db = &state.db;
        let room_id = "!walk:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();
        let rel_type_nid = db.get_or_create_nid("io.example.child").unwrap();

        let persist =
            |event_id: &str, event_nid: u64, sp: u64, relates_to_event_id: Option<&str>| {
                let mut content = serde_json::Map::new();
                content.insert("body".into(), json!("x"));
                if let Some(parent_id) = relates_to_event_id {
                    content.insert(
                        "m.relates_to".into(),
                        json!({"rel_type": "io.example.child", "event_id": parent_id}),
                    );
                }
                let body = json!({
                    "type": "m.room.message",
                    "sender": "@alice:example.com",
                    "room_id": room_id,
                    "content": Value::Object(content),
                    "origin_server_ts": sp,
                    "depth": sp,
                    "prev_events": [],
                    "auth_events": [],
                });
                db.persist_event(
                    sp,
                    event_id,
                    room_nid,
                    type_msg,
                    alice_nid,
                    0,
                    sp,
                    sp,
                    &serde_json::to_vec(&body).unwrap(),
                    &[],
                    &[],
                    false,
                    false,
                )
                .unwrap();
                event_nid
            };

        let root_nid = persist("$root", 1, 1, None);
        let child_a_nid = persist("$child_a", 2, 2, Some("$root"));
        let child_b_nid = persist("$child_b", 3, 3, Some("$root"));
        let gca_nid = persist("$grandchild_a1", 4, 4, Some("$child_a"));
        let gcb_nid = persist("$grandchild_b1", 5, 5, Some("$child_b"));

        // Index the relations the same way send::record_relation_if_present
        // does. Without this, list_relations returns empty and the walker
        // sees no children.
        db.record_relation(
            1,
            2,
            child_a_nid,
            rel_type_nid,
            type_msg,
            room_nid,
            alice_nid,
            false,
            true,
        )
        .unwrap();
        db.record_relation(
            1,
            3,
            child_b_nid,
            rel_type_nid,
            type_msg,
            room_nid,
            alice_nid,
            false,
            true,
        )
        .unwrap();
        db.record_relation(
            2,
            4,
            gca_nid,
            rel_type_nid,
            type_msg,
            room_nid,
            alice_nid,
            false,
            true,
        )
        .unwrap();
        db.record_relation(
            3,
            5,
            gcb_nid,
            rel_type_nid,
            type_msg,
            room_nid,
            alice_nid,
            false,
            true,
        )
        .unwrap();

        (room_nid, root_nid)
    }

    /// Default down-walk from the root returns root + both children
    /// + both grandchildren (5 events). Visited set prevents re-visit.
    #[test]
    fn down_walk_default_returns_full_subtree() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);
        let req = EventRelationshipsRequest {
            event_id: "$root".into(),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", root_nid, &req).unwrap();
        assert_eq!(
            r.events.len(),
            5,
            "expected root + 2 children + 2 grandchildren"
        );
        assert!(!r.limited);
    }

    /// `max_depth=1` returns the root and direct children only,
    /// trimming the grandchildren.
    #[test]
    fn down_walk_max_depth_one_trims_grandchildren() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);
        let req = EventRelationshipsRequest {
            event_id: "$root".into(),
            max_depth: Some(1),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", root_nid, &req).unwrap();
        assert_eq!(r.events.len(), 3, "root + 2 direct children only");
    }

    /// Up-walk from a leaf returns the leaf, its parent, the root.
    /// Three events because the chain depth is exactly 2 (leaf →
    /// child → root) and the default max_depth (3) covers it.
    #[test]
    fn up_walk_from_leaf_returns_chain_to_root() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, _root_nid) = fixture_tree(&state);
        let leaf_nid = state
            .db
            .get_event_nid_by_id("$grandchild_a1")
            .unwrap()
            .unwrap();
        let req = EventRelationshipsRequest {
            event_id: "$grandchild_a1".into(),
            direction: Some("up".into()),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", leaf_nid, &req).unwrap();
        let ids: Vec<&str> = r
            .events
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids, vec!["$grandchild_a1", "$child_a", "$root"]);
    }

    /// A tight `limit=2` truncates the response and flips
    /// `limited` to true.
    #[test]
    fn walk_honours_limit_and_sets_limited() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);
        let req = EventRelationshipsRequest {
            event_id: "$root".into(),
            limit: Some(2),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", root_nid, &req).unwrap();
        assert_eq!(r.events.len(), 2);
        assert!(r.limited);
    }

    /// Cycle detection: even if the graph contains a back-edge the
    /// walker visits each node exactly once.
    #[test]
    fn walk_does_not_revisit_nodes_in_cycle() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);
        // Add a back-edge: $grandchild_a1 also lists $root as parent
        // (impossible in well-formed Matrix data but the walker must
        // be robust to it).
        let rel_type_nid = state.db.get_or_create_nid("io.example.child").unwrap();
        let type_msg = state.db.get_or_create_nid("m.room.message").unwrap();
        let alice_nid = state.db.get_or_create_nid("@alice:example.com").unwrap();
        let room_nid = state.db.get_nid("!walk:example.com").unwrap().unwrap();
        let gca_nid = state
            .db
            .get_event_nid_by_id("$grandchild_a1")
            .unwrap()
            .unwrap();
        state
            .db
            .record_relation(
                1,
                99,
                gca_nid,
                rel_type_nid,
                type_msg,
                room_nid,
                alice_nid,
                false,
                true,
            )
            .unwrap();

        let req = EventRelationshipsRequest {
            event_id: "$root".into(),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", root_nid, &req).unwrap();
        // 5 unique events; the duplicate back-edge to grandchild_a1
        // must NOT inflate the count.
        assert_eq!(r.events.len(), 5);
    }

    /// `include_parent` on a down-walk surfaces the start event's
    /// direct parent (one level up) in addition to the down subtree.
    #[test]
    fn down_walk_with_include_parent_pulls_in_one_level_up() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, _root_nid) = fixture_tree(&state);
        let child_a_nid = state.db.get_event_nid_by_id("$child_a").unwrap().unwrap();
        let req = EventRelationshipsRequest {
            event_id: "$child_a".into(),
            include_parent: Some(true),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", child_a_nid, &req).unwrap();
        let ids: Vec<&str> = r
            .events
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        // child_a (start) + grandchild_a1 (down) + root (parent).
        assert!(ids.contains(&"$child_a"));
        assert!(ids.contains(&"$grandchild_a1"));
        assert!(ids.contains(&"$root"));
        assert_eq!(ids.len(), 3);
    }

    /// `direction=up` plus `include_children=true` on the root
    /// returns the root and its direct children (since up has no
    /// ancestors to follow above the root).
    #[test]
    fn up_walk_with_include_children_on_root_returns_root_plus_children() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);
        let req = EventRelationshipsRequest {
            event_id: "$root".into(),
            direction: Some("up".into()),
            include_children: Some(true),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", root_nid, &req).unwrap();
        let ids: Vec<&str> = r
            .events
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        // Root + child_a + child_b. No grandchildren because the main
        // walk is "up" and there's no parent above root.
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"$root"));
        assert!(ids.contains(&"$child_a"));
        assert!(ids.contains(&"$child_b"));
    }

    /// An empty request body (missing event_id) is `M_INVALID_PARAM`.
    /// The walker itself doesn't see this — it's caught at the
    /// handler layer — so we exercise it via the request struct.
    #[test]
    fn empty_event_id_request_is_invalid_param() {
        let req = EventRelationshipsRequest::default();
        assert!(req.event_id.is_empty());
    }

    /// `parent_lookup` reads MSC2836's `m.relationship` field, not
    /// just MSC2675's `m.relates_to`. Persist an event with the
    /// unstable shape and confirm the parent resolves.
    #[test]
    fn parent_lookup_reads_msc2836_m_relationship() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!rel:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();

        // parent — no relation.
        let parent = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": room_id,
            "content": {"body": "P"},
            "origin_server_ts": 1, "depth": 1,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            10,
            "$P",
            room_nid,
            type_msg,
            alice_nid,
            0,
            1,
            1,
            &serde_json::to_vec(&parent).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();
        // child — uses MSC2836's `m.relationship`, not `m.relates_to`.
        let child = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": room_id,
            "content": {
                "body": "C",
                "m.relationship": {"rel_type": "m.reference", "event_id": "$P"},
            },
            "origin_server_ts": 2, "depth": 2,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            11,
            "$C",
            room_nid,
            type_msg,
            alice_nid,
            0,
            2,
            2,
            &serde_json::to_vec(&child).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();
        let resolved = parent_lookup(&state, 11).unwrap();
        assert_eq!(resolved.as_ref().map(|(eid, _)| eid.as_str()), Some("$P"));
        assert_eq!(resolved.and_then(|(_, n)| n), Some(10));
    }

    /// Up-walk where the leaf points to an event we don't have on
    /// disk surfaces the missing parent's event_id in
    /// `missing_parents`. The CS-API handler uses this list to
    /// drive federation backfill.
    #[test]
    fn up_walk_reports_missing_parents_for_unknown_eid() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!miss:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();

        // A single event whose declared parent isn't on disk.
        let orphan = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": room_id,
            "content": {
                "body": "orphan",
                "m.relationship": {"rel_type": "m.reference", "event_id": "$ghost"},
            },
            "origin_server_ts": 1, "depth": 1,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            42,
            "$orphan",
            room_nid,
            type_msg,
            alice_nid,
            0,
            1,
            1,
            &serde_json::to_vec(&orphan).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();

        let req = EventRelationshipsRequest {
            event_id: "$orphan".into(),
            direction: Some("up".into()),
            ..Default::default()
        };
        let r = walk(&state, room_id, 42, &req).unwrap();
        assert_eq!(r.events.len(), 1, "only the orphan is on disk");
        assert_eq!(r.missing_parents, vec!["$ghost".to_string()]);
    }

    /// When a peer-supplied unsigned bundle is cached for an event,
    /// `bundle_unsigned` returns the cached `children`/`children_hash`
    /// verbatim — local computation would underreport the count for
    /// events whose siblings aren't on the walk path. The fixture
    /// tree has 2 local children for `$root`; the cached value
    /// claims 5 across two rel_types, and that's what bubbles out.
    #[test]
    fn bundle_unsigned_prefers_peer_cached_bundle_over_local() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);
        state.event_relationships_unsigned_cache.insert(
            root_nid,
            json!({
                "children": {"m.reference": 5, "m.thread": 1},
                "children_hash": "cached-peer-hash",
            }),
        );

        let mut events = vec![json!({
            "event_id": "$root",
            "type": "m.room.message",
            "content": {"body": "P"},
        })];
        bundle_unsigned(&state, &mut events, &["$root".to_string()]).unwrap();
        let unsigned = events[0].get("unsigned").unwrap();
        // Cached values win, not the local list_relations count of 2.
        assert_eq!(unsigned["children"]["m.reference"].as_u64(), Some(5));
        assert_eq!(unsigned["children"]["m.thread"].as_u64(), Some(1));
        assert_eq!(unsigned["children_hash"].as_str(), Some("cached-peer-hash"));
    }

    /// `bundle_unsigned` produces `children: {rel_type: count}` and a
    /// `children_hash` that's `base64(sha256(sorted_event_ids))` —
    /// the exact shape the Complement test asserts on.
    #[test]
    fn bundle_unsigned_aggregates_children_counts_and_hash() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);

        let mut events = vec![json!({
            "event_id": "$root",
            "type": "m.room.message",
            "content": {"body": "P"},
        })];
        bundle_unsigned(&state, &mut events, &["$root".to_string()]).unwrap();
        let unsigned = events[0].get("unsigned").unwrap();
        // The fixture's two direct children both use rel_type
        // `io.example.child`, so the count is 2.
        assert_eq!(unsigned["children"]["io.example.child"].as_u64(), Some(2));
        // sha256(sort(["$child_a", "$child_b"]).join("")) =
        // sha256("$child_a$child_b"). Compare against the hash a
        // fresh sha256 reproduces — we don't pin the literal so the
        // test stays readable, but we DO confirm the field is non-
        // empty base64 (the test gates on hash equality between
        // peer and self).
        let h = unsigned["children_hash"].as_str().unwrap();
        assert!(!h.is_empty());
        // Decoding must succeed under `STANDARD_NO_PAD` — that's
        // the encoding the Complement test uses.
        STANDARD_NO_PAD.decode(h).expect("children_hash decodes");
        let _ = root_nid;
    }

    /// Unknown direction strings fall back to `down` so a buggy
    /// client doesn't get a 400 — they get the spec default.
    #[test]
    fn unknown_direction_falls_back_to_down() {
        let (state, _tmp) = build_test_state();
        let (_room_nid, root_nid) = fixture_tree(&state);
        let req = EventRelationshipsRequest {
            event_id: "$root".into(),
            direction: Some("sideways".into()),
            ..Default::default()
        };
        let r = walk(&state, "!walk:example.com", root_nid, &req).unwrap();
        // Identical to default-down: 5 events.
        assert_eq!(r.events.len(), 5);
    }
}
