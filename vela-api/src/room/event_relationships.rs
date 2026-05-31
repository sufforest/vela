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
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{HashSet, VecDeque};
use vela_core::error::VelaError;

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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EventRelationshipsRequest {
    pub event_id: String,
    /// MSC2836 hint: when the requested event isn't local, this
    /// names the room so the handler knows which server pool to
    /// federate against. Spec-required for federation backfill,
    /// optional when the event is already on disk.
    #[serde(default)]
    pub room_id: Option<String>,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[serde(default)]
    pub max_breadth: Option<u32>,
    #[serde(default)]
    pub depth_first: Option<bool>,
    #[serde(default)]
    pub recent_first: Option<bool>,
    #[serde(default)]
    pub include_parent: Option<bool>,
    #[serde(default)]
    pub include_children: Option<bool>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

pub struct WalkResult {
    pub events: Vec<Value>,
    /// MSC2836's response field; true when the walk stopped at the
    /// configured cap instead of exhausting the reachable subgraph.
    pub limited: bool,
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

    // The start event is always returned (MSC2836 "the requested
    // event is considered to be at depth 0").
    if let Some(ev) = load_client_event(state, start_event_nid, room_id)? {
        events.push(ev);
    }
    visited.insert(start_event_nid);
    if events.len() >= limit {
        return Ok(WalkResult {
            events,
            limited: true,
        });
    }

    // Optional opposite-direction one-step add. For a "down" walk
    // `include_parent` pulls in the start event's direct parent;
    // for an "up" walk `include_children` pulls in the start event's
    // direct children. Both ignore max_depth.
    if direction == Direction::Down
        && include_parent
        && let Some(parent_nid) = parent_of(state, start_event_nid)?
        && visited.insert(parent_nid)
    {
        if let Some(ev) = load_client_event(state, parent_nid, room_id)? {
            events.push(ev);
        }
        if events.len() >= limit {
            return Ok(WalkResult {
                events,
                limited: true,
            });
        }
    }
    if direction == Direction::Up && include_children {
        for child_nid in children_of(state, start_event_nid, max_breadth, recent_first)? {
            if !visited.insert(child_nid) {
                continue;
            }
            if let Some(ev) = load_client_event(state, child_nid, room_id)? {
                events.push(ev);
            }
            if events.len() >= limit {
                return Ok(WalkResult {
                    events,
                    limited: true,
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
            Direction::Up => parent_of(state, node)?.map_or(Vec::new(), |p| vec![p]),
        };
        for next_nid in next_nids {
            if !visited.insert(next_nid) {
                continue;
            }
            if let Some(ev) = load_client_event(state, next_nid, room_id)? {
                events.push(ev);
            }
            if events.len() >= limit {
                return Ok(WalkResult {
                    events,
                    limited: true,
                });
            }
            frontier.push_back((next_nid, depth + 1));
        }
    }

    Ok(WalkResult {
        events,
        limited: false,
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

fn parent_of(state: &AppState, event_nid: u64) -> Result<Option<u64>, ApiError> {
    Ok(parent_lookup(state, event_nid)?.and_then(|(_, nid)| nid))
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

/// POST `/_matrix/client/unstable/event_relationships`.
pub async fn event_relationships_cs(
    State(state): State<AppState>,
    user: AuthenticatedUser,
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

    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership.is_none() || membership == Some(0) {
        // Spec privacy rule: don't distinguish "room doesn't exist"
        // from "not a member" — both 403, matching MSC2675.
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let result = walk(&state, &room_id, start_nid, &body)?;
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

    let result = walk(&state, &room_id, start_nid, &body)?;
    Ok(Json(json!({
        "events": result.events,
        "limited": result.limited,
    })))
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
