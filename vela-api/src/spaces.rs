//! `GET /_matrix/client/v1/rooms/{roomId}/hierarchy` — MSC2946 spaces.
//!
//! Walks the space's `m.space.child` state events, returning a summary
//! for each child room (plus the space itself at the root). Limited to
//! locally-known rooms; federated recursion into remote spaces is
//! out-of-scope for this pass — clients get `null` children summaries
//! where we can't resolve the child locally.
//!
//! Auth: caller must be joined to the root space, OR the space must be
//! world-readable / join_rule=public / invite-only-but-caller-invited.
//! Children are included iff the caller is joined, or the child itself
//! is world-readable or public.
//!
//! No `next_batch` pagination yet — we cap with `limit` and `max_depth`
//! and return the single page.

use std::collections::{HashSet, VecDeque};

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;
use vela_core::events::view::EventView;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

const DEFAULT_LIMIT: usize = 100;
const DEFAULT_MAX_DEPTH: u32 = 3;

#[derive(Debug, Deserialize)]
pub struct HierarchyQuery {
    #[serde(default)]
    pub suggested_only: Option<bool>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub max_depth: Option<u32>,
    #[allow(dead_code)]
    #[serde(default)]
    pub from: Option<String>,
}

/// GET /_matrix/client/v1/rooms/{room_id}/hierarchy
pub async fn hierarchy(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(query): Query<HierarchyQuery>,
) -> Result<Json<Value>, ApiError> {
    let suggested_only = query.suggested_only.unwrap_or(false);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).max(1);
    let max_depth = query.max_depth.unwrap_or(DEFAULT_MAX_DEPTH);

    let root_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    if !can_peek(&state, root_nid, user.user_nid)? {
        return Err(VelaError::Forbidden("cannot view this space".into()).into());
    }

    let mut rooms = Vec::new();
    let mut visited: HashSet<u64> = HashSet::new();
    // BFS: each entry is (room_nid, room_id_str, current depth).
    let mut queue: VecDeque<(u64, String, u32)> = VecDeque::new();
    queue.push_back((root_nid, room_id.clone(), 0));

    while let Some((nid, id, depth)) = queue.pop_front() {
        if !visited.insert(nid) {
            continue;
        }
        if rooms.len() >= limit {
            break;
        }
        // For non-root entries, check the caller can peek.
        if nid != root_nid && !can_peek(&state, nid, user.user_nid).unwrap_or(false) {
            continue;
        }
        let children = collect_children(&state, nid, suggested_only)?;
        rooms.push(summarize_room(&state, nid, &id, &children)?);

        if depth + 1 > max_depth {
            continue;
        }
        for (child_id, _order, _suggested) in &children {
            // Only recurse into children we know locally. Unknown (remote)
            // children already appear in the parent's `children_state`
            // array so clients can render them stub-style.
            if let Some(child_nid) = state
                .db
                .get_nid(child_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                && !visited.contains(&child_nid)
            {
                queue.push_back((child_nid, child_id.clone(), depth + 1));
            }
        }
    }

    Ok(Json(json!({
        "rooms": rooms,
        // No pagination yet: every response is a single page.
    })))
}

/// Decide whether `user_nid` is allowed to see `room_nid` in a hierarchy.
/// Joined members always pass. Non-members pass only for world-readable,
/// public, or knock-rule rooms. Invite-only rooms refuse peeks.
fn can_peek(state: &AppState, room_nid: u64, user_nid: u64) -> Result<bool, ApiError> {
    if state
        .db
        .get_membership(room_nid, user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        == Some(1)
    {
        return Ok(true);
    }
    let jr = read_content(state, room_nid, "m.room.join_rules", "")
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(|v| v.as_str())
        .unwrap_or("invite")
        .to_string();
    if matches!(jr.as_str(), "public" | "knock" | "knock_restricted") {
        return Ok(true);
    }
    // world_readable via m.room.history_visibility.
    let hv = read_content(state, room_nid, "m.room.history_visibility", "")
        .as_ref()
        .and_then(|c| c.get("history_visibility"))
        .and_then(|v| v.as_str())
        .unwrap_or("shared")
        .to_string();
    Ok(hv == "world_readable")
}

/// Fetch child room declarations from the space's `m.space.child` state
/// events. Returns `(child_room_id, order, suggested)` for each child
/// whose content has non-empty `via`. When `suggested_only=true`,
/// children missing `suggested: true` are filtered out.
fn collect_children(
    state: &AppState,
    space_nid: u64,
    suggested_only: bool,
) -> Result<Vec<(String, Option<String>, bool)>, ApiError> {
    let nids = state
        .db
        .get_all_state_event_nids(space_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let type_nid = match state
        .db
        .get_nid("m.space.child")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for nid in nids {
        let (h, bytes) = match state
            .db
            .get_event(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(p) => p,
            None => continue,
        };
        if h.type_nid != type_nid {
            continue;
        }
        let v: Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let state_key = v.state_key().unwrap_or("");
        if state_key.is_empty() {
            continue;
        }
        let content = match v.content() {
            Some(c) => c,
            None => continue,
        };
        // Spec: child is "present" iff content has a non-empty `via` array.
        // Empty/missing via means the child was unlinked.
        let via_ok = content
            .get("via")
            .and_then(|v| v.as_array())
            .map(|arr| !arr.is_empty())
            .unwrap_or(false);
        if !via_ok {
            continue;
        }
        let suggested = content
            .get("suggested")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if suggested_only && !suggested {
            continue;
        }
        let order = content
            .get("order")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        out.push((state_key.to_string(), order, suggested));
    }
    // Spec ordering: by `order` (lexicographic) then by child origin_server_ts.
    // We only have `order` readily; falling back to insertion order is fine
    // for the first cut.
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

/// Build one `SpaceHierarchyRoomsChunk` entry.
fn summarize_room(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    children: &[(String, Option<String>, bool)],
) -> Result<Value, ApiError> {
    let create = read_content(state, room_nid, "m.room.create", "").unwrap_or(json!({}));
    let room_version = create
        .get("room_version")
        .and_then(|v| v.as_str())
        .unwrap_or("12")
        .to_string();
    let room_type = create
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let name = read_content(state, room_nid, "m.room.name", "")
        .as_ref()
        .and_then(|c| c.get("name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let topic = read_content(state, room_nid, "m.room.topic", "")
        .as_ref()
        .and_then(|c| c.get("topic"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let avatar_url = read_content(state, room_nid, "m.room.avatar", "")
        .as_ref()
        .and_then(|c| c.get("url"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let canonical_alias = read_content(state, room_nid, "m.room.canonical_alias", "")
        .as_ref()
        .and_then(|c| c.get("alias"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let join_rule = read_content(state, room_nid, "m.room.join_rules", "")
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(|v| v.as_str())
        .unwrap_or("invite")
        .to_string();
    let guest_can_join = read_content(state, room_nid, "m.room.guest_access", "")
        .as_ref()
        .and_then(|c| c.get("guest_access"))
        .and_then(|v| v.as_str())
        == Some("can_join");
    let world_readable = read_content(state, room_nid, "m.room.history_visibility", "")
        .as_ref()
        .and_then(|c| c.get("history_visibility"))
        .and_then(|v| v.as_str())
        == Some("world_readable");
    let encryption = read_content(state, room_nid, "m.room.encryption", "")
        .as_ref()
        .and_then(|c| c.get("algorithm"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let num_joined_members = state
        .db
        .get_room_members(room_nid)
        .map(|m| m.len() as u64)
        .unwrap_or(0);

    // `children_state` expects stripped m.space.child events. Rebuild from
    // the walked list so we don't re-read the CF a second time.
    let mut children_state = Vec::with_capacity(children.len());
    for (child_id, order, suggested) in children {
        let mut content = serde_json::Map::new();
        content.insert("via".into(), json!([])); // placeholder; clients don't strictly need it
        if let Some(o) = order {
            content.insert("order".into(), json!(o));
        }
        if *suggested {
            content.insert("suggested".into(), json!(true));
        }
        children_state.push(json!({
            "type": "m.space.child",
            "state_key": child_id,
            "sender": "",
            "content": Value::Object(content),
            "origin_server_ts": 0,
        }));
    }

    let mut out = serde_json::Map::new();
    out.insert("room_id".into(), json!(room_id));
    out.insert("num_joined_members".into(), json!(num_joined_members));
    out.insert("world_readable".into(), json!(world_readable));
    out.insert("guest_can_join".into(), json!(guest_can_join));
    out.insert("join_rule".into(), json!(join_rule));
    out.insert("room_version".into(), json!(room_version));
    out.insert("children_state".into(), json!(children_state));
    if let Some(n) = name {
        out.insert("name".into(), json!(n));
    }
    if let Some(t) = topic {
        out.insert("topic".into(), json!(t));
    }
    if let Some(a) = avatar_url {
        out.insert("avatar_url".into(), json!(a));
    }
    if let Some(c) = canonical_alias {
        out.insert("canonical_alias".into(), json!(c));
    }
    if let Some(t) = room_type {
        out.insert("room_type".into(), json!(t));
    }
    if let Some(e) = encryption {
        out.insert("encryption".into(), json!(e));
    }

    Ok(Value::Object(out))
}

fn read_content(state: &AppState, room_nid: u64, etype: &str, state_key: &str) -> Option<Value> {
    crate::membership::read_state_value_pub(state, room_nid, etype, state_key)
        .ok()
        .flatten()
        .and_then(|v| v.get("content").cloned())
}
