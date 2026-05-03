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
    let mut visited: HashSet<String> = HashSet::new();
    // BFS over rooms. Each queue entry is either a local nid we
    // resolve and walk, or a remote room_id we federate to. Both
    // emit one summary into `rooms` and enqueue the discovered
    // children to keep walking.
    enum WalkEntry {
        Local(u64, String, u32),
        Remote(String, Vec<String>, u32),
    }
    let mut queue: VecDeque<WalkEntry> = VecDeque::new();
    queue.push_back(WalkEntry::Local(root_nid, room_id.clone(), 0));

    while let Some(entry) = queue.pop_front() {
        if rooms.len() >= limit {
            break;
        }
        match entry {
            WalkEntry::Local(nid, id, depth) => {
                if !visited.insert(id.clone()) {
                    continue;
                }
                // For non-root entries, check the caller can peek.
                if nid != root_nid && !can_peek(&state, nid, user.user_nid).unwrap_or(false) {
                    continue;
                }
                let children = collect_children(&state, nid, suggested_only)?;
                let is_space = is_space_room(&state, nid);
                rooms.push(summarize_room(&state, nid, &id, &children)?);

                if depth + 1 > max_depth {
                    continue;
                }
                // Spec: only spaces have meaningful `m.space.child` —
                // a non-space room may legally carry such state events
                // (the create-event type lives in `m.room.create`,
                // separate from join_rules), but the hierarchy walker
                // MUST NOT recurse into them. Without this guard, a
                // child link from a regular room R2 → R5 pulls R5 into
                // the response and Complement's `query_whole_graph`
                // assertion fires on the unexpected entry.
                if !is_space {
                    continue;
                }
                for child in &children {
                    if visited.contains(&child.child_id) {
                        continue;
                    }
                    match state
                        .db
                        .get_nid(&child.child_id)
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    {
                        Some(child_nid) => {
                            queue.push_back(WalkEntry::Local(
                                child_nid,
                                child.child_id.clone(),
                                depth + 1,
                            ));
                        }
                        None => {
                            // Remote: pull `via` servers from the
                            // m.space.child event content so we know
                            // who to federate to. Spec mandates a
                            // non-empty `via` array — defensive code
                            // here just skips entries that don't have one.
                            let via_servers: Vec<String> = child
                                .raw
                                .get("content")
                                .and_then(|c| c.get("via"))
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            if via_servers.is_empty() {
                                continue;
                            }
                            queue.push_back(WalkEntry::Remote(
                                child.child_id.clone(),
                                via_servers,
                                depth + 1,
                            ));
                        }
                    }
                }
            }
            WalkEntry::Remote(remote_id, via, depth) => {
                if !visited.insert(remote_id.clone()) {
                    continue;
                }
                let Some(resp) = fetch_remote_hierarchy(&state, &remote_id, &via).await else {
                    continue;
                };
                if let Some(room_chunk) = resp.get("room").cloned() {
                    rooms.push(room_chunk);
                }
                if depth + 1 > max_depth {
                    continue;
                }
                // Walk the children the remote returned: each is
                // either a future enqueue target or already inline.
                if let Some(remote_children) = resp.get("children").and_then(|v| v.as_array()) {
                    for child_chunk in remote_children {
                        let Some(cid) = child_chunk.get("room_id").and_then(|v| v.as_str()) else {
                            continue;
                        };
                        if visited.contains(cid) {
                            continue;
                        }
                        // Inline the chunk directly — it's already a
                        // summary the caller wants.
                        rooms.push(child_chunk.clone());
                        visited.insert(cid.to_string());
                    }
                }
                if let Some(inacc) = resp.get("inaccessible_children").and_then(|v| v.as_array()) {
                    for cid in inacc {
                        let Some(cid) = cid.as_str() else { continue };
                        if visited.contains(cid) {
                            continue;
                        }
                        // The remote can't summarise — try locally
                        // (we may host it), or follow via servers
                        // from the remote's `room.children_state`.
                        if let Ok(Some(local_nid)) = state.db.get_nid(cid) {
                            queue.push_back(WalkEntry::Local(
                                local_nid,
                                cid.to_string(),
                                depth + 1,
                            ));
                        }
                        // We don't speculate on via for purely
                        // inaccessible-and-unknown rooms. Caller's
                        // own clients can pursue them via /publicRooms
                        // or other discovery paths if they care.
                    }
                }
            }
        }
    }

    Ok(Json(json!({
        "rooms": rooms,
        // No pagination yet: every response is a single page.
    })))
}

/// Try each `via` server in turn until one returns a parseable
/// `/hierarchy` response. Returns `None` when every peer fails —
/// the caller's walker just records the room as unreachable.
async fn fetch_remote_hierarchy(state: &AppState, room_id: &str, via: &[String]) -> Option<Value> {
    for peer in via {
        match state.federation_client.fetch_hierarchy(peer, room_id).await {
            Ok(v) => return Some(v),
            Err(e) => {
                tracing::debug!(remote = %peer, %room_id, error = %e, "fetch_hierarchy failed");
            }
        }
    }
    None
}

/// Decide whether `user_nid` is allowed to see `room_nid` in a hierarchy.
/// Joined members always pass. Non-members pass only for world-readable,
/// public, or knock-rule rooms. Invite-only rooms refuse peeks.
pub(crate) fn can_peek(state: &AppState, room_nid: u64, user_nid: u64) -> Result<bool, ApiError> {
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

/// One m.space.child entry retained for hierarchy emission.
pub(crate) struct ChildEvent {
    /// Child room ID (state_key).
    pub child_id: String,
    /// Original `m.space.child` event JSON, preserved as-is so the
    /// hierarchy response carries the spec-required fields (sender,
    /// origin_server_ts, content.via).
    pub raw: Value,
    /// Cached lexicographic sort key from `content.order`.
    pub order: Option<String>,
    /// Cached origin_server_ts for tie-break sort.
    pub origin_ts: u64,
}

/// Fetch child room declarations from the space's `m.space.child` state
/// events. Returns one `ChildEvent` per child whose content has
/// non-empty `via`. When `suggested_only=true`, children missing
/// `suggested: true` are filtered out.
pub(crate) fn collect_children(
    state: &AppState,
    space_nid: u64,
    suggested_only: bool,
) -> Result<Vec<ChildEvent>, ApiError> {
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
        let state_key = v.state_key().unwrap_or("").to_string();
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
        let origin_ts = v
            .get("origin_server_ts")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        out.push(ChildEvent {
            child_id: state_key,
            raw: v,
            order,
            origin_ts,
        });
    }
    // Spec ordering: by `order` (lexicographic, missing/null last) then
    // by child origin_server_ts ascending as the tie-break.
    out.sort_by(|a, b| match (&a.order, &b.order) {
        (Some(ao), Some(bo)) => ao.cmp(bo).then(a.origin_ts.cmp(&b.origin_ts)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.origin_ts.cmp(&b.origin_ts),
    });
    Ok(out)
}

/// Build one `SpaceHierarchyRoomsChunk` entry.
pub(crate) fn summarize_room(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    children: &[ChildEvent],
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

    // `children_state` carries the actual stripped m.space.child events so
    // clients can render via/order/suggested without re-querying. Spec:
    // type, state_key, content, sender, origin_server_ts (per the
    // `StrippedStateEvent` schema referenced from the hierarchy response).
    let mut children_state = Vec::with_capacity(children.len());
    for child in children {
        let raw = child.raw.as_object();
        let content = raw
            .and_then(|o| o.get("content").cloned())
            .unwrap_or_else(|| json!({}));
        let sender = raw
            .and_then(|o| o.get("sender").cloned())
            .unwrap_or_else(|| json!(""));
        children_state.push(json!({
            "type": "m.space.child",
            "state_key": child.child_id,
            "sender": sender,
            "content": content,
            "origin_server_ts": child.origin_ts,
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

/// True iff `room_nid`'s `m.room.create` event has `type:
/// "m.space"`. Plain rooms return false even when they carry
/// `m.space.child` state events. Used by the hierarchy walker to
/// decide whether to descend into children.
fn is_space_room(state: &AppState, room_nid: u64) -> bool {
    read_content(state, room_nid, "m.room.create", "")
        .as_ref()
        .and_then(|c| c.get("type"))
        .and_then(|v| v.as_str())
        == Some("m.space")
}

fn read_content(state: &AppState, room_nid: u64, etype: &str, state_key: &str) -> Option<Value> {
    crate::membership::read_state_value_pub(state, room_nid, etype, state_key)
        .ok()
        .flatten()
        .and_then(|v| v.get("content").cloned())
}

/// GET /_matrix/federation/v1/hierarchy/{roomId}
///
/// MSC2946 single-level hierarchy summary. Shape:
///
/// ```text
/// { room: <chunk for queried space>,
///   children: [ <chunk per locally-known child> ],
///   inaccessible_children: [ <child_id we can't summarise> ] }
/// ```
///
/// Unlike the C2S `/hierarchy`, federation returns ONE level — the
/// requesting server is responsible for recursing across home
/// servers. Child rooms hosted on other servers are listed in
/// `inaccessible_children` so the caller knows where to follow up.
///
/// Auth: the requesting server must have a presence in the queried
/// room (any of its users currently joined), OR the room must be
/// world-readable / public.
pub async fn federation_hierarchy(
    axum::extract::State(state): axum::extract::State<AppState>,
    axum::extract::Path(room_id): axum::extract::Path<String>,
    axum::extract::Extension(origin): axum::extract::Extension<
        crate::middleware::federation_auth::XMatrixOrigin,
    >,
) -> Result<axum::Json<Value>, axum::http::StatusCode> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(axum::http::StatusCode::NOT_FOUND)?;

    if !origin_can_peek(&state, room_nid, &origin.0)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?
    {
        return Err(axum::http::StatusCode::FORBIDDEN);
    }

    let suggested_only = false;
    let children = collect_children(&state, room_nid, suggested_only)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let room_chunk = summarize_room(&state, room_nid, &room_id, &children)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut child_chunks = Vec::new();
    let mut inaccessible: Vec<String> = Vec::new();
    for child in &children {
        let child_room_nid = match state.db.get_nid(&child.child_id) {
            Ok(Some(n)) => n,
            _ => {
                // Not local — caller should federate to a server in
                // child.via to summarise this room themselves.
                inaccessible.push(child.child_id.clone());
                continue;
            }
        };

        // Per spec, children visible to the caller are filtered the
        // same way: requesting server must share the child or it
        // must be world-readable / public. Unreachable children
        // remain inaccessible to the caller.
        let child_visible = origin_can_peek(&state, child_room_nid, &origin.0).unwrap_or(false);
        if !child_visible {
            inaccessible.push(child.child_id.clone());
            continue;
        }

        let child_kids = collect_children(&state, child_room_nid, suggested_only)
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        let chunk = summarize_room(&state, child_room_nid, &child.child_id, &child_kids)
            .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
        child_chunks.push(chunk);
    }

    Ok(axum::Json(json!({
        "room": room_chunk,
        "children": child_chunks,
        "inaccessible_children": inaccessible,
    })))
}

/// True when the requesting server shares the room with us (any user
/// from `origin` currently joined) or the room is world-readable /
/// public. Mirrors the C2S `can_peek` semantics but at server-rather-
/// than-user granularity.
fn origin_can_peek(state: &AppState, room_nid: u64, origin: &str) -> Result<bool, ApiError> {
    // Joined members from `origin`?
    if let Ok(members) = state.db.get_room_members(room_nid) {
        for m in members {
            if let Ok(Some(uid)) = state.db.resolve_nid(m)
                && uid
                    .split_once(':')
                    .map(|(_, d)| d == origin)
                    .unwrap_or(false)
            {
                return Ok(true);
            }
        }
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
    let hv = read_content(state, room_nid, "m.room.history_visibility", "")
        .as_ref()
        .and_then(|c| c.get("history_visibility"))
        .and_then(|v| v.as_str())
        .unwrap_or("shared")
        .to_string();
    Ok(hv == "world_readable")
}
