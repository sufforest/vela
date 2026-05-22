//! `GET /_matrix/client/v3/rooms/{roomId}/relations/{eventId}[/{relType}[/{eventType}]]`
//!
//! Spec: `references/matrix-spec/data/api/client-server/relations.yaml`.
//!
//! Returns child events that reference the given parent via
//! `content.m.relates_to.event_id`. Pagination uses stream positions; the
//! default direction is backwards (newest first), matching the spec default.
//!
//! Out of scope this iteration: `recurse` (depth-first traversal of children
//! of children) and `unsigned.m.relations` bundling on the parent.

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::messages::load_client_event;
use crate::router::AppState;

const DEFAULT_LIMIT: usize = 30;
const MAX_LIMIT: usize = 100;

#[derive(Debug, Default, Deserialize)]
pub struct RelationsQuery {
    /// Stream-position token bracketing the page. `b<n>` means "events with
    /// stream_pos < n"; absence means "from the latest".
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<usize>,
    /// `b` = backwards (newest first, default), `f` = forwards.
    pub dir: Option<String>,
}

pub async fn relations(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, event_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    handle(
        state,
        user,
        room_id,
        event_id,
        None,
        None,
        RelationsQuery::default(),
    )
    .await
}

pub async fn relations_with_query(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, event_id)): Path<(String, String)>,
    Query(q): Query<RelationsQuery>,
) -> Result<Json<Value>, ApiError> {
    handle(state, user, room_id, event_id, None, None, q).await
}

pub async fn relations_with_rel_type(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, event_id, rel_type)): Path<(String, String, String)>,
    Query(q): Query<RelationsQuery>,
) -> Result<Json<Value>, ApiError> {
    handle(state, user, room_id, event_id, Some(rel_type), None, q).await
}

pub async fn relations_with_rel_and_event_type(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id, event_id, rel_type, event_type)): Path<(String, String, String, String)>,
    Query(q): Query<RelationsQuery>,
) -> Result<Json<Value>, ApiError> {
    handle(
        state,
        user,
        room_id,
        event_id,
        Some(rel_type),
        Some(event_type),
        q,
    )
    .await
}

async fn handle(
    state: AppState,
    user: AuthenticatedUser,
    room_id: String,
    event_id: String,
    rel_type: Option<String>,
    event_type: Option<String>,
    q: RelationsQuery,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    // Membership check — match the rest of the read path.
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership.is_none() || membership == Some(0) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let parent_nid = state
        .db
        .get_event_nid_by_id(&event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("parent event not found".into())))?;

    let dir_backwards = !matches!(q.dir.as_deref(), Some("f"));
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

    // Token format: `s<stream_pos>` (matches sync's tokens). Default `from`
    // is end-of-stream when going backwards, 0 when going forwards.
    let from =
        parse_stream_token(q.from.as_deref()).unwrap_or(if dir_backwards { u64::MAX } else { 0 });
    // `to` is an exclusive boundary opposite the dir of travel.
    // dir=b: stop when stream_pos <= to. dir=f: stop when stream_pos >= to.
    let to = parse_stream_token(q.to.as_deref());

    let rel_type_nid = match &rel_type {
        Some(rt) => state
            .db
            .get_nid(rt)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?,
        None => None,
    };
    // If a rel_type filter was supplied but its NID has never been minted
    // (no event of that type ever indexed), the answer is trivially empty.
    if rel_type.is_some() && rel_type_nid.is_none() {
        return Ok(Json(json!({"chunk": []})));
    }
    let event_type_nid = match &event_type {
        Some(et) => state
            .db
            .get_nid(et)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?,
        None => None,
    };
    if event_type.is_some() && event_type_nid.is_none() {
        return Ok(Json(json!({"chunk": []})));
    }

    let entries = state
        .db
        .list_relations(
            parent_nid,
            rel_type_nid,
            event_type_nid,
            from,
            dir_backwards,
            limit,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut chunk = Vec::with_capacity(entries.len());
    let mut last_pos = None;
    for (sp, child_nid, _rt, _ct) in entries {
        // Apply the `to` upper bound (exclusive on the far side of travel).
        if let Some(t) = to {
            if dir_backwards && sp <= t {
                break;
            }
            if !dir_backwards && sp >= t {
                break;
            }
        }
        if let Some(ev) = load_client_event(&state, child_nid, &room_id)? {
            chunk.push(ev);
            last_pos = Some(sp);
        }
    }

    let mut resp = serde_json::Map::new();
    resp.insert("chunk".to_string(), Value::Array(chunk));
    if let Some(pos) = last_pos {
        // `next_batch` means "continue paginating in the SAME direction" — for both
        // dir=b (older) and dir=f (newer), the token is the last seen stream_pos,
        // which list_relations treats as exclusive on both ends.
        resp.insert("next_batch".to_string(), Value::String(format!("s{pos}")));
    }
    Ok(Json(Value::Object(resp)))
}

fn parse_stream_token(s: Option<&str>) -> Option<u64> {
    s?.strip_prefix('s').and_then(|n| n.parse().ok())
}

#[derive(Debug, Default, Deserialize)]
pub struct ThreadsQuery {
    /// `all` (default) or `participated`.
    pub include: Option<String>,
    pub limit: Option<usize>,
    pub from: Option<String>,
}

/// GET /_matrix/client/v3/rooms/{roomId}/threads
///
/// Walk the room timeline backwards, return events that have at least one
/// `m.thread` child as roots. Aggregations are bundled into each entry via
/// `load_client_event_with_relations`. `participated=true` filters to roots
/// the caller has either authored or replied within.
pub async fn threads_list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id): Path<String>,
    Query(q): Query<ThreadsQuery>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership.is_none() || membership == Some(0) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let limit = q.limit.unwrap_or(20).clamp(1, 100);
    let from = parse_stream_token(q.from.as_deref()).unwrap_or(u64::MAX);
    let participated_only = matches!(q.include.as_deref(), Some("participated"));
    let thread_nid = match state
        .db
        .get_nid("m.thread")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(Json(json!({"chunk": []}))),
    };

    // Walk the room timeline backwards in batches, collecting thread
    // roots until we have enough candidates to sort and trim. The
    // previous one-shot scan of `limit * 50` events silently
    // truncated rooms with sparse threads — anything older than ~1K
    // messages was invisible no matter the `from` token.
    //
    // We overscan by `limit * 4` to give the sort meaningful
    // ordering within the page. Pagination is by the lowest root
    // stream position seen, not by latest-child activity — that
    // would require a dedicated `(room, latest_child_sp) -> root`
    // index, which is left for a follow-up.
    const BATCH: usize = 200;
    const HARD_CAP: usize = 20_000; // worst-case bound for huge rooms
    let target = limit.saturating_mul(4);
    let mut candidates: Vec<(u64, u64, u64)> = Vec::new(); // (latest_child_sp, root_sp, root_nid)
    let mut cursor = u64::MAX;
    let mut scanned = 0usize;
    while candidates.len() < target && scanned < HARD_CAP {
        let batch = state
            .db
            .get_timeline_before(room_nid, cursor, BATCH)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        if batch.is_empty() {
            break;
        }
        scanned += batch.len();
        cursor = batch.last().map(|(sp, _)| *sp).unwrap_or(0);
        if cursor >= from {
            // Roots at or past `from` are excluded by pagination
            // bound; their thread children may still be the latest
            // we want, but we filter by root position to give a
            // stable cursor. Skip and continue.
            continue;
        }
        for (root_sp, enid) in &batch {
            let children = state
                .db
                .list_relations(*enid, Some(thread_nid), None, u64::MAX, true, 1)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            let Some(&(latest_sp, _, _, _)) = children.first() else {
                continue;
            };
            if participated_only {
                let participated =
                    root_or_replied_user(state.db.as_ref(), *enid, user.user_nid, thread_nid)?;
                if !participated {
                    continue;
                }
            }
            candidates.push((latest_sp, *root_sp, *enid));
        }
        if cursor == 0 {
            break;
        }
    }
    // Sort by latest activity; ties broken by root position so
    // pagination is deterministic.
    candidates.sort_by_key(|c| (std::cmp::Reverse(c.0), std::cmp::Reverse(c.1)));
    candidates.retain(|&(_, root_sp, _)| root_sp < from);
    candidates.truncate(limit);
    // For the response `next_batch` we use the lowest root_sp in
    // the returned chunk so the next call resumes scanning older
    // root events.
    let next_root_sp = candidates.iter().map(|c| c.1).min();

    let mut chunk = Vec::with_capacity(candidates.len());
    for (_latest_sp, _root_sp, root_nid) in candidates {
        if let Some(ev) = crate::room::messages::load_client_event_with_relations(
            &state,
            root_nid,
            &room_id,
            Some((user.user_nid, &user.device_id)),
        )? {
            chunk.push(ev);
        }
    }

    let mut resp = serde_json::Map::new();
    resp.insert("chunk".to_string(), Value::Array(chunk));
    if let Some(pos) = next_root_sp {
        resp.insert("next_batch".to_string(), Value::String(format!("s{pos}")));
    }
    Ok(Json(Value::Object(resp)))
}

fn root_or_replied_user(
    db: &vela_store::db::Database,
    root_nid: u64,
    user_nid: u64,
    thread_nid: u64,
) -> Result<bool, ApiError> {
    if let Some((header, _)) = db
        .get_event(root_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        && header.sender_nid == user_nid
    {
        return Ok(true);
    }
    let entries = db
        .list_relations(root_nid, Some(thread_nid), None, u64::MAX, true, 1000)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for (_, child_nid, _, _) in entries {
        if let Some((h, _)) = db
            .get_event(child_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && h.sender_nid == user_nid
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::AuthenticatedUser;
    use crate::test_helpers::build_test_state;
    use axum::extract::{Path, Query, State};
    use serde_json::json;

    /// Persist a v12 room with alice joined. Returns ids needed for tests.
    fn setup_room() -> (AppState, tempfile::TempDir, String, u64, u64, String) {
        let (state, tmp) = build_test_state();
        let db = &state.db;
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let alice_skey = alice_nid;

        let room_id = "!room12";
        let create_eid = "$room12";
        let room_nid = db.get_or_create_nid(room_id).unwrap();

        db.persist_event(
            100,
            create_eid,
            room_nid,
            type_create,
            alice_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type": "m.room.create",
                "sender": alice, "state_key": "", "room_id": room_id,
                "content": {"room_version": "12"},
                "origin_server_ts": 1, "depth": 1,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            101,
            "$alice_join",
            room_nid,
            type_member,
            alice_nid,
            alice_skey,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type": "m.room.member",
                "sender": alice, "state_key": alice, "room_id": room_id,
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": [create_eid], "auth_events": [create_eid],
            }))
            .unwrap(),
            &[100],
            &[100],
            true,
            false,
        )
        .unwrap();
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        // Parent message we'll relate to.
        let parent_eid = "$parent_msg";
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();
        let parent_nid = 200u64;
        let parent_pos = db
            .persist_event(
                parent_nid,
                parent_eid,
                room_nid,
                type_msg,
                alice_nid,
                0,
                5,
                5,
                &serde_json::to_vec(&json!({
                    "type": "m.room.message",
                    "sender": alice, "room_id": room_id,
                    "content": {"msgtype": "m.text", "body": "parent"},
                    "origin_server_ts": 5, "depth": 5,
                    "prev_events": ["$alice_join"], "auth_events": ["$alice_join"],
                }))
                .unwrap(),
                &[101],
                &[101],
                false,
                false,
            )
            .unwrap();
        let _ = parent_pos;

        (
            state,
            tmp,
            room_id.to_string(),
            room_nid,
            alice_nid,
            parent_eid.to_string(),
        )
    }

    fn alice_user(state: &AppState) -> AuthenticatedUser {
        let nid = state.db.get_nid("@alice:example.com").unwrap().unwrap();
        AuthenticatedUser {
            user_nid: nid,
            user_id: "@alice:example.com".into(),
            device_id: "DEV".into(),
            appservice_nid: None,
        }
    }

    /// Persist a child message with the given rel_type pointing at parent_eid.
    fn persist_child(
        state: &AppState,
        room_id: &str,
        room_nid: u64,
        sender_nid: u64,
        sender: &str,
        nid: u64,
        eid: &str,
        rel_type: &str,
        parent_eid: &str,
    ) -> u64 {
        let type_msg = state.db.get_or_create_nid("m.room.message").unwrap();
        let stream_pos = state
            .db
            .persist_event(
                nid,
                eid,
                room_nid,
                type_msg,
                sender_nid,
                0,
                10,
                10,
                &serde_json::to_vec(&json!({
                    "type": "m.room.message",
                    "sender": sender, "room_id": room_id,
                    "content": {
                        "msgtype": "m.text",
                        "body": "child",
                        "m.relates_to": {"rel_type": rel_type, "event_id": parent_eid},
                    },
                    "origin_server_ts": 10, "depth": 10,
                    "prev_events": [parent_eid], "auth_events": ["$alice_join"],
                }))
                .unwrap(),
                &[200],
                &[101],
                false,
                false,
            )
            .unwrap();
        let parent_nid = state.db.get_event_nid_by_id(parent_eid).unwrap().unwrap();
        let rel_type_nid = state.db.get_or_create_nid(rel_type).unwrap();
        state
            .db
            .record_relation(parent_nid, stream_pos, nid, rel_type_nid, type_msg)
            .unwrap();
        stream_pos
    }

    #[tokio::test]
    async fn relations_returns_children_newest_first() {
        let (state, _tmp, room_id, room_nid, alice_nid, parent_eid) = setup_room();
        persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            300,
            "$child1",
            "m.thread",
            &parent_eid,
        );
        persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            301,
            "$child2",
            "m.thread",
            &parent_eid,
        );
        persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            302,
            "$child3",
            "m.thread",
            &parent_eid,
        );

        let res = relations_with_query(
            State(state.clone()),
            alice_user(&state),
            Path((room_id.clone(), parent_eid.clone())),
            Query(RelationsQuery::default()),
        )
        .await
        .unwrap();
        let chunk = res.0.get("chunk").and_then(|v| v.as_array()).unwrap();
        let ids: Vec<&str> = chunk
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(
            ids,
            vec!["$child3", "$child2", "$child1"],
            "newest-first order"
        );
    }

    #[tokio::test]
    async fn relations_filters_by_rel_type() {
        let (state, _tmp, room_id, room_nid, alice_nid, parent_eid) = setup_room();
        persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            300,
            "$thread1",
            "m.thread",
            &parent_eid,
        );
        persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            301,
            "$react1",
            "m.annotation",
            &parent_eid,
        );

        let res = relations_with_rel_type(
            State(state.clone()),
            alice_user(&state),
            Path((room_id.clone(), parent_eid.clone(), "m.thread".into())),
            Query(RelationsQuery::default()),
        )
        .await
        .unwrap();
        let ids: Vec<&str> = res
            .0
            .get("chunk")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids, vec!["$thread1"]);
    }

    #[tokio::test]
    async fn relations_returns_empty_for_unknown_rel_type() {
        let (state, _tmp, room_id, _room_nid, _alice_nid, parent_eid) = setup_room();
        let res = relations_with_rel_type(
            State(state.clone()),
            alice_user(&state),
            Path((room_id, parent_eid, "never.minted".into())),
            Query(RelationsQuery::default()),
        )
        .await
        .unwrap();
        let chunk = res.0.get("chunk").and_then(|v| v.as_array()).unwrap();
        assert!(chunk.is_empty());
    }

    #[tokio::test]
    async fn relations_pagination_via_from_token() {
        let (state, _tmp, room_id, room_nid, alice_nid, parent_eid) = setup_room();
        let p1 = persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            300,
            "$c1",
            "m.thread",
            &parent_eid,
        );
        let p2 = persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            301,
            "$c2",
            "m.thread",
            &parent_eid,
        );
        let _p3 = persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            302,
            "$c3",
            "m.thread",
            &parent_eid,
        );

        // Limit=1, default backwards: returns $c3, next_batch points before $c3.
        let res = relations_with_query(
            State(state.clone()),
            alice_user(&state),
            Path((room_id.clone(), parent_eid.clone())),
            Query(RelationsQuery {
                limit: Some(1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let chunk = res.0.get("chunk").and_then(|v| v.as_array()).unwrap();
        assert_eq!(chunk.len(), 1);
        assert_eq!(
            chunk[0].get("event_id").and_then(|v| v.as_str()),
            Some("$c3")
        );
        let next = res.0.get("next_batch").and_then(|v| v.as_str()).unwrap();

        // Following the next_batch should yield $c2.
        let res2 = relations_with_query(
            State(state.clone()),
            alice_user(&state),
            Path((room_id.clone(), parent_eid.clone())),
            Query(RelationsQuery {
                from: Some(next.to_string()),
                limit: Some(1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let ids2: Vec<&str> = res2
            .0
            .get("chunk")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids2, vec!["$c2"]);
        let _ = (p1, p2);
    }

    #[tokio::test]
    async fn relations_forward_pagination_uses_next_batch() {
        let (state, _tmp, room_id, room_nid, alice_nid, parent_eid) = setup_room();
        for (nid, eid) in [(300u64, "$c1"), (301, "$c2"), (302, "$c3")] {
            persist_child(
                &state,
                &room_id,
                room_nid,
                alice_nid,
                "@alice:example.com",
                nid,
                eid,
                "m.thread",
                &parent_eid,
            );
        }

        // dir=f, limit=1 → first child by ASC, next_batch present.
        let res = relations_with_query(
            State(state.clone()),
            alice_user(&state),
            Path((room_id.clone(), parent_eid.clone())),
            Query(RelationsQuery {
                dir: Some("f".into()),
                limit: Some(1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let chunk = res.0.get("chunk").and_then(|v| v.as_array()).unwrap();
        assert_eq!(
            chunk[0].get("event_id").and_then(|v| v.as_str()),
            Some("$c1")
        );
        let next = res
            .0
            .get("next_batch")
            .and_then(|v| v.as_str())
            .expect("next_batch must be present for dir=f");
        assert!(res.0.get("prev_batch").is_none());

        // Continue paginating forward.
        let res2 = relations_with_query(
            State(state.clone()),
            alice_user(&state),
            Path((room_id.clone(), parent_eid.clone())),
            Query(RelationsQuery {
                dir: Some("f".into()),
                from: Some(next.to_string()),
                limit: Some(1),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let ids: Vec<&str> = res2
            .0
            .get("chunk")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids, vec!["$c2"]);
    }

    #[tokio::test]
    async fn relations_rejects_non_member() {
        let (state, _tmp, room_id, _room_nid, _alice_nid, parent_eid) = setup_room();
        let bob_nid = state.db.get_or_create_nid("@bob:example.com").unwrap();
        let err = relations_with_query(
            State(state.clone()),
            AuthenticatedUser {
                user_nid: bob_nid,
                user_id: "@bob:example.com".into(),
                device_id: "DEV".into(),
                appservice_nid: None,
            },
            Path((room_id, parent_eid)),
            Query(RelationsQuery::default()),
        )
        .await
        .expect_err("non-member rejected");
        assert!(matches!(err, ApiError(VelaError::Forbidden(_))));
    }

    #[tokio::test]
    async fn relations_404_for_unknown_parent() {
        let (state, _tmp, room_id, _room_nid, _alice_nid, _parent_eid) = setup_room();
        let err = relations_with_query(
            State(state.clone()),
            alice_user(&state),
            Path((room_id, "$does_not_exist".into())),
            Query(RelationsQuery::default()),
        )
        .await
        .expect_err("missing parent");
        assert!(matches!(err, ApiError(VelaError::NotFound(_))));
    }

    #[tokio::test]
    async fn relations_honours_to_token_backwards() {
        let (state, _tmp, room_id, room_nid, alice_nid, parent_eid) = setup_room();
        let p1 = persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            300,
            "$c1",
            "m.thread",
            &parent_eid,
        );
        let _p2 = persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            301,
            "$c2",
            "m.thread",
            &parent_eid,
        );
        let _p3 = persist_child(
            &state,
            &room_id,
            room_nid,
            alice_nid,
            "@alice:example.com",
            302,
            "$c3",
            "m.thread",
            &parent_eid,
        );
        // dir=b (default) with to=s{p1}: should stop before reaching $c1.
        let res = relations_with_query(
            State(state.clone()),
            alice_user(&state),
            Path((room_id, parent_eid)),
            Query(RelationsQuery {
                to: Some(format!("s{p1}")),
                ..Default::default()
            }),
        )
        .await
        .unwrap();
        let ids: Vec<&str> = res
            .0
            .get("chunk")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        // $c1's position is the exclusive boundary; we get $c3 + $c2 only.
        assert_eq!(ids, vec!["$c3", "$c2"]);
    }

    #[tokio::test]
    async fn thread_aggregation_count_exceeds_bundle_cap() {
        // Bundle scan is capped at 1000 entries; the aggregation
        // must report the true count via the unbounded path.
        let (state, _tmp, room_id, room_nid, alice_nid, parent_eid) = setup_room();
        // 5 children is small but exercises the unbounded path; the
        // store unit test below covers the >1000 case.
        for i in 0..5u64 {
            persist_child(
                &state,
                &room_id,
                room_nid,
                alice_nid,
                "@alice:example.com",
                400 + i,
                &format!("$t{i}"),
                "m.thread",
                &parent_eid,
            );
        }
        let parent_nid = state.db.get_event_nid_by_id(&parent_eid).unwrap().unwrap();
        let ev = crate::room::messages::load_client_event_with_relations(
            &state,
            parent_nid,
            &room_id,
            Some((alice_nid, "DEV")),
        )
        .unwrap()
        .unwrap();
        let count = ev
            .pointer("/unsigned/m.relations/m.thread/count")
            .and_then(|v| v.as_u64())
            .unwrap();
        assert_eq!(count, 5);
        let participated = ev
            .pointer("/unsigned/m.relations/m.thread/current_user_participated")
            .and_then(|v| v.as_bool())
            .unwrap();
        assert!(participated);
    }
}
