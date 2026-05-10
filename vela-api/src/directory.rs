use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

/// GET /_matrix/client/v3/directory/room/{roomAlias}
pub async fn get_room_alias(
    State(state): State<AppState>,
    Path(room_alias): Path<String>,
) -> Result<Json<Value>, ApiError> {
    if let Some(server) = alias_server(&room_alias) {
        if server == state.config.server_name {
            return resolve_local_alias(&state, &room_alias);
        }
        return resolve_remote_alias(&state, &room_alias, server).await;
    }

    resolve_local_alias(&state, &room_alias)
}

fn resolve_local_alias(state: &AppState, alias: &str) -> Result<Json<Value>, ApiError> {
    let room_id = state
        .db
        .get_room_alias(alias)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("alias not found".into())))?;

    Ok(Json(json!({
        "room_id": room_id,
        "servers": [state.config.server_name],
    })))
}

async fn resolve_remote_alias(
    state: &AppState,
    alias: &str,
    server: &str,
) -> Result<Json<Value>, ApiError> {
    let resp = state
        .federation_client
        .query_directory(server, alias)
        .await
        .map_err(|e| {
            ApiError(VelaError::NotFound(format!(
                "remote alias resolution failed: {e}"
            )))
        })?;

    Ok(Json(resp))
}

#[derive(Deserialize)]
pub struct SetAliasBody {
    pub room_id: String,
}

/// PUT /_matrix/client/v3/directory/room/{roomAlias}
pub async fn set_room_alias(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_alias): Path<String>,
    Json(body): Json<SetAliasBody>,
) -> Result<Json<Value>, ApiError> {
    if state
        .db
        .get_room_alias(&room_alias)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .is_some()
    {
        return Err(ApiError(VelaError::BadJson("alias already exists".into())));
    }

    state
        .db
        .set_room_alias_with_creator(&room_alias, &body.room_id, &user.user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/v3/directory/room/{roomAlias}
///
/// Returns 404 if the alias doesn't exist locally. Per spec, the caller
/// must be the alias creator OR have sufficient power level in the target
/// room (events.m.room.aliases, falling back to state_default=50). Legacy
/// aliases stored without a creator are deletable only via the power-level
/// path — fine, since legacy data is small and migration-time only.
pub async fn delete_room_alias(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_alias): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let record = state
        .db
        .get_room_alias_record(&room_alias)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound(format!("alias {room_alias} not found"))))?;
    let (room_id, creator) = record;

    let is_creator = creator.as_deref() == Some(user.user_id.as_str());
    if !is_creator {
        let room_nid = state
            .db
            .get_nid(&room_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .ok_or_else(|| ApiError(VelaError::NotFound("alias points to unknown room".into())))?;
        let needed = events_alias_threshold(&state, room_nid)?;
        let user_pl = crate::membership::user_power(&state, room_nid, &user.user_id)?;
        if user_pl < needed {
            return Err(VelaError::Forbidden(
                "alias delete requires alias creator or sufficient power level".into(),
            )
            .into());
        }
    }

    state
        .db
        .delete_room_alias(&room_alias)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({})))
}

/// Power level threshold required to delete or rebind an alias. Reads
/// `events.m.room.aliases` from the room's current m.room.power_levels;
/// when absent, falls back to `state_default` (spec default 50). When
/// no power_levels event exists at all, allows anyone — covers the
/// very-new-room window before /createRoom finishes emitting state.
fn events_alias_threshold(state: &AppState, room_nid: u64) -> Result<i64, ApiError> {
    let Some(pl) =
        crate::membership::read_state_value_pub(state, room_nid, "m.room.power_levels", "")?
    else {
        return Ok(0);
    };
    let content = pl.get("content");
    let from_events = content
        .and_then(|c| c.get("events"))
        .and_then(|e| e.get("m.room.aliases"))
        .and_then(|v| v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)));
    if let Some(n) = from_events {
        return Ok(n);
    }
    let from_state_default = content
        .and_then(|c| c.get("state_default"))
        .and_then(|v| v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)));
    Ok(from_state_default.unwrap_or(50))
}

/// Extract the server part from a room alias (#alias:server).
fn alias_server(alias: &str) -> Option<&str> {
    alias.strip_prefix('#')?.split_once(':').map(|(_, s)| s)
}

/// GET /_matrix/client/v3/directory/list/room/{roomId}
///
/// Reports whether the room is in the published-rooms directory.
/// Reads the explicit `room_directory` flag; falls back to
/// `m.room.join_rules == "public"` for rooms created before the
/// directory flag existed.
pub async fn get_room_visibility(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    let visibility = match state
        .db
        .get_room_directory_visibility(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(true) => "public",
        Some(false) => "private",
        None => {
            // Legacy fallback for rooms predating the explicit flag.
            if read_join_rule(&state, room_nid)? == "public" {
                "public"
            } else {
                "private"
            }
        }
    };
    Ok(Json(json!({"visibility": visibility})))
}

/// PUT /_matrix/client/v3/directory/list/room/{roomId}
///
/// Body: `{"visibility": "public" | "private"}`. Caller must be a
/// joined member of the room. Updates the directory flag; does NOT
/// touch join_rules (the two are independent per spec).
pub async fn put_room_visibility(
    State(state): State<AppState>,
    user: crate::middleware::auth::AuthenticatedUser,
    Path(room_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<Value>, ApiError> {
    let visibility = body
        .get("visibility")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError(VelaError::BadJson("missing visibility".into())))?;
    let public = match visibility {
        "public" => true,
        "private" => false,
        _ => {
            return Err(
                VelaError::BadJson("visibility must be \"public\" or \"private\"".into()).into(),
            );
        }
    };
    let room_nid = state
        .db
        .get_nid(&room_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;
    // Membership gate. Only joined members can change directory
    // visibility — avoids letting non-members publish rooms they
    // don't participate in.
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("user not joined to room".into()).into());
    }
    state
        .db
        .set_room_directory_visibility(room_nid, public)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({})))
}

/// `read_join_rule(...) == "public"` — exposed for callers (e.g. the
/// user_directory search) that want directory-equivalence on legacy
/// rooms without their own copy of this fallback.
pub(crate) fn read_join_rule_public(state: &AppState, room_nid: u64) -> Result<bool, ApiError> {
    Ok(read_join_rule(state, room_nid)? == "public")
}

fn read_join_rule(state: &AppState, room_nid: u64) -> Result<String, ApiError> {
    let type_nid = match state
        .db
        .get_nid("m.room.join_rules")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok("invite".into()),
    };
    let skey_nid = match state
        .db
        .get_nid("")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok("invite".into()),
    };
    let event_nid = match state
        .db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok("invite".into()),
    };
    let bytes = match state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some((_, b)) => b,
        None => return Ok("invite".into()),
    };
    let ev: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok(ev
        .get("content")
        .and_then(|c| c.get("join_rule"))
        .and_then(|v| v.as_str())
        .unwrap_or("invite")
        .to_string())
}

/// GET /_matrix/client/v3/publicRooms
///
/// Returns rooms visible in the directory. Without a dedicated published
/// list, we surface joined rooms with `join_rule=public` as a useful
/// approximation. Callers paginate via `limit` / `since`.
pub async fn list_public_rooms(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let chunk = collect_public_rooms(&state, None)?;
    let total = chunk.len() as u64;
    Ok(Json(json!({
        "chunk": chunk,
        "total_room_count_estimate": total,
    })))
}

#[derive(Debug, Default, Deserialize)]
pub struct PublicRoomsFilter {
    pub generic_search_term: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PublicRoomsBody {
    #[serde(default)]
    pub filter: Option<PublicRoomsFilter>,
    #[serde(default)]
    #[allow(dead_code)]
    pub limit: Option<usize>,
    #[serde(default)]
    #[allow(dead_code)]
    pub since: Option<String>,
}

/// POST /_matrix/client/v3/publicRooms
///
/// Same as GET but accepts a search filter body. We do a case-insensitive
/// substring match on name/topic/canonical_alias when `generic_search_term`
/// is supplied — basic but matches what most clients expect for room
/// discovery.
pub async fn search_public_rooms(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Json(body): Json<PublicRoomsBody>,
) -> Result<Json<Value>, ApiError> {
    let term = body
        .filter
        .as_ref()
        .and_then(|f| f.generic_search_term.as_deref())
        .map(|s| s.to_lowercase());
    let chunk = collect_public_rooms(&state, term.as_deref())?;
    let total = chunk.len() as u64;
    Ok(Json(json!({
        "chunk": chunk,
        "total_room_count_estimate": total,
    })))
}

pub(crate) fn collect_public_rooms(
    state: &AppState,
    search: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    let rooms = state.db.list_room_ids().unwrap_or_default();
    let mut chunk = Vec::new();
    for room_id in rooms {
        let Some(room_nid) = state
            .db
            .get_nid(&room_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        // Filter by explicit directory flag if set; fall back to
        // `join_rules == "public"` for legacy rooms.
        let in_directory = match state
            .db
            .get_room_directory_visibility(room_nid)
            .unwrap_or(None)
        {
            Some(v) => v,
            None => read_join_rule(state, room_nid)? == "public",
        };
        if !in_directory {
            continue;
        }
        let joined = state
            .db
            .get_room_members(room_nid)
            .map(|m| m.len())
            .unwrap_or(0) as u64;
        let name = read_simple_state(state, room_nid, "m.room.name", "name");
        let topic = read_simple_state(state, room_nid, "m.room.topic", "topic");
        let canonical_alias = read_simple_state(state, room_nid, "m.room.canonical_alias", "alias");

        if let Some(term) = search {
            let hay = format!(
                "{} {} {}",
                name.as_deref().unwrap_or(""),
                topic.as_deref().unwrap_or(""),
                canonical_alias.as_deref().unwrap_or("")
            )
            .to_lowercase();
            if !hay.contains(term) {
                continue;
            }
        }

        let join_rule = read_join_rule(state, room_nid)?;
        let mut entry = serde_json::Map::new();
        entry.insert("room_id".to_string(), json!(room_id));
        entry.insert("num_joined_members".to_string(), json!(joined));
        entry.insert("world_readable".to_string(), json!(false));
        entry.insert("guest_can_join".to_string(), json!(false));
        entry.insert("join_rule".to_string(), json!(join_rule));
        if let Some(n) = name {
            entry.insert("name".to_string(), json!(n));
        }
        if let Some(t) = topic {
            entry.insert("topic".to_string(), json!(t));
        }
        if let Some(a) = canonical_alias {
            entry.insert("canonical_alias".to_string(), json!(a));
        }
        chunk.push(Value::Object(entry));
    }
    Ok(chunk)
}

fn read_simple_state(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    content_key: &str,
) -> Option<String> {
    let type_nid = state.db.get_nid(event_type).ok().flatten()?;
    let skey_nid = state.db.get_nid("").ok().flatten()?;
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .ok()
        .flatten()?;
    let (_h, bytes) = state.db.get_event(event_nid).ok().flatten()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("content")?
        .get(content_key)?
        .as_str()
        .map(|s| s.to_string())
}
