//! Discoverable surfaces: room aliases, public room listing, user
//! directory, spaces, free-text search, well-known/discovery, and
//! `timestamp_to_event`. Anything a client uses to *find* resources
//! (rather than read or modify them) lives here.

pub mod discovery;
pub mod search;
pub mod spaces;
pub mod timestamp;
pub mod user_directory;

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
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
            return resolve_local_alias(&state, &room_alias).await;
        }
        return resolve_remote_alias(&state, &room_alias, server).await;
    }

    resolve_local_alias(&state, &room_alias).await
}

async fn resolve_local_alias(state: &AppState, alias: &str) -> Result<Json<Value>, ApiError> {
    if let Some(room_id) = state
        .db
        .get_room_alias(alias)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        let servers = servers_for_alias_response(state, &room_id);
        return Ok(Json(json!({
            "room_id": room_id,
            "servers": servers,
        })));
    }

    // Local miss: ask the AS that owns this alias namespace to
    // provision on demand. The AS is expected to PUT the alias
    // mapping back during the handshake; we re-read after the call.
    if let Some(live) =
        crate::appservice::query::find_as_owning_alias(&state.appservice_registry, alias)
        && let Some(hs_token) = state.appservice_outbox.hs_token(live.appservice.nid)
    {
        let outcome = crate::appservice::query::query_alias(
            state.appservice_outbox.http_client(),
            &hs_token,
            &live,
            alias,
        )
        .await;
        if matches!(outcome, crate::appservice::query::QueryOutcome::Owned)
            && let Some(room_id) = state
                .db
                .get_room_alias(alias)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            let servers = servers_for_alias_response(state, &room_id);
            return Ok(Json(json!({
                "room_id": room_id,
                "servers": servers,
            })));
        }
    }

    Err(ApiError(VelaError::NotFound("alias not found".into())))
}

/// Compute the `servers` list returned by `/directory/room/{alias}`.
/// Spec wants every server that knows the room — clients use the
/// list as join hints. Returns our own server plus any remote peers
/// we can identify locally:
///
/// - Partial-state rooms: union in `servers_in_room` from the
///   partial-state record (the resident peer's broadcast list at
///   join time). MSC3902 tests rely on this — the directory query
///   happens before the filler completes, so the local membership
///   index doesn't yet list every peer.
/// - Full-state rooms: union in every remote server with a joined
///   member.
fn servers_for_alias_response(state: &AppState, room_id: &str) -> Vec<String> {
    let mut servers: Vec<String> = vec![state.config.server_name.clone()];
    let Ok(Some(room_nid)) = state.db.get_nid(room_id) else {
        return servers;
    };
    if let Ok((true, hint_servers)) = state.db.get_partial_state_info(room_nid) {
        for s in hint_servers {
            if s != state.config.server_name && !servers.iter().any(|x| x == &s) {
                servers.push(s);
            }
        }
    }
    if let Ok(remotes) = state
        .db
        .get_remote_servers_in_room(room_nid, &state.config.server_name)
    {
        for s in remotes {
            if !servers.iter().any(|x| x == &s) {
                servers.push(s);
            }
        }
    }
    servers
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
///
/// Records the caller as the alias creator so DELETE can authorise the
/// creator without a PL check. If the alias already exists we return
/// 409 `M_UNKNOWN` per spec — never overwrite, because that would let any
/// authenticated user steal someone else's alias-creator status.
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
        return Err(ApiError(VelaError::Custom {
            status: 409,
            errcode: "M_UNKNOWN",
            msg: format!("Room alias {room_alias} already exists."),
        }));
    }

    // M_EXCLUSIVE: callers cannot claim aliases inside an AS's
    // exclusive alias namespace, unless the caller is that AS itself.
    if let crate::appservice::exclusive::ExclusiveCheck::Refused(reason) =
        crate::appservice::exclusive::check_alias(
            &state.appservice_registry,
            &room_alias,
            user.appservice_nid,
        )
    {
        return Err(ApiError(VelaError::Custom {
            status: 400,
            errcode: "M_EXCLUSIVE",
            msg: reason,
        }));
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
                "You do not have permission to delete this alias".into(),
            )
            .into());
        }
    }

    state
        .db
        .delete_room_alias(&room_alias)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Spec: deleting an alias that's currently named in the room's
    // m.room.canonical_alias (either as `alias` or in `alt_aliases`)
    // requires emitting a fresh canonical_alias with the dead reference
    // removed — clients use the resulting timeline event as the signal
    // that the canonical pointer is stale. Without this, /messages and
    // /sync continue showing the old canonical_alias pointing at a
    // now-404 alias.
    maybe_clear_canonical_alias_on_delete(&state, &user, &room_id, &room_alias).await;

    Ok(Json(json!({})))
}

/// If the room's current `m.room.canonical_alias` names `deleted_alias`
/// in `alias` or `alt_aliases`, emit a new canonical_alias with the
/// reference removed. Best-effort — failures only mean the canonical
/// pointer stays stale; clients still see the underlying alias 404 on
/// their next /directory/room/{alias} call.
async fn maybe_clear_canonical_alias_on_delete(
    state: &AppState,
    user: &AuthenticatedUser,
    room_id: &str,
    deleted_alias: &str,
) {
    let Ok(Some(room_nid)) = state.db.get_nid(room_id) else {
        return;
    };
    let Ok(Some(canonical)) =
        crate::membership::read_state_value_pub(state, room_nid, "m.room.canonical_alias", "")
    else {
        return;
    };
    let content = canonical.get("content").and_then(|c| c.as_object());
    let Some(content) = content else { return };

    let current_alias = content.get("alias").and_then(|v| v.as_str());
    let alt_aliases: Vec<String> = content
        .get("alt_aliases")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let alias_matched = current_alias == Some(deleted_alias);
    let new_alt_aliases: Vec<String> = alt_aliases
        .iter()
        .filter(|a| a.as_str() != deleted_alias)
        .cloned()
        .collect();
    let alt_changed = new_alt_aliases.len() != alt_aliases.len();

    if !alias_matched && !alt_changed {
        return;
    }

    let mut new_content = serde_json::Map::new();
    if !alias_matched && let Some(a) = current_alias {
        new_content.insert("alias".to_string(), Value::String(a.to_string()));
    }
    if !new_alt_aliases.is_empty() {
        new_content.insert(
            "alt_aliases".to_string(),
            Value::Array(new_alt_aliases.into_iter().map(Value::String).collect()),
        );
    }

    let _ = crate::room::send::send_state_inner(
        state.clone(),
        user.clone(),
        room_id.to_string(),
        "m.room.canonical_alias".to_string(),
        String::new(),
        None,
        Value::Object(new_content),
    )
    .await;
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
#[derive(Debug, Default, Deserialize)]
pub struct PublicRoomsQuery {
    /// Remote homeserver to query instead of our local directory.
    /// When set, we forward the request via
    /// `POST /_matrix/federation/v1/publicRooms` and return the
    /// peer's response. Without it, we serve our own directory.
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(default)]
    pub since: Option<String>,
}

/// Returns rooms visible in the directory. Without a dedicated published
/// list, we surface joined rooms with `join_rule=public` as a useful
/// approximation. Callers paginate via `limit` / `since`.
pub async fn list_public_rooms(
    State(state): State<AppState>,
    Query(q): Query<PublicRoomsQuery>,
) -> Result<Json<Value>, ApiError> {
    if let Some(server) = q.server.as_deref()
        && server != state.config.server_name
    {
        return fetch_remote_public_rooms(&state, server, q.limit, q.since.as_deref(), None).await;
    }
    let chunk = collect_public_rooms(&state, None)?;
    let total = chunk.len() as u64;
    Ok(Json(json!({
        "chunk": chunk,
        "total_room_count_estimate": total,
    })))
}

async fn fetch_remote_public_rooms(
    state: &AppState,
    server: &str,
    limit: Option<u64>,
    since: Option<&str>,
    search_term: Option<&str>,
) -> Result<Json<Value>, ApiError> {
    state
        .federation_client
        .fetch_public_rooms(server, limit, since, search_term)
        .await
        .map(Json)
        .map_err(|e| {
            ApiError(VelaError::Store(format!(
                "remote publicRooms ({server}) failed: {e}"
            )))
        })
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
    Query(q): Query<PublicRoomsQuery>,
    Json(body): Json<PublicRoomsBody>,
) -> Result<Json<Value>, ApiError> {
    let term = body
        .filter
        .as_ref()
        .and_then(|f| f.generic_search_term.as_deref());
    if let Some(server) = q.server.as_deref()
        && server != state.config.server_name
    {
        return fetch_remote_public_rooms(
            &state,
            server,
            q.limit.or(body.limit.map(|l| l as u64)),
            q.since.as_deref().or(body.since.as_deref()),
            term,
        )
        .await;
    }
    let lowered = term.map(|s| s.to_lowercase());
    let chunk = collect_public_rooms(&state, lowered.as_deref())?;
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

#[cfg(test)]
mod as_query_tests {
    use super::*;
    use crate::appservice::namespace::{Namespace, NamespaceScope};
    use crate::appservice::{AppService, AppServiceConfig, hash_token};
    use crate::test_helpers::build_test_state;

    fn seed_as_with_alias_ns(
        state: &AppState,
        as_id: &str,
        url: &str,
        hs_token_cleartext: &str,
    ) -> u64 {
        let asv = AppService {
            nid: 0,
            id: as_id.into(),
            config: AppServiceConfig {
                url: url.into(),
                hs_token_hash: hash_token(hs_token_cleartext),
                as_token_hash: hash_token(&format!("as-{as_id}")),
                sender_localpart: format!("_{as_id}_bot"),
                receive_ephemeral: false,
            },
            namespaces: vec![Namespace {
                scope: NamespaceScope::Alias,
                regex: r"^#_irc_.*:example\.com$".into(),
                exclusive: true,
            }],
            enabled: true,
            owner_nid: None,
            created_at_ms: 0,
        };
        let registered = state.appservice_registry.register(asv).unwrap();
        state
            .appservice_outbox
            .set_hs_token(registered.nid, hs_token_cleartext.into());
        registered.nid
    }

    /// Local alias exists → resolves without calling the AS.
    #[tokio::test]
    async fn resolve_skips_as_query_when_alias_present_locally() {
        let server = wiremock::MockServer::start().await;
        // Expect zero calls.
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let (state, _tmp) = build_test_state();
        seed_as_with_alias_ns(&state, "irc", &server.uri(), "hs-tok");
        // Pre-populate the alias.
        state
            .db
            .set_room_alias_with_creator(
                "#_irc_chan:example.com",
                "!room0:example.com",
                "@admin:example.com",
            )
            .unwrap();
        let resp = resolve_local_alias(&state, "#_irc_chan:example.com")
            .await
            .expect("resolves");
        assert_eq!(resp.0["room_id"], "!room0:example.com");
    }

    /// Local alias missing + AS owns namespace → vela calls the AS.
    /// AS returns 200 here without provisioning; the test verifies
    /// the call happened. (The DB-write side of the handshake is the
    /// AS's responsibility; we just prove the query is wired.)
    #[tokio::test]
    async fn resolve_queries_as_when_alias_missing_and_in_namespace() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path_regex(r"^/_matrix/app/v1/rooms/.*"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let (state, _tmp) = build_test_state();
        seed_as_with_alias_ns(&state, "irc", &server.uri(), "hs-tok");

        let err = resolve_local_alias(&state, "#_irc_chan:example.com")
            .await
            .expect_err("still 404 because AS didn't provision in the test");
        assert!(matches!(err.0, VelaError::NotFound(_)));
        // Wiremock's drop impl panics if expect(1) wasn't met.
        drop(server);
    }

    /// Local alias missing + alias NOT in any AS namespace → no AS
    /// query, returns 404.
    #[tokio::test]
    async fn resolve_skips_as_query_when_alias_outside_namespace() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let (state, _tmp) = build_test_state();
        seed_as_with_alias_ns(&state, "irc", &server.uri(), "hs-tok");
        let err = resolve_local_alias(&state, "#random:example.com")
            .await
            .expect_err("404");
        assert!(matches!(err.0, VelaError::NotFound(_)));
    }
}
