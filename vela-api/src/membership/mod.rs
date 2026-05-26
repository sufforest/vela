//! (user, room) edge lifecycle — join, invite, kick, ban, leave,
//! knock. Local handlers live here alongside the federation halves
//! (`federation_join`, `federation_knock`, etc.) because the spec
//! couples them: every CS-API membership operation has a wire-side
//! counterpart that must agree on auth rules and state shape.

pub mod federation_invite;
pub mod federation_join;
pub mod federation_knock;
pub mod federation_leave;
pub mod federation_outbound_join;
pub mod federation_outbound_knock;

use std::sync::Arc;

use crate::middleware::json::Json;
use axum::body::Bytes;
use axum::extract::{Path, RawQuery, State};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::{build_event, select_auth_events};
use vela_core::events::content;
use vela_core::events::view::EventView;
use vela_core::identifiers::{EventId, Nid, RoomId};

use crate::auth_check::authorise_event;
use crate::membership::federation_outbound_join::do_remote_join;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::rooms::get_or_create_signing_key;
use crate::router::AppState;

/// Parse a raw query string, collecting all values for `key`. Accepts
/// repeated keys (`?server_name=a&server_name=b`) and comma-separated
/// values within a single entry. `serde_urlencoded` rejects repeated keys
/// at the struct level, which is why the join/knock handlers consume
/// `RawQuery` and call this helper directly.
pub(crate) fn parse_query_values(raw: Option<&str>, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(q) = raw {
        for (k, v) in form_urlencoded::parse(q.as_bytes()) {
            if k != key {
                continue;
            }
            for piece in v.split(',') {
                let trimmed = piece.trim();
                if !trimmed.is_empty() {
                    out.push(trimmed.to_string());
                }
            }
        }
    }
    out
}

/// POST /_matrix/client/v3/join/{roomIdOrAlias}
///
/// Body is optional; when present, non-`membership` fields are merged
/// into the emitted `m.room.member` content (spec: clients can attach
/// arbitrary metadata, e.g. a custom `reason` or third-party data).
pub async fn join_by_id_or_alias(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_or_alias): Path<String>,
    RawQuery(raw_query): RawQuery,
    body_bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
    let extra_content = parse_optional_body(&body_bytes)?;
    let hints = parse_query_values(raw_query.as_deref(), "server_name");
    if room_id_or_alias.starts_with('#') {
        let alias = room_id_or_alias.clone();
        let (room_id, mut servers) = resolve_alias(&state, &alias).await?;
        servers.extend(hints);
        return do_join(state, user, room_id, servers, extra_content).await;
    }
    let room_id = RoomId::parse(&room_id_or_alias)
        .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
    do_join(state, user, room_id, hints, extra_content).await
}

/// Parse an optional JSON-object body. Empty body → `None`. Any
/// non-empty body must parse as a JSON object.
fn parse_optional_body(bytes: &Bytes) -> Result<Option<Value>, ApiError> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|e| {
        ApiError(VelaError::NotJson(format!(
            "request body is not valid JSON: {e}"
        )))
    })?;
    if !v.is_object() {
        return Err(ApiError(VelaError::BadJson(
            "body must be a JSON object".into(),
        )));
    }
    Ok(Some(v))
}

async fn resolve_alias(state: &AppState, alias: &str) -> Result<(RoomId, Vec<String>), ApiError> {
    // Try local first
    if let Some(room_id_str) = state
        .db
        .get_room_alias(alias)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        let room_id = RoomId::parse(&room_id_str)
            .map_err(|_| ApiError(VelaError::NotFound("invalid room_id for alias".into())))?;
        return Ok((room_id, vec![state.config.server_name.clone()]));
    }

    // Extract server from alias and try federation
    let server = alias
        .strip_prefix('#')
        .and_then(|s| s.split_once(':'))
        .map(|(_, s)| s)
        .ok_or_else(|| ApiError(VelaError::NotFound("invalid alias format".into())))?;

    let resp = state
        .federation_client
        .query_directory(server, alias)
        .await
        .map_err(|e| ApiError(VelaError::NotFound(format!("alias resolution failed: {e}"))))?;

    let room_id_str = resp
        .get("room_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError(VelaError::NotFound("remote returned no room_id".into())))?;
    let room_id = RoomId::parse(room_id_str).map_err(|_| {
        ApiError(VelaError::NotFound(
            "remote returned invalid room_id".into(),
        ))
    })?;

    let servers: Vec<String> = resp
        .get("servers")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec![server.to_string()]);

    Ok((room_id, servers))
}

/// POST /_matrix/client/v3/rooms/{roomId}/join
pub async fn join_room(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    RawQuery(raw_query): RawQuery,
    body_bytes: Bytes,
) -> Result<Json<Value>, ApiError> {
    let extra_content = parse_optional_body(&body_bytes)?;
    let room_id = RoomId::parse(&room_id_str)
        .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
    let hints = parse_query_values(raw_query.as_deref(), "server_name");
    do_join(state, user, room_id, hints, extra_content).await
}

async fn do_join(
    state: AppState,
    user: AuthenticatedUser,
    room_id: RoomId,
    server_hints: Vec<String>,
    extra_content: Option<Value>,
) -> Result<Json<Value>, ApiError> {
    // If the room is known locally, run the regular local join flow.
    // Otherwise, if the client supplied server_name hints, dispatch to the
    // federated outbound-join path.
    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let room_nid = match room_nid {
        Some(n) => n,
        None => {
            // Not local — try federated join.
            do_remote_join(
                &state,
                &user.user_id,
                user.user_nid,
                &room_id,
                &server_hints,
            )
            .await?;
            // After the remote join the room exists locally; resolve
            // its nid and federate device lists to the new co-resident
            // servers, plus record local device-list changes so the
            // joiner's own /sync surfaces room-mates in
            // device_lists.changed.
            if let Ok(Some(rn)) = state.db.get_nid(room_id.as_str()) {
                crate::e2ee::keys::record_device_changes_on_join(&state, user.user_nid, rn);
                crate::e2ee::keys::federate_device_lists_on_join(
                    &state,
                    user.user_nid,
                    &user.user_id,
                    rn,
                );
                carry_over_predecessor_push_rules(&state, user.user_nid, rn, room_id.as_str())
                    .await;
            }
            return Ok(Json(json!({"room_id": room_id.as_str()})));
        }
    };

    // Check current membership
    let current = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if current == Some(1) {
        return Ok(Json(json!({"room_id": room_id.as_str()})));
    }

    // Federated invite case: the room NID exists locally because we
    // persisted an invite (plus stripped state) delivered via
    // /_matrix/federation/v2/invite, but the room is actually hosted
    // elsewhere. We can't build a valid join event from the stripped
    // state — it lacks signatures/hashes — so the only correct path is
    // the outbound federated-join flow. Distinguish by checking whether
    // the creator of the room is on our server.
    if !room_is_locally_hosted(&state, room_nid)? {
        // Restricted-room local-authoriser fast path: if we already
        // hold the room state and have a local member with invite
        // power who satisfies the allow list, mint the join event
        // locally and broadcast. Avoids a remote round-trip and
        // ensures `join_authorised_via_users_server` points at our
        // local user (regression check in
        // TestRestrictedRoomsLocalJoinNoCreatorsUsesPowerLevelsV12).
        //
        // Federation propagation race: if `local_authoriser_for_
        // restricted` returns None on first try, the room state may
        // just be stale — the resident server's most recent
        // m.room.power_levels (the one that promoted our local
        // member to invite power) might be still in flight. Poll
        // briefly before falling through to a remote join. Bounded
        // at ~500 ms total so a genuinely-no-local-authoriser case
        // doesn't drag the join out.
        if let Some(authoriser) =
            local_authoriser_for_restricted_with_wait(&state, room_nid, &user).await?
        {
            emit_join_event(
                &state,
                &user,
                room_nid,
                &room_id,
                Some(&authoriser),
                extra_content.as_ref(),
            )
            .await?;
            crate::e2ee::keys::record_device_changes_on_join(&state, user.user_nid, room_nid);
            crate::e2ee::keys::federate_device_lists_on_join(
                &state,
                user.user_nid,
                &user.user_id,
                room_nid,
            );
            carry_over_predecessor_push_rules(&state, user.user_nid, room_nid, room_id.as_str())
                .await;
            return Ok(Json(json!({"room_id": room_id.as_str()})));
        }

        let mut hints: Vec<String> = server_hints
            .iter()
            .filter(|s| s.as_str() != state.config.server_name.as_str())
            .cloned()
            .collect();
        if hints.is_empty() {
            // Client either omitted server_name or only listed us. Pick
            // the inviter's server first, then fall back to other servers
            // we know are in the room (creator's domain or any joined
            // remote member). TestRestrictedRoomsRemoteJoinLocalUser
            // sends `?server_name=hs1` for a room hosted on hs2, so we
            // need a way to resolve hs2 from local state.
            if let Some(inv) = invite_sender_server(&state, room_nid, user.user_nid)? {
                hints.push(inv);
            }
            for s in remote_servers_in_room(&state, room_nid)? {
                if !hints.contains(&s) {
                    hints.push(s);
                }
            }
        }
        do_remote_join(&state, &user.user_id, user.user_nid, &room_id, &hints).await?;
        crate::e2ee::keys::record_device_changes_on_join(&state, user.user_nid, room_nid);
        crate::e2ee::keys::federate_device_lists_on_join(
            &state,
            user.user_nid,
            &user.user_id,
            room_nid,
        );
        carry_over_predecessor_push_rules(&state, user.user_nid, room_nid, room_id.as_str()).await;
        return Ok(Json(json!({"room_id": room_id.as_str()})));
    }

    // Check join rules
    let join_rule_event = get_join_rule_content(&state, room_nid)?;
    let join_rule = join_rule_event
        .get("join_rule")
        .and_then(|v| v.as_str())
        .unwrap_or("invite")
        .to_string();
    let mut authoriser: Option<String> = None;

    match join_rule.as_str() {
        "public" => {} // anyone can join
        "invite" | "knock" => {
            if current != Some(2) {
                // 2 = invite
                return Err(VelaError::Forbidden("join requires an invite".into()).into());
            }
        }
        "restricted" | "knock_restricted" => {
            if current == Some(2) || current == Some(1) {
                // already invited or somehow re-joining — auth rule short-circuits.
            } else {
                let allow = join_rule_event
                    .get("allow")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if !user_qualifies_via_allow_list(&state, user.user_nid, &allow)? {
                    return Err(VelaError::Forbidden(
                        "join: not a member of any allowed room".into(),
                    )
                    .into());
                }
                authoriser = Some(pick_local_authoriser(&state, room_nid)?.ok_or_else(|| {
                    ApiError(VelaError::Forbidden(
                        "no local member with power to authorise this join".into(),
                    ))
                })?);
            }
        }
        _ => return Err(VelaError::Forbidden("cannot join this room".into()).into()),
    }

    emit_join_event(
        &state,
        &user,
        room_nid,
        &room_id,
        authoriser.as_deref(),
        extra_content.as_ref(),
    )
    .await?;

    crate::e2ee::keys::record_device_changes_on_join(&state, user.user_nid, room_nid);
    crate::e2ee::keys::federate_device_lists_on_join(
        &state,
        user.user_nid,
        &user.user_id,
        room_nid,
    );
    carry_over_predecessor_push_rules(&state, user.user_nid, room_nid, room_id.as_str()).await;

    Ok(Json(json!({"room_id": room_id.as_str()})))
}

/// If the room's `m.room.create` carries `content.predecessor.room_id`,
/// clone the joining user's `room` push rule for the predecessor so
/// the same notify settings apply in the upgraded room. Idempotent,
/// no-op when the user has no such rule.
async fn carry_over_predecessor_push_rules(
    state: &AppState,
    user_nid: u64,
    room_nid: u64,
    new_room_id: &str,
) {
    let Ok(Some(create)) = read_state_value(state, room_nid, "m.room.create", "") else {
        return;
    };
    let Some(old_room_id) = create
        .get("content")
        .and_then(|c| c.get("predecessor"))
        .and_then(|p| p.get("room_id"))
        .and_then(|v| v.as_str())
    else {
        return;
    };
    let _ = crate::room::room_upgrade::carry_over_push_rules_for_user(
        state,
        user_nid,
        old_room_id,
        new_room_id,
    )
    .await;
}

/// Wrap `local_authoriser_for_restricted` with a brief poll-and-retry
/// for the cross-server propagation race: hs2's join handler sees no
/// local-member-with-invite-power because hs1's m.room.power_levels
/// update is still in flight on the federation send queue. The first
/// call is synchronous; if it misses, sleep with exponential backoff
/// (50ms, 100ms, 200ms — ~350ms total) and re-check, breaking out as
/// soon as the state catches up. Local lookups are cheap, so the
/// retry cost is essentially the sleep total when the room
/// genuinely has no local authoriser.
async fn local_authoriser_for_restricted_with_wait(
    state: &AppState,
    room_nid: u64,
    user: &AuthenticatedUser,
) -> Result<Option<String>, ApiError> {
    if let Some(auth) = local_authoriser_for_restricted(state, room_nid, user)? {
        return Ok(Some(auth));
    }
    for delay_ms in [50u64, 100, 200] {
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        if let Some(auth) = local_authoriser_for_restricted(state, room_nid, user)? {
            return Ok(Some(auth));
        }
    }
    Ok(None)
}

/// For a non-locally-hosted restricted/knock_restricted room we
/// already have state for, decide whether we can mint the join event
/// ourselves. Returns the local authoriser's user_id when:
///   1. join_rule is restricted or knock_restricted,
///   2. the joining user qualifies via the allow-list, AND
///   3. some local member has both invite power and is currently joined.
///
/// Returns `None` for any other join_rule, when the user doesn't
/// qualify, or when no local authoriser is available. Callers fall
/// back to a remote `make_join` / `send_join` round-trip in those
/// cases.
fn local_authoriser_for_restricted(
    state: &AppState,
    room_nid: u64,
    user: &AuthenticatedUser,
) -> Result<Option<String>, ApiError> {
    let jr_content = get_join_rule_content(state, room_nid)?;
    let join_rule = jr_content
        .get("join_rule")
        .and_then(|v| v.as_str())
        .unwrap_or("invite");
    if !matches!(join_rule, "restricted" | "knock_restricted") {
        return Ok(None);
    }

    let allow = jr_content
        .get("allow")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if !user_qualifies_via_allow_list(state, user.user_nid, &allow)? {
        return Ok(None);
    }

    pick_local_authoriser(state, room_nid)
}

/// True if the room's `m.room.create` event was authored by a user on
/// THIS server — i.e. we're the resident / authoritative server. False
/// when the create event is missing (unusual) OR the creator lives on
/// another server (federation invite case). Drives the local-vs-federated
/// branch in `do_join`.
fn room_is_locally_hosted(state: &AppState, room_nid: u64) -> Result<bool, ApiError> {
    let Some(create) = read_state_value(state, room_nid, "m.room.create", "")? else {
        return Ok(false);
    };
    Ok(is_local(
        create.sender().unwrap_or(""),
        &state.config.server_name,
    ))
}

/// Find the server that invited `user_nid` to `room_nid`. Used as a
/// fallback server-name hint when a client accepts a federated invite
/// without supplying `?server_name=`. Returns the sender's domain iff
/// the current member event shows an invite.
fn invite_sender_server(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
) -> Result<Option<String>, ApiError> {
    let Some(user_id) = state
        .db
        .resolve_nid(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(None);
    };
    let Some(member) = read_state_value(state, room_nid, "m.room.member", &user_id)? else {
        return Ok(None);
    };
    if member.membership() != Some("invite") {
        return Ok(None);
    }
    Ok(member
        .sender()
        .and_then(|s| s.split_once(':').map(|(_, d)| d.to_string())))
}

/// Servers other than ours that we know are participating in the room.
/// Picks the create event's sender domain first (most likely to still be
/// resident), then any joined member's domain. Used when a client passes
/// `?server_name=` listing only ourselves and we need an alternate
/// resident to drive make_join.
fn remote_servers_in_room(state: &AppState, room_nid: u64) -> Result<Vec<String>, ApiError> {
    let our_server = state.config.server_name.as_str();
    let mut out: Vec<String> = Vec::new();
    if let Some(create) = read_state_value(state, room_nid, "m.room.create", "")?
        && let Some(sender) = create.sender()
        && let Some((_, domain)) = sender.split_once(':')
        && domain != our_server
    {
        out.push(domain.to_string());
    }
    let members = state
        .db
        .get_room_members(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for member_nid in members {
        let Some(user_id) = state
            .db
            .resolve_nid(member_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        let Some((_, domain)) = user_id.split_once(':') else {
            continue;
        };
        if domain == our_server {
            continue;
        }
        let s = domain.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

/// True if `user_nid` currently has membership=join in any room listed in
/// the `allow` array of an `m.room.join_rules` content. Each allow entry
/// has shape `{"type": "m.room_membership", "room_id": "!..."}`.
/// Public re-export for use by federation `make_join`. Thin wrapper around
/// the existing local helper.
pub fn user_qualifies_via_allow_list_pub(
    state: &AppState,
    user_nid: u64,
    allow: &[Value],
) -> Result<bool, ApiError> {
    user_qualifies_via_allow_list(state, user_nid, allow)
}

/// Public re-export for use by federation `make_join`.
pub fn pick_local_authoriser_pub(
    state: &AppState,
    room_nid: u64,
) -> Result<Option<String>, ApiError> {
    pick_local_authoriser(state, room_nid)
}

fn user_qualifies_via_allow_list(
    state: &AppState,
    user_nid: u64,
    allow: &[Value],
) -> Result<bool, ApiError> {
    for entry in allow {
        let kind = entry.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if kind != "m.room_membership" {
            continue;
        }
        let gate_room_id = entry.get("room_id").and_then(|v| v.as_str()).unwrap_or("");
        if gate_room_id.is_empty() {
            continue;
        }
        let Some(rn) = state
            .db
            .get_nid(gate_room_id)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        // Stale-state guard: if we have NO local joined member in the
        // gate room, our cached membership view for that room is no
        // longer authoritative — the last local participant left and
        // we stopped receiving state updates. Synapse's partial-state
        // tracking enforces the same: a server with no local member
        // in the allow-list room must refuse to authorise joins
        // against it. TestRestrictedRoomsRemoteJoinFailOver depends
        // on this: bob leaves the allowed_room and hs2 must then
        // fail charlie's join via hs2 alone.
        if !has_local_joined_member(state, rn)? {
            continue;
        }
        if state
            .db
            .get_membership(rn, user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            == Some(1)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// True iff at least one user on THIS server has membership=join in
/// `room_nid`. Used by `user_qualifies_via_allow_list` to decide
/// whether our cached membership view for the room is still
/// authoritative — without a local member we no longer receive state
/// updates for the room.
fn has_local_joined_member(state: &AppState, room_nid: u64) -> Result<bool, ApiError> {
    let server = state.config.server_name.as_str();
    let members = state
        .db
        .get_room_members(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    for member_nid in members {
        let Some(user_id) = state
            .db
            .resolve_nid(member_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        if is_local(&user_id, server) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Pick a local joined member with power to invite. Returns the user_id
/// string if one exists, else `None`.
///
/// Used to populate `content.join_authorised_via_users_server` for a
/// restricted-room join. The caller's auth rule already checks the
/// authoriser is joined and has invite power, so this just has to find
/// SOME qualifying user.
fn pick_local_authoriser(state: &AppState, room_nid: u64) -> Result<Option<String>, ApiError> {
    let server = &state.config.server_name;
    let members = state
        .db
        .get_room_members(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let invite_level = invite_power_level(state, room_nid)?;

    for user_nid in members {
        let user_id = match state
            .db
            .resolve_nid(user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(u) => u,
            None => continue,
        };
        if !is_local(&user_id, server) {
            continue;
        }
        if user_power(state, room_nid, &user_id)? >= invite_level {
            return Ok(Some(user_id));
        }
    }
    Ok(None)
}

fn is_local(user_id: &str, server: &str) -> bool {
    user_id
        .split_once(':')
        .map(|(_, d)| d == server)
        .unwrap_or(false)
}

fn invite_power_level(state: &AppState, room_nid: u64) -> Result<i64, ApiError> {
    let pl = read_state_value(state, room_nid, "m.room.power_levels", "")?;
    let v = pl.as_ref().and_then(|p| {
        p.get("content")
            .and_then(|c| c.get("invite"))
            .and_then(|v| v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)))
    });
    Ok(v.unwrap_or(0))
}

pub(crate) fn user_power(state: &AppState, room_nid: u64, user_id: &str) -> Result<i64, ApiError> {
    // v12: creator has infinite power. We approximate by inspecting the
    // create event sender + additional_creators.
    if let Some(create) = read_state_value(state, room_nid, "m.room.create", "")? {
        if create.sender() == Some(user_id) {
            return Ok(i64::MAX);
        }
        if let Some(arr) = create
            .content()
            .and_then(|c| c.get("additional_creators"))
            .and_then(|v| v.as_array())
            && arr.iter().any(|v| v.as_str() == Some(user_id))
        {
            return Ok(i64::MAX);
        }
    }
    let pl = read_state_value(state, room_nid, "m.room.power_levels", "")?;
    let users = pl
        .as_ref()
        .and_then(|p| p.get("content").and_then(|c| c.get("users")));
    if let Some(u) = users.and_then(|u| u.get(user_id))
        && let Some(n) = u.as_i64().or_else(|| u.as_u64().map(|u| u as i64))
    {
        return Ok(n);
    }
    let default = pl.and_then(|p| {
        p.get("content")
            .and_then(|c| c.get("users_default"))
            .and_then(|v| v.as_i64().or_else(|| v.as_u64().map(|u| u as i64)))
    });
    Ok(default.unwrap_or(0))
}

/// Public re-export so other modules can read a single state event by
/// (type, state_key). Returns the full event JSON, not just content.
pub fn read_state_value_pub(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Result<Option<Value>, ApiError> {
    read_state_value(state, room_nid, event_type, state_key)
}

fn read_state_value(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Result<Option<Value>, ApiError> {
    let tn = match state
        .db
        .get_nid(event_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let sn = match state
        .db
        .get_nid(state_key)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let event_nid = match state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let bytes = match state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some((_, b)) => b,
        None => return Ok(None),
    };
    Ok(serde_json::from_slice::<Value>(&bytes).ok())
}

/// Read the join_rules content (full object including `allow` for
/// restricted rooms). Returns `{}` if no join_rules state event exists.
fn get_join_rule_content(state: &AppState, room_nid: u64) -> Result<Value, ApiError> {
    Ok(read_state_value(state, room_nid, "m.room.join_rules", "")?
        .and_then(|ev| ev.get("content").cloned())
        .unwrap_or_else(|| json!({"join_rule": "invite"})))
}

/// POST /_matrix/client/v3/rooms/{roomId}/leave
pub async fn leave_room(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let room_id = RoomId::parse(&room_id_str)
        .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    let current = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if !matches!(current, Some(1) | Some(2) | Some(4)) {
        // must be join, invite, or knock to leave
        return Err(VelaError::Forbidden("not in this room".into()).into());
    }

    // If the room was created on a different server, the leave needs to go
    // through the federation `make_leave`/`send_leave` flow so the resident
    // server adds it to the authoritative DAG. We then persist the
    // returned-signed event locally. Otherwise (we're the resident, or it's
    // a fully-local room) emit + broadcast as before.
    let resident_server = creator_server(&state, room_nid)?;
    if let Some(rs) = resident_server
        && rs != state.config.server_name
    {
        do_remote_leave(&state, &user, room_nid, &room_id, &rs).await?;
        return Ok(Json(json!({})));
    }

    emit_membership_event(&state, &user, room_nid, &room_id, "leave", None).await?;

    Ok(Json(json!({})))
}

/// Determine the room's resident server: the domain of the create event's
/// sender. Returns `None` if we somehow don't have the create event yet
/// (caller falls back to local emit, which will likely fail loudly — fine
/// signal that something earlier broke).
fn creator_server(state: &AppState, room_nid: u64) -> Result<Option<String>, ApiError> {
    let type_nid = state
        .db
        .get_nid("m.room.create")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_nid("")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (Some(tn), Some(sn)) = (type_nid, skey_nid) else {
        return Ok(None);
    };
    let event_nid = match state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => return Ok(None),
    };
    let (_h, bytes) = match state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(p) => p,
        None => return Ok(None),
    };
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok(v.sender()
        .and_then(|s| s.split_once(':'))
        .map(|(_, d)| d.to_string())
        .filter(|d| !d.is_empty()))
}

/// Federation outbound leave flow:
/// 1. GET make_leave on resident — get unsigned template.
/// 2. Sign locally.
/// 3. PUT send_leave on resident.
/// 4. Persist the signed event locally + flip our own membership.
async fn do_remote_leave(
    state: &AppState,
    user: &AuthenticatedUser,
    room_nid: u64,
    room_id: &RoomId,
    resident: &str,
) -> Result<(), ApiError> {
    use vela_core::events::builder::sign_unsigned_template;

    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;

    let resp = state
        .federation_client
        .make_leave(resident, room_id.as_str(), &user.user_id)
        .await
        .map_err(|e| ApiError(VelaError::Forbidden(format!("make_leave: {e}"))))?;

    let mut template = resp
        .get("event")
        .and_then(|v| v.as_object())
        .cloned()
        .ok_or_else(|| ApiError(VelaError::Store("make_leave missing event".into())))?;

    // Spec: ensure origin + origin_server_ts are populated before signing.
    if !template.contains_key("origin") {
        template.insert("origin".to_string(), Value::String(server_name.clone()));
    }
    if !template.contains_key("origin_server_ts") {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        template.insert("origin_server_ts".to_string(), Value::from(now));
    }

    // Use the room's actual version for signing — vela's outbound
    // leave on a v6-v10 room must produce v6-v10 canonical bytes or
    // the resident server will reject our signature.
    let outbound_leave_room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (signed_event, event_id) = sign_unsigned_template(
        template,
        &signing_key,
        server_name,
        outbound_leave_room_version,
    );

    if let Err(e) = state
        .federation_client
        .send_leave_v2(
            resident,
            room_id.as_str(),
            event_id.as_str(),
            Value::Object(signed_event.clone()),
        )
        .await
    {
        tracing::warn!(target = %resident, error = %e, "send_leave failed; persisting locally anyway");
    }

    // Persist our own copy + flip membership locally so the user sees the
    // leave regardless of remote success.
    let event_nid = state.db.next_nid()?;
    let json_bytes = vela_core::canonical::canonical_json_object(&signed_event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_or_create_nid(&user.user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let depth = signed_event
        .get("depth")
        .and_then(|v| v.as_u64())
        .unwrap_or(1);
    let origin_ts = signed_event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            user.user_nid,
            skey_nid,
            origin_ts,
            depth,
            &json_bytes,
            &[],
            &[],
            true,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    crate::e2ee::keys::record_device_changes_on_leave(state, user.user_nid, room_nid);
    state
        .db
        .set_membership(room_nid, user.user_nid, 0)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(state, user.user_nid);

    Ok(())
}

#[derive(Deserialize)]
pub struct UserIdBody {
    pub user_id: String,
}

/// POST /_matrix/client/v3/rooms/{roomId}/invite
pub async fn invite_user(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Json(body): Json<UserIdBody>,
) -> Result<Json<Value>, ApiError> {
    let room_id = RoomId::parse(&room_id_str)
        .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    check_sender_joined(&state, room_nid, user.user_nid)?;

    // AS demand-provisioning: if the invitee lives on this server,
    // matches an AS user namespace, and doesn't yet exist locally,
    // ask the owning AS to provision before we emit the invite. The
    // AS responds 200 once it has called `/register` back to mint
    // the user; we then re-check existence and proceed.
    maybe_query_as_for_unknown_user(&state, &body.user_id).await;

    emit_membership_event_for_target(
        &state,
        &user,
        room_nid,
        &room_id,
        &body.user_id,
        "invite",
        None,
    )
    .await?;

    Ok(Json(json!({})))
}

/// If `user_id` is local, falls in an AS user namespace, and has no
/// row yet, ping the owning AS so it can provision. Best-effort: any
/// failure (no AS owns it, AS unreachable, AS 404) is silently
/// ignored — downstream code handles "user still missing" with the
/// usual M_FORBIDDEN/M_INVALID_USERNAME.
async fn maybe_query_as_for_unknown_user(state: &AppState, user_id: &str) {
    // Local-only: skip when the invitee is hosted on another server.
    let server = match user_id.rsplit_once(':') {
        Some((_, s)) => s,
        None => return,
    };
    if server != state.config.server_name {
        return;
    }
    // Already exists → nothing to provision.
    match state.db.user_exists(user_id) {
        Ok(true) => return,
        Ok(false) => {}
        Err(_) => return,
    }
    let Some(live) =
        crate::appservice::query::find_as_owning_user(&state.appservice_registry, user_id)
    else {
        return;
    };
    let Some(hs_token) = state.appservice_outbox.hs_token(live.appservice.nid) else {
        return;
    };
    let _ = crate::appservice::query::query_user(
        state.appservice_outbox.http_client(),
        &hs_token,
        &live,
        user_id,
    )
    .await;
}

/// Internal entry point used by `createRoom` to dispatch a federated invite
/// after the room is fully persisted. Skips the membership precheck
/// (`createRoom` has just made the caller a joined member) and otherwise
/// runs the same emit-and-federate path as `invite_user`.
pub async fn invite_user_internal(
    state: AppState,
    user: AuthenticatedUser,
    room_nid: u64,
    room_id: RoomId,
    target_user_id: String,
    is_direct: bool,
) -> Result<(), ApiError> {
    let extra = if is_direct {
        Some(json!({"is_direct": true}))
    } else {
        None
    };
    emit_membership_event_for_target(
        &state,
        &user,
        room_nid,
        &room_id,
        &target_user_id,
        "invite",
        extra.as_ref(),
    )
    .await
}

/// Internal entry point used by the admin bot to kick a target out of
/// the admin room. Bypasses the public-API `check_sender_joined` and
/// "target must currently be joined/invited/knocking" guards: the bot
/// caller has already validated membership-state for the demote case.
pub async fn kick_target_for_admin(
    state: AppState,
    sender: AuthenticatedUser,
    room_nid: u64,
    room_id: RoomId,
    target_user_id: String,
) -> Result<(), ApiError> {
    emit_membership_event_for_target(
        &state,
        &sender,
        room_nid,
        &room_id,
        &target_user_id,
        "leave",
        None,
    )
    .await
}

/// POST /_matrix/client/v3/rooms/{roomId}/kick
pub async fn kick_user(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Json(body): Json<UserIdBody>,
) -> Result<Json<Value>, ApiError> {
    let room_id = RoomId::parse(&room_id_str)
        .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    check_sender_joined(&state, room_nid, user.user_nid)?;

    let target_nid = state
        .db
        .get_nid(&body.user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let target_membership =
        target_nid.and_then(|n| state.db.get_membership(room_nid, n).ok().flatten());
    // Allow kick when target is joined (1), invited (2), or knocking
    // (4). Rejecting a knock is "kick" in the spec — TestKnocking's
    // "A_user_in_the_room_can_reject_a_knock" expects this to work.
    if !matches!(target_membership, Some(1) | Some(2) | Some(4)) {
        return Err(VelaError::Forbidden("target is not in the room".into()).into());
    }

    emit_membership_event_for_target(
        &state,
        &user,
        room_nid,
        &room_id,
        &body.user_id,
        "leave",
        None,
    )
    .await?;

    Ok(Json(json!({})))
}

/// POST /_matrix/client/v3/rooms/{roomId}/ban
pub async fn ban_user(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Json(body): Json<UserIdBody>,
) -> Result<Json<Value>, ApiError> {
    let room_id = RoomId::parse(&room_id_str)
        .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    check_sender_joined(&state, room_nid, user.user_nid)?;

    emit_membership_event_for_target(
        &state,
        &user,
        room_nid,
        &room_id,
        &body.user_id,
        "ban",
        None,
    )
    .await?;

    Ok(Json(json!({})))
}

/// POST /_matrix/client/v3/rooms/{roomId}/unban
pub async fn unban_user(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_str): Path<String>,
    Json(body): Json<UserIdBody>,
) -> Result<Json<Value>, ApiError> {
    let room_id = RoomId::parse(&room_id_str)
        .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    check_sender_joined(&state, room_nid, user.user_nid)?;

    emit_membership_event_for_target(
        &state,
        &user,
        room_nid,
        &room_id,
        &body.user_id,
        "leave",
        None,
    )
    .await?;

    Ok(Json(json!({})))
}

#[derive(Debug, Default, Deserialize)]
pub struct KnockBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /_matrix/client/v3/knock/{roomIdOrAlias}
///
/// Local knocks only for now: federated `make_knock`/`send_knock` is the
/// follow-up. Auth-rules already enforce the v12 `check_member_knock`
/// preconditions (compatible join_rule, sender not banned/invited/joined).
pub async fn knock_room(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(room_id_or_alias): Path<String>,
    RawQuery(raw_query): RawQuery,
    Json(body): Json<KnockBody>,
) -> Result<Json<Value>, ApiError> {
    // Spec: /knock takes a roomId OR a roomAlias. For alias-form,
    // resolve through the directory (local first, then federation
    // /query/directory). Use the returned `servers` array as
    // automatic hints for the federated make_knock path so the
    // caller doesn't have to also supply `?server_name=`.
    let (room_id, alias_hints) = if room_id_or_alias.starts_with('#') {
        let (room_id, hints) = resolve_alias(&state, &room_id_or_alias).await?;
        (room_id, hints)
    } else {
        let room_id = RoomId::parse(&room_id_or_alias)
            .map_err(|_| ApiError(VelaError::NotFound("room not found".into())))?;
        (room_id, Vec::new())
    };

    // Unknown room → assume remote; use `?server_name=` hints to locate a
    // resident server and run the federated make_knock/send_knock flow.
    let room_nid = match state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(n) => n,
        None => {
            // Server hints: prefer explicit `?server_name=` from the
            // client; fall back to the directory-resolved server list
            // when the room came in as an alias.
            let mut hints = parse_query_values(raw_query.as_deref(), "server_name");
            if hints.is_empty() {
                hints = alias_hints;
            }
            crate::membership::federation_outbound_knock::do_remote_knock(
                &state,
                &user.user_id,
                user.user_nid,
                &room_id,
                &hints,
                body.reason.as_deref(),
            )
            .await?;
            return Ok(Json(json!({"room_id": room_id.as_str()})));
        }
    };

    // Room exists locally but isn't hosted here — re-knock after a prior
    // federated knock falls into this branch. Stripped state from the
    // first knock isn't a valid base for authoring locally (no signatures,
    // no origin_server_ts), so we have to federate again. We must NOT
    // short-circuit on "already in knock state" here — federation is
    // async, so the resident server may have moved the user out of knock
    // (kick / leave) without our membership table having caught up yet.
    // TestKnocking's "reject a knock" → "knock without reason" sequence
    // hits exactly that race.
    if !room_is_locally_hosted(&state, room_nid)? {
        let mut hints = parse_query_values(raw_query.as_deref(), "server_name");
        if hints.is_empty() {
            hints = alias_hints;
        }
        crate::membership::federation_outbound_knock::do_remote_knock(
            &state,
            &user.user_id,
            user.user_nid,
            &room_id,
            &hints,
            body.reason.as_deref(),
        )
        .await?;
        return Ok(Json(json!({"room_id": room_id.as_str()})));
    }

    // Locally-hosted re-knock: if the user is already in knock state
    // here, don't mint a second event. Spec allows the repeat, but
    // Synapse preserves the original knock's content (including reason)
    // — a fresh event would silently replace the visible reason for
    // everyone in the room. TestKnocking's "Users in the room see a
    // user's membership update when they knock" relies on the first
    // knock's reason still being visible after the second knock. Safe
    // for locally-hosted rooms only because we control the authoritative
    // state; for federated rooms the resident may have moved the user
    // out of knock since our last sync.
    let current_membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if current_membership == Some(4) {
        return Ok(Json(json!({"room_id": room_id.as_str()})));
    }

    // Pre-check: surface a clearer error than the auth-rules path when the
    // room can't accept knocks at all.
    let join_rule = get_join_rule(&state, room_nid)?;
    if join_rule != "knock" && join_rule != "knock_restricted" {
        return Err(VelaError::Forbidden("this room does not allow knocking".into()).into());
    }

    let signing_key = get_or_create_signing_key(&state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let member_content = content::member_content_knock(body.reason.as_deref());

    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut max_depth: u64 = 0;
    let mut prev_event_ids = Vec::new();
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
        if let Some(id) = state
            .db
            .get_event_id_by_nid(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && let Ok(eid) = EventId::parse(&id)
        {
            prev_event_ids.push(eid);
        }
    }

    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            let id_str = state.db.get_event_id_by_nid(en).ok()??;
            EventId::parse(&id_str).ok()
        };
        select_auth_events(
            "m.room.member",
            &user.user_id,
            Some(&user.user_id),
            Some(&member_content),
            room_version,
            &lookup,
        )
    };

    let depth = max_depth + 1;
    let (event, event_id) = build_event(
        "m.room.member",
        Some(&user.user_id),
        member_content,
        &user.user_id,
        Some(&room_id),
        &prev_event_ids,
        &auth_events,
        depth,
        &signing_key,
        server_name,
        room_version,
    );

    authorise_event(&state, room_nid, &event_id, &event, None)?;

    // Persist
    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_or_create_nid(&user.user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let auth_nids = resolve_auth_nids(&state, &auth_events)?;
    let origin_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            user.user_nid,
            skey_nid,
            origin_ts,
            depth,
            &json_bytes,
            &extremity_nids,
            &auth_nids,
            true,  // is_state
            false, // suppress_current_state
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .set_membership(room_nid, user.user_nid, 4)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(&state, user.user_nid);

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state.federation_sender.broadcast(room_nid, event_nid);

    // Wake any /sync long-polls listening on this room. Without this
    // the knock event only surfaces on the next sync poll (initial or
    // 30s timeout) — peers in the room don't see the knocker until
    // then. Every other state-persist + broadcast pair in vela does
    // this; the local knock handler was the holdout.
    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }

    Ok(Json(json!({"room_id": room_id.as_str()})))
}

// --- Helpers ---

fn check_sender_joined(state: &AppState, room_nid: u64, user_nid: u64) -> Result<(), ApiError> {
    let m = state
        .db
        .get_membership(room_nid, user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if m != Some(1) {
        return Err(VelaError::Forbidden("sender not in room".into()).into());
    }
    Ok(())
}

fn get_join_rule(state: &AppState, room_nid: u64) -> Result<String, ApiError> {
    let type_nid = state
        .db
        .get_nid("m.room.join_rules")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_nid("")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let (Some(tn), Some(sn)) = (type_nid, skey_nid)
        && let Some(event_nid) = state
            .db
            .get_state_event_nid(room_nid, tn, sn)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        && let Some((_, json_bytes)) = state
            .db
            .get_event(event_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        && let Ok(ev) = serde_json::from_slice::<Value>(&json_bytes)
        && let Some(rule) = ev
            .get("content")
            .and_then(|c| c.get("join_rule"))
            .and_then(|r| r.as_str())
    {
        return Ok(rule.to_string());
    }
    Ok("invite".to_string()) // default
}

fn membership_u8(membership: &str) -> u8 {
    match membership {
        "join" => 1,
        "invite" => 2,
        "ban" => 3,
        "knock" => 4,
        _ => 0, // leave
    }
}

/// Emit a membership event where the sender is also the target (join, leave).
async fn emit_membership_event(
    state: &AppState,
    user: &AuthenticatedUser,
    room_nid: u64,
    room_id: &RoomId,
    membership: &str,
    extra_content: Option<&Value>,
) -> Result<(), ApiError> {
    emit_membership_event_for_target(
        state,
        user,
        room_nid,
        room_id,
        &user.user_id,
        membership,
        extra_content,
    )
    .await
}

/// Merge non-protected fields from `extra` into `target`. The
/// `membership` and `join_authorised_via_users_server` keys are always
/// owned by the server — clients can't override them via custom join
/// content. All other keys are copied verbatim, overwriting on conflict.
fn merge_extra_content(target: &mut Value, extra: Option<&Value>) {
    let Some(extra) = extra else { return };
    let Some(extra_obj) = extra.as_object() else {
        return;
    };
    let target_obj = match target.as_object_mut() {
        Some(o) => o,
        None => return,
    };
    for (k, v) in extra_obj {
        if k == "membership" || k == "join_authorised_via_users_server" {
            continue;
        }
        target_obj.insert(k.clone(), v.clone());
    }
}

/// Emit a join membership event for the calling user. When `authoriser`
/// is supplied (restricted-room join), `content.join_authorised_via_users_server`
/// is set so the auth-rule path can validate per v12 rule 5.3.5.
async fn emit_join_event(
    state: &AppState,
    user: &AuthenticatedUser,
    room_nid: u64,
    room_id: &RoomId,
    authoriser: Option<&str>,
    extra_content: Option<&Value>,
) -> Result<(), ApiError> {
    let authoriser = match authoriser {
        Some(a) => a,
        None => {
            return emit_membership_event(state, user, room_nid, room_id, "join", extra_content)
                .await;
        }
    };

    // Inline the build path so we can attach join_authorised_via_users_server
    // to the content. Mirrors `emit_membership_event_for_target` shape.
    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let mut member_content = content::member_content_join(None, None);
    member_content.as_object_mut().unwrap().insert(
        "join_authorised_via_users_server".to_string(),
        Value::String(authoriser.to_string()),
    );
    merge_extra_content(&mut member_content, extra_content);

    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut max_depth: u64 = 0;
    let mut prev_event_ids = Vec::new();
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
        if let Some(id) = state
            .db
            .get_event_id_by_nid(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && let Ok(eid) = EventId::parse(&id)
        {
            prev_event_ids.push(eid);
        }
    }

    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            let id_str = state.db.get_event_id_by_nid(en).ok()??;
            EventId::parse(&id_str).ok()
        };
        select_auth_events(
            "m.room.member",
            &user.user_id,
            Some(&user.user_id),
            Some(&member_content),
            room_version,
            &lookup,
        )
    };

    let depth = max_depth + 1;
    let (event, event_id) = build_event(
        "m.room.member",
        Some(&user.user_id),
        member_content,
        &user.user_id,
        Some(room_id),
        &prev_event_ids,
        &auth_events,
        depth,
        &signing_key,
        server_name,
        room_version,
    );

    authorise_event(state, room_nid, &event_id, &event, None)?;

    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_or_create_nid(&user.user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let auth_nids = resolve_auth_nids(state, &auth_events)?;
    let origin_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            user.user_nid,
            skey_nid,
            origin_ts,
            depth,
            &json_bytes,
            &extremity_nids,
            &auth_nids,
            true,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .set_membership(room_nid, user.user_nid, 1)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(state, user.user_nid);

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state.federation_sender.broadcast(room_nid, event_nid);

    // Wake /sync long-polls for peers in the room — without this, the
    // restricted-room join only surfaces on the next sync poll, not
    // on the long-poll wake. Other emit_* membership paths fire this;
    // the restricted-join variant was the holdout.
    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }
    Ok(())
}

/// Emit a fresh `m.room.member` with `membership=join` for the caller,
/// carrying updated displayname/avatar_url in content. Used by the
/// profile setters to propagate name/avatar changes into each room's
/// membership event so clients see the new value everywhere.
///
/// Best-effort: any per-room failure is logged and ignored. The user's
/// stored profile has already been updated regardless.
pub async fn propagate_profile_update(
    state: &AppState,
    user: &AuthenticatedUser,
    displayname: Option<&str>,
    avatar_url: Option<&str>,
) {
    let joined_rooms = match state.db.get_user_joined_rooms(user.user_nid) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "propagate_profile_update: get_user_joined_rooms failed");
            return;
        }
    };
    for room_nid in joined_rooms {
        let room_id_str = match state.db.resolve_nid(room_nid) {
            Ok(Some(s)) => s,
            _ => continue,
        };
        let room_id = match RoomId::parse(&room_id_str) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Err(e) =
            emit_self_profile_event(state, user, room_nid, &room_id, displayname, avatar_url).await
        {
            tracing::debug!(
                room = %room_id_str,
                error = ?e.0,
                "profile propagation skipped for room",
            );
        }
    }
}

/// Inner worker for `propagate_profile_update` — emits one member event.
async fn emit_self_profile_event(
    state: &AppState,
    user: &AuthenticatedUser,
    room_nid: u64,
    room_id: &RoomId,
    displayname: Option<&str>,
    avatar_url: Option<&str>,
) -> Result<(), ApiError> {
    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    let member_content = content::member_content_join(displayname, avatar_url);

    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut max_depth: u64 = 0;
    let mut prev_event_ids = Vec::new();
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
        if let Some(id) = state
            .db
            .get_event_id_by_nid(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && let Ok(eid) = EventId::parse(&id)
        {
            prev_event_ids.push(eid);
        }
    }
    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            state
                .db
                .get_event_id_by_nid(en)
                .ok()?
                .map(|s| EventId::parse(&s).ok())?
        };
        select_auth_events(
            "m.room.member",
            &user.user_id,
            Some(&user.user_id),
            Some(&member_content),
            room_version,
            &lookup,
        )
    };

    let (event, event_id) = build_event(
        "m.room.member",
        Some(&user.user_id),
        member_content,
        &user.user_id,
        Some(room_id),
        &prev_event_ids,
        &auth_events,
        max_depth + 1,
        &signing_key,
        server_name,
        room_version,
    );
    authorise_event(state, room_nid, &event_id, &event, None)?;

    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_or_create_nid(&user.user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let origin_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let auth_nids = resolve_auth_nids(state, &auth_events)?;

    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            user.user_nid,
            skey_nid,
            origin_ts,
            max_depth + 1,
            &json_bytes,
            &resolve_auth_nids(state, &prev_event_ids)?,
            &auth_nids,
            true,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state.federation_sender.broadcast(room_nid, event_nid);
    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }
    Ok(())
}

/// Emit a membership event for a target user (invite, kick, ban).
async fn emit_membership_event_for_target(
    state: &AppState,
    sender: &AuthenticatedUser,
    room_nid: u64,
    room_id: &RoomId,
    target_user_id: &str,
    membership: &str,
    extra_content: Option<&Value>,
) -> Result<(), ApiError> {
    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Build content
    let mut member_content = match membership {
        "join" => content::member_content_join(None, None),
        "invite" => content::member_content_invite(),
        "ban" => json!({"membership": "ban"}),
        "knock" => content::member_content_knock(None),
        _ => content::member_content_leave(),
    };
    merge_extra_content(&mut member_content, extra_content);

    // Get prev_events from extremities
    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut max_depth: u64 = 0;
    let mut prev_event_ids = Vec::new();
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
        if let Some(id) = state
            .db
            .get_event_id_by_nid(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            prev_event_ids.push(EventId::parse(&id).unwrap());
        }
    }

    // Select auth events from current state
    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            state
                .db
                .get_event_id_by_nid(en)
                .ok()?
                .map(|s| EventId::parse(&s).ok())?
        };
        select_auth_events(
            "m.room.member",
            &sender.user_id,
            Some(target_user_id),
            Some(&member_content),
            room_version,
            &lookup,
        )
    };

    let (event, event_id) = build_event(
        "m.room.member",
        Some(target_user_id),
        member_content,
        &sender.user_id,
        Some(room_id),
        &prev_event_ids,
        &auth_events,
        max_depth + 1,
        &signing_key,
        server_name,
        room_version,
    );

    // Gate: authorise against current room state before persisting.
    authorise_event(state, room_nid, &event_id, &event, None)?;

    // Persist
    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_or_create_nid(target_user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let origin_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let auth_nids = resolve_auth_nids(state, &auth_events)?;

    let target_user_nid = state
        .db
        .get_or_create_nid(target_user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            sender.user_nid,
            skey_nid,
            origin_ts,
            max_depth + 1,
            &json_bytes,
            &extremity_nids,
            &auth_nids,
            true,
            false, // suppress_current_state: local events always update state
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // For leave/kick/ban (target was joined and is now no longer):
    // surface the departure to local observers via the device_list_left
    // CF so /sync's `device_lists.left` reflects the new "no longer
    // shared" relationships. Run BEFORE the membership update so
    // `get_room_members` still includes the observer set.
    let was_joined = state
        .db
        .get_membership(room_nid, target_user_nid)
        .ok()
        .flatten()
        == Some(1);
    let now_left = matches!(membership, "leave" | "ban");
    if was_joined && now_left {
        crate::e2ee::keys::record_device_changes_on_leave(state, target_user_nid, room_nid);
    }
    // Update membership
    state
        .db
        .set_membership(room_nid, target_user_nid, membership_u8(membership))
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Wake the target's pending /sync so invites/joins/kicks appear
    // instantly instead of after the long-poll timeout.
    crate::router::notify_user(state, target_user_nid);

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // E2EE hook: notify all room members that target user's device keys may have changed.
    // This triggers clients to re-fetch keys, preventing "Unable to decrypt" errors.
    if matches!(membership, "join" | "leave" | "ban") {
        let current_members = state.db.get_room_members(room_nid).unwrap_or_default();
        let _ = state
            .db
            .notify_device_key_change(target_user_nid, &current_members, stream_pos);
    }

    // Federate to remote servers.
    state.federation_sender.broadcast(room_nid, event_nid);

    // Federated-invite hook: when we invite a user on another server, we also
    // PUT the signed event to their `/_matrix/federation/v2/invite/{room}/{event}`.
    // The remote validates and may add their signature.
    //
    // Awaited inline (not spawned). Spec / industry behaviour: clients
    // expect synchronous /invite — both Synapse and Continuwuity block
    // the C2S response until the remote ACKs. Fire-and-forget races
    // tests like TestFederationRejectInvite where the invitee's
    // server gets a /leave call immediately after the C2S /invite
    // returns 200; if the federation POST hasn't landed, the remote
    // hasn't created the room/membership and the leave 404s.
    //
    // On federation failure we still log and return 200 to the
    // client: the local invite event is already authorised +
    // persisted, and the remote can pick it up later via backfill
    // once they have a member in the room. Keeping the C2S call
    // succeeding matches synapse's "best-effort" semantics — the
    // client sees the invite locally even when federation flaps.
    if membership == "invite" {
        let server = &state.config.server_name;
        if !is_local_user(target_user_id, server) {
            let target_server = match target_user_id.split_once(':') {
                Some((_, d)) => d.to_string(),
                None => return Ok(()),
            };
            let invite_room_state = build_invite_stripped_state(state, room_nid, room_id.as_str())?;
            let body = json!({
                "event": Value::Object(event.clone()),
                "room_version": room_version.as_str(),
                "invite_room_state": invite_room_state,
            });
            if let Err(e) = state
                .federation_client
                .send_invite_v2(&target_server, room_id.as_str(), event_id.as_str(), body)
                .await
            {
                tracing::warn!(
                    target = %target_server,
                    event = %event_id.as_str(),
                    error = %e,
                    "federated invite POST failed; remote can backfill later"
                );
            }
        }
    }

    // Notify sync
    if let Some(sender_ch) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender_ch.send(stream_pos);
    }

    Ok(())
}

fn is_local_user(user_id: &str, server: &str) -> bool {
    user_id
        .split_once(':')
        .map(|(_, d)| d == server)
        .unwrap_or(false)
}

/// Build the `invite_room_state` array for the recipient — stripped state
/// events giving them just enough context to render the room invite. Spec:
/// `client-server-api/#invite_state` (mirrors what we send in CS-API sync's
/// `rooms.invite.{id}.invite_state`).
///
/// MSC4311 (room version 12): the `m.room.create` event MUST appear in
/// full — recipients need it to verify the room_id, which v12 derives
/// from a hash of the create event.
fn build_invite_stripped_state(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
) -> Result<Vec<Value>, ApiError> {
    static STRIPPED_TYPES: &[&str] = &[
        "m.room.create",
        "m.room.name",
        "m.room.avatar",
        "m.room.canonical_alias",
        "m.room.join_rules",
        "m.room.member",
    ];
    let state_nids = state
        .db
        .get_all_state_event_nids(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut out = Vec::new();
    for nid in state_nids {
        let Some((_h, bytes)) = state
            .db
            .get_event(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        let Ok(ev) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let etype = ev.event_type().unwrap_or("");
        if !STRIPPED_TYPES.contains(&etype) {
            continue;
        }
        if etype == "m.room.create" {
            // MSC4311: emit the full create event. Re-derive event_id
            // (v3+ events on the wire don't carry event_id) and ensure
            // room_id is present so receivers can verify the version-
            // appropriate hash matches.
            let stripped_state_room_version = state
                .db
                .get_room_version_typed(room_nid)
                .unwrap_or(vela_core::events::room_version::RoomVersion::V12);
            let event_id = vela_core::events::hash::compute_event_id_for_version(
                ev.as_object().unwrap_or(&Map::new()),
                stripped_state_room_version,
            );
            let mut full = ev;
            if let Some(obj) = full.as_object_mut() {
                obj.insert("event_id".to_string(), json!(event_id.as_str()));
                if !obj.contains_key("room_id") {
                    obj.insert("room_id".to_string(), json!(room_id));
                }
            }
            out.push(full);
        } else {
            out.push(json!({
                "type": ev.get("type"),
                "state_key": ev.get("state_key"),
                "sender": ev.get("sender"),
                "content": ev.get("content"),
                "room_id": room_id,
            }));
        }
    }
    Ok(out)
}

fn resolve_auth_nids(state: &AppState, auth_events: &[EventId]) -> Result<Vec<u64>, ApiError> {
    let mut nids = Vec::new();
    for id in auth_events {
        if let Some(nid) = state
            .db
            .get_event_nid_by_id(id.as_str())
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            nids.push(nid);
        }
    }
    Ok(nids)
}

/// Drive the user out of every room they're joined / invited / knocking
/// in, emitting `m.room.member` `leave` events with a deactivation
/// reason. Local-resident rooms persist immediately and broadcast
/// federation in the background; remote-resident rooms spawn a
/// background `make_leave`/`send_leave` task. Any per-room error is
/// logged and skipped — one stuck room must not block the overall
/// deactivation.
///
/// Used by the deactivate endpoint; not part of the spec contract for
/// `/leave`. Don't use this from a regular leave handler.
pub(crate) async fn force_leave_all_rooms_for_deactivation(
    state: &AppState,
    user: &AuthenticatedUser,
    reason: &str,
) {
    use std::collections::BTreeSet;

    // Union joined / invited / knocked rooms. Already-left/banned states
    // need no action. Use BTreeSet to dedupe and keep iteration stable.
    let mut rooms: BTreeSet<u64> = BTreeSet::new();
    if let Ok(joined) = state.db.get_user_joined_rooms(user.user_nid) {
        rooms.extend(joined);
    }
    if let Ok(invited) = state.db.get_user_invited_rooms(user.user_nid) {
        rooms.extend(invited);
    }
    if let Ok(knocked) = state.db.get_user_knocked_rooms(user.user_nid) {
        rooms.extend(knocked);
    }
    if rooms.is_empty() {
        return;
    }

    for room_nid in rooms {
        let room_id_str = match state.db.resolve_nid(room_nid) {
            Ok(Some(s)) => s,
            _ => {
                tracing::warn!(room_nid, "deactivate: failed to resolve room_id, skipping");
                continue;
            }
        };
        let room_id = match RoomId::parse(&room_id_str) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(room = %room_id_str, error = %e, "deactivate: bad room_id, skipping");
                continue;
            }
        };

        // Determine resident server. If remote, schedule the remote leave
        // off the response path so federation latency doesn't block us.
        let resident = match creator_server(state, room_nid) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(room = %room_id_str, error = ?e.0, "deactivate: creator_server lookup failed, skipping");
                continue;
            }
        };
        if let Some(rs) = resident
            && rs != state.config.server_name
        {
            let state_clone = state.clone();
            let user_clone = AuthenticatedUser {
                user_nid: user.user_nid,
                user_id: user.user_id.clone(),
                device_id: user.device_id.clone(),
                appservice_nid: None,
            };
            let room_id_owned = room_id.clone();
            let resident_owned = rs.clone();
            tokio::spawn(async move {
                if let Err(e) = do_remote_leave(
                    &state_clone,
                    &user_clone,
                    room_nid,
                    &room_id_owned,
                    &resident_owned,
                )
                .await
                {
                    tracing::warn!(
                        room = %room_id_owned.as_str(),
                        resident = %resident_owned,
                        error = ?e.0,
                        "deactivate: remote leave failed",
                    );
                }
            });
            continue;
        }

        // Local-resident: emit leave with reason in content.
        if let Err(e) = emit_self_leave_with_reason(state, user, room_nid, &room_id, reason).await {
            tracing::warn!(
                room = %room_id_str,
                error = ?e.0,
                "deactivate: local leave emit failed, continuing",
            );
        }
    }
}

/// Emit a self-targeted `m.room.member` leave for `user` in `room_nid`,
/// embedding `reason` in the event content. Mirrors
/// `emit_membership_event_for_target` for the leave path; kept separate
/// because the standard helpers don't plumb a reason.
async fn emit_self_leave_with_reason(
    state: &AppState,
    user: &AuthenticatedUser,
    room_nid: u64,
    room_id: &RoomId,
    reason: &str,
) -> Result<(), ApiError> {
    let signing_key = get_or_create_signing_key(state)?;
    let server_name = &state.config.server_name;
    let room_version = state
        .db
        .get_room_version_typed(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Idempotency: if we're already not joined/invited/knocked, skip.
    let current = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if !matches!(current, Some(1) | Some(2) | Some(4)) {
        return Ok(());
    }

    let mut member_content = content::member_content_leave();
    if !reason.is_empty()
        && let Some(obj) = member_content.as_object_mut()
    {
        obj.insert("reason".to_string(), Value::String(reason.to_string()));
    }

    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut max_depth: u64 = 0;
    let mut prev_event_ids = Vec::new();
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
        if let Some(id) = state
            .db
            .get_event_id_by_nid(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            prev_event_ids.push(EventId::parse(&id).unwrap());
        }
    }

    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            state
                .db
                .get_event_id_by_nid(en)
                .ok()?
                .map(|s| EventId::parse(&s).ok())?
        };
        select_auth_events(
            "m.room.member",
            &user.user_id,
            Some(&user.user_id),
            Some(&member_content),
            room_version,
            &lookup,
        )
    };

    let (event, event_id) = build_event(
        "m.room.member",
        Some(&user.user_id),
        member_content,
        &user.user_id,
        Some(room_id),
        &prev_event_ids,
        &auth_events,
        max_depth + 1,
        &signing_key,
        server_name,
        room_version,
    );

    authorise_event(state, room_nid, &event_id, &event, None)?;

    let event_nid = state.db.next_nid()?;
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_or_create_nid(&user.user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let origin_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let auth_nids = resolve_auth_nids(state, &auth_events)?;

    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            event_id.as_str(),
            room_nid,
            type_nid,
            user.user_nid,
            skey_nid,
            origin_ts,
            max_depth + 1,
            &json_bytes,
            &extremity_nids,
            &auth_nids,
            true,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .set_membership(room_nid, user.user_nid, 0)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    crate::router::notify_user(state, user.user_nid);

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let current_members = state.db.get_room_members(room_nid).unwrap_or_default();
    let _ = state
        .db
        .notify_device_key_change(user.user_nid, &current_members, stream_pos);

    state.federation_sender.broadcast(room_nid, event_nid);

    if let Some(sender_ch) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender_ch.send(stream_pos);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::AuthenticatedUser;
    use crate::test_helpers::build_test_state;
    use axum::extract::{Path, RawQuery, State};

    /// Regression for Complement Bug B + follow-up: `?server_name=hs1`
    /// single value, comma-separated, AND repeated keys all parse.
    #[test]
    fn parse_query_values_handles_single_and_repeated_and_csv() {
        assert_eq!(
            parse_query_values(Some("server_name=hs1"), "server_name"),
            vec!["hs1"]
        );
        assert_eq!(
            parse_query_values(Some("server_name=hs1&server_name=hs2"), "server_name"),
            vec!["hs1", "hs2"]
        );
        assert_eq!(
            parse_query_values(Some("server_name=hs1,hs2"), "server_name"),
            vec!["hs1", "hs2"]
        );
        assert!(parse_query_values(Some(""), "server_name").is_empty());
        assert!(parse_query_values(None, "server_name").is_empty());
    }

    #[test]
    fn parse_query_values_percent_decodes() {
        // Port colons arrive URL-encoded; form_urlencoded handles the decode.
        assert_eq!(
            parse_query_values(
                Some("server_name=host.docker.internal%3A62444"),
                "server_name",
            ),
            vec!["host.docker.internal:62444"]
        );
    }

    /// Build a v12 room owned by alice with `join_rule=knock` and a member
    /// list (alice joined) ready for someone else to knock on. Returns
    /// `(state, room_id_str, room_nid, bob_nid)`.
    fn setup_knock_room() -> (AppState, tempfile::TempDir, String, u64, u64) {
        let (state, tmp) = build_test_state();
        let db = &state.db;
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let type_pl = db.get_or_create_nid("m.room.power_levels").unwrap();
        let type_jr = db.get_or_create_nid("m.room.join_rules").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();

        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let bob_nid = db.get_or_create_nid(bob).unwrap();
        let alice_skey = alice_nid;

        let room_id = "!room12";
        let create_eid = "$room12";
        let room_nid = db.get_or_create_nid(room_id).unwrap();

        let create_json = json!({
            "type": "m.room.create",
            "sender": alice,
            "state_key": "",
            "room_id": room_id,
            "content": {"room_version": "12"},
            "origin_server_ts": 1, "depth": 1,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            100,
            create_eid,
            room_nid,
            type_create,
            alice_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&create_json).unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();

        let alice_join_eid = "$alice_join";
        let alice_join_json = json!({
            "type": "m.room.member",
            "sender": alice, "state_key": alice, "room_id": room_id,
            "content": {"membership": "join"},
            "origin_server_ts": 2, "depth": 2,
            "prev_events": [create_eid], "auth_events": [create_eid],
        });
        db.persist_event(
            101,
            alice_join_eid,
            room_nid,
            type_member,
            alice_nid,
            alice_skey,
            2,
            2,
            &serde_json::to_vec(&alice_join_json).unwrap(),
            &[100],
            &[100],
            true,
            false,
        )
        .unwrap();

        let pl_eid = "$pl";
        let pl_json = json!({
            "type": "m.room.power_levels",
            "sender": alice, "state_key": "", "room_id": room_id,
            "content": {"users": {}, "users_default": 0},
            "origin_server_ts": 3, "depth": 3,
            "prev_events": [alice_join_eid], "auth_events": [alice_join_eid],
        });
        db.persist_event(
            102,
            pl_eid,
            room_nid,
            type_pl,
            alice_nid,
            skey_empty,
            3,
            3,
            &serde_json::to_vec(&pl_json).unwrap(),
            &[101],
            &[101],
            true,
            false,
        )
        .unwrap();

        let jr_eid = "$jr";
        let jr_json = json!({
            "type": "m.room.join_rules",
            "sender": alice, "state_key": "", "room_id": room_id,
            "content": {"join_rule": "knock"},
            "origin_server_ts": 4, "depth": 4,
            "prev_events": [pl_eid], "auth_events": [pl_eid, alice_join_eid],
        });
        db.persist_event(
            103,
            jr_eid,
            room_nid,
            type_jr,
            alice_nid,
            skey_empty,
            4,
            4,
            &serde_json::to_vec(&jr_json).unwrap(),
            &[102],
            &[102, 101],
            true,
            false,
        )
        .unwrap();

        db.set_membership(room_nid, alice_nid, 1).unwrap();

        (state, tmp, room_id.to_string(), room_nid, bob_nid)
    }

    fn user(nid: u64, user_id: &str) -> AuthenticatedUser {
        AuthenticatedUser {
            user_nid: nid,
            user_id: user_id.into(),
            device_id: "DEV".into(),
            appservice_nid: None,
        }
    }

    #[tokio::test]
    async fn knock_room_succeeds_when_join_rule_is_knock() {
        let (state, _tmp, room_id, room_nid, bob_nid) = setup_knock_room();

        let res = knock_room(
            State(state.clone()),
            user(bob_nid, "@bob:example.com"),
            Path(room_id.clone()),
            RawQuery(None),
            Json(KnockBody {
                reason: Some("let me in".into()),
            }),
        )
        .await
        .expect("knock allowed");
        assert_eq!(
            res.0.get("room_id").and_then(|v| v.as_str()),
            Some(room_id.as_str())
        );
        assert_eq!(state.db.get_membership(room_nid, bob_nid).unwrap(), Some(4));
    }

    #[tokio::test]
    async fn knock_room_rejects_when_join_rule_is_invite() {
        // Override join_rules to "invite" by overwriting the existing event.
        let (state, _tmp, room_id, room_nid, bob_nid) = setup_knock_room();
        let type_jr = state.db.get_nid("m.room.join_rules").unwrap().unwrap();
        let skey_empty = state.db.get_nid("").unwrap().unwrap();
        let alice_nid = state.db.get_nid("@alice:example.com").unwrap().unwrap();

        let jr2_json = json!({
            "type": "m.room.join_rules",
            "sender": "@alice:example.com", "state_key": "", "room_id": room_id,
            "content": {"join_rule": "invite"},
            "origin_server_ts": 10, "depth": 10,
            "prev_events": ["$jr"], "auth_events": ["$pl", "$alice_join"],
        });
        state
            .db
            .persist_event(
                200,
                "$jr2",
                room_nid,
                type_jr,
                alice_nid,
                skey_empty,
                10,
                10,
                &serde_json::to_vec(&jr2_json).unwrap(),
                &[103],
                &[102, 101],
                true,
                false,
            )
            .unwrap();

        let err = knock_room(
            State(state.clone()),
            user(bob_nid, "@bob:example.com"),
            Path(room_id),
            RawQuery(None),
            Json(KnockBody::default()),
        )
        .await
        .expect_err("knock forbidden");
        match err {
            ApiError(VelaError::Forbidden(reason)) => {
                assert!(reason.contains("knock"), "reason={reason}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
        assert_ne!(state.db.get_membership(room_nid, bob_nid).unwrap(), Some(4));
    }

    #[tokio::test]
    async fn knock_room_appears_as_knock_state_in_sync() {
        // Drives the round-trip: knock → sync sees rooms.knock.{id}.knock_state.
        let (state, _tmp, room_id, _room_nid, bob_nid) = setup_knock_room();
        let _ = knock_room(
            State(state.clone()),
            user(bob_nid, "@bob:example.com"),
            Path(room_id.clone()),
            RawQuery(None),
            Json(KnockBody { reason: None }),
        )
        .await
        .unwrap();

        let resp =
            crate::sync::build_sync_response(&state, &user(bob_nid, "@bob:example.com"), &[], None)
                .unwrap();
        let knocks = resp.pointer("/rooms/knock").unwrap().as_object().unwrap();
        assert!(
            knocks.contains_key(&room_id),
            "knock room missing: {knocks:?}"
        );
        let events = resp
            .pointer(&format!("/rooms/knock/{}/knock_state/events", room_id))
            .unwrap()
            .as_array()
            .unwrap();
        assert!(!events.is_empty(), "knock_state.events should be populated");
    }

    #[tokio::test]
    async fn knock_room_alias_path_returns_not_found_for_now() {
        let (state, _tmp, _room_id, _room_nid, bob_nid) = setup_knock_room();
        let err = knock_room(
            State(state.clone()),
            user(bob_nid, "@bob:example.com"),
            Path("#alias:example.com".to_string()),
            RawQuery(None),
            Json(KnockBody::default()),
        )
        .await
        .expect_err("alias unsupported");
        assert!(matches!(err, ApiError(VelaError::NotFound(_))));
    }

    // ----- restricted-room local join tests -----

    /// Build a v12 setup with two rooms:
    /// - "allowed_room" (public) where bob is joined.
    /// - "restricted_room" with `join_rule=restricted, allow=[allowed_room]`.
    ///
    /// Alice is the creator/sole member of restricted_room and qualifies
    /// as the authoriser. Returns identifiers.
    fn setup_restricted_room() -> (
        AppState,
        tempfile::TempDir,
        String, // restricted_room_id
        u64,    // restricted_room_nid
        u64,    // bob_nid
    ) {
        let (state, tmp) = build_test_state();
        let db = &state.db;
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let type_pl = db.get_or_create_nid("m.room.power_levels").unwrap();
        let type_jr = db.get_or_create_nid("m.room.join_rules").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();

        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let bob_nid = db.get_or_create_nid(bob).unwrap();

        // Allowed (public) room: alice + bob both joined.
        // v12: room_id = "!" + create_event_id[1..] — must match exactly.
        let allowed_room_id = "!allowed";
        let allowed_create = "$allowed";
        let allowed_nid = db.get_or_create_nid(allowed_room_id).unwrap();
        db.persist_event(
            10,
            allowed_create,
            allowed_nid,
            type_create,
            alice_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type": "m.room.create",
                "sender": alice, "state_key": "", "room_id": allowed_room_id,
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
            11,
            "$alice_a",
            allowed_nid,
            type_member,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type": "m.room.member",
                "sender": alice, "state_key": alice, "room_id": allowed_room_id,
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": [allowed_create], "auth_events": [allowed_create],
            }))
            .unwrap(),
            &[10],
            &[10],
            true,
            false,
        )
        .unwrap();
        db.set_membership(allowed_nid, alice_nid, 1).unwrap();
        db.set_membership(allowed_nid, bob_nid, 1).unwrap();

        // Restricted room: alice is creator and only member; allow points
        // to allowed_room.
        let restricted_room_id = "!restricted";
        let restricted_create = "$restricted";
        let restricted_nid = db.get_or_create_nid(restricted_room_id).unwrap();
        db.persist_event(
            20,
            restricted_create,
            restricted_nid,
            type_create,
            alice_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type": "m.room.create",
                "sender": alice, "state_key": "", "room_id": restricted_room_id,
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
            21,
            "$alice_r",
            restricted_nid,
            type_member,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type": "m.room.member",
                "sender": alice, "state_key": alice, "room_id": restricted_room_id,
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": [restricted_create], "auth_events": [restricted_create],
            }))
            .unwrap(),
            &[20],
            &[20],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            22,
            "$pl_r",
            restricted_nid,
            type_pl,
            alice_nid,
            skey_empty,
            3,
            3,
            &serde_json::to_vec(&json!({
                "type": "m.room.power_levels",
                "sender": alice, "state_key": "", "room_id": restricted_room_id,
                "content": {"users": {}, "users_default": 0, "invite": 0},
                "origin_server_ts": 3, "depth": 3,
                "prev_events": ["$alice_r"], "auth_events": ["$alice_r"],
            }))
            .unwrap(),
            &[21],
            &[21],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            23,
            "$jr_r",
            restricted_nid,
            type_jr,
            alice_nid,
            skey_empty,
            4,
            4,
            &serde_json::to_vec(&json!({
                "type": "m.room.join_rules",
                "sender": alice, "state_key": "", "room_id": restricted_room_id,
                "content": {
                    "join_rule": "restricted",
                    "allow": [{"type": "m.room_membership", "room_id": allowed_room_id}],
                },
                "origin_server_ts": 4, "depth": 4,
                "prev_events": ["$pl_r"], "auth_events": ["$pl_r", "$alice_r"],
            }))
            .unwrap(),
            &[22],
            &[22, 21],
            true,
            false,
        )
        .unwrap();
        db.set_membership(restricted_nid, alice_nid, 1).unwrap();

        (
            state,
            tmp,
            restricted_room_id.to_string(),
            restricted_nid,
            bob_nid,
        )
    }

    #[tokio::test]
    async fn restricted_join_via_allowed_room_succeeds_with_authoriser() {
        let (state, _tmp, room_id, room_nid, bob_nid) = setup_restricted_room();

        let res = join_room(
            State(state.clone()),
            user(bob_nid, "@bob:example.com"),
            Path(room_id.clone()),
            RawQuery(None),
            Bytes::new(),
        )
        .await
        .expect("restricted join allowed");
        assert_eq!(
            res.0.get("room_id").and_then(|v| v.as_str()),
            Some(room_id.as_str())
        );
        assert_eq!(state.db.get_membership(room_nid, bob_nid).unwrap(), Some(1));

        // The persisted member event must carry the authoriser hint.
        let type_member = state.db.get_nid("m.room.member").unwrap().unwrap();
        let bob_skey = state.db.get_nid("@bob:example.com").unwrap().unwrap();
        let event_nid = state
            .db
            .get_state_event_nid(room_nid, type_member, bob_skey)
            .unwrap()
            .unwrap();
        let (_, bytes) = state.db.get_event(event_nid).unwrap().unwrap();
        let ev: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            ev.pointer("/content/join_authorised_via_users_server")
                .and_then(|v| v.as_str()),
            Some("@alice:example.com")
        );
    }

    #[tokio::test]
    async fn restricted_join_rejected_without_allowed_room_membership() {
        let (state, _tmp, room_id, room_nid, _bob_nid) = setup_restricted_room();
        // Charlie is on hs1 but isn't in any allowed room.
        let charlie_nid = state.db.get_or_create_nid("@charlie:example.com").unwrap();

        let err = join_room(
            State(state.clone()),
            user(charlie_nid, "@charlie:example.com"),
            Path(room_id),
            RawQuery(None),
            Bytes::new(),
        )
        .await
        .expect_err("not a member of any allowed room");
        match err {
            ApiError(VelaError::Forbidden(reason)) => {
                assert!(reason.contains("allowed room"), "reason: {reason}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
        assert_eq!(
            state.db.get_membership(room_nid, charlie_nid).unwrap(),
            None
        );
    }
}
