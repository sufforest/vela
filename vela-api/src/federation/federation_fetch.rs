//! Inbound federation fetch endpoints.
//!
//! - `GET /_matrix/federation/v1/event/{eventId}`
//! - `GET /_matrix/federation/v1/state/{roomId}?event_id=...`
//! - `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...`
//! - `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`
//! - `POST /_matrix/federation/v1/get_missing_events/{roomId}`
//!
//! All behind the existing `federation_auth` middleware, which verifies
//! the X-Matrix signature and injects `Extension<XMatrixOrigin>` (the
//! requesting server). Each handler then enforces `origin_in_room` — the
//! signature proves identity, but a server still has to be in the room to
//! read its events (spec's "server is in the room" rule).

use std::collections::{HashSet, VecDeque};

use crate::middleware::json::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;

use crate::federation::federation_state::{
    auth_chain_pdu_json, auth_chain_union_event_ids, auth_chain_union_pdu_json,
    load_event_json_by_event_id, state_before_event, state_before_event_ids,
};
use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// Cap on `/get_missing_events` response size. Spec default is 10.
const DEFAULT_MISSING_LIMIT: u32 = 10;
const MAX_MISSING_LIMIT: u32 = 100;

/// The spec's "server is in the room" check (Synapse's
/// `assert_host_in_room`): `origin` must have at least one *joined*
/// member in the room. The X-Matrix signature only proves *which* server
/// is asking — without this, any server on the federation could read any
/// room's state and (via /backfill, /event) its message bodies given just
/// a room id and one event id. Join-only on purpose: a server with only
/// invited/knocking users has no claim to the room's history. Mirrors the
/// origin-in-room gate already on `event_relationships_fed`.
fn origin_in_room(state: &AppState, room_nid: u64, origin: &str) -> bool {
    let Ok(members) = state.db.get_room_members(room_nid) else {
        return false;
    };
    for nid in members {
        if let Ok(Some(mxid)) = state.db.resolve_nid(nid)
            && mxid
                .split_once(':')
                .map(|(_, d)| d == origin)
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// GET /_matrix/federation/v1/event/{eventId}
pub async fn get_event(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    debug!(%event_id, origin = %origin.0, "federation /event request");

    let json = load_event_json_by_event_id(&state.db, &event_id).ok_or(StatusCode::NOT_FOUND)?;

    // The requesting server must be in the event's room. Resolve the room
    // from the event itself (this endpoint takes no room id) and 404 a
    // non-resident server — same code as "event not found", so it can't
    // probe which events we hold for rooms it isn't in.
    let room_id = json
        .get("room_id")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            // v12 (MSC4291) `m.room.create` events carry no `room_id`; the
            // room id is the create event id with the sigil swapped
            // ($X -> !X) — the reverse of get_event_auth's derivation.
            if json.get("type").and_then(|v| v.as_str()) == Some("m.room.create") {
                event_id.strip_prefix('$').map(|rest| format!("!{rest}"))
            } else {
                None
            }
        })
        .ok_or(StatusCode::NOT_FOUND)?;
    let room_nid = state
        .db
        .get_nid(&room_id)
        .ok()
        .flatten()
        .ok_or(StatusCode::NOT_FOUND)?;
    if !origin_in_room(&state, room_nid, &origin.0) {
        return Err(StatusCode::NOT_FOUND);
    }

    // Transaction-shaped response per spec.
    Ok(Json(json!({
        "origin": state.config.server_name,
        "origin_server_ts": crate::federation::federation_client::now_ms(),
        "pdus": [json],
    })))
}

#[derive(Deserialize)]
pub struct StateQuery {
    pub event_id: String,
}

/// GET /_matrix/federation/v1/state/{roomId}?event_id=...
pub async fn get_state(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Query(q): Query<StateQuery>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    debug!(event_id = %q.event_id, origin = %origin.0, "federation /state request");

    if let Ok(Some(room_nid)) = state.db.get_nid(&room_id) {
        // The requesting server must be in the room (see origin_in_room).
        if !origin_in_room(&state, room_nid, &origin.0) {
            return Err(StatusCode::FORBIDDEN);
        }
        // MSC3902: while the room is partial-state we don't have the full
        // membership at any post-join event. Refuse rather than return a
        // confidently-wrong incomplete state — the caller (typically a
        // joining server's filler) will retry or fall back to another
        // peer. Mirrors how Complement's MSC3902 mocks behave from the
        // remote side; spec test
        // TestPartialStateJoin/CanReceiveEvents*PartialStateJoin.
        if let Ok((true, _)) = state.db.get_partial_state_info(room_nid) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // state_before_event runs state_res which is CPU-bound — isolate from
    // the async runtime via spawn_blocking.
    let db = state.db.clone();
    let event_id_owned = q.event_id.clone();
    let state_map =
        match tokio::task::spawn_blocking(move || state_before_event(&db, &event_id_owned))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            Ok(Some(m)) => m,
            Ok(None) => return Err(StatusCode::BAD_REQUEST),
            Err(_) => return Err(StatusCode::NOT_FOUND),
        };

    // Build PDU array from the resolved state map.
    let mut pdus = Vec::with_capacity(state_map.len());
    let mut state_event_ids: Vec<String> = Vec::with_capacity(state_map.len());
    for pdu in state_map.values() {
        if let Some(json) = load_event_json_by_event_id(&state.db, &pdu.event_id) {
            pdus.push(json);
        }
        state_event_ids.push(pdu.event_id.clone());
    }

    // Auth chain: single combined BFS over all state events.
    let roots: Vec<&str> = state_event_ids.iter().map(|s| s.as_str()).collect();
    let auth_chain = auth_chain_union_pdu_json(&state.db, &roots).unwrap_or_default();

    Ok(Json(json!({
        "pdus": pdus,
        "auth_chain": auth_chain,
    })))
}

/// GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...
pub async fn get_state_ids(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    Query(q): Query<StateQuery>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    debug!(event_id = %q.event_id, origin = %origin.0, "federation /state_ids request");

    if let Ok(Some(room_nid)) = state.db.get_nid(&room_id) {
        // The requesting server must be in the room (see origin_in_room).
        if !origin_in_room(&state, room_nid, &origin.0) {
            return Err(StatusCode::FORBIDDEN);
        }
        // MSC3902: refuse while the room is partial-state (see get_state
        // for the rationale). Same condition, same response.
        if let Ok((true, _)) = state.db.get_partial_state_info(room_nid) {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // CPU isolation as in get_state.
    let db = state.db.clone();
    let event_id_owned = q.event_id.clone();
    let state_ids =
        match tokio::task::spawn_blocking(move || state_before_event_ids(&db, &event_id_owned))
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            Ok(Some(m)) => m,
            Ok(None) => return Err(StatusCode::BAD_REQUEST),
            Err(_) => return Err(StatusCode::NOT_FOUND),
        };

    let pdu_ids: Vec<String> = state_ids.values().cloned().collect();

    let roots: Vec<&str> = pdu_ids.iter().map(|s| s.as_str()).collect();
    let auth_chain_ids = auth_chain_union_event_ids(&state.db, &roots).unwrap_or_default();

    Ok(Json(json!({
        "pdu_ids": pdu_ids,
        "auth_chain_ids": auth_chain_ids,
    })))
}

/// GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}
pub async fn get_event_auth(
    State(state): State<AppState>,
    Path((room_id, event_id)): Path<(String, String)>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    debug!(%event_id, origin = %origin.0, "federation /event_auth request");

    // The requesting server must be in the room (see origin_in_room).
    if let Ok(Some(room_nid)) = state.db.get_nid(&room_id)
        && !origin_in_room(&state, room_nid, &origin.0)
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut chain = auth_chain_pdu_json(&state.db, &event_id).map_err(|_| StatusCode::NOT_FOUND)?;

    // v12 (MSC4291) strips `m.room.create` from every event's
    // `auth_events`, so a chain walk via auth_events alone never
    // surfaces it. Peers querying /event_auth still expect the create
    // event in the response — derive its event_id from the room_id
    // (sigil swap `!` → `$`) and prepend.
    if let Some(rest) = room_id.strip_prefix('!') {
        let create_eid = format!("${rest}");
        if let Some(create_json) = load_event_json_by_event_id(&state.db, &create_eid) {
            chain.insert(0, create_json);
        }
    }

    Ok(Json(json!({ "auth_chain": chain })))
}

#[derive(Deserialize)]
pub struct MissingEventsRequest {
    pub earliest_events: Vec<String>,
    pub latest_events: Vec<String>,
    #[serde(default)]
    pub limit: Option<u32>,
    #[serde(default)]
    #[allow(dead_code)]
    pub min_depth: Option<u32>,
}

/// GET /_matrix/federation/v1/backfill/{roomId}?v=...&limit=N
///
/// Walk back through `prev_events` from `v`, collecting up to `limit` events.
/// Returns a transaction-shaped response.
///
/// Parses the query string manually because the spec passes `v` as a
/// repeated query parameter (`?v=$a&v=$b`), which `serde_urlencoded` —
/// what axum's default `Query` extractor uses — silently flattens to
/// the last occurrence. Vela was returning 400 BAD_REQUEST without
/// logging because the deserialised `v: Vec<String>` came back empty,
/// and the only signal was that paginate_dag callers got 0 events
/// from /messages backfill.
pub async fn get_backfill(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    // The requesting server must be in the room (see origin_in_room).
    // /backfill returns unredacted message bodies, so this is the most
    // sensitive of the read endpoints to leave ungated.
    if let Ok(Some(room_nid)) = state.db.get_nid(&room_id)
        && !origin_in_room(&state, room_nid, &origin.0)
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut v_params: Vec<String> = Vec::new();
    let mut limit_param: Option<u32> = None;
    if let Some(qs) = raw_query.as_deref() {
        for pair in qs.split('&') {
            let Some((k, val)) = pair.split_once('=') else {
                continue;
            };
            // Spec event IDs use the URL-unreserved char set plus `$`,
            // and our outbound /backfill caller doesn't percent-encode
            // — so a byte-for-byte string copy here matches what was
            // signed. If we later normalise outbound encoding, this
            // side has to decode in lockstep.
            match k {
                "v" => v_params.push(val.to_string()),
                "limit" => limit_param = val.parse().ok(),
                _ => {}
            }
        }
    }
    if v_params.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let q_v = v_params;
    let limit = limit_param.unwrap_or(10).min(100) as usize;

    debug!(
        origin = %origin.0,
        starting = q_v.len(),
        limit,
        "federation /backfill request"
    );

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = q_v.into_iter().collect();
    let mut pdus: Vec<Value> = Vec::new();

    while let Some(eid) = queue.pop_front() {
        if pdus.len() >= limit {
            break;
        }
        if !seen.insert(eid.clone()) {
            continue;
        }
        let Some(nid) = state.db.get_event_nid_by_id(&eid).ok().flatten() else {
            continue;
        };
        let Some(json) = load_event_json_by_event_id(&state.db, &eid) else {
            continue;
        };
        pdus.push(json);

        if let Ok(prev) = state.db.get_prev_events(nid) {
            for pnid in prev {
                if let Ok(Some(peid)) = state.db.get_event_id_by_nid(pnid)
                    && !seen.contains(&peid)
                {
                    queue.push_back(peid);
                }
            }
        }
    }

    Ok(Json(json!({
        "origin": state.config.server_name,
        "origin_server_ts": crate::federation::federation_client::now_ms(),
        "pdus": pdus,
    })))
}

/// POST /_matrix/federation/v1/get_missing_events/{roomId}
pub async fn get_missing_events(
    State(state): State<AppState>,
    Path(room_id): Path<String>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
    axum::extract::Extension(VerifiedBody(body)): axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, StatusCode> {
    let body = body.ok_or(StatusCode::BAD_REQUEST)?;
    let req: MissingEventsRequest =
        serde_json::from_value(body).map_err(|_| StatusCode::BAD_REQUEST)?;

    // The requesting server must be in the room (see origin_in_room).
    // Per-event history-visibility redaction below further trims what a
    // resident server sees; this gate keeps non-residents out entirely.
    if let Ok(Some(room_nid)) = state.db.get_nid(&room_id)
        && !origin_in_room(&state, room_nid, &origin.0)
    {
        return Err(StatusCode::FORBIDDEN);
    }

    let limit = req
        .limit
        .unwrap_or(DEFAULT_MISSING_LIMIT)
        .min(MAX_MISSING_LIMIT) as usize;

    debug!(
        %room_id,
        origin = %origin.0,
        earliest = req.earliest_events.len(),
        latest = req.latest_events.len(),
        limit,
        "federation /get_missing_events request"
    );

    // BFS backwards through prev_events from `latest_events`, stopping at
    // `earliest_events` or when `limit` events have been collected. The
    // walk discovers events latest-first; the response is then sorted
    // by depth ascending so the caller receives them in topological
    // (oldest-first) order — what receivers need to fill a DAG gap.
    //
    // Spec: events listed in `earliest_events` AND `latest_events` are
    // excluded from the response — the caller already has both ends
    // and only needs the gap between them.
    let earliest: HashSet<String> = req.earliest_events.into_iter().collect();
    let latest: HashSet<String> = req.latest_events.iter().cloned().collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = req.latest_events.into_iter().collect();
    let mut out: Vec<(u64, Value)> = Vec::new();

    while let Some(eid) = queue.pop_front() {
        if out.len() >= limit {
            break;
        }
        if earliest.contains(&eid) || !seen.insert(eid.clone()) {
            continue;
        }

        // Find the event in our DB.
        let Some(nid) = state.db.get_event_nid_by_id(&eid).ok().flatten() else {
            continue;
        };

        // Latest_events are walk seeds, not output.
        if !latest.contains(&eid) {
            let Some(json) = load_event_json_by_event_id(&state.db, &eid) else {
                continue;
            };
            out.push((nid, json));
        }

        // Enqueue its prev_events for further BFS.
        if let Ok(prev) = state.db.get_prev_events(nid) {
            for pnid in prev {
                if let Ok(Some(peid)) = state.db.get_event_id_by_nid(pnid)
                    && !seen.contains(&peid)
                    && !earliest.contains(&peid)
                {
                    queue.push_back(peid);
                }
            }
        }
    }

    // History-visibility filter: when the requesting server's users
    // wouldn't have been able to see an event under the room's
    // visibility policy at that event, return a redacted copy. The
    // policy is per-event, so we look up the state snapshot recorded
    // for each event and inspect both `m.room.history_visibility`
    // and the requesting origin's member events at that point.
    let final_out: Vec<Value> = out
        .into_iter()
        .map(|(nid, json)| {
            if should_redact_for_origin(&state, nid, &origin.0) {
                let obj = json.as_object().cloned().unwrap_or_default();
                Value::Object(vela_core::events::redact::redact_event(&obj))
            } else {
                json
            }
        })
        .collect();

    let mut final_out = final_out;
    final_out.sort_by_key(|ev| ev.get("depth").and_then(|d| d.as_u64()).unwrap_or(u64::MAX));

    Ok(Json(json!({ "events": final_out })))
}

/// True when the requesting server's users could not see the event
/// under the room's history-visibility policy as it stood at that
/// event. Falls back to "do not redact" on missing snapshots — better
/// to over-share than to silently hide events from a peer that has a
/// legitimate need for the chain.
fn should_redact_for_origin(state: &AppState, event_nid: u64, origin: &str) -> bool {
    let Ok(Some(state_nids)) = state.db.get_state_at_event(event_nid) else {
        return false;
    };
    let visibility = find_history_visibility_in_state(state, &state_nids);
    match visibility.as_str() {
        "world_readable" | "shared" => false,
        "joined" => !origin_has_member_with_membership(state, &state_nids, origin, &["join"]),
        "invited" => {
            !origin_has_member_with_membership(state, &state_nids, origin, &["join", "invite"])
        }
        // Unknown/missing → spec default "shared".
        _ => false,
    }
}

/// Read `m.room.history_visibility/""` from a state snapshot. Returns
/// the spec default `"shared"` when the event is missing or malformed.
fn find_history_visibility_in_state(state: &AppState, state_nids: &[u64]) -> String {
    let Ok(Some(type_nid)) = state.db.get_nid("m.room.history_visibility") else {
        return "shared".to_string();
    };
    for &nid in state_nids {
        let Ok(Some((header, bytes))) = state.db.get_event(nid) else {
            continue;
        };
        if header.type_nid != type_nid {
            continue;
        }
        let Ok(ev) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Some(v) = ev
            .get("content")
            .and_then(|c| c.get("history_visibility"))
            .and_then(|v| v.as_str())
        {
            return v.to_string();
        }
        return "shared".to_string();
    }
    "shared".to_string()
}

/// True when at least one user from `origin` has an `m.room.member`
/// state event in `state_nids` whose `membership` is one of `wanted`.
fn origin_has_member_with_membership(
    state: &AppState,
    state_nids: &[u64],
    origin: &str,
    wanted: &[&str],
) -> bool {
    let Ok(Some(member_type_nid)) = state.db.get_nid("m.room.member") else {
        return false;
    };
    for &nid in state_nids {
        let Ok(Some((header, bytes))) = state.db.get_event(nid) else {
            continue;
        };
        if header.type_nid != member_type_nid {
            continue;
        }
        let Ok(ev) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let Some(state_key) = ev.get("state_key").and_then(|v| v.as_str()) else {
            continue;
        };
        // state_key is a user_id `@local:server`.
        let Some((_, server)) = state_key.split_once(':') else {
            continue;
        };
        if server != origin {
            continue;
        }
        let membership = ev
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if wanted.contains(&membership) {
            return true;
        }
    }
    false
}

#[derive(Deserialize)]
pub struct DirectoryQuery {
    pub room_alias: String,
}

/// GET /_matrix/federation/v1/query/directory?room_alias=...
pub async fn query_directory(
    State(state): State<AppState>,
    Query(q): Query<DirectoryQuery>,
) -> Result<Json<Value>, StatusCode> {
    let alias = q.room_alias;
    let room_id = state
        .db
        .get_room_alias(&alias)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(json!({
        "room_id": room_id,
        "servers": [state.config.server_name],
    })))
}

#[derive(Deserialize)]
pub struct ProfileQuery {
    pub user_id: String,
    /// Optional restriction to a single field (`displayname` or
    /// `avatar_url`). When absent, both fields are returned.
    #[serde(default)]
    pub field: Option<String>,
}

/// GET /_matrix/federation/v1/query/profile?user_id=...&field=...
///
/// Returns the requested user's profile fields. Spec allows either
/// field to be missing if unset; we return them as-is. Validates the
/// `user_id`'s server portion against the appendix grammar — a
/// non-numeric port (e.g. `localhost:http`) is a 400 per spec.
pub async fn query_profile(
    State(state): State<AppState>,
    Query(q): Query<ProfileQuery>,
) -> Result<Json<Value>, StatusCode> {
    let server_part = q
        .user_id
        .strip_prefix('@')
        .and_then(|s| s.split_once(':'))
        .map(|(_, s)| s);
    if !server_part.map(is_valid_server_name).unwrap_or(false) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let user_nid = state
        .db
        .get_nid(&q.user_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let record = state
        .db
        .get_user(user_nid)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    let displayname = record.get("displayname").cloned();
    let avatar_url = record.get("avatar_url").cloned();

    let mut out = serde_json::Map::new();
    match q.field.as_deref() {
        Some("displayname") => {
            if let Some(v) = displayname {
                out.insert("displayname".into(), v);
            }
        }
        Some("avatar_url") => {
            if let Some(v) = avatar_url {
                out.insert("avatar_url".into(), v);
            }
        }
        _ => {
            if let Some(v) = displayname {
                out.insert("displayname".into(), v);
            }
            if let Some(v) = avatar_url {
                out.insert("avatar_url".into(), v);
            }
        }
    }

    Ok(Json(Value::Object(out)))
}

/// Validate a server-name string against the appendix grammar:
///
/// ```text
/// server_name = hostname [ ":" port ]
/// port        = 1*5DIGIT
/// hostname    = IPv4address / "[" IPv6address "]" / dns-name
/// dns-char    = DIGIT / ALPHA / "-" / "."
/// ```
///
/// Used for inbound-federation parameter validation. We're permissive
/// on the hostname character set (any byte that survives the
/// dns-char / IPv4 / IPv6 union) because the wire format guarantees
/// the value is already a UTF-8 string; the spec-critical bit is the
/// **port**: it MUST be 1-5 decimal digits when present, and a
/// non-numeric port (e.g. `localhost:http`) MUST be rejected with 400.
fn is_valid_server_name(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let (host, port) = if s.starts_with('[') {
        // IPv6 literal: [..]:port. Find the closing bracket.
        match s.find(']') {
            Some(i) => {
                let host = &s[..=i];
                let rest = &s[i + 1..];
                if rest.is_empty() {
                    (host, None)
                } else if let Some(p) = rest.strip_prefix(':') {
                    (host, Some(p))
                } else {
                    return false;
                }
            }
            None => return false,
        }
    } else {
        // Hostname or IPv4. Optional `:port` suffix.
        match s.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (s, None),
        }
    };
    if host.is_empty() {
        return false;
    }
    if let Some(p) = port
        && (p.is_empty() || p.len() > 5 || !p.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    true
}

/// Common query/body shape for both GET and POST `/publicRooms`.
#[derive(Default, Deserialize)]
pub struct FederationPublicRoomsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub since: Option<String>,
    #[serde(default)]
    pub include_all_networks: Option<bool>,
    #[serde(default)]
    pub third_party_instance_id: Option<String>,
    #[serde(default)]
    pub generic_search_term: Option<String>,
    /// POST-only nested filter object — same as the C2S body.
    #[serde(default)]
    pub filter: Option<FederationPublicRoomsFilter>,
}

#[derive(Deserialize)]
pub struct FederationPublicRoomsFilter {
    #[serde(default)]
    pub generic_search_term: Option<String>,
}

/// GET /_matrix/federation/v1/publicRooms
///
/// Spec-optional federation directory. Gated by
/// `[server] allow_public_rooms_over_federation` (default false) so
/// privacy-first deployments don't expose the local room list to
/// the federation graph by default. When disabled, peers see a 404
/// — the same response they'd get from a server that simply doesn't
/// run this endpoint.
pub async fn get_federation_public_rooms(
    State(state): State<AppState>,
    Query(q): Query<FederationPublicRoomsRequest>,
    axum::extract::Extension(_origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    serve_federation_public_rooms(&state, &q)
}

/// POST /_matrix/federation/v1/publicRooms
pub async fn post_federation_public_rooms(
    State(state): State<AppState>,
    axum::extract::Extension(_origin): axum::extract::Extension<XMatrixOrigin>,
    axum::extract::Extension(VerifiedBody(body)): axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, StatusCode> {
    let req: FederationPublicRoomsRequest = match body {
        Some(b) => serde_json::from_value(b).map_err(|_| StatusCode::BAD_REQUEST)?,
        None => FederationPublicRoomsRequest::default(),
    };
    serve_federation_public_rooms(&state, &req)
}

fn serve_federation_public_rooms(
    state: &AppState,
    req: &FederationPublicRoomsRequest,
) -> Result<Json<Value>, StatusCode> {
    if !state.config.allow_public_rooms_over_federation {
        return Err(StatusCode::NOT_FOUND);
    }

    // generic_search_term can come either at the top level (GET /
    // legacy) or nested under `filter` (POST /publicRooms-style).
    let search_term = req
        .generic_search_term
        .as_deref()
        .or_else(|| {
            req.filter
                .as_ref()
                .and_then(|f| f.generic_search_term.as_deref())
        })
        .map(|s| s.to_lowercase());

    let chunk = crate::directory::collect_public_rooms(state, search_term.as_deref())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let total = chunk.len() as u64;

    Ok(Json(json!({
        "chunk": chunk,
        "total_room_count_estimate": total,
    })))
}

#[cfg(test)]
mod tests {
    use super::is_valid_server_name;

    #[test]
    fn server_name_accepts_well_formed() {
        assert!(is_valid_server_name("matrix.org"));
        assert!(is_valid_server_name("matrix.org:8888"));
        assert!(is_valid_server_name("1.2.3.4"));
        assert!(is_valid_server_name("1.2.3.4:1234"));
        assert!(is_valid_server_name("[1234:5678::abcd]"));
        assert!(is_valid_server_name("[1234:5678::abcd]:5678"));
        assert!(is_valid_server_name("localhost"));
        assert!(is_valid_server_name("localhost:8008"));
        // Five-digit port — boundary case.
        assert!(is_valid_server_name("host:65535"));
    }

    #[test]
    fn server_name_rejects_non_numeric_port() {
        // The case Complement asserts: `localhost:http` MUST 400.
        assert!(!is_valid_server_name("localhost:http"));
        assert!(!is_valid_server_name("hs1:abc"));
        assert!(!is_valid_server_name("hs1:80a"));
    }

    #[test]
    fn server_name_rejects_other_malformed() {
        // Empty string.
        assert!(!is_valid_server_name(""));
        // Empty port after colon.
        assert!(!is_valid_server_name("hs1:"));
        // Empty host before colon.
        assert!(!is_valid_server_name(":8008"));
        // Port with 6+ digits exceeds the 1*5DIGIT grammar.
        assert!(!is_valid_server_name("hs1:123456"));
        // Unclosed IPv6 bracket.
        assert!(!is_valid_server_name("[1234:5678::abcd"));
        // Garbage after IPv6 closing bracket without colon prefix.
        assert!(!is_valid_server_name("[1234::abcd]xyz"));
    }
}

#[cfg(test)]
mod residency_tests {
    use super::{XMatrixOrigin, get_backfill, get_event, origin_in_room};
    use crate::middleware::json::Json;
    use crate::router::AppState;
    use crate::test_helpers::build_test_state;
    use axum::extract::{Extension, Path, RawQuery, State};
    use axum::http::StatusCode;
    use serde_json::{Value, json};

    fn xorigin(s: &str) -> Extension<XMatrixOrigin> {
        Extension(XMatrixOrigin(s.to_string()))
    }

    /// A room with a joined member at `@a:good.example` and a persisted
    /// message event `$e1` in it.
    fn room_with_member(state: &AppState) -> String {
        let db = &state.db;
        let room_id = "!residency:local".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let sender = db.get_or_create_nid("@a:good.example").unwrap();
        db.set_membership(room_nid, sender, 1).unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();
        let event = json!({
            "event_id": "$e1", "type": "m.room.message",
            "sender": "@a:good.example", "room_id": room_id,
            "content": {"msgtype": "m.text", "body": "hi"},
            "origin_server_ts": 1, "depth": 1, "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            500,
            "$e1",
            room_nid,
            type_msg,
            sender,
            0,
            1,
            1,
            &serde_json::to_vec(&event).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();
        room_id
    }

    #[test]
    fn origin_in_room_matches_joined_member_domain_only() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!r:local").unwrap();
        db.set_membership(
            room_nid,
            db.get_or_create_nid("@bob:good.example").unwrap(),
            1,
        )
        .unwrap();
        // A LEFT member's server must not count as resident.
        db.set_membership(
            room_nid,
            db.get_or_create_nid("@carol:left.example").unwrap(),
            0,
        )
        .unwrap();

        assert!(origin_in_room(&state, room_nid, "good.example"));
        assert!(!origin_in_room(&state, room_nid, "evil.example"));
        assert!(!origin_in_room(&state, room_nid, "left.example"));
    }

    #[tokio::test]
    async fn event_not_found_for_non_resident_server() {
        let (state, _tmp) = build_test_state();
        let _room_id = room_with_member(&state);

        // Non-resident server gets 404 — same as "no such event", so it
        // can't probe which events we hold for rooms it isn't in.
        let err = get_event(
            State(state.clone()),
            Path("$e1".to_string()),
            xorigin("evil.example"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND);

        // Resident server can fetch it.
        let ok: Result<Json<Value>, StatusCode> = get_event(
            State(state.clone()),
            Path("$e1".to_string()),
            xorigin("good.example"),
        )
        .await;
        assert!(
            ok.is_ok(),
            "resident server must be able to fetch the event"
        );
    }

    /// v12 (MSC4291) `m.room.create` events carry no `room_id`. `/event`
    /// must still resolve the room (from the create event's own id) and
    /// serve it to a resident server — not 404 it.
    #[tokio::test]
    async fn event_resolves_v12_create_without_room_id() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!cr8:local";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let sender = db.get_or_create_nid("@a:good.example").unwrap();
        db.set_membership(room_nid, sender, 1).unwrap();
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let skey = db.get_or_create_nid("").unwrap();
        // v12 create event: deliberately NO `room_id` field.
        let create = json!({
            "event_id": "$cr8:local", "type": "m.room.create",
            "sender": "@a:good.example", "content": {"room_version": "12"},
            "origin_server_ts": 1, "depth": 1, "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            600,
            "$cr8:local",
            room_nid,
            type_create,
            sender,
            skey,
            1,
            1,
            &serde_json::to_vec(&create).unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();

        let ok: Result<Json<Value>, StatusCode> = get_event(
            State(state.clone()),
            Path("$cr8:local".to_string()),
            xorigin("good.example"),
        )
        .await;
        assert!(
            ok.is_ok(),
            "resident server must be able to fetch a v12 create event with no room_id"
        );
        let err = get_event(
            State(state.clone()),
            Path("$cr8:local".to_string()),
            xorigin("evil.example"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::NOT_FOUND, "non-resident still 404");
    }

    #[tokio::test]
    async fn backfill_forbidden_for_non_resident_server() {
        let (state, _tmp) = build_test_state();
        let room_id = room_with_member(&state);

        // Non-resident → 403 before any walk.
        let err = get_backfill(
            State(state.clone()),
            Path(room_id.clone()),
            RawQuery(Some("v=$e1&limit=10".to_string())),
            xorigin("evil.example"),
        )
        .await
        .unwrap_err();
        assert_eq!(err, StatusCode::FORBIDDEN);

        // Resident → passes the gate (walk succeeds, 200).
        let ok = get_backfill(
            State(state.clone()),
            Path(room_id),
            RawQuery(Some("v=$e1&limit=10".to_string())),
            xorigin("good.example"),
        )
        .await;
        assert!(ok.is_ok(), "resident server must pass the residency gate");
    }
}
