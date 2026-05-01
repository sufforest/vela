//! Inbound federation fetch endpoints.
//!
//! - `GET /_matrix/federation/v1/event/{eventId}`
//! - `GET /_matrix/federation/v1/state/{roomId}?event_id=...`
//! - `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...`
//! - `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}`
//! - `POST /_matrix/federation/v1/get_missing_events/{roomId}`
//!
//! All behind the existing `federation_auth` middleware. Handlers take
//! `Extension<XMatrixOrigin>` so we can log/audit who's asking (not yet used
//! for access control — a server that can sign the request and is in the
//! same rooms as us is authorised per spec).

use std::collections::{HashSet, VecDeque};

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::debug;

use crate::federation_state::{
    auth_chain_pdu_json, auth_chain_union_event_ids, auth_chain_union_pdu_json,
    load_event_json_by_event_id, state_before_event, state_before_event_ids,
};
use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// Cap on `/get_missing_events` response size. Spec default is 10.
const DEFAULT_MISSING_LIMIT: u32 = 10;
const MAX_MISSING_LIMIT: u32 = 100;

/// GET /_matrix/federation/v1/event/{eventId}
pub async fn get_event(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    debug!(%event_id, origin = %origin.0, "federation /event request");

    let json = load_event_json_by_event_id(&state.db, &event_id).ok_or(StatusCode::NOT_FOUND)?;

    // Transaction-shaped response per spec.
    Ok(Json(json!({
        "origin": state.config.server_name,
        "origin_server_ts": crate::federation_client::now_ms(),
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
    Path(_room_id): Path<String>,
    Query(q): Query<StateQuery>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    debug!(event_id = %q.event_id, origin = %origin.0, "federation /state request");

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
    Path(_room_id): Path<String>,
    Query(q): Query<StateQuery>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    debug!(event_id = %q.event_id, origin = %origin.0, "federation /state_ids request");

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

#[derive(Deserialize)]
pub struct BackfillQuery {
    /// Event IDs to start walking back from (repeated ?v= params).
    #[serde(default)]
    pub v: Vec<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// GET /_matrix/federation/v1/backfill/{roomId}?v=...&limit=N
///
/// Walk back through `prev_events` from `v`, collecting up to `limit` events.
/// Returns a transaction-shaped response.
pub async fn get_backfill(
    State(state): State<AppState>,
    Path(_room_id): Path<String>,
    Query(q): Query<BackfillQuery>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, StatusCode> {
    if q.v.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let limit = q.limit.unwrap_or(10).min(100) as usize;

    debug!(
        origin = %origin.0,
        starting = q.v.len(),
        limit,
        "federation /backfill request"
    );

    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = q.v.into_iter().collect();
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
        "origin_server_ts": crate::federation_client::now_ms(),
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
    let earliest: HashSet<String> = req.earliest_events.into_iter().collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = req.latest_events.into_iter().collect();
    let mut out: Vec<Value> = Vec::new();

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
        let Some(json) = load_event_json_by_event_id(&state.db, &eid) else {
            continue;
        };
        out.push(json);

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

    out.sort_by_key(|ev| ev.get("depth").and_then(|d| d.as_u64()).unwrap_or(u64::MAX));

    Ok(Json(json!({ "events": out })))
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
