//! Inbound federation join endpoints.
//!
//! - `GET /_matrix/federation/v1/make_join/{roomId}/{userId}?ver=X,Y`
//! - `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`
//!
//! 3b restriction: only rooms with `join_rules=public` accept federated joins.
//! Invite-only flows are handled via the client `/invite` API; restricted and
//! knock rooms need `join_authorised_via_users_server` crypto (deferred to 3c).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use serde_json::{Map, Value, json};
use tracing::{debug, warn};

use vela_core::auth_rules::{AuthError, check_auth};
use vela_core::events::builder::select_auth_events;
use vela_core::events::content;
use vela_core::events::pdu::Pdu;
use vela_core::events::room_version::RoomVersion;
use vela_core::federation::keys::{decode_public_key, verify_event_signature};
use vela_core::identifiers::{EventId, Nid};

use crate::federation_state::{
    auth_chain_including_seeds, load_event_json_by_event_id, load_pdu_by_event_id,
};
use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// Parse a raw query string into supported room versions from repeated
/// `ver=` keys, comma-separated values, or a mix of both. Defaults to
/// `["1"]` per spec when no `ver` is provided.
///
/// We parse manually because `serde_urlencoded` (axum's default `Query`
/// backend) rejects repeated keys for the same struct field — and the
/// spec specifically defines `?ver=1&ver=7&ver=12` as the canonical
/// representation.
/// Public re-export so federation_knock can share the parser.
pub fn parse_supported_versions_pub(query: Option<&str>) -> Vec<String> {
    parse_supported_versions(query)
}

fn parse_supported_versions(query: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(q) = query {
        for (k, v) in form_urlencoded::parse(q.as_bytes()) {
            if k != "ver" {
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
    if out.is_empty() {
        out.push("1".to_string());
    }
    out
}

/// GET /_matrix/federation/v1/make_join/{roomId}/{userId}
pub async fn make_join(
    State(state): State<AppState>,
    Path((room_id, user_id)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    debug!(%room_id, %user_id, origin = %origin.0, "make_join");

    // Version negotiation. We only serve v12 rooms; if the origin doesn't
    // list 12 in its supported versions, return M_INCOMPATIBLE_ROOM_VERSION
    // with the room's actual version so the origin knows to upgrade.
    let supported = parse_supported_versions(raw_query.as_deref());
    let our_version = RoomVersion::V12.as_str();
    if !supported.iter().any(|v| v == our_version) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errcode": "M_INCOMPATIBLE_ROOM_VERSION",
                "error": "room is v12; requesting server does not list 12 in ver",
                "room_version": our_version,
            })),
        ));
    }

    // Validate the user belongs to the calling origin.
    match user_id.split_once(':') {
        Some((_, domain)) if domain == origin.0 => {}
        _ => {
            return Err(err_response(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "userId does not belong to origin",
            ));
        }
    }

    // Look up room.
    let room_nid = match state.db.get_nid(&room_id) {
        Ok(Some(n)) => n,
        _ => {
            return Err(err_response(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                "room not known locally",
            ));
        }
    };

    // Accept public + restricted/knock_restricted rooms outright.
    // For invite-only rooms, accept iff the user has a current
    // `m.room.member` invite — the spec lets invited users
    // make_join just like the public path. Knock rooms
    // intentionally fall through to make_knock instead.
    let join_rules_content = read_join_rules_content(&state, room_nid);
    let join_rule = join_rules_content
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(|r| r.as_str())
        .unwrap_or("invite");

    let user_nid = state.db.get_or_create_nid(&user_id).map_err(db_err)?;
    let current_membership = state.db.get_membership(room_nid, user_nid).ok().flatten();

    let join_rule_allows = matches!(join_rule, "public" | "restricted" | "knock_restricted");
    let invited = current_membership == Some(2);
    if !join_rule_allows && !invited {
        return Err(err_response(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "room is invite-only or knock-only; federation make_join not allowed",
        ));
    }

    // Reject if user is banned. Already-joined users get a fresh template
    // (the origin is presumably retrying a prior failed join).
    match current_membership {
        Some(1) => {
            warn!(%user_id, "make_join for already-joined user (issuing fresh template)");
        }
        Some(3) => {
            return Err(err_response(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "user is banned",
            ));
        }
        _ => {}
    }

    let room_version = RoomVersion::V12;

    // For restricted / knock_restricted, embed a `join_authorised_via_users_server`
    // pointing at a local member with invite power. The calling user must
    // also satisfy the allow list. Auth rule 5.3.5 (check_member_join) will
    // enforce both on the send_join side.
    let authoriser: Option<String> = if matches!(join_rule, "restricted" | "knock_restricted") {
        let allow = join_rules_content
            .as_ref()
            .and_then(|c| c.get("allow"))
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        match crate::membership::user_qualifies_via_allow_list_pub(&state, user_nid, &allow) {
            Ok(true) => {}
            Ok(false) => {
                return Err(err_response(
                    StatusCode::FORBIDDEN,
                    "M_FORBIDDEN",
                    "user is not a member of any allow-list room",
                ));
            }
            Err(e) => return Err(db_err(e.0)),
        }
        match crate::membership::pick_local_authoriser_pub(&state, room_nid) {
            Ok(Some(a)) => Some(a),
            Ok(None) => {
                return Err(err_response(
                    StatusCode::FORBIDDEN,
                    "M_UNABLE_TO_GRANT_JOIN",
                    "no local member with invite power to authorise join",
                ));
            }
            Err(e) => return Err(db_err(e.0)),
        }
    } else {
        None
    };

    // Build a TEMPLATE event (no hashes, no signatures — origin will sign).
    let mut content_val = content::member_content_join(None, None);
    if let Some(a) = &authoriser {
        content_val.as_object_mut().unwrap().insert(
            "join_authorised_via_users_server".to_string(),
            Value::String(a.clone()),
        );
    }

    let auth_events = select_auth_events(
        "m.room.member",
        &user_id,
        Some(&user_id),
        Some(&content_val),
        room_version,
        &|etype: &str, skey: &str| -> Option<EventId> {
            let tn = state.db.get_nid(etype).ok()??;
            let sn = state.db.get_nid(skey).ok()??;
            let en = state.db.get_state_event_nid(room_nid, tn, sn).ok()??;
            let eid = state.db.get_event_id_by_nid(en).ok()??;
            EventId::parse(&eid).ok()
        },
    );

    // prev_events from extremities, plus depth from the deepest extremity + 1.
    let extremity_nids = state.db.get_extremities(room_nid).map_err(db_err)?;
    let mut prev_event_ids: Vec<String> = Vec::new();
    let mut max_depth: u64 = 0;
    for &enid in &extremity_nids {
        if let Ok(Some(d)) = state.db.get_event_depth(enid)
            && d > max_depth
        {
            max_depth = d;
        }
        if let Ok(Some(id)) = state.db.get_event_id_by_nid(enid) {
            prev_event_ids.push(id);
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut template = Map::new();
    template.insert("type".into(), json!("m.room.member"));
    template.insert("state_key".into(), json!(user_id));
    template.insert("sender".into(), json!(user_id));
    template.insert("room_id".into(), json!(room_id));
    template.insert("content".into(), content_val);
    template.insert("origin".into(), json!(origin.0));
    template.insert("origin_server_ts".into(), json!(now));
    template.insert("depth".into(), json!(max_depth + 1));
    template.insert("prev_events".into(), json!(prev_event_ids));
    template.insert(
        "auth_events".into(),
        json!(auth_events.iter().map(|e| e.as_str()).collect::<Vec<_>>()),
    );

    // For restricted joins, the resident server (us) must sign the template
    // on behalf of the authoriser's homeserver — vela only picks local
    // authorisers, so we sign with our own key. The requesting server adds
    // its own signature on send_join, and the resident verifies both. Per
    // server-server spec §"Restricted rooms".
    if authoriser.is_some() {
        vela_core::events::hash::add_content_hash(&mut template);
        state
            .signing_key
            .sign_event(&mut template, &state.config.server_name);
    }

    Ok(Json(json!({
        "room_version": room_version.as_str(),
        "event": template,
    })))
}

/// PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}
///
/// Legacy variant. Identical input validation and persist logic to v2;
/// only the success response shape differs — v1 wraps the body in a
/// `[200, {...}]` array, a quirk of the original spec that v2 fixed.
/// We delegate to `send_join_v2` and reshape on success; errors pass
/// through unchanged (the `{errcode, error}` JSON is the same in both
/// versions).
pub async fn send_join_v1(
    state: State<AppState>,
    path: Path<(String, String)>,
    origin: axum::extract::Extension<XMatrixOrigin>,
    body: axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let v2 = send_join_v2(state, path, origin, body).await?;
    Ok(Json(json!([200, v2.0])))
}

/// PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
pub async fn send_join_v2(
    State(state): State<AppState>,
    Path((room_id, event_id)): Path<(String, String)>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
    axum::extract::Extension(VerifiedBody(body)): axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    debug!(%room_id, %event_id, origin = %origin.0, "send_join v2");

    let event_json = body.ok_or_else(|| {
        err_response(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "empty send_join body",
        )
    })?;
    let event_obj = event_json.as_object().ok_or_else(|| {
        err_response(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "event is not an object",
        )
    })?;

    // Spec-mandated structural checks.
    let event_type = event_obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_response(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing type"))?;
    if event_type != "m.room.member" {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "send_join event must be m.room.member",
        ));
    }
    let membership = event_obj
        .get("content")
        .and_then(|c| c.get("membership"))
        .and_then(|m| m.as_str())
        .ok_or_else(|| err_response(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing membership"))?;
    if membership != "join" {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "send_join membership must be join",
        ));
    }
    let sender = event_obj
        .get("sender")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_response(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing sender"))?;
    let state_key = event_obj
        .get("state_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_response(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing state_key"))?;
    if sender != state_key {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "sender must equal state_key",
        ));
    }
    // Sender's domain must equal the request origin.
    let sender_domain = sender.split_once(':').map(|(_, d)| d).unwrap_or("");
    if sender_domain != origin.0 {
        return Err(err_response(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "sender domain does not match origin",
        ));
    }

    // Verify the signature over the event.
    let keys = state
        .remote_keys
        .get_or_fetch(sender_domain)
        .await
        .map_err(|_| {
            err_response(
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "cannot fetch origin keys",
            )
        })?;
    let sig_root = event_obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(sender_domain))
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            err_response(
                StatusCode::UNAUTHORIZED,
                "M_UNAUTHORIZED",
                "missing signature from origin",
            )
        })?;
    let mut sig_verified = false;
    for (key_id, _) in sig_root {
        let Some(pub_b64) = keys.verify_keys.get(key_id) else {
            continue;
        };
        let Ok(public_key) = decode_public_key(pub_b64) else {
            continue;
        };
        if verify_event_signature(event_obj, sender_domain, key_id, &public_key).is_ok() {
            sig_verified = true;
            break;
        }
    }
    if !sig_verified {
        return Err(err_response(
            StatusCode::UNAUTHORIZED,
            "M_UNAUTHORIZED",
            "signature verification failed",
        ));
    }

    // Restricted-join extra check: when the event carries
    // `join_authorised_via_users_server`, the spec requires a signature
    // from the authoriser's server in addition to the sender's. This is
    // the cryptographic proof that a qualifying user on the authorising
    // server actually approved the join.
    if let Some(authoriser) = event_obj
        .get("content")
        .and_then(|c| c.get("join_authorised_via_users_server"))
        .and_then(|v| v.as_str())
    {
        let authoriser_domain = authoriser.split_once(':').map(|(_, d)| d).unwrap_or("");
        if authoriser_domain.is_empty() {
            return Err(err_response(
                StatusCode::BAD_REQUEST,
                "M_BAD_JSON",
                "join_authorised_via_users_server has no domain",
            ));
        }
        // Skip the duplicate verify when sender and authoriser are the
        // same domain — the sender check above already covered it.
        if authoriser_domain != sender_domain {
            let auth_keys = state
                .remote_keys
                .get_or_fetch(authoriser_domain)
                .await
                .map_err(|_| {
                    err_response(
                        StatusCode::UNAUTHORIZED,
                        "M_UNAUTHORIZED",
                        "cannot fetch authoriser keys",
                    )
                })?;
            let auth_sigs = event_obj
                .get("signatures")
                .and_then(|v| v.as_object())
                .and_then(|s| s.get(authoriser_domain))
                .and_then(|v| v.as_object())
                .ok_or_else(|| {
                    err_response(
                        StatusCode::UNAUTHORIZED,
                        "M_UNAUTHORIZED",
                        "missing signature from authoriser server",
                    )
                })?;
            let mut auth_verified = false;
            for (key_id, _) in auth_sigs {
                let Some(pub_b64) = auth_keys.verify_keys.get(key_id) else {
                    continue;
                };
                let Ok(public_key) = decode_public_key(pub_b64) else {
                    continue;
                };
                if verify_event_signature(event_obj, authoriser_domain, key_id, &public_key).is_ok()
                {
                    auth_verified = true;
                    break;
                }
            }
            if !auth_verified {
                return Err(err_response(
                    StatusCode::UNAUTHORIZED,
                    "M_UNAUTHORIZED",
                    "authoriser signature verification failed",
                ));
            }
        }
    }

    // Look up room.
    let room_nid = match state.db.get_nid(&room_id) {
        Ok(Some(n)) => n,
        _ => {
            return Err(err_response(
                StatusCode::NOT_FOUND,
                "M_NOT_FOUND",
                "room unknown",
            ));
        }
    };
    // Accept public + restricted/knock_restricted send_join; auth rule
    // 5.3.5 will enforce the join_authorised_via_users_server constraint
    // for restricted variants. Invite-only/knock-only rooms also accept
    // when the joiner already has an invite — Synapse parity, and the
    // path TestDeviceListsUpdateOverFederation exercises (alice invites
    // bob across federation; bob's hs2 then send_joins via hs1).
    let join_rule = read_join_rules_content(&state, room_nid)
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(|r| r.as_str())
        .unwrap_or("invite")
        .to_string();
    let joiner_nid = state.db.get_or_create_nid(state_key).map_err(db_err)?;
    let joiner_invited = state.db.get_membership(room_nid, joiner_nid).ok().flatten() == Some(2);
    let join_rule_allows = matches!(
        join_rule.as_str(),
        "public" | "restricted" | "knock_restricted"
    );
    if !join_rule_allows && !joiner_invited {
        return Err(err_response(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "room is invite-only or knock-only; send_join not allowed",
        ));
    }

    // Verify event_id in URL matches the computed reference hash. An origin
    // could otherwise send a legitimate signed event under a chosen URL id,
    // causing us to persist it under a fabricated identifier.
    let computed_event_id = vela_core::events::hash::compute_event_id(event_obj);
    if computed_event_id.as_str() != event_id {
        return Err(err_response(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "URL event_id does not match the event's reference hash",
        ));
    }

    // Content hash check (spec §Validating hashes and signatures). If the
    // declared content hash doesn't match, the spec says to substitute the
    // redacted form before proceeding.
    let declared_hash = event_obj
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let computed_hash = vela_core::events::hash::compute_content_hash(event_obj);
    let use_redacted = match declared_hash {
        Some(d) => d != computed_hash,
        None => true,
    };
    let effective_event_obj: Map<String, Value> = if use_redacted {
        tracing::warn!(%event_id, "send_join: content hash mismatch, using redacted form");
        vela_core::events::redact::redact_event(event_obj)
    } else {
        event_obj.clone()
    };

    // Build PDU from the hash-validated event JSON.
    let pdu = Pdu::from_json(event_id.clone(), &effective_event_obj).ok_or_else(|| {
        err_response(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "malformed event fields after hash check",
        )
    })?;

    // Acquire the room lock for read-state/persist atomicity.
    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Banned users MUST NOT be able to /send_join, even if their forged
    // event references stale auth_events from BEFORE the ban. The event's
    // claimed auth_events are an attacker-controlled choice — auth-rule
    // check 5.3 ("if state_key's current membership is `ban`, reject")
    // would let it through here because the attacker omitted the ban
    // event from auth_events. Independently consult our current room
    // state and reject up front. Spec: server-server-api §Auth chain
    // — receivers MAY apply additional state-resolution-based checks
    // beyond the bare auth-events check.
    if let Some(current_member) =
        crate::federation_state::load_state_pdu(&state.db, room_nid, "m.room.member", state_key)
        && current_member.membership() == Some("ban")
    {
        return Err(err_response(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "user is banned from this room",
        ));
    }

    // Check auth against the event's claimed auth_events.
    let mut auth_state: std::collections::HashMap<(String, String), Pdu> =
        std::collections::HashMap::new();
    for aev in &pdu.auth_events {
        let Some(auth_pdu) = load_pdu_by_event_id(&state.db, aev) else {
            return Err(err_response(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "unknown auth event",
            ));
        };
        if let Some(sk) = auth_pdu.state_key.as_deref() {
            auth_state.insert((auth_pdu.event_type.clone(), sk.to_string()), auth_pdu);
        }
    }
    // v12 (MSC4291): m.room.create is absent from auth_events.
    crate::federation_state::ensure_create_in_state(&state.db, room_nid, &mut auth_state);
    let auth_fn = |t: &str, sk: &str| auth_state.get(&(t.to_string(), sk.to_string()));
    if let Err(AuthError::Rejected(reason)) = check_auth(&pdu, &auth_fn) {
        let state_keys: Vec<String> = auth_state
            .keys()
            .map(|(t, sk)| format!("{t}/{sk}"))
            .collect();
        let state_event_count = state
            .db
            .get_all_state_event_nids(room_nid)
            .map(|v| v.len())
            .unwrap_or(0);
        warn!(
            %event_id, %reason, %room_id,
            auth_state_keys = ?state_keys,
            persisted_state_event_count = state_event_count,
            "send_join rejected"
        );
        return Err(err_response(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            &format!("auth check failed: {reason}"),
        ));
    }

    // Build the state + auth_chain response BEFORE persisting (so the
    // response reflects pre-join state per spec).
    let state_events_before = match state.db.get_all_state_event_nids(room_nid) {
        Ok(nids) => {
            let mut evs = Vec::with_capacity(nids.len());
            for nid in nids {
                if let Ok(Some(eid)) = state.db.get_event_id_by_nid(nid)
                    && let Some(j) = load_event_json_by_event_id(&state.db, &eid)
                {
                    evs.push(j);
                }
            }
            evs
        }
        Err(_) => Vec::new(),
    };
    // Auth chain for the join event: walk pdu.auth_events transitively via the
    // DB. We do this BEFORE persist (the join event itself isn't in the DB yet
    // and shouldn't be in the chain anyway — the chain is the dependencies of
    // the join event, not the join event itself).
    let auth_chain_ids =
        auth_chain_including_seeds(&state.db, &pdu.auth_events).unwrap_or_default();
    let mut auth_chain_pdus: Vec<Value> = Vec::with_capacity(auth_chain_ids.len());
    for id in &auth_chain_ids {
        if let Some(j) = load_event_json_by_event_id(&state.db, id) {
            auth_chain_pdus.push(j);
        }
    }

    // Persist the join event via the receive-pipeline machinery.
    let persist_result =
        crate::federation_receive::persist_join_event(&state, room_nid, &pdu, &effective_event_obj)
            .await;
    if let Err(reason) = persist_result {
        return Err(err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &format!("persist failed: {reason}"),
        ));
    }

    // Surface the remote joiner in our local users' next /sync
    // `device_lists.changed`. The standalone `m.device_list_update`
    // EDU may follow later; without this bookkeeping our local
    // users only learn about the new co-resident's keys when they
    // happen to /keys/query for them. Spec: device-list updates
    // SHOULD reflect all newly-shared peers immediately on join.
    if let Ok(remote_user_nid) = state.db.get_or_create_nid(state_key) {
        let our_server = state.config.server_name.as_str();
        let stream_pos = state.db.next_stream_position().as_u64();
        if let Ok(members) = state.db.get_room_members(room_nid) {
            let mut local_observers: Vec<u64> = Vec::new();
            for m in members {
                if m == remote_user_nid {
                    continue;
                }
                if let Ok(Some(uid)) = state.db.resolve_nid(m)
                    && uid
                        .split_once(':')
                        .map(|(_, d)| d == our_server)
                        .unwrap_or(false)
                {
                    local_observers.push(m);
                }
            }
            if !local_observers.is_empty() {
                let _ = state.db.notify_device_key_change(
                    remote_user_nid,
                    &local_observers,
                    stream_pos,
                );
                for &nid in &local_observers {
                    crate::router::notify_user(&state, nid);
                }
            }
        }
    }

    Ok(Json(json!({
        "auth_chain": auth_chain_pdus,
        "state": state_events_before,
        "event": Value::Null,
    })))
}

/// Read the current `m.room.join_rules` content. Returns `None` when the
/// state event is missing or malformed.
fn read_join_rules_content(state: &AppState, room_nid: u64) -> Option<Value> {
    let tn = state.db.get_nid("m.room.join_rules").ok().flatten()?;
    let sn = state.db.get_nid("").ok().flatten()?;
    let enid = state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .ok()
        .flatten()?;
    let (_h, bytes) = state.db.get_event(enid).ok().flatten()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("content").cloned()
}

fn err_response(code: StatusCode, errcode: &str, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "errcode": errcode, "error": msg })))
}

fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    err_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "M_UNKNOWN",
        &format!("db: {e}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::federation_auth::XMatrixOrigin;
    use crate::test_helpers::build_test_state;
    use axum::extract::{Path, RawQuery};
    use serde_json::json;

    /// Construct a minimal local v12 room with alice joined + creator and
    /// the given join_rules content. Returns `(state, room_id)`.
    async fn make_room_with_join_rules(
        server_name: &str,
        join_rules_content: Value,
    ) -> (AppState, tempfile::TempDir, String, String) {
        let (state, tmp) = crate::test_helpers::build_test_state_with_name(server_name);
        let db = &state.db;
        let room_id = format!("!room:{server_name}");
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        db.create_room_meta(room_nid, &room_id, "12").unwrap();

        let alice = format!("@alice:{server_name}");
        let alice_nid = db.get_or_create_nid(&alice).unwrap();
        let create_type = db.get_or_create_nid("m.room.create").unwrap();
        let member_type = db.get_or_create_nid("m.room.member").unwrap();
        let join_rules_type = db.get_or_create_nid("m.room.join_rules").unwrap();
        let empty_skey = db.get_or_create_nid("").unwrap();

        let create = json!({
            "type": "m.room.create",
            "sender": alice,
            "state_key": "",
            "room_id": room_id,
            "content": {"room_version": "12"},
            "origin_server_ts": 1, "depth": 1,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            10,
            "$create",
            room_nid,
            create_type,
            alice_nid,
            empty_skey,
            1,
            1,
            &serde_json::to_vec(&create).unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();

        let alice_join = json!({
            "type": "m.room.member",
            "sender": alice,
            "state_key": alice,
            "room_id": room_id,
            "content": {"membership": "join"},
            "origin_server_ts": 2, "depth": 2,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            11,
            "$alice_join",
            room_nid,
            member_type,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&alice_join).unwrap(),
            &[10],
            &[10],
            true,
            false,
        )
        .unwrap();
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        let rules = json!({
            "type": "m.room.join_rules",
            "sender": alice,
            "state_key": "",
            "room_id": room_id,
            "content": join_rules_content,
            "origin_server_ts": 3, "depth": 3,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            12,
            "$join_rules",
            room_nid,
            join_rules_type,
            alice_nid,
            empty_skey,
            3,
            3,
            &serde_json::to_vec(&rules).unwrap(),
            &[11],
            &[10, 11],
            true,
            false,
        )
        .unwrap();

        (state, tmp, room_id, alice)
    }

    #[tokio::test]
    async fn make_join_picks_local_authoriser_for_restricted_room() {
        // Gate room (public) with bob joined; restricted room allow-lists it.
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let gate_room = "!gate:example.com";
        let gate_nid = db.get_or_create_nid(gate_room).unwrap();
        db.create_room_meta(gate_nid, gate_room, "12").unwrap();
        let bob_nid = db.get_or_create_nid("@bob:remote.example").unwrap();
        db.set_membership(gate_nid, bob_nid, 1).unwrap();

        // Build the restricted room in the same state.
        let restricted = "!restricted:example.com";
        let restricted_nid = db.get_or_create_nid(restricted).unwrap();
        db.create_room_meta(restricted_nid, restricted, "12")
            .unwrap();

        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let create_type = db.get_or_create_nid("m.room.create").unwrap();
        let member_type = db.get_or_create_nid("m.room.member").unwrap();
        let join_rules_type = db.get_or_create_nid("m.room.join_rules").unwrap();
        let empty_skey = db.get_or_create_nid("").unwrap();

        db.persist_event(
            100,
            "$create",
            restricted_nid,
            create_type,
            alice_nid,
            empty_skey,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type": "m.room.create", "sender": "@alice:example.com",
                "state_key": "", "room_id": restricted,
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
            restricted_nid,
            member_type,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type": "m.room.member", "sender": "@alice:example.com",
                "state_key": "@alice:example.com", "room_id": restricted,
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[100],
            &[100],
            true,
            false,
        )
        .unwrap();
        db.set_membership(restricted_nid, alice_nid, 1).unwrap();
        db.persist_event(
            102,
            "$rules",
            restricted_nid,
            join_rules_type,
            alice_nid,
            empty_skey,
            3,
            3,
            &serde_json::to_vec(&json!({
                "type": "m.room.join_rules", "sender": "@alice:example.com",
                "state_key": "", "room_id": restricted,
                "content": {
                    "join_rule": "restricted",
                    "allow": [{"type": "m.room_membership", "room_id": gate_room}],
                },
                "origin_server_ts": 3, "depth": 3,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[101],
            &[100, 101],
            true,
            false,
        )
        .unwrap();

        let origin = axum::Extension(XMatrixOrigin("remote.example".into()));
        let resp = make_join(
            axum::extract::State(state.clone()),
            Path((restricted.to_string(), "@bob:remote.example".to_string())),
            RawQuery(Some("ver=12".to_string())),
            origin,
        )
        .await
        .expect("make_join ok");

        let authoriser = resp
            .0
            .pointer("/event/content/join_authorised_via_users_server")
            .and_then(|v| v.as_str())
            .expect("authoriser present");
        assert_eq!(authoriser, "@alice:example.com");

        // The resident server (us) must have signed the template on
        // behalf of the authoriser's homeserver. The requesting server
        // adds its own signature on send_join. Without our signature,
        // the spec's two-server proof for restricted joins breaks.
        let sigs = resp
            .0
            .pointer("/event/signatures")
            .and_then(|v| v.as_object())
            .expect("template carries signatures");
        assert!(
            sigs.contains_key(&state.config.server_name),
            "template must be signed by the authoriser's server (us): {sigs:?}"
        );
        let hashes = resp
            .0
            .pointer("/event/hashes")
            .and_then(|v| v.as_object())
            .expect("template carries content hash");
        assert!(hashes.contains_key("sha256"));
    }

    #[tokio::test]
    async fn make_join_rejects_when_user_not_in_allow_list() {
        // bob is NOT in the gate room — should get 403.
        let (state, _tmp, restricted, _alice) = make_room_with_join_rules(
            "example.com",
            json!({
                "join_rule": "restricted",
                "allow": [{"type": "m.room_membership", "room_id": "!gate:example.com"}],
            }),
        )
        .await;

        let origin = axum::Extension(XMatrixOrigin("remote.example".into()));
        let err = make_join(
            axum::extract::State(state.clone()),
            Path((restricted, "@bob:remote.example".to_string())),
            RawQuery(Some("ver=12".to_string())),
            origin,
        )
        .await
        .expect_err("expected forbidden");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn make_join_rejects_invite_only_rooms() {
        let (state, _tmp, restricted, _alice) =
            make_room_with_join_rules("example.com", json!({"join_rule": "invite"})).await;
        let origin = axum::Extension(XMatrixOrigin("remote.example".into()));
        let err = make_join(
            axum::extract::State(state.clone()),
            Path((restricted, "@bob:remote.example".to_string())),
            RawQuery(Some("ver=12".to_string())),
            origin,
        )
        .await
        .expect_err("invite rooms reject make_join");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
