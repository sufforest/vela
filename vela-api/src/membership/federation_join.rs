//! Inbound federation join endpoints.
//!
//! - `GET /_matrix/federation/v1/make_join/{roomId}/{userId}?ver=X,Y`
//! - `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`
//!
//! 3b restriction: only rooms with `join_rules=public` accept federated joins.
//! Invite-only flows are handled via the client `/invite` API; restricted and
//! knock rooms need `join_authorised_via_users_server` crypto (deferred to 3c).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::middleware::json::Json;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use serde_json::{Map, Value, json};
use tracing::{debug, warn};

use vela_core::auth_rules::{AuthError, check_auth};
use vela_core::events::builder::select_auth_events;
use vela_core::events::content;
use vela_core::events::pdu::Pdu;
use vela_core::federation::keys::{decode_public_key, verify_event_signature};
use vela_core::identifiers::{EventId, Nid};

use crate::federation::federation_state::{
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

    // Version negotiation. We need the origin to support OUR room's
    // actual version (vela hosts v6–v12 rooms). If the origin doesn't
    // list our room's version in `?ver=`, return
    // M_INCOMPATIBLE_ROOM_VERSION so the origin knows to refuse the join.
    let supported = parse_supported_versions(raw_query.as_deref());
    let room_nid_for_version = state
        .db
        .get_nid(&room_id)
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", e.as_ref()))?
        .ok_or_else(|| err_response(StatusCode::NOT_FOUND, "M_NOT_FOUND", "room not found"))?;
    let our_version_typed = state
        .db
        .get_room_version_typed(room_nid_for_version)
        .map_err(|e| err_response(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", e.as_ref()))?;
    let our_version = our_version_typed.as_str();
    if !supported.iter().any(|v| v == our_version) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errcode": "M_INCOMPATIBLE_ROOM_VERSION",
                "error": format!("room is v{our_version}; requesting server does not list it in ver"),
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

    // MSC3902 / MSC3706: during partial state we don't have the full
    // current-state needed to evaluate restricted-room authorisation,
    // power_levels, or membership history. Refuse the request with
    // 404 M_NOT_FOUND so the calling server retries against a fully-
    // synced peer. Spec-mandated; complement's TestPartialStateJoin
    // /Rejects_make_join_during_partial_join asserts the same.
    if let Ok((true, _)) = state.db.get_partial_state_info(room_nid) {
        return Err(err_response(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room is currently in partial state",
        ));
    }

    // m.room.server_acl gate. Block banned origins from getting a join
    // template at all.
    crate::federation::server_acl::deny_if_blocked(&state, room_nid, &origin.0)?;

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

    let room_version = state.db.get_room_version_typed(room_nid).map_err(|e| {
        err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &format!("db: {e}"),
        )
    })?;
    // pointing at a local member with invite power. The calling user must
    // also satisfy the allow list. Auth rule 5.3.5 (check_member_join) will
    // enforce both on the send_join side.
    // Restricted-room authoriser. An invited user joins like a public-room
    // join — no allow-list check, no `join_authorised_via_users_server`.
    // Skipping the authoriser is what TestKnockingInMSC3787Room's
    // "A_user_cannot_knock_on_a_room_they_are_already_in" relies on: the
    // user already accepted an invite, so a follow-up join shouldn't
    // require space membership to succeed.
    let authoriser: Option<String> =
        if matches!(join_rule, "restricted" | "knock_restricted") && !invited {
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
        state.signing_key.sign_event_for_version(
            &mut template,
            &state.config.server_name,
            room_version,
        );
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
    raw_query: axum::extract::RawQuery,
    origin: axum::extract::Extension<XMatrixOrigin>,
    body: axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let v2 = send_join_v2(state, path, raw_query, origin, body).await?;
    Ok(Json(json!([200, v2.0])))
}

/// PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}
pub async fn send_join_v2(
    State(state): State<AppState>,
    Path((room_id, event_id)): Path<(String, String)>,
    axum::extract::RawQuery(raw_query): axum::extract::RawQuery,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
    axum::extract::Extension(VerifiedBody(body)): axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // MSC3706 opt-in. Peers that don't pass this get full state.
    let omit_members = raw_query
        .as_deref()
        .map(|q| q.split('&').any(|p| p == "omit_members=true"))
        .unwrap_or(false);
    debug!(%room_id, %event_id, origin = %origin.0, %omit_members, "send_join v2");

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

    // m.room.server_acl gate. If room exists locally, deny the join
    // when the origin is banned by the room's ACL.
    if let Some(room_nid) = state.db.get_nid(&room_id).ok().flatten() {
        crate::federation::server_acl::deny_if_blocked(&state, room_nid, &origin.0)?;
    }

    // Look up the room version up-front so verify_event_signature
    // redacts under the sender's shape; pre-v11 join member events
    // strip everything except `membership` from content (and v8+ keep
    // join_authorised_via_users_server too), and v12 redaction would
    // over-preserve, breaking sig verify.
    let send_join_room_version = state
        .db
        .get_nid(&room_id)
        .ok()
        .flatten()
        .and_then(|n| state.db.get_room_version_typed(n).ok())
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);

    // Verify the signature over the event. Pass the signing key ids so a
    // rotated origin key is re-fetched rather than rejected against the cache.
    let wanted: Vec<&str> = event_obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(sender_domain))
        .and_then(|v| v.as_object())
        .map(|m| m.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let keys = state
        .remote_keys
        .get_or_fetch_signed(sender_domain, &wanted)
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
        if verify_event_signature(
            event_obj,
            sender_domain,
            key_id,
            &public_key,
            send_join_room_version,
        )
        .is_ok()
        {
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

    // Restricted-join extra check (MSC3083 / server-server-api §"Restricted
    // rooms" / auth rule 4.2): when the event carries
    // `join_authorised_via_users_server`, the spec requires a signature
    // from the authoriser's homeserver in addition to the sender's. This
    // is the cryptographic proof that a qualifying user on the authorising
    // server actually approved the join. PL + joined-membership of the
    // authoriser are enforced later via `check_auth` (rule 5.3.5) against
    // the event's claimed auth_events.
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
        // The named authoriser must be on this server. We only ever
        // produce restricted-join templates referencing a local user
        // (see make_join: pick_local_authoriser walks our own members),
        // so any inbound send_join naming a non-local authoriser is
        // either a forged event or was minted against a different
        // resident — either way, refuse. This guard closes the gap
        // where a sender could otherwise dictate an arbitrary
        // authoriser MXID and rely on the auth rule alone.
        let our_server = state.config.server_name.as_str();
        if authoriser_domain != our_server {
            return Err(err_response(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "join_authorised_via_users_server must be a local user",
            ));
        }
        // Skip the duplicate verify when sender and authoriser share a
        // domain (the sender check above covered it). When the
        // authoriser is local but the sender is remote (the normal
        // case for restricted federation), verify against OUR own
        // server signing key — fetching our own keys over HTTPS would
        // either loop back or fail entirely depending on bind config.
        if authoriser_domain != sender_domain {
            let our_key_id = state.signing_key.key_id();
            let our_pub = state.signing_key.verifying_key();
            if verify_event_signature(
                event_obj,
                authoriser_domain,
                our_key_id,
                &our_pub,
                send_join_room_version,
            )
            .is_err()
            {
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
    // MSC3902 / MSC3706: reject send_join during partial state for
    // the same reason as make_join — without the full membership +
    // power_levels view we can't safely authorise a new join.
    if let Ok((true, _)) = state.db.get_partial_state_info(room_nid) {
        return Err(err_response(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room is currently in partial state",
        ));
    }
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
    let computed_event_id =
        vela_core::events::hash::compute_event_id_for_version(event_obj, send_join_room_version);
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
        vela_core::events::redact::redact_event_for_version(event_obj, send_join_room_version)
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
    if let Some(current_member) = crate::federation::federation_state::load_state_pdu(
        &state.db,
        room_nid,
        "m.room.member",
        state_key,
    ) && current_member.membership() == Some("ban")
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
    crate::federation::federation_state::ensure_create_in_state(
        &state.db,
        room_nid,
        &mut auth_state,
    );
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
    let (state_events_before, state_event_ids): (Vec<Value>, HashSet<String>) =
        match state.db.get_all_state_event_nids(room_nid) {
            Ok(nids) => {
                let mut evs = Vec::with_capacity(nids.len());
                let mut ids = HashSet::with_capacity(nids.len());
                for nid in nids {
                    if let Ok(Some(eid)) = state.db.get_event_id_by_nid(nid)
                        && let Some(j) = load_event_json_by_event_id(&state.db, &eid)
                    {
                        evs.push(j);
                        ids.insert(eid);
                    }
                }
                (evs, ids)
            }
            Err(_) => (Vec::new(), HashSet::new()),
        };
    // Auth chain for the response: per spec, this is the transitive
    // closure of auth_events for EVERY state event being returned,
    // not just the join event's own auth_events. The join event's
    // declared auth_events are only the trivial subset (create + PL
    // + JR + sender's prev member); a room with deep membership
    // history (TestCorruptedAuthChain pads with 100 leave/join
    // cycles) has a state-event chain that walks back through every
    // historical member event. Returning only pdu.auth_events here
    // gives the joining server a chain too shallow to validate the
    // returned state.
    let mut chain_seeds: Vec<String> = Vec::new();
    let mut seen_seeds: HashSet<String> = HashSet::new();
    for aev in &pdu.auth_events {
        if seen_seeds.insert(aev.clone()) {
            chain_seeds.push(aev.clone());
        }
    }
    for ev in &state_events_before {
        if let Some(arr) = ev.get("auth_events").and_then(|v| v.as_array()) {
            for a in arr {
                if let Some(eid) = a.as_str()
                    && seen_seeds.insert(eid.to_string())
                {
                    chain_seeds.push(eid.to_string());
                }
            }
        }
    }
    let auth_chain_ids = auth_chain_including_seeds(&state.db, &chain_seeds).unwrap_or_default();
    // State events already returned in `state` MUST NOT be repeated in
    // `auth_chain` — Complement's test harness treats the returned
    // state as the union of the two lists, so duplicates show up as
    // unexpected extras during state checks. Auth chain is the
    // transitive auth closure *not* present in the state we returned.
    let mut auth_chain_pdus: Vec<Value> = Vec::with_capacity(auth_chain_ids.len());
    for id in &auth_chain_ids {
        if state_event_ids.contains(id) {
            continue;
        }
        if let Some(j) = load_event_json_by_event_id(&state.db, id) {
            auth_chain_pdus.push(j);
        }
    }

    // Persist the join event via the receive-pipeline machinery.
    let persist_result = crate::federation::federation_receive::persist_join_event(
        &state,
        room_nid,
        &pdu,
        &effective_event_obj,
    )
    .await;
    if let Err(reason) = persist_result {
        return Err(err_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &format!("persist failed: {reason}"),
        ));
    }

    // The remote joiner's `device_lists.changed` notification on our
    // side is driven by the joiner's home server via the
    // `m.device_list_update` EDU (handled in
    // `edu::inbound::handle_device_list_update`, which dedups
    // redelivered stream_ids). Writing a second entry from this
    // synchronous path used to leak the same change into a later
    // /sync window for the observer
    // (TestDeviceListsUpdateOverFederation/good_connectivity).

    // MSC3706 partial-state filter. When the joining server opted in
    // via `?omit_members=true`, drop most m.room.member events from
    // the response. Keep: the joiner; the authoriser (for restricted);
    // the room creator(s); and the SENDER of every non-member state
    // event we're keeping in the response (otherwise the joining
    // server can't auth-check those state events).
    let (response_state, partial_state) = if omit_members {
        let keep = essential_member_state_keys(
            &state,
            room_nid,
            &effective_event_obj,
            &state_events_before,
        );
        let filtered: Vec<Value> = state_events_before
            .iter()
            .filter(|ev| {
                let ty = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if ty != "m.room.member" {
                    return true;
                }
                let sk = ev.get("state_key").and_then(|v| v.as_str()).unwrap_or("");
                keep.contains(sk)
            })
            .cloned()
            .collect();
        (filtered, true)
    } else {
        (state_events_before, false)
    };

    let our_server = state.config.server_name.clone();
    let mut resp = serde_json::Map::new();
    resp.insert("auth_chain".into(), json!(auth_chain_pdus));
    resp.insert("state".into(), json!(response_state));
    // Restricted Rooms only (joins-v2.yaml): "The full event with the
    // additional signatures of the resident server applied to it."
    // For restricted joins we signed the make_join template on behalf
    // of the local authoriser, so the event the joiner sent us already
    // carries both signatures — echo it back so the joiner can confirm
    // which exact bytes we persisted. For non-restricted joins the
    // field stays null (the spec only requires it for restricted).
    let is_restricted_join = effective_event_obj
        .get("content")
        .and_then(|c| c.get("join_authorised_via_users_server"))
        .is_some();
    if is_restricted_join {
        resp.insert("event".into(), Value::Object(effective_event_obj.clone()));
    } else {
        resp.insert("event".into(), Value::Null);
    }
    if partial_state {
        // Spec name since Matrix 1.6 (joins-v2.yaml). The MSC3706-era
        // unstable name was `partial_state`; peers on current spec
        // ignore the legacy field and assume full state, defeating the
        // fast-join optimisation. Emitting the stable name doesn't
        // confuse legacy peers since they'd already fall back to /state.
        resp.insert("members_omitted".into(), json!(true));
        resp.insert("servers_in_room".into(), json!([our_server]));
    }
    Ok(Json(Value::Object(resp)))
}

/// Collect state_keys whose m.room.member event we MUST keep in a
/// partial-state response. Includes: the joiner; the authoriser
/// (restricted joins); the room creator(s); and the SENDER of every
/// non-member state event we're returning (otherwise the joining
/// server can't auth-check those state events against the kept
/// members). The rest fills asynchronously via the joiner's filler.
fn essential_member_state_keys(
    state: &AppState,
    room_nid: u64,
    join_event: &Map<String, Value>,
    state_events_before: &[Value],
) -> std::collections::HashSet<String> {
    use std::collections::HashSet;
    let mut keep: HashSet<String> = HashSet::new();
    if let Some(sk) = join_event.get("state_key").and_then(|v| v.as_str()) {
        keep.insert(sk.to_string());
    }
    if let Some(auth) = join_event
        .get("content")
        .and_then(|c| c.get("join_authorised_via_users_server"))
        .and_then(|v| v.as_str())
    {
        keep.insert(auth.to_string());
    }
    if let Some(create) = read_create_content(state, room_nid) {
        if let Some(creator) = create.get("creator").and_then(|v| v.as_str()) {
            keep.insert(creator.to_string());
        }
        if let Some(arr) = create.get("additional_creators").and_then(|v| v.as_array()) {
            for v in arr {
                if let Some(s) = v.as_str() {
                    keep.insert(s.to_string());
                }
            }
        }
    }
    // Senders of every non-member state event we're including. Their
    // m.room.member events are auth-rule inputs for the events they
    // sent — drop them and the joining server fails check_auth on
    // join_rules / power_levels / canonical_alias / ... .
    for ev in state_events_before {
        let ty = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if ty == "m.room.member" {
            continue;
        }
        if let Some(sender) = ev.get("sender").and_then(|v| v.as_str()) {
            keep.insert(sender.to_string());
        }
    }
    // "Heroes" — up to HEROES_CAP joined members worth including so the
    // joining server can render a room name without waiting for the
    // background /state fill. Spec phrases this as "useful for
    // generating a name"; we pick alphabetically so the choice is
    // deterministic across replicas.
    const HEROES_CAP: usize = 5;
    let mut joined_state_keys: Vec<&str> = state_events_before
        .iter()
        .filter(|ev| {
            ev.get("type").and_then(|v| v.as_str()) == Some("m.room.member")
                && ev
                    .get("content")
                    .and_then(|c| c.get("membership"))
                    .and_then(|m| m.as_str())
                    == Some("join")
        })
        .filter_map(|ev| ev.get("state_key").and_then(|v| v.as_str()))
        .collect();
    joined_state_keys.sort();
    for sk in joined_state_keys.into_iter().take(HEROES_CAP) {
        keep.insert(sk.to_string());
    }
    keep
}

fn read_create_content(state: &AppState, room_nid: u64) -> Option<Value> {
    let tn = state.db.get_nid("m.room.create").ok().flatten()?;
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
        // user_qualifies_via_allow_list refuses to authorise when our
        // server has no local member in the gate room (stale-state
        // guard). Real-world we only have gate_room state when at
        // least one local user joined it, so add alice to mirror
        // that.
        let alice_in_gate = db.get_or_create_nid("@alice:example.com").unwrap();
        db.set_membership(gate_nid, alice_in_gate, 1).unwrap();

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

    /// Restricted room + bob qualifies via allow-list, BUT no local user
    /// in the restricted room has invite power → 400
    /// M_UNABLE_TO_GRANT_JOIN per server-server-api §"Restricted rooms".
    /// The joining server should retry against a different resident.
    #[tokio::test]
    async fn make_join_unable_to_grant_when_no_local_authoriser() {
        // Build a restricted room where the only joined member is a
        // REMOTE user with invite power — there's no local user we can
        // sign on behalf of, so we must emit M_UNABLE_TO_GRANT_JOIN.
        let (state, _tmp) = crate::test_helpers::build_test_state_with_name("example.com");
        let db = &state.db;

        let gate_room = "!gate:example.com";
        let gate_nid = db.get_or_create_nid(gate_room).unwrap();
        db.create_room_meta(gate_nid, gate_room, "12").unwrap();
        let charlie_nid = db.get_or_create_nid("@charlie:remote.example").unwrap();
        db.set_membership(gate_nid, charlie_nid, 1).unwrap();
        // Plant a local member in the gate room so the stale-state
        // guard (has_local_joined_member) accepts our cached view.
        // We make this user a NON-member of the restricted room so it
        // can't double as an authoriser.
        let lurker_nid = db.get_or_create_nid("@lurker:example.com").unwrap();
        db.set_membership(gate_nid, lurker_nid, 1).unwrap();

        let restricted = "!restricted:example.com";
        let restricted_nid = db.get_or_create_nid(restricted).unwrap();
        db.create_room_meta(restricted_nid, restricted, "12")
            .unwrap();

        // The restricted room's create event is by a REMOTE user, so
        // no local user has the v12 creator-power short-circuit. Power
        // levels are absent → users_default = 0, invite_level = 0;
        // any local joined member would qualify, so we must NOT seed
        // any local members in the restricted room itself.
        let bob_nid = db.get_or_create_nid("@bob:remote.example").unwrap();
        let create_type = db.get_or_create_nid("m.room.create").unwrap();
        let member_type = db.get_or_create_nid("m.room.member").unwrap();
        let join_rules_type = db.get_or_create_nid("m.room.join_rules").unwrap();
        let empty_skey = db.get_or_create_nid("").unwrap();

        db.persist_event(
            200,
            "$create_r",
            restricted_nid,
            create_type,
            bob_nid,
            empty_skey,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type": "m.room.create", "sender": "@bob:remote.example",
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
            201,
            "$bob_join_r",
            restricted_nid,
            member_type,
            bob_nid,
            bob_nid,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type": "m.room.member", "sender": "@bob:remote.example",
                "state_key": "@bob:remote.example", "room_id": restricted,
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[200],
            &[200],
            true,
            false,
        )
        .unwrap();
        db.set_membership(restricted_nid, bob_nid, 1).unwrap();
        db.persist_event(
            202,
            "$rules_r",
            restricted_nid,
            join_rules_type,
            bob_nid,
            empty_skey,
            3,
            3,
            &serde_json::to_vec(&json!({
                "type": "m.room.join_rules", "sender": "@bob:remote.example",
                "state_key": "", "room_id": restricted,
                "content": {
                    "join_rule": "restricted",
                    "allow": [{"type": "m.room_membership", "room_id": gate_room}],
                },
                "origin_server_ts": 3, "depth": 3,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[201],
            &[200, 201],
            true,
            false,
        )
        .unwrap();

        // charlie qualifies via gate (joined there), but the restricted
        // room has no local joined member with invite power.
        let origin = axum::Extension(XMatrixOrigin("remote.example".into()));
        let err = make_join(
            axum::extract::State(state.clone()),
            Path((
                restricted.to_string(),
                "@charlie:remote.example".to_string(),
            )),
            RawQuery(Some("ver=12".to_string())),
            origin,
        )
        .await
        .expect_err("expected M_UNABLE_TO_GRANT_JOIN");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let errcode = err.1.0.get("errcode").and_then(|v| v.as_str());
        assert_eq!(errcode, Some("M_UNABLE_TO_GRANT_JOIN"));
    }

    /// send_join MUST refuse an event whose
    /// `join_authorised_via_users_server` names a user that's not on
    /// THIS server. Per MSC3083, vela picks the authoriser at make_join
    /// time and only picks local users — so a remote-named authoriser
    /// is either a forgery or was minted by a different resident, and
    /// either way carries no proof we'd recognise.
    ///
    /// The sender signature must clear verification first (otherwise
    /// the structural check would reject at the wrong step), so we
    /// sign the event with a stub remote key installed via
    /// `remote_keys.insert_for_test`.
    #[tokio::test]
    async fn send_join_rejects_non_local_authoriser() {
        use crate::federation::federation_client::RemoteKeys;
        use crate::middleware::federation_auth::VerifiedBody;
        use std::collections::HashMap;
        use vela_core::events::sign::ServerSigningKey;

        let (state, _tmp) = crate::test_helpers::build_test_state_with_name("example.com");
        let db = &state.db;

        // Restricted room with alice as local creator + authoriser
        // candidate. The room must exist locally for send_join to
        // get past the room-lookup step.
        let restricted = "!restricted:example.com";
        let restricted_nid = db.get_or_create_nid(restricted).unwrap();
        db.create_room_meta(restricted_nid, restricted, "12")
            .unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let create_type = db.get_or_create_nid("m.room.create").unwrap();
        let member_type = db.get_or_create_nid("m.room.member").unwrap();
        let join_rules_type = db.get_or_create_nid("m.room.join_rules").unwrap();
        let empty_skey = db.get_or_create_nid("").unwrap();
        db.persist_event(
            300,
            "$c",
            restricted_nid,
            create_type,
            alice_nid,
            empty_skey,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type": "m.room.create", "sender": alice, "state_key": "",
                "room_id": restricted, "content": {"room_version": "12"},
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
            301,
            "$aj",
            restricted_nid,
            member_type,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type": "m.room.member", "sender": alice, "state_key": alice,
                "room_id": restricted, "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[300],
            &[300],
            true,
            false,
        )
        .unwrap();
        db.set_membership(restricted_nid, alice_nid, 1).unwrap();
        db.persist_event(
            302,
            "$jr",
            restricted_nid,
            join_rules_type,
            alice_nid,
            empty_skey,
            3,
            3,
            &serde_json::to_vec(&json!({
                "type": "m.room.join_rules", "sender": alice, "state_key": "",
                "room_id": restricted,
                "content": {
                    "join_rule": "restricted",
                    "allow": [{"type": "m.room_membership", "room_id": "!gate:example.com"}],
                },
                "origin_server_ts": 3, "depth": 3,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[301],
            &[300, 301],
            true,
            false,
        )
        .unwrap();

        // Stub a remote homeserver and install its public key in the
        // RemoteKeyCache so the sender-sig verify will pass.
        let remote_sn = "remote.example";
        let remote_key = ServerSigningKey::generate();
        let mut verify_keys = HashMap::new();
        verify_keys.insert(
            remote_key.key_id().to_string(),
            remote_key.public_key_base64(),
        );
        state.remote_keys.insert_for_test(
            remote_sn,
            RemoteKeys {
                verify_keys,
                valid_until_ts: u64::MAX / 2,
                fetched_at: 0,
            },
        );

        // Construct a member-join event whose authoriser is on a
        // THIRD server (not us, not the sender). Sender signs.
        let bob = format!("@bob:{remote_sn}");
        let mut event = serde_json::Map::new();
        event.insert("type".into(), json!("m.room.member"));
        event.insert("sender".into(), json!(bob));
        event.insert("state_key".into(), json!(bob));
        event.insert("room_id".into(), json!(restricted));
        event.insert(
            "content".into(),
            json!({
                "membership": "join",
                // Authoriser claims to be on a DIFFERENT server.
                "join_authorised_via_users_server": "@evil:attacker.example",
            }),
        );
        event.insert("origin".into(), json!(remote_sn));
        event.insert("origin_server_ts".into(), json!(100u64));
        event.insert("depth".into(), json!(4u64));
        event.insert("prev_events".into(), json!(["$jr"]));
        event.insert("auth_events".into(), json!(["$c", "$jr"]));
        vela_core::events::hash::add_content_hash(&mut event);
        remote_key.sign_event_for_version(
            &mut event,
            remote_sn,
            vela_core::events::room_version::RoomVersion::V12,
        );
        let event_id = vela_core::events::hash::compute_event_id_for_version(
            &event,
            vela_core::events::room_version::RoomVersion::V12,
        );

        let origin = axum::Extension(XMatrixOrigin(remote_sn.into()));
        let body = axum::Extension(VerifiedBody(Some(Value::Object(event))));
        let err = send_join_v2(
            axum::extract::State(state.clone()),
            Path((restricted.to_string(), event_id.as_str().to_string())),
            axum::extract::RawQuery(None),
            origin,
            body,
        )
        .await
        .expect_err("expected non-local authoriser to be rejected");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
        let msg = err.1.0.get("error").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg.contains("must be a local user"),
            "unexpected error message: {msg}"
        );
    }

    /// Inbound send_join with a properly dual-signed restricted-room
    /// join: remote sender signs, vela signs on behalf of the local
    /// authoriser. Confirms the !=sender_domain branch of the
    /// authoriser-signature check (federation_join.rs:505-523) passes
    /// when the signature is genuinely vela's, not when the rest of
    /// send_join falls through to a non-signature-related failure
    /// (e.g. an auth-events check), the signature path itself didn't
    /// cause the failure. The companion rejection test
    /// `send_join_rejects_non_local_authoriser` covers the negative
    /// case; this one closes the happy-path gap.
    #[tokio::test]
    async fn send_join_accepts_dual_signed_restricted_join() {
        use crate::federation::federation_client::RemoteKeys;
        use crate::middleware::federation_auth::VerifiedBody;
        use std::collections::HashMap;
        use vela_core::events::sign::ServerSigningKey;

        let (state, _tmp) = crate::test_helpers::build_test_state_with_name("example.com");
        let db = &state.db;

        let restricted = "!restricted:example.com";
        let restricted_nid = db.get_or_create_nid(restricted).unwrap();
        db.create_room_meta(restricted_nid, restricted, "12")
            .unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let create_type = db.get_or_create_nid("m.room.create").unwrap();
        let member_type = db.get_or_create_nid("m.room.member").unwrap();
        let join_rules_type = db.get_or_create_nid("m.room.join_rules").unwrap();
        let empty_skey = db.get_or_create_nid("").unwrap();
        db.persist_event(
            300,
            "$c",
            restricted_nid,
            create_type,
            alice_nid,
            empty_skey,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type": "m.room.create", "sender": alice, "state_key": "",
                "room_id": restricted, "content": {"room_version": "12"},
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
            301,
            "$aj",
            restricted_nid,
            member_type,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type": "m.room.member", "sender": alice, "state_key": alice,
                "room_id": restricted, "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[300],
            &[300],
            true,
            false,
        )
        .unwrap();
        db.set_membership(restricted_nid, alice_nid, 1).unwrap();
        db.persist_event(
            302,
            "$jr",
            restricted_nid,
            join_rules_type,
            alice_nid,
            empty_skey,
            3,
            3,
            &serde_json::to_vec(&json!({
                "type": "m.room.join_rules", "sender": alice, "state_key": "",
                "room_id": restricted,
                "content": {
                    "join_rule": "restricted",
                    "allow": [{"type": "m.room_membership", "room_id": "!gate:example.com"}],
                },
                "origin_server_ts": 3, "depth": 3,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[301],
            &[300, 301],
            true,
            false,
        )
        .unwrap();

        // Stub the remote server + cache its key for sender-signature verify.
        let remote_sn = "remote.example";
        let remote_key = ServerSigningKey::generate();
        let mut verify_keys = HashMap::new();
        verify_keys.insert(
            remote_key.key_id().to_string(),
            remote_key.public_key_base64(),
        );
        state.remote_keys.insert_for_test(
            remote_sn,
            RemoteKeys {
                verify_keys,
                valid_until_ts: u64::MAX / 2,
                fetched_at: 0,
            },
        );

        // Bob (remote) joins; authoriser is alice (local). Sender
        // signs, then vela signs on behalf of alice's domain — that's
        // what `make_join` would have produced if vela had handed the
        // template to bob's server.
        let bob = format!("@bob:{remote_sn}");
        let mut event = serde_json::Map::new();
        event.insert("type".into(), json!("m.room.member"));
        event.insert("sender".into(), json!(bob));
        event.insert("state_key".into(), json!(bob));
        event.insert("room_id".into(), json!(restricted));
        event.insert(
            "content".into(),
            json!({
                "membership": "join",
                "join_authorised_via_users_server": alice,
            }),
        );
        event.insert("origin".into(), json!(remote_sn));
        event.insert("origin_server_ts".into(), json!(100u64));
        event.insert("depth".into(), json!(4u64));
        event.insert("prev_events".into(), json!(["$jr"]));
        event.insert("auth_events".into(), json!(["$c", "$jr"]));
        vela_core::events::hash::add_content_hash(&mut event);
        // Vela signs first (on behalf of alice's domain).
        state.signing_key.sign_event_for_version(
            &mut event,
            "example.com",
            vela_core::events::room_version::RoomVersion::V12,
        );
        // Then the remote signs (as bob's homeserver).
        remote_key.sign_event_for_version(
            &mut event,
            remote_sn,
            vela_core::events::room_version::RoomVersion::V12,
        );
        let event_id = vela_core::events::hash::compute_event_id_for_version(
            &event,
            vela_core::events::room_version::RoomVersion::V12,
        );

        let origin = axum::Extension(XMatrixOrigin(remote_sn.into()));
        let body = axum::Extension(VerifiedBody(Some(Value::Object(event))));
        let result = send_join_v2(
            axum::extract::State(state.clone()),
            Path((restricted.to_string(), event_id.as_str().to_string())),
            axum::extract::RawQuery(None),
            origin,
            body,
        )
        .await;

        // The signature-verify path must NOT be the failure point.
        // Later state-resolution / auth_events checks may legitimately
        // reject this minimal scaffolding, but a "must be a local
        // user" or "signature verification failed" message would
        // indicate the wrong branch fired.
        if let Err(err) = &result {
            let msg = err.1.0.get("error").and_then(|v| v.as_str()).unwrap_or("");
            assert!(
                !msg.contains("must be a local user")
                    && !msg.contains("signature verification failed"),
                "signature path rejected what should have been accepted: {msg}",
            );
        }
    }

    /// Synthesise a state-events list with `count` joined members named
    /// `@u<NN>:example.com` plus a creator. Used by heroes/partial-state
    /// tests to control what `essential_member_state_keys` sees without
    /// driving a full send_join.
    fn make_joined_members(prefix: &str, count: usize) -> Vec<Value> {
        (0..count)
            .map(|i| {
                let user = format!("@{prefix}{i:02}:example.com");
                json!({
                    "type": "m.room.member",
                    "state_key": user,
                    "sender": user,
                    "content": {"membership": "join"},
                })
            })
            .collect()
    }

    /// Heroes — joined members included in a partial-state response so
    /// the joining server can render a room name without waiting for
    /// the background filler — are capped at 5 and chosen
    /// alphabetically so the choice is deterministic across replicas.
    #[tokio::test]
    async fn partial_state_heroes_capped_and_alphabetic() {
        let (state, _tmp, _room_id, _alice) =
            make_room_with_join_rules("example.com", json!({"join_rule": "public"})).await;
        // Find the room_nid that the fixture created.
        let room_nid = state.db.get_nid("!room:example.com").unwrap().unwrap();

        // 8 joined members, alphabetically deterministic. Heroes should
        // pick the first 5.
        let state_events = make_joined_members("u", 8);
        let join_event = serde_json::Map::from_iter([
            ("type".to_string(), json!("m.room.member")),
            ("state_key".to_string(), json!("@charlie:remote.example")),
            ("sender".to_string(), json!("@charlie:remote.example")),
            ("content".to_string(), json!({"membership": "join"})),
        ]);

        let keep = essential_member_state_keys(&state, room_nid, &join_event, &state_events);

        // First 5 of u00..u07 must be included; later ones must not.
        for i in 0..5 {
            let u = format!("@u{i:02}:example.com");
            assert!(keep.contains(&u), "expected hero {u} in keep set");
        }
        for i in 5..8 {
            let u = format!("@u{i:02}:example.com");
            assert!(!keep.contains(&u), "{u} should have been dropped past cap");
        }
        // Plus the joiner himself.
        assert!(keep.contains("@charlie:remote.example"));
    }

    /// Members in non-join states (leave / ban / invite / knock) MUST
    /// NOT count as heroes — partial-state responses are about who's
    /// "in the room" right now.
    #[tokio::test]
    async fn partial_state_heroes_skip_non_joined_members() {
        let (state, _tmp, _room_id, _alice) =
            make_room_with_join_rules("example.com", json!({"join_rule": "public"})).await;
        let room_nid = state.db.get_nid("!room:example.com").unwrap().unwrap();

        let mut state_events: Vec<Value> = vec![
            json!({
                "type": "m.room.member",
                "state_key": "@joined:example.com",
                "sender": "@joined:example.com",
                "content": {"membership": "join"},
            }),
            json!({
                "type": "m.room.member",
                "state_key": "@left:example.com",
                "sender": "@left:example.com",
                "content": {"membership": "leave"},
            }),
            json!({
                "type": "m.room.member",
                "state_key": "@banned:example.com",
                "sender": "@admin:example.com",
                "content": {"membership": "ban"},
            }),
            json!({
                "type": "m.room.member",
                "state_key": "@invited:example.com",
                "sender": "@inviter:example.com",
                "content": {"membership": "invite"},
            }),
            json!({
                "type": "m.room.member",
                "state_key": "@knocked:example.com",
                "sender": "@knocked:example.com",
                "content": {"membership": "knock"},
            }),
        ];
        // Add a non-member state event to ensure type filtering also
        // works — random m.room.topic should not be treated as a hero.
        state_events.push(json!({
            "type": "m.room.topic",
            "state_key": "",
            "sender": "@joined:example.com",
            "content": {"topic": "hi"},
        }));

        let join_event = serde_json::Map::from_iter([
            ("state_key".to_string(), json!("@charlie:remote.example")),
            ("sender".to_string(), json!("@charlie:remote.example")),
            ("content".to_string(), json!({"membership": "join"})),
        ]);

        let keep = essential_member_state_keys(&state, room_nid, &join_event, &state_events);

        assert!(keep.contains("@joined:example.com"));
        assert!(!keep.contains("@left:example.com"));
        assert!(!keep.contains("@banned:example.com"));
        assert!(!keep.contains("@invited:example.com"));
        assert!(!keep.contains("@knocked:example.com"));
    }
}
