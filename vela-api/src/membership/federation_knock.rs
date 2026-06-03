//! Inbound federation `make_knock` / `send_knock`.
//!
//! Spec:
//! - `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}?ver=X`
//! - `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}`
//!
//! Mirrors `federation_join.rs` but emits / accepts a `membership=knock`
//! event. Only valid when the room's `join_rule` is `knock` or
//! `knock_restricted` — otherwise the knocking server gets `M_FORBIDDEN`.

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
use vela_core::events::hash::compute_content_hash;
use vela_core::events::pdu::Pdu;
use vela_core::events::view::EventView;
use vela_core::federation::keys::{decode_public_key, verify_event_signature};
use vela_core::identifiers::{EventId, Nid};

use crate::federation::federation_state::{ensure_create_in_state, load_pdu_by_event_id};
use crate::membership::federation_join::parse_supported_versions_pub as parse_supported_versions;
use crate::middleware::federation_auth::{VerifiedBody, XMatrixOrigin};
use crate::router::AppState;

/// GET /_matrix/federation/v1/make_knock/{roomId}/{userId}?ver=X
pub async fn make_knock(
    State(state): State<AppState>,
    Path((room_id, user_id)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    debug!(%room_id, %user_id, origin = %origin.0, "make_knock");

    let supported = parse_supported_versions(raw_query.as_deref());
    let room_nid_for_version = state
        .db
        .get_nid(&room_id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", e.as_ref()))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "M_NOT_FOUND", "room not found"))?;
    let our_version_typed = state
        .db
        .get_room_version_typed(room_nid_for_version)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "M_UNKNOWN", e.as_ref()))?;
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

    match user_id.split_once(':') {
        Some((_, domain)) if domain == origin.0 => {}
        _ => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                "userId does not belong to origin",
            ));
        }
    }

    let room_nid = state.db.get_nid(&room_id).map_err(db_err)?.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room not known locally",
        )
    })?;

    // MSC3902 / MSC3706: refuse make_knock during partial state. Same
    // rationale as make_join — we lack the full state needed to
    // authorise the knock against join_rules / server_acl.
    if let Ok((true, _)) = state.db.get_partial_state_info(room_nid) {
        return Err(err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room is currently in partial state",
        ));
    }

    // m.room.server_acl gate.
    crate::federation::server_acl::deny_if_blocked(&state, room_nid, &origin.0)?;

    // Knock requires `join_rule: knock` or `knock_restricted`. Other rules
    // (public, invite, restricted) reject — knocking on a public room makes
    // no sense and on an invite-only room is forbidden by spec.
    let join_rule = read_join_rules_content(&state, room_nid)
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(|r| r.as_str())
        .unwrap_or("invite")
        .to_string();
    if !matches!(join_rule.as_str(), "knock" | "knock_restricted") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "room does not allow knocking",
        ));
    }

    let user_nid = state.db.get_or_create_nid(&user_id).map_err(db_err)?;
    if let Some(3) = state.db.get_membership(room_nid, user_nid).ok().flatten() {
        return Err(err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "user is banned"));
    }

    let room_version = state.db.get_room_version_typed(room_nid).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "M_UNKNOWN",
            &format!("db: {e}"),
        )
    })?;
    let content_val = content::member_content_knock(None);
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

    Ok(Json(json!({
        "room_version": room_version.as_str(),
        "event": template,
    })))
}

/// PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}
pub async fn send_knock_v1(
    State(state): State<AppState>,
    Path((room_id, event_id)): Path<(String, String)>,
    axum::extract::Extension(origin): axum::extract::Extension<XMatrixOrigin>,
    axum::extract::Extension(VerifiedBody(body)): axum::extract::Extension<VerifiedBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    debug!(%room_id, %event_id, origin = %origin.0, "send_knock v1");

    // MSC3902 / MSC3706: refuse during partial state BEFORE body
    // validation so the test can rely on the partial-state error
    // surfacing even when the knock event payload itself is
    // malformed (the spec test exercises both rejection paths
    // through the same code path).
    if let Ok(Some(room_nid)) = state.db.get_nid(&room_id)
        && let Ok((true, _)) = state.db.get_partial_state_info(room_nid)
    {
        return Err(err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room is currently in partial state",
        ));
    }

    let event_json = body.ok_or_else(|| {
        err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "empty send_knock body",
        )
    })?;
    let event_obj = event_json
        .as_object()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "event not an object"))?;

    if event_obj.event_type() != Some("m.room.member") {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "send_knock event must be m.room.member",
        ));
    }
    if event_obj.membership() != Some("knock") {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "send_knock membership must be knock",
        ));
    }
    let sender = event_obj
        .sender()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing sender"))?;
    let state_key = event_obj
        .state_key()
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "missing state_key"))?;
    if sender != state_key {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "sender must equal state_key",
        ));
    }
    let sender_domain = sender.split_once(':').map(|(_, d)| d).unwrap_or("");
    if sender_domain != origin.0 {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "sender domain does not match origin",
        ));
    }

    let room_nid = state.db.get_nid(&room_id).map_err(db_err)?.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "M_NOT_FOUND",
            "room not known locally",
        )
    })?;

    // m.room.server_acl gate.
    crate::federation::server_acl::deny_if_blocked(&state, room_nid, &origin.0)?;

    // Same join_rule gate as make_knock — defence in depth in case the room
    // changed rules between the two calls.
    let join_rule = read_join_rules_content(&state, room_nid)
        .as_ref()
        .and_then(|c| c.get("join_rule"))
        .and_then(|r| r.as_str())
        .unwrap_or("invite")
        .to_string();
    if !matches!(join_rule.as_str(), "knock" | "knock_restricted") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "room no longer allows knocking",
        ));
    }

    // Verify signature.
    let keys = state
        .remote_keys
        .get_or_fetch(sender_domain)
        .await
        .map_err(|e| {
            err(
                StatusCode::FORBIDDEN,
                "M_FORBIDDEN",
                &format!("key fetch: {e}"),
            )
        })?;
    let sigs = event_obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .and_then(|s| s.get(sender_domain))
        .and_then(|v| v.as_object())
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "M_FORBIDDEN", "no signatures"))?;
    let send_knock_room_version = state
        .db
        .get_room_version_typed(room_nid)
        .unwrap_or(vela_core::events::room_version::RoomVersion::V12);
    let mut verified = false;
    for (key_id, _) in sigs {
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
            send_knock_room_version,
        )
        .is_ok()
        {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            "signature verification failed",
        ));
    }

    // event_id in URL must match the computed reference hash. Use
    // the room's actual version: redaction shape differs across
    // versions, and pre-v11 events would mismatch under the V12
    // default.
    let computed_event_id =
        vela_core::events::hash::compute_event_id_for_version(event_obj, send_knock_room_version);
    if computed_event_id.as_str() != event_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "M_BAD_JSON",
            "URL event_id does not match the event's reference hash",
        ));
    }

    // Hash check; on mismatch, redact.
    let declared = event_obj
        .get("hashes")
        .and_then(|h| h.get("sha256"))
        .and_then(|v| v.as_str());
    let computed = compute_content_hash(event_obj);
    let to_persist: Map<String, Value> = match declared {
        Some(d) if d == computed => event_obj.clone(),
        _ => vela_core::events::redact::redact_event(event_obj),
    };
    let pdu = Pdu::from_json(event_id.clone(), &to_persist)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "M_BAD_JSON", "malformed PDU"))?;

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Idempotent re-knock: if the user is already in knock state on us
    // (the resident), accept without persisting a new event. Synapse
    // does the same thing — surfacing every repeat knock as a fresh
    // state event clobbers `content.reason` for everyone in the room
    // and breaks TestKnocking's "Users in the room see a user's
    // membership update when they knock" #01 sub-test, which expects
    // the *first* knock's reason to remain visible.
    let sender_nid_check = state.db.get_or_create_nid(sender).map_err(db_err)?;
    if state
        .db
        .get_membership(room_nid, sender_nid_check)
        .ok()
        .flatten()
        == Some(4)
    {
        let knock_room_state = build_knock_room_state(&state, room_nid).map_err(db_err)?;
        return Ok(Json(json!({"knock_room_state": knock_room_state})));
    }

    // Auth check via the rule engine.
    let mut auth_state = std::collections::HashMap::new();
    for aev in &pdu.auth_events {
        if let Some(p) = load_pdu_by_event_id(&state.db, aev)
            && let Some(sk) = p.state_key.as_deref()
        {
            auth_state.insert((p.event_type.clone(), sk.to_string()), p);
        }
    }
    ensure_create_in_state(&state.db, room_nid, &mut auth_state);
    let auth_fn = |t: &str, sk: &str| auth_state.get(&(t.to_string(), sk.to_string()));
    if let Err(AuthError::Rejected(reason)) = check_auth(&pdu, &auth_fn) {
        warn!(%event_id, %reason, "send_knock rejected");
        return Err(err(
            StatusCode::FORBIDDEN,
            "M_FORBIDDEN",
            &format!("auth check failed: {reason}"),
        ));
    }

    // Persist.
    let type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(db_err)?;
    let sender_nid = state.db.get_or_create_nid(sender).map_err(db_err)?;
    let state_key_nid = state.db.get_or_create_nid(state_key).map_err(db_err)?;
    let mut prev_nids: Vec<u64> = Vec::new();
    for pid in &pdu.prev_events {
        if let Ok(Some(n)) = state.db.get_event_nid_by_id(pid) {
            prev_nids.push(n);
        }
    }
    let mut auth_nids: Vec<u64> = Vec::new();
    for aid in &pdu.auth_events {
        if let Ok(Some(n)) = state.db.get_event_nid_by_id(aid) {
            auth_nids.push(n);
        }
    }
    let event_nid = state.db.next_nid().map_err(db_err)?;
    let json_bytes = vela_core::canonical::canonical_json_object(&to_persist);
    let stream_pos = state
        .db
        .persist_event(
            event_nid,
            &event_id,
            room_nid,
            type_nid,
            sender_nid,
            state_key_nid,
            pdu.origin_server_ts,
            pdu.depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            true,
            false,
        )
        .map_err(db_err)?;

    state
        .db
        .promote_state_event(room_nid, event_nid, type_nid, state_key_nid)
        .map_err(db_err)?;

    // 4 = knock in our membership index.
    crate::router::apply_membership_change(&state, room_nid, sender_nid, 4, stream_pos);
    state.federation_sender.broadcast(room_nid, event_nid);

    // Build the stripped state response. Spec: subset of state events that
    // let the knocking server render the room while the knock waits.
    let knock_room_state = build_knock_room_state(&state, room_nid).map_err(db_err)?;

    Ok(Json(json!({"knock_room_state": knock_room_state})))
}

/// Spec-defined types that go into knock_room_state. The knocking server
/// uses these to render room chrome (name, avatar, topic) while waiting
/// to be admitted. We also include the knocker's own member event.
const STRIPPED_TYPES: &[&str] = &[
    "m.room.create",
    "m.room.name",
    "m.room.avatar",
    "m.room.canonical_alias",
    "m.room.join_rules",
    "m.room.encryption",
    "m.room.member",
];

fn build_knock_room_state(state: &AppState, room_nid: u64) -> Result<Vec<Value>, rocksdb::Error> {
    let nids = state.db.get_all_state_event_nids(room_nid)?;
    let mut out = Vec::new();
    for nid in nids {
        let Some((_h, bytes)) = state.db.get_event(nid)? else {
            continue;
        };
        let Ok(v): Result<Value, _> = serde_json::from_slice(&bytes) else {
            continue;
        };
        let etype = v.event_type().unwrap_or("");
        if !STRIPPED_TYPES.contains(&etype) {
            continue;
        }
        out.push(json!({
            "type": v.get("type"),
            "state_key": v.get("state_key"),
            "sender": v.get("sender"),
            "content": v.get("content"),
        }));
    }
    Ok(out)
}

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

fn err(code: StatusCode, errcode: &str, msg: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({"errcode": errcode, "error": msg})))
}

fn db_err<E: std::fmt::Display>(e: E) -> (StatusCode, Json<Value>) {
    err(
        StatusCode::INTERNAL_SERVER_ERROR,
        "M_UNKNOWN",
        &format!("db: {e}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state_with_name;

    /// Build a v12 room with alice joined and the given join_rules content.
    fn setup_room(server: &str, jr_content: Value) -> (AppState, tempfile::TempDir, String) {
        let (state, tmp) = build_test_state_with_name(server);
        let db = &state.db;
        let room_id = format!("!room:{server}");
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        db.create_room_meta(room_nid, &room_id, "12").unwrap();
        let alice = format!("@alice:{server}");
        let alice_nid = db.get_or_create_nid(&alice).unwrap();
        let create_t = db.get_or_create_nid("m.room.create").unwrap();
        let member_t = db.get_or_create_nid("m.room.member").unwrap();
        let jr_t = db.get_or_create_nid("m.room.join_rules").unwrap();
        let empty_skey = db.get_or_create_nid("").unwrap();
        db.persist_event(
            10,
            "$create",
            room_nid,
            create_t,
            alice_nid,
            empty_skey,
            1,
            1,
            &serde_json::to_vec(&json!({
                "type":"m.room.create","sender":alice,"state_key":"","room_id":room_id,
                "content":{"room_version":"12"},"origin_server_ts":1,"depth":1,
                "prev_events":[],"auth_events":[]
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
            "$alice_join",
            room_nid,
            member_t,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&json!({
                "type":"m.room.member","sender":alice,"state_key":alice,"room_id":room_id,
                "content":{"membership":"join"},"origin_server_ts":2,"depth":2,
                "prev_events":[],"auth_events":[]
            }))
            .unwrap(),
            &[10],
            &[10],
            true,
            false,
        )
        .unwrap();
        db.set_membership(room_nid, alice_nid, 1).unwrap();
        db.persist_event(
            12,
            "$rules",
            room_nid,
            jr_t,
            alice_nid,
            empty_skey,
            3,
            3,
            &serde_json::to_vec(&json!({
                "type":"m.room.join_rules","sender":alice,"state_key":"","room_id":room_id,
                "content":jr_content,"origin_server_ts":3,"depth":3,
                "prev_events":[],"auth_events":[]
            }))
            .unwrap(),
            &[11],
            &[10, 11],
            true,
            false,
        )
        .unwrap();
        (state, tmp, room_id)
    }

    #[tokio::test]
    async fn make_knock_returns_template_for_knock_room() {
        let (state, _tmp, room_id) = setup_room("example.com", json!({"join_rule": "knock"}));
        let resp = make_knock(
            axum::extract::State(state.clone()),
            Path((room_id.clone(), "@bob:remote.example".into())),
            RawQuery(Some("ver=12".into())),
            axum::Extension(XMatrixOrigin("remote.example".into())),
        )
        .await
        .expect("ok");
        assert_eq!(resp.0["room_version"], "12");
        let template = resp.0["event"].as_object().unwrap();
        assert_eq!(template["type"], "m.room.member");
        assert_eq!(template["state_key"], "@bob:remote.example");
        assert_eq!(template["content"]["membership"], "knock");
    }

    #[tokio::test]
    async fn make_knock_rejects_public_room() {
        let (state, _tmp, room_id) = setup_room("example.com", json!({"join_rule": "public"}));
        let err_ = make_knock(
            axum::extract::State(state.clone()),
            Path((room_id, "@bob:remote.example".into())),
            RawQuery(Some("ver=12".into())),
            axum::Extension(XMatrixOrigin("remote.example".into())),
        )
        .await
        .expect_err("public room should reject knock");
        assert_eq!(err_.0, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn make_knock_rejects_origin_mismatch() {
        let (state, _tmp, room_id) = setup_room("example.com", json!({"join_rule": "knock"}));
        // user_id says remote.example but origin says other.example.
        let err_ = make_knock(
            axum::extract::State(state.clone()),
            Path((room_id, "@bob:remote.example".into())),
            RawQuery(Some("ver=12".into())),
            axum::Extension(XMatrixOrigin("other.example".into())),
        )
        .await
        .expect_err("origin mismatch should reject");
        assert_eq!(err_.0, StatusCode::FORBIDDEN);
    }

    /// server_acl with `deny: ["banned.example"]` must 403 a knock from
    /// banned.example before the join-rule check fires. Confirms the
    /// gate is wired into make_knock (and, by symmetry, the other
    /// federation handlers it covers).
    #[tokio::test]
    async fn make_knock_denies_banned_origin_via_server_acl() {
        let (state, _tmp, room_id) = setup_room("example.com", json!({"join_rule": "knock"}));
        let db = &state.db;
        let room_nid = db.get_nid(&room_id).unwrap().unwrap();
        let alice_nid = db.get_nid("@alice:example.com").unwrap().unwrap();
        let acl_t = db.get_or_create_nid("m.room.server_acl").unwrap();
        let empty_skey = db.get_or_create_nid("").unwrap();
        db.persist_event(
            13,
            "$acl",
            room_nid,
            acl_t,
            alice_nid,
            empty_skey,
            4,
            4,
            &serde_json::to_vec(&json!({
                "type":"m.room.server_acl","sender":"@alice:example.com","state_key":"",
                "room_id":room_id,
                "content":{"allow":["*"],"deny":["banned.example"]},
                "origin_server_ts":4,"depth":4,"prev_events":[],"auth_events":[]
            }))
            .unwrap(),
            &[12],
            &[10, 11],
            true,
            false,
        )
        .unwrap();

        let err_ = make_knock(
            axum::extract::State(state.clone()),
            Path((room_id, "@mallory:banned.example".into())),
            RawQuery(Some("ver=12".into())),
            axum::Extension(XMatrixOrigin("banned.example".into())),
        )
        .await
        .expect_err("banned origin must be denied");
        assert_eq!(err_.0, StatusCode::FORBIDDEN);
        let body = err_.1.0.to_string();
        assert!(body.contains("server_acl"), "errcode body: {body}");
    }

    #[tokio::test]
    async fn build_knock_room_state_filters_to_stripped_types() {
        let (state, _tmp, room_id) = setup_room("example.com", json!({"join_rule": "knock"}));
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();
        let stripped = build_knock_room_state(&state, room_nid).unwrap();
        let types: std::collections::HashSet<&str> = stripped
            .iter()
            .filter_map(|v| v.get("type").and_then(|t| t.as_str()))
            .collect();
        assert!(
            types.contains("m.room.create"),
            "create must be in stripped state"
        );
        assert!(
            types.contains("m.room.join_rules"),
            "join_rules must be in stripped state"
        );
        assert!(
            types.contains("m.room.member"),
            "member must be in stripped state"
        );
        // Unrelated types not in our test setup; but be sure no invalid leakage.
        for t in &types {
            assert!(STRIPPED_TYPES.contains(t), "unexpected stripped type: {t}");
        }
    }
}
