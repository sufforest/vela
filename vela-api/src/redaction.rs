//! `PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}`
//!
//! Builds an `m.room.redaction` PDU and — if the sender is allowed to redact
//! the target under room v3+ handling rules — writes a redaction marker so
//! the target event renders redacted to clients.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use vela_core::auth_rules::can_apply_redaction;
use vela_core::canonical::canonical_json_object;
use vela_core::error::VelaError;
use vela_core::events::builder::{build_event, select_auth_events};
use vela_core::events::pdu::Pdu;
use vela_core::events::room_version::RoomVersion;
use vela_core::identifiers::{EventId, Nid, RoomId};

use crate::auth_check::authorise_event;
use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::rooms::get_or_create_signing_key;
use crate::router::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct RedactBody {
    #[serde(default)]
    pub reason: Option<String>,
}

/// PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}
pub async fn redact_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((room_id_str, target_event_id, txn_id)): Path<(String, String, String)>,
    Json(body): Json<RedactBody>,
) -> Result<Json<Value>, ApiError> {
    let room_id =
        RoomId::parse(&room_id_str).map_err(|e| ApiError(VelaError::BadJson(e.to_string())))?;

    let room_nid = state
        .db
        .get_nid(room_id.as_str())
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("room not found".into())))?;

    // Sender must be joined to send any room event.
    let membership = state
        .db
        .get_membership(room_nid, user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if membership != Some(1) {
        return Err(VelaError::Forbidden("not a member of this room".into()).into());
    }

    let lock = state
        .room_locks
        .entry(Nid(room_nid))
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    // Idempotency (inside lock). Scope keyed by (room, target event)
    // so the same txn_id used to redact a different event in the
    // same room — or the same event in a different room — is treated
    // as a fresh request.
    let txn_scope = format!("redact/{}/{}", room_id_str, target_event_id);
    if let Some(existing_event_id) = state
        .db
        .get_transaction(user.user_nid, &user.device_id, &txn_scope, &txn_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        return Ok(Json(json!({"event_id": existing_event_id})));
    }

    // Target may or may not exist locally — the spec explicitly allows
    // redacting an event we don't have (e.g. it lived only on a remote
    // server before we federated in, or we missed it during a network
    // partition). When we DO have it, validate that it belongs to this
    // room and use its sender for the same-server permission check.
    // When we don't, fall back to the redact-power-level check alone:
    // the redaction is sent over federation and the receiver applies
    // its own permission gate per spec §Handling redactions.
    let target = load_target(&state, &target_event_id).ok();
    if let Some((_, target_pdu)) = &target
        && target_pdu.room_id != room_id.as_str()
    {
        return Err(VelaError::NotFound("event not found in this room".into()).into());
    }

    // Per v3-handling-redactions: sender either shares a server with the
    // target event's sender or has power >= redact level. Reject early so
    // the client sees a clear 403 rather than a silent no-op.
    let create_pdu = load_state_pdu(&state, room_nid, "m.room.create", "")
        .ok_or_else(|| ApiError(VelaError::NotFound("room has no create event".into())))?;
    let pl_pdu = load_state_pdu(&state, room_nid, "m.room.power_levels", "");
    let state_fn = |t: &str, sk: &str| -> Option<&Pdu> {
        match (t, sk) {
            ("m.room.create", "") => Some(&create_pdu),
            ("m.room.power_levels", "") => pl_pdu.as_ref(),
            _ => None,
        }
    };
    let permission_ok = match &target {
        Some((_, target_pdu)) => {
            can_apply_redaction(&user.user_id, &target_pdu.sender, &state_fn, &create_pdu)
        }
        // Target unknown — sender must have the redact power level
        // (we can't compare servers without the target's sender).
        None => vela_core::auth_rules::has_redact_power(&user.user_id, &state_fn, &create_pdu),
    };
    if !permission_ok {
        return Err(
            VelaError::Forbidden("insufficient power level to redact this event".into()).into(),
        );
    }

    // Build the redaction event content. v11+ carries `redacts` in content.
    let mut content = Map::new();
    content.insert("redacts".to_string(), json!(target_event_id));
    if let Some(reason) = body.reason
        && !reason.is_empty()
    {
        content.insert("reason".to_string(), json!(reason));
    }
    let content = Value::Object(content);

    let signing_key = get_or_create_signing_key(&state)?;
    let server_name = &state.config.server_name;
    let room_version = RoomVersion::V12;
    let event_type = "m.room.redaction";

    let extremity_nids = state
        .db
        .get_extremities(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut max_depth: u64 = 0;
    for &enid in &extremity_nids {
        if let Some(d) = state
            .db
            .get_event_depth(enid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            && d > max_depth
        {
            max_depth = d;
        }
    }

    let prev_events = resolve_nids_to_event_ids(&state, &extremity_nids)?;
    let depth = max_depth + 1;

    let auth_events = {
        let lookup = |etype: &str, skey: &str| -> Option<EventId> {
            let type_nid = state.db.get_nid(etype).ok()??;
            let skey_nid = state.db.get_nid(skey).ok()??;
            let event_nid = state
                .db
                .get_state_event_nid(room_nid, type_nid, skey_nid)
                .ok()??;
            resolve_nids_to_event_ids(&state, &[event_nid])
                .ok()?
                .into_iter()
                .next()
        };
        select_auth_events(
            event_type,
            &user.user_id,
            None,
            Some(&content),
            room_version,
            &lookup,
        )
    };

    let (event, event_id) = build_event(
        event_type,
        None,
        content,
        &user.user_id,
        Some(&room_id),
        &prev_events,
        &auth_events,
        depth,
        &signing_key,
        server_name,
        room_version,
    );

    // Standard PDU auth (rule 8 + rule 11). Separate from the apply check above.
    authorise_event(&state, room_nid, &event_id, &event, None)?;

    let event_nid = state.db.next_nid();
    let json_bytes = canonical_json_object(&event);
    let type_nid = state
        .db
        .get_or_create_nid(event_type)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let prev_nids: Vec<u64> = extremity_nids;
    let auth_nids = resolve_event_ids_to_nids(&state, &auth_events)?;

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
            0,
            origin_ts,
            depth,
            &json_bytes,
            &prev_nids,
            &auth_nids,
            false,
            false,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Apply the redaction locally if we have the target — marks the
    // event so subsequent reads strip content. If we don't have the
    // target (federated room where the event preceded our join), the
    // redaction is still federated to remote servers; they apply
    // their own copy.
    if let Some((target_nid, _)) = &target {
        state
            .db
            .mark_redacted_by(*target_nid, event_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    }

    state.federation_sender.broadcast(room_nid, event_nid);

    state
        .db
        .set_transaction(
            user.user_nid,
            &user.device_id,
            &txn_scope,
            &txn_id,
            event_id.as_str(),
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .update_room_bump(room_nid, origin_ts, event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    if let Some(sender) = state.room_senders.get(&Nid(room_nid)) {
        let _ = sender.send(stream_pos);
    }

    Ok(Json(json!({"event_id": event_id.as_str()})))
}

fn load_target(state: &AppState, event_id: &str) -> Result<(u64, Pdu), ApiError> {
    let nid = state
        .db
        .get_event_nid_by_id(event_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;
    let (_header, json_bytes) = state
        .db
        .get_event(nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("event not found".into())))?;
    let obj: Map<String, Value> = serde_json::from_slice::<Value>(&json_bytes)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .ok_or_else(|| ApiError(VelaError::Store("stored event is not a JSON object".into())))?;
    let pdu = Pdu::from_json(event_id.to_string(), &obj)
        .ok_or_else(|| ApiError(VelaError::Store("stored event failed PDU parse".into())))?;
    Ok((nid, pdu))
}

fn load_state_pdu(
    state: &AppState,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Option<Pdu> {
    let type_nid = state.db.get_nid(event_type).ok().flatten()?;
    let skey_nid = state.db.get_nid(state_key).ok().flatten()?;
    let event_nid = state
        .db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .ok()
        .flatten()?;
    let (_header, bytes) = state.db.get_event(event_nid).ok().flatten()?;
    let event_id = state.db.get_event_id_by_nid(event_nid).ok().flatten()?;
    let obj: Map<String, Value> = serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .as_object()?
        .clone();
    Pdu::from_json(event_id, &obj)
}

fn resolve_nids_to_event_ids(state: &AppState, nids: &[u64]) -> Result<Vec<EventId>, ApiError> {
    let mut ids = Vec::new();
    for &nid in nids {
        if let Some(id_str) = state
            .db
            .get_event_id_by_nid(nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            ids.push(
                EventId::parse(&id_str).unwrap_or_else(|_| EventId::from_reference_hash("unknown")),
            );
        }
    }
    Ok(ids)
}

fn resolve_event_ids_to_nids(state: &AppState, ids: &[EventId]) -> Result<Vec<u64>, ApiError> {
    let mut nids = Vec::new();
    for id in ids {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::load_client_event;
    use crate::test_helpers::build_test_state;
    use axum::extract::{Path, State};
    use serde_json::json;

    /// Build a minimal single-room v12 setup with alice (creator) joined,
    /// bob @ other.com joined, a power_levels with default redact level 50,
    /// and one message from alice. Returns (state, room_nid, message_nid,
    /// message_event_id).
    async fn setup_room() -> (AppState, tempfile::TempDir, u64, u64, String) {
        let (state, tmp) = build_test_state();
        let db = &state.db;

        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let type_pl = db.get_or_create_nid("m.room.power_levels").unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();

        let alice = "@alice:example.com";
        let bob = "@bob:other.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let bob_nid = db.get_or_create_nid(bob).unwrap();
        let alice_skey = alice_nid;
        let bob_skey = bob_nid;

        let room_id = "!room12";
        let create_eid = "$room12";
        let room_nid = db.get_or_create_nid(room_id).unwrap();

        let create_json = json!({
            "type": "m.room.create",
            "sender": alice,
            "state_key": "",
            "room_id": room_id,
            "content": {"room_version": "12"},
            "origin_server_ts": 1,
            "depth": 1,
            "prev_events": [],
            "auth_events": [],
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
            "sender": alice,
            "state_key": alice,
            "room_id": room_id,
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
            "sender": alice,
            "state_key": "",
            "room_id": room_id,
            "content": {"users": {}, "users_default": 0, "redact": 50},
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

        let bob_join_eid = "$bob_join";
        let bob_join_json = json!({
            "type": "m.room.member",
            "sender": bob,
            "state_key": bob,
            "room_id": room_id,
            "content": {"membership": "join"},
            "origin_server_ts": 4, "depth": 4,
            "prev_events": [pl_eid], "auth_events": [create_eid, pl_eid],
        });
        db.persist_event(
            103,
            bob_join_eid,
            room_nid,
            type_member,
            bob_nid,
            bob_skey,
            4,
            4,
            &serde_json::to_vec(&bob_join_json).unwrap(),
            &[102],
            &[100, 102],
            true,
            false,
        )
        .unwrap();

        let msg_eid = "$msg_alice";
        let msg_json = json!({
            "type": "m.room.message",
            "sender": alice,
            "room_id": room_id,
            "content": {"msgtype": "m.text", "body": "hello"},
            "origin_server_ts": 5, "depth": 5,
            "prev_events": [bob_join_eid], "auth_events": [pl_eid, alice_join_eid],
        });
        db.persist_event(
            104,
            msg_eid,
            room_nid,
            type_msg,
            alice_nid,
            0,
            5,
            5,
            &serde_json::to_vec(&msg_json).unwrap(),
            &[103],
            &[102, 101],
            false,
            false,
        )
        .unwrap();

        db.set_membership(room_nid, alice_nid, 1).unwrap();
        db.set_membership(room_nid, bob_nid, 1).unwrap();

        // Mint access tokens so AuthenticatedUser resolution would work if
        // called; but in these tests we construct AuthenticatedUser directly.
        let _ = tmp; // keep alive

        (state, tmp, room_nid, 104, msg_eid.to_string())
    }

    fn alice_user(state: &AppState) -> AuthenticatedUser {
        let user_nid = state.db.get_nid("@alice:example.com").unwrap().unwrap();
        AuthenticatedUser {
            user_nid,
            user_id: "@alice:example.com".into(),
            device_id: "ALICE_DEV".into(),
        }
    }

    fn bob_user(state: &AppState) -> AuthenticatedUser {
        let user_nid = state.db.get_nid("@bob:other.com").unwrap().unwrap();
        AuthenticatedUser {
            user_nid,
            user_id: "@bob:other.com".into(),
            device_id: "BOB_DEV".into(),
        }
    }

    #[tokio::test]
    async fn alice_redacts_own_message_succeeds_and_renders_redacted() {
        let (state, _tmp, room_nid, msg_nid, msg_eid) = setup_room().await;

        let res = redact_event(
            State(state.clone()),
            alice_user(&state),
            Path(("!room12".into(), msg_eid.clone(), "txn1".into())),
            Json(RedactBody {
                reason: Some("bad".into()),
            }),
        )
        .await
        .expect("redact succeeds");

        let redactor_id = res
            .0
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        assert!(redactor_id.starts_with('$'));

        // Marker is recorded.
        let marker = state.db.get_redacted_by(msg_nid).unwrap();
        assert!(marker.is_some(), "redaction marker should be written");

        // Render of the target event drops content and adds redacted_because.
        let rendered = load_client_event(&state, msg_nid, "!room12")
            .unwrap()
            .expect("event renders");
        let content = rendered.get("content").unwrap();
        assert_eq!(content, &json!({}), "content stripped to {{}}");
        let redacted_because = rendered
            .pointer("/unsigned/redacted_because")
            .expect("unsigned.redacted_because present");
        assert_eq!(
            redacted_because.get("event_id").and_then(|v| v.as_str()),
            Some(redactor_id.as_str())
        );
        assert_eq!(
            redacted_because
                .pointer("/content/redacts")
                .and_then(|v| v.as_str()),
            Some(msg_eid.as_str())
        );

        // Idempotency: same txn returns the same event_id.
        let res2 = redact_event(
            State(state.clone()),
            alice_user(&state),
            Path(("!room12".into(), msg_eid.clone(), "txn1".into())),
            Json(RedactBody::default()),
        )
        .await
        .unwrap();
        assert_eq!(
            res2.0.get("event_id").and_then(|v| v.as_str()),
            Some(redactor_id.as_str())
        );

        let _ = room_nid;
    }

    #[tokio::test]
    async fn cross_server_user_without_power_gets_forbidden() {
        let (state, _tmp, _room_nid, msg_nid, msg_eid) = setup_room().await;

        let err = redact_event(
            State(state.clone()),
            bob_user(&state),
            Path(("!room12".into(), msg_eid, "txn_bob".into())),
            Json(RedactBody::default()),
        )
        .await
        .expect_err("bob lacks power and is on another server");

        assert!(
            matches!(err, ApiError(VelaError::Forbidden(_))),
            "expected Forbidden, got {err:?}"
        );
        // No marker written.
        assert!(state.db.get_redacted_by(msg_nid).unwrap().is_none());
    }

    #[tokio::test]
    async fn cross_server_user_with_redact_power_succeeds() {
        let (state, _tmp, room_nid, msg_nid, msg_eid) = setup_room().await;
        let db = &state.db;

        // Promote bob to power 50 with a new power_levels event.
        let type_pl = db.get_nid("m.room.power_levels").unwrap().unwrap();
        let skey_empty = db.get_nid("").unwrap().unwrap();
        let alice_nid = db.get_nid("@alice:example.com").unwrap().unwrap();
        let pl2_eid = "$pl2";
        let pl2_json = json!({
            "type": "m.room.power_levels",
            "sender": "@alice:example.com",
            "state_key": "",
            "room_id": "!room12",
            "content": {
                "users": {"@bob:other.com": 50},
                "users_default": 0,
                "redact": 50,
            },
            "origin_server_ts": 10, "depth": 10,
            "prev_events": ["$msg_alice"],
            "auth_events": ["$pl", "$alice_join"],
        });
        db.persist_event(
            200,
            pl2_eid,
            room_nid,
            type_pl,
            alice_nid,
            skey_empty,
            10,
            10,
            &serde_json::to_vec(&pl2_json).unwrap(),
            &[104],
            &[102, 101],
            true,
            false,
        )
        .unwrap();

        let res = redact_event(
            State(state.clone()),
            bob_user(&state),
            Path(("!room12".into(), msg_eid, "txn_bob2".into())),
            Json(RedactBody::default()),
        )
        .await
        .expect("bob at power 50 can redact");
        assert!(res.0.get("event_id").is_some());
        assert!(state.db.get_redacted_by(msg_nid).unwrap().is_some());
    }

    #[tokio::test]
    async fn non_member_gets_forbidden() {
        let (state, _tmp, _room_nid, _msg_nid, msg_eid) = setup_room().await;
        let charlie_nid = state.db.get_or_create_nid("@charlie:example.com").unwrap();

        let err = redact_event(
            State(state.clone()),
            AuthenticatedUser {
                user_nid: charlie_nid,
                user_id: "@charlie:example.com".into(),
                device_id: "CHARLIE".into(),
            },
            Path(("!room12".into(), msg_eid, "txn_c".into())),
            Json(RedactBody::default()),
        )
        .await
        .expect_err("non-member cannot redact");
        match err {
            ApiError(VelaError::Forbidden(reason)) => {
                assert!(reason.contains("not a member"), "reason: {reason}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    /// Spec `federation/v1/redaction` allows redacting an event we
    /// don't have locally — e.g. a federated event that preceded our
    /// join. The redaction is built and broadcast over federation;
    /// receivers apply their local copy. Used by Complement
    /// `TestFederationRedactSendsWithoutEvent`.
    #[tokio::test]
    async fn missing_target_event_redacts_when_user_has_redact_power() {
        let (state, _tmp, _room_nid, _msg_nid, _msg_eid) = setup_room().await;

        let result = redact_event(
            State(state.clone()),
            alice_user(&state),
            Path(("!room12".into(), "$does_not_exist".into(), "txn_m".into())),
            Json(RedactBody::default()),
        )
        .await
        .expect("redaction with missing target should succeed when caller has power");
        // Returned event_id should be the redaction we just emitted.
        assert!(
            result.0.get("event_id").and_then(|v| v.as_str()).is_some(),
            "expected event_id in response: {:?}",
            result.0
        );
    }
}
