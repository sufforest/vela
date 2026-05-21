//! Dispatch ephemeral EDUs (typing, receipts) to interested
//! application services. An AS receives an EDU when it has opted in
//! via `receive_ephemeral` AND has namespace interest in the room
//! (or in the EDU's user). Per the AS transaction body, ephemeral
//! events ride alongside PDUs in the `ephemeral` array.
//!
//! Each call here enqueues an ephemeral-only outbox transaction.
//! The worker batches retries and applies the same backoff as PDU
//! delivery — typing storms don't escape the outbox.

use serde_json::{Value, json};

use crate::appservice::interest::{InterestEvent, matching};
use crate::router::AppState;

/// Dispatch one ephemeral EDU to every AS with `receive_ephemeral`
/// and namespace interest in the room. The `room_id` is annotated
/// on the EDU per spec. `sender` (used for interest filtering) is
/// the user the EDU is about: typer for typing, receiver for
/// receipts.
pub fn dispatch_ephemeral_to_room(
    state: &AppState,
    room_id: &str,
    room_nid: u64,
    sender: &str,
    edu: Value,
) {
    let interested = matching(
        &state.appservice_registry,
        &InterestEvent {
            room_id,
            sender,
            state_key: None,
        },
    );
    if interested.is_empty() {
        return;
    }
    // Annotate room_id once; the payload is identical across ASes.
    let mut annotated = edu;
    if let Some(obj) = annotated.as_object_mut() {
        obj.entry("room_id".to_string())
            .or_insert_with(|| Value::String(room_id.to_string()));
    }
    for live in interested {
        if !live.appservice.config.receive_ephemeral {
            continue;
        }
        if let Err(e) = state
            .appservice_outbox
            .enqueue_ephemeral(live.appservice.nid, vec![annotated.clone()])
        {
            tracing::warn!(
                appservice_nid = live.appservice.nid,
                room_nid,
                error = %e,
                "failed to enqueue ephemeral EDU; dropping",
            );
        }
    }
}

/// Build the m.typing EDU envelope from a list of currently-typing
/// user MXIDs. The AS sees the full current set on every transition,
/// matching the shape /sync emits.
pub fn typing_edu(user_ids: Vec<String>) -> Value {
    json!({
        "type": "m.typing",
        "content": { "user_ids": user_ids },
    })
}

/// Build a minimal m.receipt EDU for a single new receipt.
/// `thread_id` is included only when present (unthreaded receipts
/// omit the field entirely).
pub fn receipt_edu(
    event_id: &str,
    receipt_type: &str,
    user_id: &str,
    ts: u64,
    thread_id: Option<&str>,
) -> Value {
    let mut user_entry = serde_json::Map::new();
    user_entry.insert("ts".into(), json!(ts));
    if let Some(tid) = thread_id {
        user_entry.insert("thread_id".into(), json!(tid));
    }
    let mut type_map = serde_json::Map::new();
    type_map.insert(user_id.to_string(), Value::Object(user_entry));
    let mut event_map = serde_json::Map::new();
    event_map.insert(receipt_type.to_string(), Value::Object(type_map));
    let mut content = serde_json::Map::new();
    content.insert(event_id.to_string(), Value::Object(event_map));
    json!({
        "type": "m.receipt",
        "content": content,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appservice::namespace::{Namespace, NamespaceScope};
    use crate::appservice::{AppService, AppServiceConfig, hash_token};
    use crate::test_helpers::build_test_state;

    fn seed_as(state: &AppState, id: &str, receive_ephemeral: bool, room_regex: &str) -> u64 {
        let asv = AppService {
            nid: 0,
            id: id.into(),
            config: AppServiceConfig {
                url: "http://localhost".into(),
                hs_token_hash: hash_token(&format!("hs-{id}")),
                as_token_hash: hash_token(&format!("as-{id}")),
                sender_localpart: format!("_{id}_bot"),
                receive_ephemeral,
            },
            namespaces: vec![Namespace {
                scope: NamespaceScope::Room,
                regex: room_regex.into(),
                exclusive: false,
            }],
            enabled: true,
            owner_nid: None,
            created_at_ms: 0,
        };
        state.appservice_registry.register(asv).unwrap().nid
    }

    #[test]
    fn dispatch_enqueues_for_opted_in_as() {
        let (state, _tmp) = build_test_state();
        let nid = seed_as(&state, "br", true, r"^!bridge:.*$");
        dispatch_ephemeral_to_room(
            &state,
            "!bridge:example.com",
            1,
            "@alice:example.com",
            typing_edu(vec!["@alice:example.com".into()]),
        );
        let peeked = state
            .db
            .peek_appservice_outbox(nid)
            .unwrap()
            .expect("outbox row enqueued");
        let ephemeral = peeked.1["ephemeral"].as_array().expect("ephemeral array");
        assert_eq!(ephemeral.len(), 1);
        assert_eq!(ephemeral[0]["type"], "m.typing");
        assert_eq!(ephemeral[0]["room_id"], "!bridge:example.com");
    }

    #[test]
    fn dispatch_skips_as_without_receive_ephemeral() {
        let (state, _tmp) = build_test_state();
        let nid = seed_as(&state, "br", false, r"^!bridge:.*$");
        dispatch_ephemeral_to_room(
            &state,
            "!bridge:example.com",
            1,
            "@alice:example.com",
            typing_edu(vec!["@alice:example.com".into()]),
        );
        assert!(
            state.db.peek_appservice_outbox(nid).unwrap().is_none(),
            "AS without receive_ephemeral must NOT receive EDU",
        );
    }

    #[test]
    fn dispatch_skips_as_without_room_interest() {
        let (state, _tmp) = build_test_state();
        let nid = seed_as(&state, "br", true, r"^!other:.*$");
        dispatch_ephemeral_to_room(
            &state,
            "!bridge:example.com",
            1,
            "@alice:example.com",
            typing_edu(vec!["@alice:example.com".into()]),
        );
        assert!(
            state.db.peek_appservice_outbox(nid).unwrap().is_none(),
            "AS without room interest must NOT receive EDU",
        );
    }

    #[test]
    fn typing_edu_shape() {
        let edu = typing_edu(vec!["@alice:e".into(), "@bob:e".into()]);
        assert_eq!(edu["type"], "m.typing");
        let users = edu["content"]["user_ids"].as_array().unwrap();
        assert_eq!(users.len(), 2);
    }

    #[test]
    fn receipt_edu_shape_threaded() {
        let edu = receipt_edu("$evt", "m.read", "@alice:e", 1234, Some("main"));
        assert_eq!(edu["type"], "m.receipt");
        let entry = &edu["content"]["$evt"]["m.read"]["@alice:e"];
        assert_eq!(entry["ts"], 1234);
        assert_eq!(entry["thread_id"], "main");
    }

    #[test]
    fn receipt_edu_shape_unthreaded_omits_thread_id() {
        let edu = receipt_edu("$evt", "m.read", "@alice:e", 1234, None);
        let entry = &edu["content"]["$evt"]["m.read"]["@alice:e"];
        assert!(entry.get("thread_id").is_none());
    }
}
