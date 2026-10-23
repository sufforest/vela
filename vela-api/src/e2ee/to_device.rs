use std::collections::HashMap;

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

#[derive(Deserialize)]
pub struct SendToDeviceRequest {
    pub messages: HashMap<String, HashMap<String, Value>>,
}

/// PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}
///
/// Local recipients land in the per-device `to_device_messages` CF
/// for `/sync` to drain. Remote recipients are bundled by destination
/// server into one `m.direct_to_device` EDU per server and queued for
/// the federation sender via `enqueue_to_device_outbound`.
pub async fn send_to_device(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((event_type, _txn_id)): Path<(String, String)>,
    Json(body): Json<SendToDeviceRequest>,
) -> Result<Json<Value>, ApiError> {
    let our_server = state.config.server_name.as_str();

    // Bundle remote recipients by destination server. The spec's
    // m.direct_to_device EDU `messages` field is `{user_id → {device_id → content}}`,
    // so we group by server-extracted-from-user_id and emit one EDU
    // per server.
    let mut remote_by_server: HashMap<String, serde_json::Map<String, Value>> = HashMap::new();
    // Track local recipients whose /sync needs to wake. Without this,
    // their long-poll sits until timeout — Element's E2EE verification
    // flow appears to hang because m.key.verification.* events ride
    // to-device and don't surface for up to 30 s.
    let mut local_recipients: std::collections::HashSet<u64> = std::collections::HashSet::new();

    for (target_user_id, devices) in &body.messages {
        let target_server = match target_user_id.split_once(':') {
            Some((_, d)) => d,
            None => continue, // malformed user_id
        };

        if target_server == our_server {
            // --- Local: write to per-device queue ---
            let target_user_nid = match state
                .db
                .get_nid(target_user_id)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                Some(nid) => nid,
                None => continue,
            };
            for (device_id, content) in devices {
                if device_id == "*" {
                    // All registered devices, not only those with E2EE
                    // keys uploaded: a freshly logged-in client has a
                    // device but no keys yet and must still get its
                    // to-device traffic (same rule as the inbound path).
                    let registered = state
                        .db
                        .list_devices(target_user_nid)
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                    for dev in &registered {
                        let Some(did) = dev.get("device_id").and_then(|v| v.as_str()) else {
                            continue;
                        };
                        state
                            .db
                            .queue_to_device(
                                target_user_nid,
                                did,
                                &event_type,
                                &user.user_id,
                                content,
                            )
                            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                    }
                } else {
                    state
                        .db
                        .queue_to_device(
                            target_user_nid,
                            device_id,
                            &event_type,
                            &user.user_id,
                            content,
                        )
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                }
            }
            local_recipients.insert(target_user_nid);
        } else {
            // --- Remote: accumulate into per-server EDU bundle ---
            let bundle = remote_by_server
                .entry(target_server.to_string())
                .or_default();
            // Inner shape: messages[<user_id>] = {<device_id>: <content>}.
            let user_entry = bundle
                .entry(target_user_id.clone())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(obj) = user_entry.as_object_mut() {
                // `*` travels as-is: the EDU schema lets a device id be
                // `*` for all of the user's devices, and the receiving
                // server is the one that knows that list (we expand it
                // the same way on the inbound side).
                for (device_id, content) in devices {
                    obj.insert(device_id.clone(), content.clone());
                }
            }
        }
    }

    // Write one EDU per destination + wake the corresponding senders.
    for (target_server, messages) in remote_by_server {
        if messages.is_empty() {
            continue;
        }
        let content = json!({
            "sender": user.user_id,
            "type": event_type,
            "message_id": Uuid::new_v4().simple().to_string(),
            "messages": Value::Object(messages),
        });
        if let Err(e) = state
            .db
            .enqueue_to_device_outbound(&target_server, &content)
        {
            tracing::warn!(target = %target_server, error = %e, "to-device enqueue failed");
            continue;
        }
        // Wake just this destination — fast-path the common case
        // where the federation sender is idle waiting on Notify.
        state.federation_sender.notify_destination(&target_server);
    }

    // Wake any local recipient's /sync long-poll so their client picks
    // up the to-device events on the very next round-trip. Without
    // this the recipient's session sits idle until something else
    // wakes them (a room event, force-refresh, or the 30 s timeout)
    // — which makes Element's verification + E2EE setup feel broken.
    for recipient_nid in local_recipients {
        crate::router::notify_user(&state, recipient_nid);
    }

    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state_with_name;

    async fn send(state: &AppState, messages: Value) -> Result<Json<Value>, ApiError> {
        let user = AuthenticatedUser {
            user_nid: state.db.get_or_create_nid("@alice:example.com").unwrap(),
            user_id: "@alice:example.com".into(),
            device_id: "ALICEDEV".into(),
            appservice_nid: None,
        };
        let body: SendToDeviceRequest =
            serde_json::from_value(json!({"messages": messages})).unwrap();
        send_to_device(
            State(state.clone()),
            user,
            Path(("m.room_key_request".to_string(), "txn1".to_string())),
            Json(body),
        )
        .await
    }

    /// A local wildcard reaches every registered device, including one
    /// that has not uploaded E2EE keys yet.
    #[tokio::test]
    async fn local_wildcard_reaches_devices_without_keys() {
        let (state, _tmp) = build_test_state_with_name("example.com");
        let bob_nid = state.db.get_or_create_nid("@bob:example.com").unwrap();
        state.db.create_device(bob_nid, "FRESH").unwrap();
        state.db.create_device(bob_nid, "OLD").unwrap();
        send(
            &state,
            json!({"@bob:example.com": {"*": {"action": "request"}}}),
        )
        .await
        .expect("send_to_device");
        for dev in ["FRESH", "OLD"] {
            let queued = state.db.get_to_device_messages(bob_nid, dev).unwrap();
            assert_eq!(queued.len(), 1, "device {dev} got {}", queued.len());
            assert_eq!(queued[0].1["sender"], "@alice:example.com");
        }
    }

    /// A message to all of a remote user's devices is queued for that
    /// user's server with the `*` device id intact, next to messages
    /// addressed to a named device.
    #[tokio::test]
    async fn wildcard_device_is_forwarded_to_remote_servers() {
        let (state, _tmp) = build_test_state_with_name("example.com");
        send(
            &state,
            json!({
                "@bob:remote.example": {
                    "*": {"action": "request", "n": 1},
                    "BOBDEV": {"action": "request", "n": 2},
                }
            }),
        )
        .await
        .expect("send_to_device");

        let (queued, _) = state
            .db
            .scan_to_device_outbound("remote.example", 0, 10)
            .unwrap();
        assert_eq!(queued.len(), 1, "one EDU per destination: {queued:?}");
        let messages = &queued[0].1["messages"]["@bob:remote.example"];
        assert_eq!(messages["*"]["n"], 1, "wildcard dropped: {messages}");
        assert_eq!(messages["BOBDEV"]["n"], 2);
        assert_eq!(queued[0].1["type"], "m.room_key_request");
        assert_eq!(queued[0].1["sender"], "@alice:example.com");
    }
}
