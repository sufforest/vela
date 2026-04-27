use std::collections::HashMap;

use axum::Json;
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
                    let all_device_keys = state
                        .db
                        .get_all_device_keys(target_user_nid)
                        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                    for (did, _) in &all_device_keys {
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
                for (device_id, content) in devices {
                    // Wildcard fan-out doesn't apply for remote — we
                    // don't know the peer's device list. Caller must
                    // address specific devices.
                    if device_id == "*" {
                        continue;
                    }
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
