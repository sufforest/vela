//! Outbound push dispatch.
//!
//! Spec: `push-gateway-api/#post_matrixpushv1notify`.
//!
//! When a local user sends a message, we enumerate joined room members
//! (excluding the sender), look up each recipient's registered pushers,
//! and POST a notification to each pusher's configured URL.
//!
//! Dispatch runs in a background task so the send path never blocks on
//! push gateway latency. Failures are logged and dropped — retries and
//! backoff are out of scope for now (push is best-effort by design).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tracing::warn;

use crate::router::AppState;

/// Spawn a task that dispatches push notifications for `event_nid` to all
/// non-sender local members of `room_nid`. Non-blocking; returns immediately.
pub fn dispatch_for_event(
    state: &AppState,
    room_nid: u64,
    room_id: String,
    event_id: String,
    event_nid: u64,
    sender_nid: u64,
) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) =
            dispatch_inner(&state, room_nid, &room_id, &event_id, event_nid, sender_nid).await
        {
            warn!(error = %e, "push dispatch failed");
        }
    });
}

async fn dispatch_inner(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    event_id: &str,
    event_nid: u64,
    sender_nid: u64,
) -> Result<(), String> {
    // Need the full event to put into the push body.
    let (header, body) = state
        .db
        .get_event(event_nid)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("event {event_nid} not found"))?;

    let event: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let event_type = event
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("m.room.message")
        .to_string();
    let sender = state
        .db
        .resolve_nid(header.sender_nid)
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    let content = event.get("content").cloned().unwrap_or_else(|| json!({}));

    let members = state
        .db
        .get_room_members(room_nid)
        .map_err(|e| e.to_string())?;

    // Build the notification template once; per-recipient we just attach
    // their `devices` list.
    let notification_base = json!({
        "event_id": event_id,
        "room_id": room_id,
        "type": event_type,
        "sender": sender,
        "content": content,
    });

    let client = push_http_client();

    let room_member_count = members.len() as u64;

    for member_nid in members {
        if member_nid == sender_nid {
            continue;
        }
        let pushers = match state.db.list_pushers(member_nid) {
            Ok(p) => p,
            Err(e) => {
                warn!(user_nid = member_nid, error = %e, "list_pushers failed");
                continue;
            }
        };
        if pushers.is_empty() {
            continue;
        }

        // Resolve this recipient's rule set + display name, then ask the
        // evaluator whether the event should notify. This is where
        // per-room mute and suppress_notices actually kick in.
        let rules = match crate::pushrules::load_user_rules(state, member_nid) {
            Ok(r) => r,
            Err(e) => {
                warn!(user_nid = member_nid, error = ?e.0, "load_user_rules failed");
                continue;
            }
        };
        let recipient_user_id = state
            .db
            .resolve_nid(member_nid)
            .ok()
            .flatten()
            .unwrap_or_default();
        let display_name = recipient_display_name(state, member_nid);
        let ctx = vela_core::push_rules::RoomContext {
            joined_member_count: room_member_count,
            recipient_display_name: display_name,
            recipient_user_id: recipient_user_id.clone(),
        };
        let action = vela_core::push_rules::evaluate(&event, &rules, &ctx);
        if !action.notify {
            continue;
        }

        for pusher in pushers {
            let Some(url) = pusher
                .get("data")
                .and_then(|d| d.get("url"))
                .and_then(|u| u.as_str())
            else {
                continue;
            };
            let app_id = pusher.get("app_id").and_then(|v| v.as_str()).unwrap_or("");
            let pushkey = pusher.get("pushkey").and_then(|v| v.as_str()).unwrap_or("");
            let device_data = pusher.get("data").cloned().unwrap_or_else(|| json!({}));

            // Bubble the evaluator's tweaks (sound, highlight) into the
            // per-device entry so push gateways can style the notification.
            let mut tweaks = serde_json::Map::new();
            for (k, v) in &action.tweaks {
                tweaks.insert(k.clone(), v.clone());
            }
            let mut notification = notification_base.clone();
            if let Some(obj) = notification.as_object_mut() {
                obj.insert(
                    "devices".into(),
                    json!([{
                        "app_id": app_id,
                        "pushkey": pushkey,
                        "data": device_data,
                        "tweaks": tweaks,
                    }]),
                );
            }
            let body = json!({"notification": notification});
            let url = url.to_string();
            let client = client.clone();
            // One request per pusher, fire-and-forget. Spawning keeps slow
            // gateways from serialising delivery across recipients.
            tokio::spawn(async move {
                match client.post(&url).json(&body).send().await {
                    Ok(resp) if resp.status().is_success() => {}
                    Ok(resp) => {
                        warn!(status = %resp.status(), url = %url, "push gateway returned non-2xx")
                    }
                    Err(e) => warn!(error = %e, url = %url, "push gateway request failed"),
                }
            });
        }
    }

    Ok(())
}

/// Look up the recipient's display name (stored on the user record so
/// `contains_display_name` mentions work). None when no display name set.
fn recipient_display_name(state: &AppState, user_nid: u64) -> Option<String> {
    let user = state.db.get_user(user_nid).ok().flatten()?;
    user.get("displayname")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn push_http_client() -> Arc<reqwest::Client> {
    // Cheap to clone, but build once per dispatch so request-level config
    // lives alongside the dispatch. Longer-lived reuse would require stashing
    // a client on AppState — not worth it for the current call volume.
    Arc::new(
        reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client"),
    )
}
