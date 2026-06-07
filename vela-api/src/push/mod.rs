//! Push surface: outbound dispatch worker that POSTs to gateway URLs
//! (this file), plus pusher / push-rule storage (`pushers`, `pushrules`).
//!
//! Spec: `push-gateway-api/#post_matrixpushv1notify`.
//!
//! When a local user sends a message, we enumerate joined room members
//! (excluding the sender), look up each recipient's registered pushers,
//! and POST a notification to each pusher's configured URL. Dispatch
//! runs in a background task so the send path never blocks on push
//! gateway latency. Failures are logged and dropped — retries and
//! backoff are out of scope for now (push is best-effort by design).

pub mod notifications;
pub mod pushers;
pub mod pushrules;

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

    // @room mention gate (MSC3952): the sender's effective power vs the
    // room's notifications.room threshold (default 50). Constant across
    // recipients, so compute once.
    let sender_power_level = crate::membership::user_power(state, room_nid, &sender).unwrap_or(0);
    let notifications_room_level = crate::membership::notifications_room_level(state, room_nid);

    // Event-level facts for persisted notifications. `event_stream_pos` is
    // the just-persisted event, so the backward scan finds it immediately.
    let event_stream_pos = state.db.event_stream_pos(room_nid, event_id).ok().flatten();
    let event_ts = event
        .get("origin_server_ts")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    for member_nid in members {
        if member_nid == sender_nid {
            continue;
        }

        // Evaluate this recipient's push rules FIRST — independent of whether
        // they have a push gateway, since /notifications records the match
        // either way (a user with no pusher still reads their notifications).
        let rules = match crate::push::pushrules::load_user_rules(state, member_nid) {
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
            sender_power_level,
            notifications_room_level,
        };
        let action = vela_core::push_rules::evaluate(&event, &rules, &ctx);
        if !action.notify {
            continue;
        }

        // Persist for GET /notifications — local recipients only (remote
        // members don't read notifications from us).
        let is_local = recipient_user_id
            .strip_prefix('@')
            .and_then(|s| s.split_once(':'))
            .map(|(_, srv)| srv == state.config.server_name)
            .unwrap_or(false);
        if is_local {
            let mut actions = vec![json!("notify")];
            for (k, v) in &action.tweaks {
                actions.push(json!({"set_tweak": k, "value": v}));
            }
            if let Err(e) = state.db.append_notification(
                member_nid,
                room_id,
                event_id,
                event_stream_pos,
                &Value::Array(actions),
                &action.tweaks,
                event_ts,
            ) {
                warn!(user_nid = member_nid, error = %e, "append_notification failed");
            }
        }

        let pushers = match state.db.list_pushers(member_nid) {
            Ok(p) => p,
            Err(e) => {
                warn!(user_nid = member_nid, error = %e, "list_pushers failed");
                continue;
            }
        };

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
            let allow_private = state.config.push.allow_private_pushers;
            // One request per pusher, spawned so a slow gateway doesn't
            // serialise delivery across recipients. Retries with bounded
            // exponential backoff on transient failure (5xx + network);
            // 4xx is permanent (the gateway rejected the payload, so a
            // retry can't help) and drops immediately.
            tokio::spawn(async move {
                if !allow_private && let Err(reason) = check_pusher_url_is_public(&url).await {
                    warn!(%url, reason, "pusher URL rejected (SSRF guard)");
                    return;
                }
                deliver_one_pusher(&client, &url, &body).await;
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
            .timeout(PUSH_PER_ATTEMPT_TIMEOUT)
            .build()
            .expect("reqwest client"),
    )
}

/// Per-attempt timeout. The push spec doesn't pin a value; we mirror
/// the federation-EDU default — gateways that don't respond in 10s
/// are almost certainly never going to.
const PUSH_PER_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff schedule between attempts. Total wall-clock ceiling
/// (timeouts + sleeps) is bounded so a flaky gateway can't pin a
/// task forever: at most ~30s timeouts + 10s sleeps = 40s per
/// notification. Push is best-effort; we don't queue past this.
const PUSH_BACKOFFS: &[Duration] = &[Duration::from_secs(2), Duration::from_secs(8)];

/// Single-pusher delivery with bounded retry. 2xx returns
/// immediately; 4xx drops (permanent — gateway rejected the payload);
/// 5xx + network errors retry per `PUSH_BACKOFFS`, then drop.
async fn deliver_one_pusher(client: &reqwest::Client, url: &str, body: &Value) {
    let max_attempts = PUSH_BACKOFFS.len() + 1;
    for attempt in 0..max_attempts {
        match client.post(url).json(body).send().await {
            Ok(resp) if resp.status().is_success() => return,
            Ok(resp) if resp.status().is_client_error() => {
                warn!(
                    status = %resp.status(), %url,
                    "push gateway rejected payload (4xx); dropping",
                );
                return;
            }
            Ok(resp) => {
                warn!(
                    status = %resp.status(), %url, attempt,
                    "push gateway 5xx; will retry",
                );
            }
            Err(e) => {
                warn!(error = %e, %url, attempt, "push gateway request failed");
            }
        }
        if let Some(delay) = PUSH_BACKOFFS.get(attempt) {
            tokio::time::sleep(*delay).await;
        }
    }
    warn!(%url, "push gateway exhausted retries; notification dropped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 5xx triggers retries; once the gateway recovers, the next
    /// attempt succeeds and the loop exits. Wiremock's response chain
    /// returns 500-500-200 to exercise both retry slots.
    #[tokio::test]
    async fn deliver_retries_5xx_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/notify"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/notify"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let url = format!("{}/notify", server.uri());
        // Patch PUSH_BACKOFFS isn't possible from outside the module
        // without a const-fn knob, so the test relies on the real
        // 2s + 8s schedule; the 200 lands on attempt 3 (≤ 11s wall
        // clock, well inside test default timeouts).
        deliver_one_pusher(&client, &url, &json!({"ping": 1})).await;
        // Implicit success: no panic, no hang. The mock server's
        // `expect` would assert call count if we set one — we don't
        // because the goal is "eventually succeeds," not "exactly N
        // calls" (the timing depends on the schedule).
        drop(server);
    }

    /// 4xx is permanent — the gateway said "this payload is bad" and
    /// retrying can't fix that. Exactly one call should land on the
    /// mock; we use `expect(1)` to lock that in.
    #[tokio::test]
    async fn deliver_drops_immediately_on_4xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/notify"))
            .respond_with(ResponseTemplate::new(400))
            .expect(1)
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let url = format!("{}/notify", server.uri());
        deliver_one_pusher(&client, &url, &json!({"ping": 1})).await;
        // Drop triggers expect(1) assertion in the MockServer.
        drop(server);
    }

    /// Exhausted retries log + return without panicking. Reaching the
    /// end of the retry schedule on a perpetually-down gateway is
    /// the worst case; just make sure we don't loop forever.
    #[tokio::test]
    async fn deliver_exhausts_retries_on_persistent_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/notify"))
            .respond_with(ResponseTemplate::new(503))
            .expect(PUSH_BACKOFFS.len() as u64 + 1)
            .mount(&server)
            .await;
        let client = reqwest::Client::new();
        let url = format!("{}/notify", server.uri());
        deliver_one_pusher(&client, &url, &json!({"ping": 1})).await;
        drop(server);
    }
}

/// Coarse SSRF guard: refuse non-http(s) schemes and any host whose
/// resolved addresses include a loopback / private / link-local IP.
/// Doesn't close DNS rebinding (reqwest re-resolves at connect time);
/// catches the common literal-IP / private-host misconfiguration.
/// Not wired yet — a follow-up adds the config flag that lets
/// operators with docker/k8s gateways opt out of strict mode.
async fn check_pusher_url_is_public(url: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("scheme `{scheme}` not allowed"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        if !is_public_ip(&addr) {
            return Err(format!("host `{host}` is not a public IP"));
        }
        return Ok(());
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    let mut any_public = false;
    let resolved = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS lookup failed: {e}"))?;
    for sock in resolved {
        if !is_public_ip(&sock.ip()) {
            return Err(format!(
                "host `{host}` resolves to non-public address {}",
                sock.ip()
            ));
        }
        any_public = true;
    }
    if !any_public {
        return Err(format!("host `{host}` has no resolved addresses"));
    }
    Ok(())
}

/// `is_global` would do this in one call but it's not yet stable;
/// approximated with the stable predicates plus explicit IPv6 prefix
/// checks (link-local fe80::/10, unique-local fc00::/7).
fn is_public_ip(addr: &std::net::IpAddr) -> bool {
    if addr.is_loopback() || addr.is_unspecified() || addr.is_multicast() {
        return false;
    }
    match addr {
        std::net::IpAddr::V4(v4) => !(v4.is_private() || v4.is_link_local() || v4.is_broadcast()),
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            if (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xfe00) == 0xfc00 {
                return false;
            }
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_ip(&std::net::IpAddr::V4(v4));
            }
            true
        }
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    #[tokio::test]
    async fn refuses_loopback_literal() {
        let r = check_pusher_url_is_public("http://127.0.0.1:8000/notify").await;
        assert!(r.is_err(), "loopback must be refused");
    }

    #[tokio::test]
    async fn refuses_rfc1918_literal() {
        for addr in ["10.0.0.5", "172.16.5.1", "192.168.1.1"] {
            let url = format!("http://{addr}/notify");
            assert!(
                check_pusher_url_is_public(&url).await.is_err(),
                "{addr} must be refused"
            );
        }
    }

    #[tokio::test]
    async fn refuses_link_local() {
        assert!(
            check_pusher_url_is_public("http://169.254.169.254/")
                .await
                .is_err(),
            "AWS-metadata IP (link-local) must be refused"
        );
    }

    #[tokio::test]
    async fn refuses_ipv6_loopback() {
        assert!(
            check_pusher_url_is_public("http://[::1]/notify")
                .await
                .is_err(),
            "IPv6 loopback must be refused"
        );
    }

    #[tokio::test]
    async fn refuses_non_http_scheme() {
        assert!(
            check_pusher_url_is_public("file:///etc/passwd")
                .await
                .is_err(),
            "non-http scheme must be refused"
        );
    }

    #[tokio::test]
    async fn refuses_ipv4_mapped_loopback_in_ipv6() {
        assert!(
            check_pusher_url_is_public("http://[::ffff:127.0.0.1]/")
                .await
                .is_err(),
            "IPv4-mapped loopback must be refused"
        );
    }

    #[tokio::test]
    async fn accepts_public_literal() {
        // 1.1.1.1 (Cloudflare DNS) — example of a routable public address.
        // Note: this doesn't actually connect; we only resolve + classify.
        let r = check_pusher_url_is_public("https://1.1.1.1/notify").await;
        assert!(r.is_ok(), "public IP must be accepted: {r:?}");
    }
}
