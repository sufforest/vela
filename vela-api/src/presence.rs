//! `/presence/{userId}/status` — user online-ness + status message.
//!
//! Spec: `client-server-api/#presence`.
//!
//! The stored record (`{presence, status_msg?, last_active_ms?}`) is
//! whatever the client last set explicitly. Real "online-ness" decays
//! from that record over time: when `now - last_active_ms` exceeds the
//! configured `idle_after`, effective presence transitions
//! `online → unavailable`; after `offline_after`, to `offline`. The
//! decay is computed on every read (`format_status`) so clients always
//! see the right answer, and a background sweeper (see
//! `presence_sweeper.rs`) persists the transitions and broadcasts the
//! federation EDU so remote peers also see them.
//!
//! Bug history: before this layer existed, presence sat permanently at
//! whatever the client last said. Closing the browser left the user as
//! "online" forever from every other client's perspective.

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::{AppState, PresenceConfig};

#[derive(Debug, Deserialize)]
pub struct PutPresenceBody {
    pub presence: String,
    #[serde(default)]
    pub status_msg: Option<String>,
}

/// PUT /_matrix/client/v3/presence/{userId}/status
pub async fn put_status(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(body): Json<PutPresenceBody>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only set own presence".into()).into());
    }
    let now = now_ms();
    let mut rec = serde_json::Map::new();
    rec.insert("presence".into(), json!(body.presence));
    if let Some(msg) = body.status_msg {
        rec.insert("status_msg".into(), json!(msg));
    }
    rec.insert("last_active_ms".into(), json!(now));
    state
        .db
        .set_local_presence(user.user_nid, &Value::Object(rec))
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Wake federation senders for peers that share a joined room with
    // this user so the m.presence EDU rides out promptly.
    state
        .federation_sender
        .notify_user_subscribers(user.user_nid);
    Ok(Json(json!({})))
}

/// GET /_matrix/client/v3/presence/{userId}/status
pub async fn get_status(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let target_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("user not found".into())))?;
    let rec = state
        .db
        .get_presence(target_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_else(|| json!({"presence": "offline"}));
    Ok(Json(format_status(&rec, &state.config.presence)))
}

/// Compute the effective presence value right now, given the stored
/// value and the activity timestamp.
///
/// Decay only fires on records whose stored value is `"online"`. An
/// `"unavailable"` or `"offline"` value the client supplied
/// explicitly is honoured as-is — we do not push such users to
/// `online` regardless of activity. (The activity timestamp ticks on
/// every /sync, including ones with `set_presence=offline`, which is
/// the documented way for clients to remain reachable without showing
/// as available.)
///
/// `last_active_ms = None` means "we have no activity record at all"
/// — typically a record set via PUT /presence that never went through
/// /sync. We treat that as no-decay, returning the stored value.
pub fn effective_presence(
    stored: &str,
    last_active_ms: Option<u64>,
    cfg: &PresenceConfig,
    now: u64,
) -> &'static str {
    let stored_decayable = stored == "online";
    if !stored_decayable {
        return match stored {
            "unavailable" => "unavailable",
            "offline" => "offline",
            _ => "offline",
        };
    }
    let Some(last) = last_active_ms else {
        return "online";
    };
    let age = now.saturating_sub(last);
    if age >= cfg.offline_after_ms {
        "offline"
    } else if age >= cfg.idle_after_ms {
        "unavailable"
    } else {
        "online"
    }
}

/// Shape presence as clients expect: `{presence, last_active_ago?,
/// currently_active?, status_msg?}`. The `presence` field is the
/// **effective** value (post-decay), not the raw stored value.
pub fn format_status(rec: &Value, cfg: &PresenceConfig) -> Value {
    let stored = rec
        .get("presence")
        .and_then(|v| v.as_str())
        .unwrap_or("offline");
    let last_active_ms = rec.get("last_active_ms").and_then(|v| v.as_u64());
    let now = now_ms();
    let effective = effective_presence(stored, last_active_ms, cfg, now);

    let mut out = serde_json::Map::new();
    out.insert("presence".into(), json!(effective));
    if let Some(msg) = rec.get("status_msg").and_then(|v| v.as_str())
        && !msg.is_empty()
    {
        out.insert("status_msg".into(), json!(msg));
    }
    if let Some(last) = last_active_ms {
        let age = now.saturating_sub(last);
        out.insert("last_active_ago".into(), json!(age));
        // currently_active: spec field — true only when the user is
        // both online (effective) AND has activity within the idle
        // window. Mirrors what Synapse emits.
        let active = effective == "online" && age < cfg.idle_after_ms;
        out.insert("currently_active".into(), json!(active));
    }
    Value::Object(out)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PresenceConfig {
        PresenceConfig::default()
    }

    #[test]
    fn effective_online_within_idle_window_stays_online() {
        let now = 10_000_000;
        // 1 second ago — well within the 5-minute idle window.
        let last = now - 1_000;
        assert_eq!(
            effective_presence("online", Some(last), &cfg(), now),
            "online"
        );
    }

    #[test]
    fn effective_online_past_idle_decays_to_unavailable() {
        let now = 10_000_000;
        // 6 minutes ago — past `idle_after_ms = 5min`, before
        // `offline_after_ms = 30min`.
        let last = now - 6 * 60 * 1000;
        assert_eq!(
            effective_presence("online", Some(last), &cfg(), now),
            "unavailable"
        );
    }

    #[test]
    fn effective_online_past_offline_decays_to_offline() {
        let now = 10_000_000;
        // 35 minutes ago — past `offline_after_ms = 30min`.
        let last = now - 35 * 60 * 1000;
        assert_eq!(
            effective_presence("online", Some(last), &cfg(), now),
            "offline"
        );
    }

    #[test]
    fn effective_explicit_unavailable_does_not_promote_to_online() {
        let now = 10_000_000;
        let last = now - 1_000;
        // Client explicitly set unavailable a moment ago — stays
        // unavailable regardless of activity recency.
        assert_eq!(
            effective_presence("unavailable", Some(last), &cfg(), now),
            "unavailable"
        );
    }

    #[test]
    fn effective_explicit_offline_stays_offline() {
        let now = 10_000_000;
        let last = now - 1_000;
        assert_eq!(
            effective_presence("offline", Some(last), &cfg(), now),
            "offline"
        );
    }

    #[test]
    fn effective_no_activity_timestamp_returns_stored() {
        let now = 10_000_000;
        assert_eq!(effective_presence("online", None, &cfg(), now), "online");
    }

    #[test]
    fn format_status_online_recent_is_currently_active() {
        let now = now_ms();
        let rec = json!({
            "presence": "online",
            "status_msg": "hi",
            "last_active_ms": now,
        });
        let v = format_status(&rec, &cfg());
        assert_eq!(v["presence"], "online");
        assert_eq!(v["status_msg"], "hi");
        assert_eq!(v["currently_active"], true);
        assert!(v["last_active_ago"].as_u64().unwrap() < 5_000);
    }

    #[test]
    fn format_status_missing_record_defaults_offline() {
        let v = format_status(&json!({}), &cfg());
        assert_eq!(v["presence"], "offline");
        assert!(v.get("last_active_ago").is_none());
    }

    #[test]
    fn format_status_stale_online_decays_to_unavailable() {
        // 10-minute-stale stored "online" — was the regression case
        // before decay was implemented (presence stuck at "online"
        // forever after browser close).
        let rec = json!({
            "presence": "online",
            "last_active_ms": now_ms().saturating_sub(10 * 60 * 1000),
        });
        let v = format_status(&rec, &cfg());
        assert_eq!(v["presence"], "unavailable");
        assert_eq!(v["currently_active"], false);
    }

    #[test]
    fn format_status_long_stale_online_decays_to_offline() {
        let rec = json!({
            "presence": "online",
            "last_active_ms": now_ms().saturating_sub(45 * 60 * 1000),
        });
        let v = format_status(&rec, &cfg());
        assert_eq!(v["presence"], "offline");
        assert_eq!(v["currently_active"], false);
    }

    #[test]
    fn format_status_empty_status_msg_dropped() {
        let rec = json!({"presence": "unavailable", "status_msg": ""});
        let v = format_status(&rec, &cfg());
        assert!(v.get("status_msg").is_none());
    }
}
