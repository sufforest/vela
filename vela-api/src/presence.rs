//! `/presence/{userId}/status` — user online-ness + status message.
//!
//! Spec: `client-server-api/#presence`.
//!
//! We track presence locally only — spec allows this, and our
//! design-decision set has federation presence EDUs marked as
//! deliberately out-of-scope (known_limitations). Clients on the same
//! server see each others' presence via the sync bundle; cross-server
//! presence surfaces as the default `offline`.

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

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
    Ok(Json(format_status(&rec)))
}

/// Shape presence as clients expect: `{presence, last_active_ago?, status_msg?}`.
/// `last_active_ago` is derived from the stored timestamp so the value
/// decays without us having to touch the record on every read.
pub fn format_status(rec: &Value) -> Value {
    let presence = rec
        .get("presence")
        .and_then(|v| v.as_str())
        .unwrap_or("offline");
    let mut out = serde_json::Map::new();
    out.insert("presence".into(), json!(presence));
    if let Some(msg) = rec.get("status_msg").and_then(|v| v.as_str())
        && !msg.is_empty()
    {
        out.insert("status_msg".into(), json!(msg));
    }
    if let Some(last) = rec.get("last_active_ms").and_then(|v| v.as_u64()) {
        let now = now_ms();
        let age = now.saturating_sub(last);
        out.insert("last_active_ago".into(), json!(age));
        // currently_active: true within 5 min of last activity and state isn't explicitly offline/unavailable.
        let active = age < 5 * 60 * 1000 && presence == "online";
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

    #[test]
    fn format_status_online_recent_is_currently_active() {
        let rec = json!({
            "presence": "online",
            "status_msg": "hi",
            "last_active_ms": now_ms(),
        });
        let v = format_status(&rec);
        assert_eq!(v["presence"], "online");
        assert_eq!(v["status_msg"], "hi");
        assert_eq!(v["currently_active"], true);
        assert!(v["last_active_ago"].as_u64().unwrap() < 1000);
    }

    #[test]
    fn format_status_missing_record_defaults_offline() {
        let v = format_status(&json!({}));
        assert_eq!(v["presence"], "offline");
        assert!(v.get("last_active_ago").is_none());
    }

    #[test]
    fn format_status_stale_not_currently_active() {
        let rec = json!({
            "presence": "online",
            "last_active_ms": now_ms().saturating_sub(10 * 60 * 1000),
        });
        let v = format_status(&rec);
        assert_eq!(v["currently_active"], false);
    }

    #[test]
    fn format_status_empty_status_msg_dropped() {
        let rec = json!({"presence": "unavailable", "status_msg": ""});
        let v = format_status(&rec);
        assert!(v.get("status_msg").is_none());
    }
}
