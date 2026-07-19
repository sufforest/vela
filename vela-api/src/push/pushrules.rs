//! Push rules — round-trips client-set rules via account data.
//!
//! Spec: `references/matrix-spec/content/client-server-api/modules/push.md`.
//!
//! We store user-modified rules under the global account data type
//! `m.push_rules`. Reads merge stored kinds into the canonical empty
//! shape so clients always get the five expected arrays. Push *evaluation*
//! and push-gateway delivery are still deferred — these endpoints make the
//! shape work for clients that want to view/modify their own rules.

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};

use vela_core::error::VelaError;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

const STORE_TYPE: &str = "m.push_rules";

/// GET /_matrix/client/v3/pushrules/
pub async fn get_pushrules(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let global = load_global(&state, user.user_nid)?;
    Ok(Json(json!({ "global": global })))
}

/// GET /_matrix/client/v3/pushrules/global/
pub async fn get_global_pushrules(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Value>, ApiError> {
    let global = load_global(&state, user.user_nid)?;
    Ok(Json(global))
}

/// GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}
pub async fn get_pushrule(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let global = load_global(&state, user.user_nid)?;
    let arr = global
        .get(&kind)
        .and_then(|v| v.as_array())
        .ok_or_else(|| ApiError(VelaError::NotFound(format!("unknown rule kind: {kind}"))))?;
    let rule = arr
        .iter()
        .find(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some(rule_id.as_str()))
        .cloned()
        .ok_or_else(|| ApiError(VelaError::NotFound("rule not found".into())))?;
    Ok(Json(rule))
}

/// PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}
///
/// Insert or replace a rule. Body is the rule's content (actions,
/// conditions, pattern, etc.); we add `rule_id`/`default`/`enabled` for
/// completeness and write it back to the user's `m.push_rules`.
pub async fn put_pushrule(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((kind, rule_id)): Path<(String, String)>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if !valid_kind(&kind) {
        return Err(VelaError::NotFound(format!("unknown rule kind: {kind}")).into());
    }
    let _guard = pushrule_user_guard(&state, user.user_nid).await;
    let mut global = load_global(&state, user.user_nid)?;
    let arr = global
        .as_object_mut()
        .unwrap()
        .entry(kind.clone())
        .or_insert_with(|| json!([]));
    let arr = arr.as_array_mut().unwrap();
    arr.retain(|r| r.get("rule_id").and_then(|v| v.as_str()) != Some(rule_id.as_str()));

    let mut rule = body.as_object().cloned().unwrap_or_default();
    // Reject a malformed `event_match` condition (spec requires `pattern`).
    // Beyond spec-conformance, this keeps the evaluator's no-pattern branch —
    // which matches the recipient's own mxid, reserved for the default
    // `invite_for_me` rule — unreachable from user-submitted rules.
    if let Some(conds) = rule.get("conditions").and_then(|v| v.as_array())
        && conds.iter().any(|c| {
            c.get("kind").and_then(|v| v.as_str()) == Some("event_match")
                && c.get("pattern").and_then(|v| v.as_str()).is_none()
        })
    {
        return Err(VelaError::BadJson("event_match condition requires a `pattern`".into()).into());
    }
    rule.insert("rule_id".to_string(), json!(rule_id));
    rule.entry("enabled".to_string()).or_insert(json!(true));
    rule.entry("default".to_string()).or_insert(json!(false));
    arr.push(Value::Object(rule));

    save_global(&state, user.user_nid, &global)?;
    Ok(Json(json!({})))
}

/// DELETE /_matrix/client/v3/pushrules/global/{kind}/{ruleId}
pub async fn delete_pushrule(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let _guard = pushrule_user_guard(&state, user.user_nid).await;
    let mut global = load_global(&state, user.user_nid)?;
    if let Some(arr) = global.get_mut(&kind).and_then(|v| v.as_array_mut()) {
        arr.retain(|r| r.get("rule_id").and_then(|v| v.as_str()) != Some(rule_id.as_str()));
    }
    save_global(&state, user.user_nid, &global)?;
    Ok(Json(json!({})))
}

/// Per-user lock around the m.push_rules read-modify-write cycle.
/// Without this, two concurrent PUT/DELETE pushrules from the same
/// user race: both load the current m.push_rules blob, both apply
/// their own rule change to the in-memory copy, and the later save
/// clobbers the earlier one — silently dropping a rule. Bites
/// TestPushRuleRoomUpgrade where multiple subtests SetPushRule for
/// the same bob in parallel.
async fn pushrule_user_guard(state: &AppState, user_nid: u64) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = state
        .user_locks
        .entry(user_nid)
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    lock.lock_owned().await
}

#[derive(Deserialize)]
pub struct EnabledBody {
    pub enabled: bool,
}

/// PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled
pub async fn put_pushrule_enabled(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((kind, rule_id)): Path<(String, String)>,
    Json(body): Json<EnabledBody>,
) -> Result<Json<Value>, ApiError> {
    let _guard = pushrule_user_guard(&state, user.user_nid).await;
    update_rule_field(
        &state,
        user.user_nid,
        &kind,
        &rule_id,
        "enabled",
        json!(body.enabled),
    )
}

/// GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/enabled
pub async fn get_pushrule_enabled(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let global = load_global(&state, user.user_nid)?;
    let rule = find_rule(&global, &kind, &rule_id)
        .ok_or_else(|| ApiError(VelaError::NotFound("rule not found".into())))?;
    let enabled = rule
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    Ok(Json(json!({"enabled": enabled})))
}

#[derive(Deserialize)]
pub struct ActionsBody {
    pub actions: Value,
}

/// PUT /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions
pub async fn put_pushrule_actions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((kind, rule_id)): Path<(String, String)>,
    Json(body): Json<ActionsBody>,
) -> Result<Json<Value>, ApiError> {
    let _guard = pushrule_user_guard(&state, user.user_nid).await;
    update_rule_field(
        &state,
        user.user_nid,
        &kind,
        &rule_id,
        "actions",
        body.actions,
    )
}

/// GET /_matrix/client/v3/pushrules/global/{kind}/{ruleId}/actions
pub async fn get_pushrule_actions(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((kind, rule_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    let global = load_global(&state, user.user_nid)?;
    let rule = find_rule(&global, &kind, &rule_id)
        .ok_or_else(|| ApiError(VelaError::NotFound("rule not found".into())))?;
    let actions = rule.get("actions").cloned().unwrap_or_else(|| json!([]));
    Ok(Json(json!({"actions": actions})))
}

// ---- helpers ----

/// Canonical default rules. Users who haven't customised get this so
/// /pushrules returns a non-empty set and the evaluator has something
/// to match against.
fn empty_kinds() -> Value {
    vela_core::push_rules::default_global_rules()
}

fn valid_kind(k: &str) -> bool {
    matches!(k, "override" | "content" | "room" | "sender" | "underride")
}

/// Public loader used by the push dispatcher. Returns the merged rule
/// set (server defaults + user overrides) ready to hand to
/// `vela_core::push_rules::evaluate`.
pub fn load_user_rules(state: &AppState, user_nid: u64) -> Result<Value, ApiError> {
    load_global(state, user_nid)
}

fn load_global(state: &AppState, user_nid: u64) -> Result<Value, ApiError> {
    let stored = state
        .db
        .get_account_data(user_nid, STORE_TYPE)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut out = empty_kinds();
    if let Some(stored_global) = stored
        .as_ref()
        .and_then(|v| v.get("global"))
        .and_then(|v| v.as_object())
    {
        let out_obj = out.as_object_mut().unwrap();
        for (k, v) in stored_global {
            out_obj.insert(k.clone(), v.clone());
        }
    }
    Ok(out)
}

fn save_global(state: &AppState, user_nid: u64, global: &Value) -> Result<(), ApiError> {
    let body = json!({"global": global});
    // Push rules live in the same per-user storage class as account
    // data (same CF, synthesized into every initial /sync), so the same
    // size cap applies — otherwise a client refused by the account-data
    // cap just parks its blob in push rules instead. Enforced only on
    // GROWTH: a pre-existing over-cap ruleset can always be shrunk back
    // under the limit one delete at a time.
    let max = state.config.max_account_data_bytes;
    let new_size = serde_json::to_vec(&body)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if max != 0 && new_size > max {
        let old_size = state
            .db
            .get_account_data(user_nid, STORE_TYPE)
            .ok()
            .flatten()
            .and_then(|v| serde_json::to_vec(&v).ok())
            .map_or(0, |v| v.len());
        if new_size > old_size {
            tracing::warn!(new_size, max, "refused oversized push ruleset");
            return Err(ApiError(VelaError::EventTooLarge(format!(
                "push rules too large ({new_size} > {max} bytes)"
            ))));
        }
    }
    state
        .db
        .set_account_data(user_nid, STORE_TYPE, &body)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    // Wake any pending /sync long-poll so the rule change appears
    // immediately. Without this, clients that wait for incremental
    // sync after editing a rule sit until the 30s default timeout.
    if let Some(sender) = state.user_senders.get(&user_nid) {
        let _ = sender.send(());
    }
    Ok(())
}

fn find_rule<'a>(global: &'a Value, kind: &str, rule_id: &str) -> Option<&'a Value> {
    global
        .get(kind)?
        .as_array()?
        .iter()
        .find(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some(rule_id))
}

fn update_rule_field(
    state: &AppState,
    user_nid: u64,
    kind: &str,
    rule_id: &str,
    field: &str,
    value: Value,
) -> Result<Json<Value>, ApiError> {
    let mut global = load_global(state, user_nid)?;
    let arr = global
        .as_object_mut()
        .unwrap()
        .entry(kind.to_string())
        .or_insert_with(|| json!([]));
    let arr = arr.as_array_mut().unwrap();
    if let Some(rule) = arr
        .iter_mut()
        .find(|r| r.get("rule_id").and_then(|v| v.as_str()) == Some(rule_id))
    {
        rule.as_object_mut()
            .unwrap()
            .insert(field.to_string(), value);
    } else {
        // Auto-create a stub rule with sensible defaults so clients can
        // PUT /enabled or /actions before PUTting the full rule.
        let mut rule = serde_json::Map::new();
        rule.insert("rule_id".to_string(), json!(rule_id));
        rule.insert("enabled".to_string(), json!(true));
        rule.insert("default".to_string(), json!(false));
        rule.insert("actions".to_string(), json!([]));
        rule.insert(field.to_string(), value);
        arr.push(Value::Object(rule));
    }
    save_global(state, user_nid, &global)?;
    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    /// The account-data size cap applies to push rules too — but only on
    /// growth, so an over-cap legacy ruleset can still be shrunk.
    #[test]
    fn save_global_caps_growth_but_allows_shrink() {
        let (state, _tmp) = build_test_state();
        let nid = state.db.create_user("@u:example.com", "h").unwrap();

        let over = state.config.max_account_data_bytes;
        let big = json!({"underride": [{"rule_id": "big", "pattern": "x".repeat(over + 1000)}]});
        let err = save_global(&state, nid, &big).expect_err("oversized ruleset refused");
        assert!(matches!(err.0, VelaError::EventTooLarge(_)));

        // Seed an over-cap blob directly (legacy state), then verify a
        // smaller-but-still-over-cap write is allowed (shrink path).
        state
            .db
            .set_account_data(nid, STORE_TYPE, &json!({"global": {"underride": [{"rule_id": "big", "pattern": "x".repeat(over + 50_000)}]}}))
            .unwrap();
        save_global(&state, nid, &big).expect("shrinking write allowed");

        // And a small ruleset is always fine.
        save_global(&state, nid, &json!({"underride": []})).expect("small ruleset ok");
    }
}
