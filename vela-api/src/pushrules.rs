//! Push rules — round-trips client-set rules via account data.
//!
//! Spec: `references/matrix-spec/content/client-server-api/modules/push.md`.
//!
//! We store user-modified rules under the global account data type
//! `m.push_rules`. Reads merge stored kinds into the canonical empty
//! shape so clients always get the five expected arrays. Push *evaluation*
//! and push-gateway delivery are still deferred — these endpoints make the
//! shape work for clients that want to view/modify their own rules.

use axum::Json;
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
    let mut global = load_global(&state, user.user_nid)?;
    let arr = global
        .as_object_mut()
        .unwrap()
        .entry(kind.clone())
        .or_insert_with(|| json!([]));
    let arr = arr.as_array_mut().unwrap();
    arr.retain(|r| r.get("rule_id").and_then(|v| v.as_str()) != Some(rule_id.as_str()));

    let mut rule = body.as_object().cloned().unwrap_or_default();
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
    let mut global = load_global(&state, user.user_nid)?;
    if let Some(arr) = global.get_mut(&kind).and_then(|v| v.as_array_mut()) {
        arr.retain(|r| r.get("rule_id").and_then(|v| v.as_str()) != Some(rule_id.as_str()));
    }
    save_global(&state, user.user_nid, &global)?;
    Ok(Json(json!({})))
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
