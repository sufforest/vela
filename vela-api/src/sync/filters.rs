//! `POST /user/{userId}/filter` and `GET /user/{userId}/filter/{filterId}`.
//!
//! Spec: `references/matrix-spec/data/api/client-server/filter.yaml`.
//!
//! Filters are stored verbatim and applied on `/sync` via the `?filter=`
//! query parameter (id, base64-url-no-pad of a monotonic counter, never
//! starts with `{`). Inline-JSON filters (`?filter={...}`) are parsed in
//! the sync handler — see `apply_filter_to_room`.

use crate::middleware::json::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};

use vela_core::error::VelaError;
use vela_core::events::view::EventView;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::router::AppState;

pub async fn post_filter(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(user_id): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only define own filters".into()).into());
    }
    validate_filter_shape(&body)?;
    let id = state
        .db
        .store_filter(user.user_nid, &body)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(Json(json!({"filter_id": id})))
}

/// Shallow structural check: each known container must be an object; each
/// known list field must be a list. We don't validate individual element
/// types beyond "is a string" because unknown fields in filters are
/// spec-allowed to be ignored.
fn validate_filter_shape(body: &Value) -> Result<(), ApiError> {
    let top = body
        .as_object()
        .ok_or_else(|| ApiError(VelaError::BadJson("filter must be an object".into())))?;
    for (k, v) in top {
        match k.as_str() {
            "presence" | "account_data" => must_be_object(k, v)?,
            "room" => {
                let r = v.as_object().ok_or_else(|| {
                    ApiError(VelaError::BadJson(format!("filter.{k} must be an object")))
                })?;
                for (rk, rv) in r {
                    match rk.as_str() {
                        "timeline" | "state" | "ephemeral" | "account_data" | "not_rooms"
                        | "rooms" | "include_leave" => match rk.as_str() {
                            "rooms" | "not_rooms" => must_be_array(&format!("room.{rk}"), rv)?,
                            "include_leave" => {
                                if !rv.is_boolean() {
                                    return Err(VelaError::BadJson(format!(
                                        "filter.room.{rk} must be a boolean"
                                    ))
                                    .into());
                                }
                            }
                            _ => {
                                must_be_object(&format!("room.{rk}"), rv)?;
                                if let Some(obj) = rv.as_object() {
                                    for (fk, fv) in obj {
                                        match fk.as_str() {
                                            "types" | "not_types" => must_be_string_array(
                                                &format!("room.{rk}.{fk}"),
                                                fv,
                                            )?,
                                            "senders" | "not_senders" => must_be_user_id_array(
                                                &format!("room.{rk}.{fk}"),
                                                fv,
                                            )?,
                                            "rooms" | "not_rooms" => must_be_room_id_array(
                                                &format!("room.{rk}.{fk}"),
                                                fv,
                                            )?,
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }
            "event_fields" => must_be_array(k, v)?,
            _ => {}
        }
    }
    // Inside `presence`, list fields must also be arrays when present.
    if let Some(p) = body.get("presence").and_then(|v| v.as_object()) {
        for (fk, fv) in p {
            match fk.as_str() {
                "types" | "not_types" | "senders" | "not_senders" | "rooms" | "not_rooms" => {
                    must_be_array(&format!("presence.{fk}"), fv)?
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn must_be_object(name: &str, v: &Value) -> Result<(), ApiError> {
    if !v.is_object() {
        return Err(VelaError::BadJson(format!("filter.{name} must be an object")).into());
    }
    Ok(())
}

fn must_be_array(name: &str, v: &Value) -> Result<(), ApiError> {
    if !v.is_array() {
        return Err(VelaError::BadJson(format!("filter.{name} must be an array")).into());
    }
    Ok(())
}

/// Array of strings (event types in `types` / `not_types`). Spec
/// allows arbitrary strings (including wildcards), so we don't pin
/// the format beyond "is a string."
fn must_be_string_array(name: &str, v: &Value) -> Result<(), ApiError> {
    let arr = v.as_array().ok_or_else(|| {
        ApiError(VelaError::BadJson(format!(
            "filter.{name} must be an array"
        )))
    })?;
    for (i, e) in arr.iter().enumerate() {
        if !e.is_string() {
            return Err(VelaError::BadJson(format!("filter.{name}[{i}] must be a string")).into());
        }
    }
    Ok(())
}

/// Array of user_ids — must each look like `@localpart:domain`.
fn must_be_user_id_array(name: &str, v: &Value) -> Result<(), ApiError> {
    let arr = v.as_array().ok_or_else(|| {
        ApiError(VelaError::BadJson(format!(
            "filter.{name} must be an array"
        )))
    })?;
    for (i, e) in arr.iter().enumerate() {
        let s = e.as_str().ok_or_else(|| {
            ApiError(VelaError::BadJson(format!(
                "filter.{name}[{i}] must be a string user_id"
            )))
        })?;
        if !s.starts_with('@') || !s.contains(':') {
            return Err(
                VelaError::BadJson(format!("filter.{name}[{i}] is not a valid user_id")).into(),
            );
        }
    }
    Ok(())
}

/// Array of room_ids — must each look like `!opaque:domain`.
fn must_be_room_id_array(name: &str, v: &Value) -> Result<(), ApiError> {
    let arr = v.as_array().ok_or_else(|| {
        ApiError(VelaError::BadJson(format!(
            "filter.{name} must be an array"
        )))
    })?;
    for (i, e) in arr.iter().enumerate() {
        let s = e.as_str().ok_or_else(|| {
            ApiError(VelaError::BadJson(format!(
                "filter.{name}[{i}] must be a string room_id"
            )))
        })?;
        if !s.starts_with('!') || !s.contains(':') {
            return Err(
                VelaError::BadJson(format!("filter.{name}[{i}] is not a valid room_id")).into(),
            );
        }
    }
    Ok(())
}

pub async fn get_filter(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path((user_id, filter_id)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    if user.user_id != user_id {
        return Err(VelaError::Forbidden("can only read own filters".into()).into());
    }
    let f = state
        .db
        .get_filter(user.user_nid, &filter_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .ok_or_else(|| ApiError(VelaError::NotFound("filter not found".into())))?;
    Ok(Json(f))
}

/// Apply the timeline-side of a sync filter to a single room sync block.
/// Edits the `timeline.events` array in place.
///
/// Supported filter fields (spec subset):
/// - `room.timeline.limit`: cap event count.
/// - `room.timeline.types`: allow-list event types.
/// - `room.timeline.not_types`: deny-list event types.
/// - `room.timeline.not_senders`: deny-list senders.
/// - `room.timeline.rooms`/`not_rooms`: applied at the per-room loop, not here.
///
/// Other filter fields (state filter, ephemeral, presence, event_format,
/// event_fields) are accepted-but-ignored for now.
pub fn apply_timeline_filter(room: &mut Value, timeline_filter: &Value) {
    let Some(events) = room
        .pointer_mut("/timeline/events")
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };

    let allow_types = timeline_filter
        .get("types")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect::<Vec<_>>()
        });
    let deny_types = timeline_filter
        .get("not_types")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect::<Vec<_>>()
        });
    let deny_senders = timeline_filter
        .get("not_senders")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect::<Vec<_>>()
        });

    events.retain(|e| {
        let etype = e.event_type().unwrap_or("");
        let sender = e.sender().unwrap_or("");
        if let Some(allow) = &allow_types {
            // Wildcard support: `m.room.*` matches `m.room.message` etc.
            let ok = allow.iter().any(|p| type_matches(etype, p));
            if !ok {
                return false;
            }
        }
        if let Some(deny) = &deny_types
            && deny.iter().any(|p| type_matches(etype, p))
        {
            return false;
        }
        if let Some(deny) = &deny_senders
            && deny.iter().any(|s| s == sender)
        {
            return false;
        }
        true
    });

    if let Some(limit) = timeline_filter
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        && events.len() > limit
    {
        // Spec: keep most recent. Our timeline is already chronological
        // (oldest first), so trim from the front.
        let drop = events.len() - limit;
        events.drain(0..drop);
    }
}

/// Apply the state-side of a sync filter to a single room sync block.
/// Edits the `state.events` array in place. Same shape as the timeline
/// filter (the spec uses `RoomEventFilter` for both).
pub fn apply_state_filter(room: &mut Value, state_filter: &Value) {
    let Some(events) = room
        .pointer_mut("/state/events")
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };

    let allow_types = state_filter
        .get("types")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect::<Vec<_>>()
        });
    let deny_types = state_filter
        .get("not_types")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect::<Vec<_>>()
        });
    let deny_senders = state_filter
        .get("not_senders")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect::<Vec<_>>()
        });

    events.retain(|e| {
        let etype = e.event_type().unwrap_or("");
        let sender = e.sender().unwrap_or("");
        if let Some(allow) = &allow_types
            && !allow.iter().any(|p| type_matches(etype, p))
        {
            return false;
        }
        if let Some(deny) = &deny_types
            && deny.iter().any(|p| type_matches(etype, p))
        {
            return false;
        }
        if let Some(deny) = &deny_senders
            && deny.iter().any(|s| s == sender)
        {
            return false;
        }
        true
    });
}

/// True if either the `state` or `timeline` sub-filter requests
/// lazy-loaded members. Spec accepts the flag in both locations.
pub fn lazy_load_members_enabled(
    state_filter: Option<&Value>,
    timeline_filter: Option<&Value>,
) -> bool {
    let read = |f: Option<&Value>| {
        f.and_then(|x| x.get("lazy_load_members"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    };
    read(state_filter) || read(timeline_filter)
}

/// True if the client has opted out of the lazy-load member trim. Only
/// the `state` sub-filter carries this — the timeline location is
/// allowed by the spec but in practice only `state.include_redundant_members`
/// is honoured.
pub fn include_redundant_members(state_filter: Option<&Value>) -> bool {
    state_filter
        .and_then(|x| x.get("include_redundant_members"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Trim `state.events` to only the m.room.member events whose state_key
/// is the sender of a timeline event (plus the requesting user). Non-member
/// state events are kept unconditionally. This implements the spec's
/// lazy-load contract: clients render display names + avatars from the
/// member events, and only those for active senders are needed.
pub fn apply_lazy_load_state(room: &mut Value, user_id: &str) {
    use std::collections::HashSet;
    let mut keep: HashSet<String> = room
        .pointer("/timeline/events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("sender").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    keep.insert(user_id.to_string());

    if let Some(state_events) = room
        .pointer_mut("/state/events")
        .and_then(|v| v.as_array_mut())
    {
        state_events.retain(|ev| {
            let etype = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if etype != "m.room.member" {
                return true;
            }
            let sk = ev.get("state_key").and_then(|s| s.as_str()).unwrap_or("");
            keep.contains(sk)
        });
    }
}

/// Apply room-level allow/deny lists. Returns true if the room should be
/// included in the sync response at all.
pub fn room_passes_filter(room_id: &str, room_filter: &Value) -> bool {
    if let Some(allow) = room_filter.get("rooms").and_then(|v| v.as_array())
        && !allow.iter().any(|r| r.as_str() == Some(room_id))
    {
        return false;
    }
    if let Some(deny) = room_filter.get("not_rooms").and_then(|v| v.as_array())
        && deny.iter().any(|r| r.as_str() == Some(room_id))
    {
        return false;
    }
    true
}

fn type_matches(actual: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        actual.starts_with(prefix)
    } else {
        actual == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lazy_load_flag_read_from_either_subfilter() {
        let on = json!({"lazy_load_members": true});
        let off = json!({});
        assert!(lazy_load_members_enabled(Some(&on), None));
        assert!(lazy_load_members_enabled(None, Some(&on)));
        assert!(lazy_load_members_enabled(Some(&on), Some(&off)));
        assert!(!lazy_load_members_enabled(None, None));
        assert!(!lazy_load_members_enabled(Some(&off), Some(&off)));
    }

    #[test]
    fn include_redundant_members_off_by_default() {
        assert!(!include_redundant_members(None));
        assert!(!include_redundant_members(Some(&json!({}))));
        assert!(include_redundant_members(Some(
            &json!({"include_redundant_members": true})
        )));
    }

    #[test]
    fn lazy_load_keeps_only_timeline_senders_and_self() {
        let mut room = json!({
            "state": {"events": [
                {"type": "m.room.member", "state_key": "@alice:s",
                 "sender": "@alice:s", "content": {"membership": "join"}},
                {"type": "m.room.member", "state_key": "@bob:s",
                 "sender": "@bob:s", "content": {"membership": "join"}},
                {"type": "m.room.member", "state_key": "@charlie:s",
                 "sender": "@charlie:s", "content": {"membership": "join"}},
                {"type": "m.room.power_levels", "state_key": "",
                 "sender": "@alice:s", "content": {}},
            ]},
            "timeline": {"events": [
                {"type": "m.room.message", "sender": "@charlie:s", "content": {}},
            ]},
        });
        apply_lazy_load_state(&mut room, "@alice:s");
        let state_events = room["state"]["events"].as_array().unwrap();
        let kinds: Vec<(&str, &str)> = state_events
            .iter()
            .map(|e| {
                (
                    e["type"].as_str().unwrap(),
                    e["state_key"].as_str().unwrap(),
                )
            })
            .collect();
        // Power_levels kept (non-member). Charlie kept (timeline sender).
        // Alice kept (self). Bob trimmed.
        assert!(kinds.contains(&("m.room.power_levels", "")));
        assert!(kinds.contains(&("m.room.member", "@charlie:s")));
        assert!(kinds.contains(&("m.room.member", "@alice:s")));
        assert!(!kinds.contains(&("m.room.member", "@bob:s")));
    }

    /// Mirrors Complement TestFilter's getFilters() — every invalid filter
    /// shape should be rejected by validate_filter_shape. If any of these
    /// pass validation, vela's filter accept-set is too loose and a future
    /// run of TestFilter will fail.
    #[test]
    fn complement_invalid_filters_all_rejected() {
        let cases = [
            json!({"presence": "not_an_object"}),
            json!({"room": {"timeline": "not_an_object"}}),
            json!({"room": {"state": "not_an_object"}}),
            json!({"room": {"ephemeral": "not_an_object"}}),
            json!({"room": {"account_data": "not_an_object"}}),
            json!({"room": {"timeline": {"rooms": "not_a_list"}}}),
            json!({"room": {"timeline": {"not_rooms": "not_a_list"}}}),
            json!({"room": {"timeline": {"senders": "not_a_list"}}}),
            json!({"room": {"timeline": {"not_senders": "not_a_list"}}}),
            json!({"room": {"timeline": {"types": "not_a_list"}}}),
            json!({"room": {"timeline": {"not_types": "not_a_list"}}}),
            json!({"room": {"timeline": {"types": [1]}}}),
            json!({"room": {"timeline": {"rooms": ["not_a_room_id"]}}}),
            json!({"room": {"timeline": {"senders": ["not_a_sender_id"]}}}),
        ];
        for (i, body) in cases.iter().enumerate() {
            let res = super::validate_filter_shape(body);
            assert!(res.is_err(), "case {i} should reject but accepted: {body}");
        }
    }

    #[test]
    fn well_formed_filters_pass() {
        let cases = [
            json!({}),
            json!({"presence": {}}),
            json!({"presence": {"types": ["m.presence"]}}),
            json!({
                "room": {
                    "state": {"lazy_load_members": true},
                    "timeline": {"limit": 20, "types": ["m.room.message"]},
                    "rooms": ["!a:hs1"],
                    "include_leave": true,
                }
            }),
            json!({"event_fields": ["type", "content.body"]}),
        ];
        for (i, body) in cases.iter().enumerate() {
            let res = super::validate_filter_shape(body);
            assert!(res.is_ok(), "case {i} should pass: {body}");
        }
    }

    #[test]
    fn lazy_load_keeps_self_when_timeline_empty() {
        let mut room = json!({
            "state": {"events": [
                {"type": "m.room.member", "state_key": "@alice:s",
                 "sender": "@alice:s", "content": {"membership": "join"}},
                {"type": "m.room.member", "state_key": "@bob:s",
                 "sender": "@bob:s", "content": {"membership": "join"}},
            ]},
            "timeline": {"events": []},
        });
        apply_lazy_load_state(&mut room, "@alice:s");
        let kinds: Vec<&str> = room["state"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["state_key"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, vec!["@alice:s"]);
    }
}
