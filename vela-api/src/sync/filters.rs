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

/// Apply a `RoomEventFilter`'s event-level predicates to an event array in
/// place: `types`/`not_types` (with `m.x.*` wildcards), `senders` (allow-list)
/// / `not_senders` (deny-list), and `contains_url` (keep only events that have
/// — or, if `false`, lack — a `content.url` key). Shared by the timeline and
/// state sync sections, which both carry a `RoomEventFilter`. `limit` is the
/// caller's concern: only the timeline honours it, and only after the
/// most-recent trim. Room events always carry a sender, so the sender lists
/// apply unconditionally (unlike the sender-less `apply_event_filter`).
fn retain_room_event_filter(events: &mut Vec<Value>, filter: &Value) {
    let str_list = |k: &str| {
        filter.get(k).and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
    };
    let allow_types = str_list("types");
    let deny_types = str_list("not_types");
    let allow_senders = str_list("senders");
    let deny_senders = str_list("not_senders");
    let contains_url = filter.get("contains_url").and_then(|v| v.as_bool());

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
        // `not_senders` takes precedence over `senders` per spec: a sender in
        // both lists is excluded. Checking the deny-list first honours that.
        if let Some(deny) = &deny_senders
            && deny.iter().any(|s| s == sender)
        {
            return false;
        }
        if let Some(allow) = &allow_senders
            && !allow.iter().any(|s| s == sender)
        {
            return false;
        }
        if let Some(want_url) = contains_url {
            // Match Synapse: a `url` key whose value is a string. `{"url":
            // null}` or a non-string url counts as "no url", so the two
            // servers agree on which events a `contains_url` filter keeps.
            let has_url = e
                .get("content")
                .and_then(|c| c.get("url"))
                .is_some_and(|u| u.is_string());
            if has_url != want_url {
                return false;
            }
        }
        true
    });
}

/// Apply the timeline-side of a sync filter to a single room sync block.
/// Edits the `timeline.events` array in place.
///
/// Supported filter fields (spec subset):
/// - `room.timeline.limit`: cap event count.
/// - `room.timeline.types` / `not_types`: allow/deny event types.
/// - `room.timeline.senders` / `not_senders`: allow/deny senders.
/// - `room.timeline.contains_url`: keep only events with/without `content.url`.
/// - `room.timeline.rooms`/`not_rooms`: applied at the per-room loop, not here.
///
/// The `state`, `ephemeral`, `presence`, and `account_data` sub-filters are
/// applied by their own helpers (`apply_state_filter` / `apply_event_filter`)
/// at the call sites. `event_format` / `event_fields` remain accepted-but-
/// ignored.
///
/// Known limitation: the timeline is already trimmed to `limit` upstream
/// (the DB query), then filtered here, so a highly selective predicate
/// (`contains_url`, a narrow `senders`) can return fewer than `limit`
/// matching events even when more exist earlier in history. Matching
/// Synapse (filter in the query, then limit) would require pushing these
/// predicates into the timeline read.
pub fn apply_timeline_filter(room: &mut Value, timeline_filter: &Value) {
    let Some(events) = room
        .pointer_mut("/timeline/events")
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };

    retain_room_event_filter(events, timeline_filter);

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

/// Apply the state-side of a sync filter to a single room sync block. Same
/// shape as the timeline filter (the spec uses `RoomEventFilter` for both).
///
/// A room block carries state under the legacy `state` key or, under MSC4222,
/// the `state_after` key — built internally under the stable name and renamed
/// for the client afterwards, so at this point it's always `state_after`.
/// Element opts into MSC4222, so filtering only `/state/events` would be a
/// no-op for the primary client; we filter whichever key is present.
pub fn apply_state_filter(room: &mut Value, state_filter: &Value) {
    for pointer in ["/state/events", "/state_after/events"] {
        if let Some(events) = room.pointer_mut(pointer).and_then(|v| v.as_array_mut()) {
            retain_room_event_filter(events, state_filter);
        }
    }
}

/// Apply an `EventFilter`'s `types` / `not_types` / `senders` / `not_senders`
/// / `limit` to a flat event array in place — used for the `presence`,
/// per-room `ephemeral`, and global/room `account_data` sync sections, which
/// carry a plain `EventFilter` (no room dimension). Same type-wildcard
/// (`m.x.*`) and limit semantics as the timeline filter. `senders` is a no-op
/// for sender-less events (account_data, typing), which is the spec intent.
pub fn apply_event_filter(events: &mut Vec<Value>, filter: &Value) {
    let str_list = |k: &str| {
        filter.get(k).and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
    };
    let allow_types = str_list("types");
    let deny_types = str_list("not_types");
    let allow_senders = str_list("senders");
    let deny_senders = str_list("not_senders");

    events.retain(|e| {
        let etype = e.event_type().unwrap_or("");
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
        // Only constrain by sender when the events actually carry one.
        if allow_senders.is_some() || deny_senders.is_some() {
            let sender = e.sender().unwrap_or("");
            if let Some(allow) = &allow_senders
                && !allow.iter().any(|s| s == sender)
            {
                return false;
            }
            if let Some(deny) = &deny_senders
                && deny.iter().any(|s| s == sender)
            {
                return false;
            }
        }
        true
    });

    if let Some(limit) = filter
        .get("limit")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        && events.len() > limit
    {
        events.truncate(limit);
    }
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
pub fn apply_lazy_load_state(room: &mut Value, user_id: &str, use_state_after: bool) {
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

    // Lazy-loading MUST also retain the room heroes' membership events: the
    // client renders an unnamed room's name/avatar (e.g. a DM) from them.
    // Without this, a room with no recent timeline message from the other
    // member loses that member event and shows up as "Empty room" after a
    // fresh login (the client has nothing cached to fall back on). The
    // heroes were computed into `summary.m.heroes` upstream.
    if let Some(heroes) = room.pointer("/summary/m.heroes").and_then(|v| v.as_array()) {
        for hero in heroes.iter().filter_map(|v| v.as_str()) {
            keep.insert(hero.to_string());
        }
    }

    // MSC4222 puts the state list under `state_after.events` instead of
    // the legacy `state.events`. Same filtering shape either way.
    let pointer = if use_state_after {
        "/state_after/events"
    } else {
        "/state/events"
    };
    if let Some(state_events) = room.pointer_mut(pointer).and_then(|v| v.as_array_mut()) {
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
        apply_lazy_load_state(&mut room, "@alice:s", false);
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

    #[test]
    fn lazy_load_keeps_heroes_member_for_unnamed_room() {
        // A DM with no recent timeline messages: @bob is the room hero
        // (used to derive the room name). Lazy-load must keep @bob's member
        // event even though he isn't a timeline sender — otherwise the
        // client has no member to name the room and renders "Empty room".
        let mut room = json!({
            "summary": {"m.heroes": ["@bob:s"]},
            "state": {"events": [
                {"type": "m.room.member", "state_key": "@alice:s",
                 "sender": "@alice:s", "content": {"membership": "join"}},
                {"type": "m.room.member", "state_key": "@bob:s",
                 "sender": "@bob:s", "content": {"membership": "join"}},
            ]},
            "timeline": {"events": []},
        });
        apply_lazy_load_state(&mut room, "@alice:s", false);
        let kinds: Vec<(&str, &str)> = room["state"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["type"].as_str().unwrap(),
                    e["state_key"].as_str().unwrap(),
                )
            })
            .collect();
        assert!(kinds.contains(&("m.room.member", "@alice:s")), "self kept");
        assert!(
            kinds.contains(&("m.room.member", "@bob:s")),
            "hero member must survive lazy-load so the DM has a name; got {kinds:?}"
        );
    }

    #[test]
    fn lazy_load_keeps_heroes_member_under_state_after() {
        // Same as above but on the MSC4222 `state_after` path — the one
        // Element actually uses (`org.matrix.msc4222.use_state_after=true`),
        // which is where the "Empty room" bug surfaced.
        let mut room = json!({
            "summary": {"m.heroes": ["@bob:s"]},
            "state_after": {"events": [
                {"type": "m.room.member", "state_key": "@alice:s",
                 "sender": "@alice:s", "content": {"membership": "join"}},
                {"type": "m.room.member", "state_key": "@bob:s",
                 "sender": "@bob:s", "content": {"membership": "join"}},
            ]},
            "timeline": {"events": []},
        });
        apply_lazy_load_state(&mut room, "@alice:s", true);
        let kinds: Vec<(&str, &str)> = room["state_after"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["type"].as_str().unwrap(),
                    e["state_key"].as_str().unwrap(),
                )
            })
            .collect();
        assert!(
            kinds.contains(&("m.room.member", "@bob:s")),
            "hero member must survive lazy-load under state_after; got {kinds:?}"
        );
    }

    #[test]
    fn event_filter_applies_types_senders_and_limit() {
        let ev = |t: &str, s: &str| json!({"type": t, "sender": s, "content": {}});

        // not_types denies; the rest pass.
        let mut events = vec![ev("m.presence", "@a:s"), ev("m.receipt", "@a:s")];
        apply_event_filter(&mut events, &json!({"not_types": ["m.receipt"]}));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "m.presence");

        // types allow-list with a wildcard.
        let mut events = vec![ev("m.room.foo", "@a:s"), ev("m.tag", "@a:s")];
        apply_event_filter(&mut events, &json!({"types": ["m.room.*"]}));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["type"], "m.room.foo");

        // senders allow-list (relevant for presence).
        let mut events = vec![ev("m.presence", "@a:s"), ev("m.presence", "@b:s")];
        apply_event_filter(&mut events, &json!({"senders": ["@a:s"]}));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["sender"], "@a:s");

        // limit caps the count.
        let mut events = vec![ev("x", "@a:s"), ev("x", "@a:s"), ev("x", "@a:s")];
        apply_event_filter(&mut events, &json!({"limit": 2}));
        assert_eq!(events.len(), 2);

        // sender-less events (account_data / typing) survive when only a type
        // filter is set — the senders constraint must not strip them.
        let mut events = vec![json!({"type": "m.tag", "content": {}})];
        apply_event_filter(&mut events, &json!({"not_types": ["m.fully_read"]}));
        assert_eq!(events.len(), 1);
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
        apply_lazy_load_state(&mut room, "@alice:s", false);
        let kinds: Vec<&str> = room["state"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["state_key"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, vec!["@alice:s"]);
    }

    fn timeline_senders(room: &Value) -> Vec<String> {
        room["timeline"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["sender"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn timeline_senders_allow_list() {
        let mk = |s: &str| json!({"type": "m.room.message", "sender": s, "content": {}});
        let mut room = json!({"timeline": {"events": [mk("@a:s"), mk("@b:s"), mk("@c:s")]}});
        apply_timeline_filter(&mut room, &json!({"senders": ["@a:s", "@b:s"]}));
        assert_eq!(timeline_senders(&room), vec!["@a:s", "@b:s"]);
    }

    #[test]
    fn not_senders_takes_precedence_over_senders() {
        // A sender listed in both is excluded (spec).
        let mk = |s: &str| json!({"type": "m.room.message", "sender": s, "content": {}});
        let mut room = json!({"timeline": {"events": [mk("@a:s"), mk("@b:s")]}});
        apply_timeline_filter(
            &mut room,
            &json!({"senders": ["@a:s", "@b:s"], "not_senders": ["@a:s"]}),
        );
        assert_eq!(timeline_senders(&room), vec!["@b:s"]);
    }

    #[test]
    fn contains_url_filters_timeline_and_state() {
        let with_url =
            json!({"type": "m.room.message", "sender": "@a:s", "content": {"url": "mxc://x/y"}});
        let no_url = json!({"type": "m.room.message", "sender": "@a:s", "content": {"body": "hi"}});

        // true → keep only events with a content.url key.
        let mut room = json!({"timeline": {"events": [with_url.clone(), no_url.clone()]}});
        apply_timeline_filter(&mut room, &json!({"contains_url": true}));
        let evs = room["timeline"]["events"].as_array().unwrap();
        assert_eq!(evs.len(), 1);
        assert!(evs[0]["content"].get("url").is_some());

        // false → drop events that have a url.
        let mut room = json!({"timeline": {"events": [with_url.clone(), no_url.clone()]}});
        apply_timeline_filter(&mut room, &json!({"contains_url": false}));
        let evs = room["timeline"]["events"].as_array().unwrap();
        assert_eq!(evs.len(), 1);
        assert!(evs[0]["content"].get("url").is_none());

        // state filter honours it too.
        let mut room = json!({"state": {"events": [with_url, no_url]}});
        apply_state_filter(&mut room, &json!({"contains_url": true}));
        assert_eq!(room["state"]["events"].as_array().unwrap().len(), 1);

        // omitted → no url-based filtering.
        let mut room = json!({"timeline": {"events": [
            json!({"type": "m.room.message", "sender": "@a:s", "content": {"url": "mxc://x/y"}}),
            json!({"type": "m.room.message", "sender": "@a:s", "content": {}}),
        ]}});
        apply_timeline_filter(&mut room, &json!({}));
        assert_eq!(room["timeline"]["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn contains_url_requires_a_string_url() {
        // A null or non-string url counts as "no url" (Synapse parity), so
        // contains_url:true drops them and contains_url:false keeps them.
        let null_url =
            json!({"type": "m.room.message", "sender": "@a:s", "content": {"url": null}});
        let int_url = json!({"type": "m.room.message", "sender": "@a:s", "content": {"url": 5}});
        let no_content = json!({"type": "m.room.message", "sender": "@a:s"});

        let mut room = json!({"timeline": {"events": [null_url.clone(), int_url.clone(), no_content.clone()]}});
        apply_timeline_filter(&mut room, &json!({"contains_url": true}));
        assert_eq!(
            room["timeline"]["events"].as_array().unwrap().len(),
            0,
            "no string url anywhere → contains_url:true keeps nothing"
        );

        let mut room = json!({"timeline": {"events": [null_url, int_url, no_content]}});
        apply_timeline_filter(&mut room, &json!({"contains_url": false}));
        assert_eq!(
            room["timeline"]["events"].as_array().unwrap().len(),
            3,
            "contains_url:false keeps events without a string url"
        );
    }

    #[test]
    fn empty_senders_list_excludes_all() {
        // `senders: []` is present-but-empty → no sender matches → everything
        // is dropped (distinct from an absent `senders`, which filters nothing).
        let mk = |s: &str| json!({"type": "m.room.message", "sender": s, "content": {}});
        let mut room = json!({"timeline": {"events": [mk("@a:s"), mk("@b:s")]}});
        apply_timeline_filter(&mut room, &json!({"senders": []}));
        assert!(room["timeline"]["events"].as_array().unwrap().is_empty());
    }

    #[test]
    fn state_filter_applies_under_state_after() {
        // MSC4222 rooms carry state under `state_after`, not `state`. The
        // state filter must reach it or it's a no-op for Element.
        let ev = |t: &str, sender: &str| json!({"type": t, "state_key": "", "sender": sender, "content": {}});
        let mut room = json!({"state_after": {"events": [
            ev("m.room.topic", "@a:s"),
            ev("m.room.name", "@b:s"),
        ]}});
        apply_state_filter(&mut room, &json!({"not_senders": ["@b:s"]}));
        let types: Vec<&str> = room["state_after"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, vec!["m.room.topic"], "state_after must be filtered");
    }
}
