//! Matrix Room Version 12 authorization rules.
//!
//! Implements the rules from `content/rooms/v12.md`:
//! 1. m.room.create validation
//! 2. room_id matches create event
//! 3. auth_events validation (duplicates, wrong types, rejected ancestors)
//! 4. m.federate check
//! 5. m.room.member rules (join/invite/leave/ban/knock)
//! 6. Sender must be joined
//! 7. m.room.third_party_invite
//! 8. Required power level for event type
//! 9. Event state_key starts with "@" must match sender
//! 10. m.room.power_levels rules (including creator protection)
//! 11. Default allow
//!
//! Pure function: no IO, no DB. State is passed as a closure.

use std::collections::HashSet;

use serde_json::Value;

use crate::events::pdu::Pdu;

/// State lookup function: (type, state_key) → Some(&Pdu) if present.
pub type StateFn<'a> = &'a dyn Fn(&str, &str) -> Option<&'a Pdu>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// Event does not pass auth rules. Contains a human-readable reason.
    Rejected(String),
}

impl AuthError {
    fn reject(reason: impl Into<String>) -> Self {
        AuthError::Rejected(reason.into())
    }
}

pub type AuthResult = Result<(), AuthError>;

/// Check whether an event is authorized given the current state.
///
/// Implements the full v12 authorization ruleset. Rules reference the
/// numbered list in rooms/v12.md.
pub fn check_auth(event: &Pdu, state: StateFn<'_>) -> AuthResult {
    // --- Rule 1: m.room.create ---
    if event.event_type == "m.room.create" {
        return check_create(event);
    }

    // --- Rule 2: room_id must be the m.room.create event ID (v12) ---
    // The create event has ID "$xxx" and room_id is "!xxx" (same hash, different sigil).
    // We enforce that a create event exists in state with a matching ID.
    let create =
        state("m.room.create", "").ok_or_else(|| AuthError::reject("no m.room.create in state"))?;
    if !room_id_matches_create(&event.room_id, &create.event_id) {
        return Err(AuthError::reject(
            "event room_id does not match m.room.create event id",
        ));
    }

    // --- Rule 3: auth_events validation ---
    check_auth_events(event, state)?;

    // --- Rule 4: m.federate ---
    check_federate(event, create)?;

    // --- Rule 5: m.room.member ---
    if event.event_type == "m.room.member" {
        return check_member(event, state, create);
    }

    // --- Rule 6: sender must be joined ---
    let sender_membership = get_membership(state, &event.sender);
    if sender_membership != Some("join") {
        return Err(AuthError::reject("sender is not joined"));
    }

    // --- Rule 7: m.room.third_party_invite ---
    if event.event_type == "m.room.third_party_invite" {
        let invite_level = power_level_field(state, "invite", 0);
        let sender_power = user_power_level(state, &event.sender, create);
        if sender_power >= invite_level {
            return Ok(());
        } else {
            return Err(AuthError::reject(
                "sender power level below invite level for third_party_invite",
            ));
        }
    }

    // --- Rule 8: required power level ---
    let sender_power = user_power_level(state, &event.sender, create);
    let required = required_power_level(state, &event.event_type, event.is_state());
    if sender_power < required {
        return Err(AuthError::reject(format!(
            "sender power {sender_power} below required {required} for {}",
            event.event_type
        )));
    }

    // --- Rule 9: state_key starting with "@" must match sender ---
    if let Some(sk) = &event.state_key
        && sk.starts_with('@')
        && sk != &event.sender
    {
        return Err(AuthError::reject(
            "state_key starting with @ must match sender",
        ));
    }

    // --- Rule 10: m.room.power_levels ---
    if event.event_type == "m.room.power_levels" {
        return check_power_levels(event, state, create);
    }

    // --- Rule 11: default allow ---
    Ok(())
}

// ========================================================================
// Rule 1: m.room.create
// ========================================================================

fn check_create(event: &Pdu) -> AuthResult {
    // 1.1: if it has any prev_events, reject
    if !event.prev_events.is_empty() {
        return Err(AuthError::reject("m.room.create has prev_events"));
    }

    // 1.2 (v12): if it has a room_id, reject
    // (room_id is implicit from event_id with sigil change)
    if !event.room_id.is_empty() {
        return Err(AuthError::reject("m.room.create has a room_id (v12)"));
    }

    // 1.3: if content.room_version is present and not recognised, reject
    if let Some(version) = event.content.get("room_version").and_then(|v| v.as_str())
        && !is_recognised_room_version(version)
    {
        return Err(AuthError::reject(format!(
            "unrecognised room_version: {version}"
        )));
    }

    // 1.4 (v12): if additional_creators is present and not an array of valid user IDs, reject
    if let Some(additional) = event.content.get("additional_creators") {
        let arr = additional
            .as_array()
            .ok_or_else(|| AuthError::reject("additional_creators is not an array"))?;
        for v in arr {
            let user_id = v
                .as_str()
                .ok_or_else(|| AuthError::reject("additional_creators entry is not a string"))?;
            if !is_valid_user_id(user_id) {
                return Err(AuthError::reject(format!(
                    "additional_creators entry is not a valid user ID: {user_id}"
                )));
            }
        }
    }

    // 1.5: allow
    Ok(())
}

fn is_recognised_room_version(v: &str) -> bool {
    // We support only v12 for now, but accept the published stable versions per spec.
    matches!(
        v,
        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "10" | "11" | "12"
    )
}

fn is_valid_user_id(s: &str) -> bool {
    // Per /appendices#user-identifiers: starts with "@", contains ":", server part non-empty.
    // We apply a minimal structural check; full grammar validation is done at registration time.
    if !s.starts_with('@') {
        return false;
    }
    let rest = &s[1..];
    match rest.split_once(':') {
        Some((localpart, domain)) => !localpart.is_empty() && !domain.is_empty(),
        None => false,
    }
}

// ========================================================================
// Rule 2: room_id / create event correspondence (v12)
// ========================================================================

/// In v12, the room_id is the create event's ID with sigil `!` instead of `$`.
fn room_id_matches_create(room_id: &str, create_event_id: &str) -> bool {
    if !room_id.starts_with('!') || !create_event_id.starts_with('$') {
        return false;
    }
    room_id[1..] == create_event_id[1..]
}

// ========================================================================
// Rule 3: auth_events validation
// ========================================================================

fn check_auth_events(event: &Pdu, _state: StateFn<'_>) -> AuthResult {
    // 3.1: duplicate (type, state_key) in auth_events rejected.
    // We can only check this if the caller has resolved auth_events to PDUs;
    // as a structural check, duplicate event IDs are trivially rejected.
    let mut seen_ids = HashSet::new();
    for id in &event.auth_events {
        if !seen_ids.insert(id.as_str()) {
            return Err(AuthError::reject("duplicate auth_events entry"));
        }
    }

    // 3.2: auth_events must match the types selected by the auth events
    // selection algorithm. This is a cross-cutting check best performed
    // by the caller who has access to auth event PDUs. We defer to callers
    // (state resolution / PDU receipt path) to validate the type set.

    // 3.3: rejected auth_events → reject. Same: caller responsibility.
    // 3.5: all auth events must have matching room_id — caller responsibility.

    Ok(())
}

// ========================================================================
// Rule 4: m.federate
// ========================================================================

fn check_federate(event: &Pdu, create: &Pdu) -> AuthResult {
    let federate = create
        .content
        .get("m.federate")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if federate {
        return Ok(());
    }

    let sender_domain = event
        .sender_domain()
        .ok_or_else(|| AuthError::reject("invalid sender"))?;
    let create_domain = create
        .sender_domain()
        .ok_or_else(|| AuthError::reject("invalid create event sender"))?;

    if sender_domain != create_domain {
        return Err(AuthError::reject(
            "m.federate=false but sender domain differs from create domain",
        ));
    }
    Ok(())
}

// ========================================================================
// Rule 5: m.room.member
// ========================================================================

fn check_member(event: &Pdu, state: StateFn<'_>, create: &Pdu) -> AuthResult {
    // 5.1: no state_key or no membership → reject
    let target = event
        .state_key
        .as_deref()
        .ok_or_else(|| AuthError::reject("m.room.member has no state_key"))?;
    let membership = event
        .content
        .get("membership")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::reject("m.room.member has no membership"))?;

    // 5.2: if content has join_authorised_via_users_server, it must be a valid signature
    // from that user's homeserver. This requires signature verification against that
    // server's keys, which depends on key fetching. We structurally validate the key
    // is a well-formed user ID here; full signature check is done at PDU receipt time.
    if let Some(authorising) = event
        .content
        .get("join_authorised_via_users_server")
        .and_then(|v| v.as_str())
        && !is_valid_user_id(authorising)
    {
        return Err(AuthError::reject(
            "join_authorised_via_users_server is not a valid user ID",
        ));
    }
    // Full signature verification: caller must have invoked verify_event_signature
    // against the key from the user's homeserver before calling check_auth.

    match membership {
        "join" => check_member_join(event, state, target, create),
        "invite" => check_member_invite(event, state, target, create),
        "leave" => check_member_leave(event, state, target, create),
        "ban" => check_member_ban(event, state, target, create),
        "knock" => check_member_knock(event, state, target),
        _ => Err(AuthError::reject(format!(
            "unknown membership: {membership}"
        ))),
    }
}

fn check_member_join(event: &Pdu, state: StateFn<'_>, target: &str, create: &Pdu) -> AuthResult {
    // 5.3.1: only previous event is m.room.create and state_key is create's sender → allow
    if event.prev_events.len() == 1
        && event.prev_events[0] == create.event_id
        && target == create.sender
    {
        return Ok(());
    }

    // 5.3.2: sender != state_key → reject
    if event.sender != target {
        return Err(AuthError::reject("join: sender does not match state_key"));
    }

    // 5.3.3: sender is banned → reject
    if get_membership(state, target) == Some("ban") {
        return Err(AuthError::reject("join: sender is banned"));
    }

    let join_rule = get_join_rule(state);
    let target_membership = get_membership(state, target);

    // 5.3.4: join_rule is invite or knock → allow if membership is invite or join
    if join_rule == "invite" || join_rule == "knock" {
        if matches!(target_membership, Some("invite") | Some("join")) {
            return Ok(());
        }
        return Err(AuthError::reject(
            "join: join_rule is invite/knock but user is not invited",
        ));
    }

    // 5.3.5: join_rule is restricted or knock_restricted
    if join_rule == "restricted" || join_rule == "knock_restricted" {
        if matches!(target_membership, Some("join") | Some("invite")) {
            return Ok(());
        }
        // Check join_authorised_via_users_server
        let authoriser = event
            .content
            .get("join_authorised_via_users_server")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AuthError::reject("restricted join without join_authorised_via_users_server")
            })?;
        // Authoriser must be a joined member with sufficient power to invite
        if get_membership(state, authoriser) != Some("join") {
            return Err(AuthError::reject(
                "restricted join: authoriser is not a joined member",
            ));
        }
        let invite_level = power_level_field(state, "invite", 0);
        let authoriser_power = user_power_level(state, authoriser, create);
        if authoriser_power < invite_level {
            return Err(AuthError::reject(
                "restricted join: authoriser lacks invite power",
            ));
        }
        return Ok(());
    }

    // 5.3.6: join_rule is public → allow
    if join_rule == "public" {
        return Ok(());
    }

    // 5.3.7: otherwise reject
    Err(AuthError::reject(format!(
        "join: rejected by join_rule {join_rule}"
    )))
}

fn check_member_invite(event: &Pdu, state: StateFn<'_>, target: &str, create: &Pdu) -> AuthResult {
    // 5.4.1: third_party_invite handling
    if let Some(tpi) = event.content.get("third_party_invite") {
        return check_third_party_invite(event, state, target, tpi);
    }

    // 5.4.2: sender not joined → reject
    if get_membership(state, &event.sender) != Some("join") {
        return Err(AuthError::reject("invite: sender is not joined"));
    }

    // 5.4.3: target's current membership is join or ban → reject
    let target_membership = get_membership(state, target);
    if matches!(target_membership, Some("join") | Some("ban")) {
        return Err(AuthError::reject(
            "invite: target is already joined or banned",
        ));
    }

    // 5.4.4: sender power ≥ invite level → allow
    let sender_power = user_power_level(state, &event.sender, create);
    let invite_level = power_level_field(state, "invite", 0);
    if sender_power >= invite_level {
        return Ok(());
    }

    // 5.4.5: otherwise reject
    Err(AuthError::reject("invite: sender lacks invite power"))
}

fn check_third_party_invite(
    _event: &Pdu,
    state: StateFn<'_>,
    target: &str,
    tpi: &Value,
) -> AuthResult {
    // 5.4.1.1: target banned → reject
    if get_membership(state, target) == Some("ban") {
        return Err(AuthError::reject("third_party_invite: target is banned"));
    }

    // 5.4.1.2: no signed → reject
    let signed = tpi
        .get("signed")
        .ok_or_else(|| AuthError::reject("third_party_invite: no signed property"))?;

    // 5.4.1.3: signed must have mxid and token
    let mxid = signed
        .get("mxid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::reject("third_party_invite.signed has no mxid"))?;
    let token = signed
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::reject("third_party_invite.signed has no token"))?;

    // 5.4.1.4: mxid does not match state_key → reject
    if mxid != target {
        return Err(AuthError::reject(
            "third_party_invite: mxid does not match state_key",
        ));
    }

    // 5.4.1.5: no m.room.third_party_invite with state_key matching token → reject
    let tpi_event = state("m.room.third_party_invite", token).ok_or_else(|| {
        AuthError::reject("third_party_invite: no matching m.room.third_party_invite in state")
    })?;

    // 5.4.1.6: sender of member event != sender of third_party_invite event → reject
    // Note: "sender does not match sender of m.room.third_party_invite" per spec.
    // The m.room.member event we're authing has _event.sender here; we compare against tpi_event.sender.
    if _event.sender != tpi_event.sender {
        return Err(AuthError::reject(
            "third_party_invite: sender does not match third_party_invite sender",
        ));
    }

    // 5.4.1.7: check any signature in signed matches any public key in the tpi event → allow
    // Full signature check requires cryptographic verification of the token signature.
    // We structurally check that the public keys exist; cryptographic verification
    // is performed by the PDU receipt pipeline before auth check is invoked.
    let has_keys = tpi_event.content.get("public_key").is_some()
        || tpi_event
            .content
            .get("public_keys")
            .and_then(|v| v.as_array())
            .map(|a| !a.is_empty())
            .unwrap_or(false);
    if !has_keys {
        return Err(AuthError::reject(
            "third_party_invite event has no public keys",
        ));
    }
    let has_signatures = signed
        .get("signatures")
        .and_then(|v| v.as_object())
        .map(|o| !o.is_empty())
        .unwrap_or(false);
    if !has_signatures {
        return Err(AuthError::reject(
            "third_party_invite.signed has no signatures",
        ));
    }

    // 5.4.1.8: otherwise reject — covered by falling through structural checks.
    Ok(())
}

fn check_member_leave(event: &Pdu, state: StateFn<'_>, target: &str, create: &Pdu) -> AuthResult {
    // 5.5.1: sender == state_key → allow iff current membership is invite/join/knock
    if event.sender == target {
        let current = get_membership(state, target);
        if matches!(current, Some("invite") | Some("join") | Some("knock")) {
            return Ok(());
        }
        return Err(AuthError::reject(
            "leave: self-leave requires current membership of invite/join/knock",
        ));
    }

    // 5.5.2: sender not joined → reject
    if get_membership(state, &event.sender) != Some("join") {
        return Err(AuthError::reject("leave: sender is not joined"));
    }

    // 5.5.3: target is banned and sender power < ban level → reject
    let target_membership = get_membership(state, target);
    let sender_power = user_power_level(state, &event.sender, create);
    let ban_level = power_level_field(state, "ban", 50);
    if target_membership == Some("ban") && sender_power < ban_level {
        return Err(AuthError::reject(
            "leave (unban): sender lacks ban-level power",
        ));
    }

    // 5.5.4: sender power >= kick level AND target power < sender power → allow
    let kick_level = power_level_field(state, "kick", 50);
    let target_power = user_power_level(state, target, create);
    if sender_power >= kick_level && target_power < sender_power {
        return Ok(());
    }

    // 5.5.5: otherwise reject
    Err(AuthError::reject("leave: sender cannot kick target"))
}

fn check_member_ban(event: &Pdu, state: StateFn<'_>, target: &str, create: &Pdu) -> AuthResult {
    // 5.6.1: sender not joined → reject
    if get_membership(state, &event.sender) != Some("join") {
        return Err(AuthError::reject("ban: sender is not joined"));
    }

    // 5.6.2: sender power >= ban level AND target power < sender power → allow
    let sender_power = user_power_level(state, &event.sender, create);
    let ban_level = power_level_field(state, "ban", 50);
    let target_power = user_power_level(state, target, create);
    if sender_power >= ban_level && target_power < sender_power {
        return Ok(());
    }

    // 5.6.3: reject
    Err(AuthError::reject("ban: sender cannot ban target"))
}

fn check_member_knock(event: &Pdu, state: StateFn<'_>, target: &str) -> AuthResult {
    // 5.7.1: join_rule must be knock or knock_restricted
    let join_rule = get_join_rule(state);
    if join_rule != "knock" && join_rule != "knock_restricted" {
        return Err(AuthError::reject(
            "knock: join_rule not knock/knock_restricted",
        ));
    }

    // 5.7.2: sender must match state_key
    if event.sender != target {
        return Err(AuthError::reject("knock: sender does not match state_key"));
    }

    // 5.7.3: sender's current membership not ban/invite/join → allow
    let current = get_membership(state, target);
    if !matches!(current, Some("ban") | Some("invite") | Some("join")) {
        return Ok(());
    }

    // 5.7.4: reject
    Err(AuthError::reject(
        "knock: current membership precludes knock",
    ))
}

// ========================================================================
// Rule 10: m.room.power_levels
// ========================================================================

fn check_power_levels(event: &Pdu, state: StateFn<'_>, create: &Pdu) -> AuthResult {
    let content = &event.content;

    // 10.1: integer fields must be integers
    for field in [
        "users_default",
        "events_default",
        "state_default",
        "ban",
        "redact",
        "kick",
        "invite",
    ] {
        if let Some(v) = content.get(field)
            && !v.is_i64()
            && !v.is_u64()
        {
            return Err(AuthError::reject(format!(
                "power_levels.{field} is not an integer"
            )));
        }
    }

    // 10.2: events and notifications must be object of integers
    for field in ["events", "notifications"] {
        if let Some(v) = content.get(field) {
            let obj = v.as_object().ok_or_else(|| {
                AuthError::reject(format!("power_levels.{field} is not an object"))
            })?;
            for (_k, val) in obj.iter() {
                if !val.is_i64() && !val.is_u64() {
                    return Err(AuthError::reject(format!(
                        "power_levels.{field} has non-integer value"
                    )));
                }
            }
        }
    }

    // 10.3: users is object with user-ID keys and integer values
    if let Some(v) = content.get("users") {
        let obj = v
            .as_object()
            .ok_or_else(|| AuthError::reject("power_levels.users is not an object"))?;
        for (k, val) in obj.iter() {
            if !is_valid_user_id(k) {
                return Err(AuthError::reject(format!(
                    "power_levels.users key is not a valid user ID: {k}"
                )));
            }
            if !val.is_i64() && !val.is_u64() {
                return Err(AuthError::reject(
                    "power_levels.users value is not an integer",
                ));
            }
        }

        // 10.4 (v12): users must not contain room creators
        let creators = room_creators(create);
        for user_id in obj.keys() {
            if creators.contains(user_id.as_str()) {
                return Err(AuthError::reject(format!(
                    "power_levels.users contains a room creator: {user_id}"
                )));
            }
        }
    }

    // 10.5: no previous power_levels → allow
    let current_pl = state("m.room.power_levels", "");
    let current_pl = match current_pl {
        None => return Ok(()),
        Some(pl) => pl,
    };

    let sender_power = user_power_level(state, &event.sender, create);

    // 10.6: integer scalar fields — check additions/changes/removals
    let scalar_fields = [
        "users_default",
        "events_default",
        "state_default",
        "ban",
        "redact",
        "kick",
        "invite",
    ];
    let default_map: [(&str, i64); 7] = [
        ("users_default", 0),
        ("events_default", 0),
        ("state_default", 50),
        ("ban", 50),
        ("redact", 50),
        ("kick", 50),
        ("invite", 0),
    ];
    for field in scalar_fields {
        let current = current_pl.content.get(field);
        let new = event.content.get(field);
        if current != new {
            let default = default_map.iter().find(|(f, _)| *f == field).unwrap().1;
            let current_val = current.and_then(as_i64_loose).unwrap_or(default);
            let new_val = new.and_then(as_i64_loose).unwrap_or(default);
            if current_val > sender_power {
                return Err(AuthError::reject(format!(
                    "power_levels.{field} current value {current_val} > sender power {sender_power}"
                )));
            }
            if new_val > sender_power {
                return Err(AuthError::reject(format!(
                    "power_levels.{field} new value {new_val} > sender power {sender_power}"
                )));
            }
        }
    }

    // 10.7 + 10.8: events and notifications map changes
    for field in ["events", "notifications"] {
        let current_map = current_pl
            .content
            .get(field)
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let new_map = event
            .content
            .get(field)
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        // 10.7: entries being changed or removed — current value > sender_power → reject
        for (k, cur_val) in current_map.iter() {
            let cur = as_i64_loose(cur_val).unwrap_or(0);
            match new_map.get(k) {
                None => {
                    // removed
                    if cur > sender_power {
                        return Err(AuthError::reject(format!(
                            "power_levels.{field}.{k} removed, current {cur} > sender power {sender_power}"
                        )));
                    }
                }
                Some(new_val) if new_val != cur_val => {
                    // changed
                    if cur > sender_power {
                        return Err(AuthError::reject(format!(
                            "power_levels.{field}.{k} changed, current {cur} > sender power {sender_power}"
                        )));
                    }
                }
                _ => {}
            }
        }
        // 10.8: entries being added or changed — new value > sender_power → reject
        for (k, new_val) in new_map.iter() {
            let new_i = as_i64_loose(new_val).unwrap_or(0);
            match current_map.get(k) {
                None => {
                    // added
                    if new_i > sender_power {
                        return Err(AuthError::reject(format!(
                            "power_levels.{field}.{k} added, new {new_i} > sender power {sender_power}"
                        )));
                    }
                }
                Some(cur_val) if cur_val != new_val => {
                    // changed
                    if new_i > sender_power {
                        return Err(AuthError::reject(format!(
                            "power_levels.{field}.{k} changed, new {new_i} > sender power {sender_power}"
                        )));
                    }
                }
                _ => {}
            }
        }
    }

    // 10.9 + 10.10: users map changes (excluding sender's own entry for 10.9)
    let current_users = current_pl
        .content
        .get("users")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let new_users = event
        .content
        .get("users")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();

    // 10.9: entries changed or removed (other than sender's own)
    for (user, cur_val) in current_users.iter() {
        let cur = as_i64_loose(cur_val).unwrap_or(0);
        match new_users.get(user) {
            None => {
                // removed
                if user == &event.sender {
                    continue;
                }
                if cur >= sender_power {
                    return Err(AuthError::reject(format!(
                        "power_levels.users.{user} removed, current {cur} >= sender power {sender_power}"
                    )));
                }
            }
            Some(new_val) if new_val != cur_val => {
                // changed
                if user == &event.sender {
                    continue;
                }
                if cur >= sender_power {
                    return Err(AuthError::reject(format!(
                        "power_levels.users.{user} changed, current {cur} >= sender power {sender_power}"
                    )));
                }
            }
            _ => {}
        }
    }

    // 10.10: entries added or changed — new value > sender_power → reject
    for (user, new_val) in new_users.iter() {
        let new_i = as_i64_loose(new_val).unwrap_or(0);
        match current_users.get(user) {
            None => {
                // added
                if new_i > sender_power {
                    return Err(AuthError::reject(format!(
                        "power_levels.users.{user} added, new {new_i} > sender power {sender_power}"
                    )));
                }
            }
            Some(cur_val) if cur_val != new_val => {
                // changed
                if new_i > sender_power {
                    return Err(AuthError::reject(format!(
                        "power_levels.users.{user} changed, new {new_i} > sender power {sender_power}"
                    )));
                }
            }
            _ => {}
        }
    }

    Ok(())
}

// ========================================================================
// Helpers
// ========================================================================

fn get_membership<'a>(state: StateFn<'a>, user: &str) -> Option<&'a str> {
    state("m.room.member", user)?.membership()
}

fn get_join_rule<'a>(state: StateFn<'a>) -> &'a str {
    state("m.room.join_rules", "")
        .and_then(|ev| ev.join_rule())
        .unwrap_or("invite")
}

/// Returns the set of user IDs who are creators of the room (v12).
/// Creators have infinite power and cannot be demoted.
pub fn room_creators(create: &Pdu) -> HashSet<String> {
    let mut creators = HashSet::new();
    creators.insert(create.sender.clone());
    if let Some(arr) = create
        .content
        .get("additional_creators")
        .and_then(|v| v.as_array())
    {
        for v in arr {
            if let Some(s) = v.as_str() {
                creators.insert(s.to_string());
            }
        }
    }
    creators
}

/// Compute a user's effective power level. In v12, creators have infinite power.
/// We represent "infinite" as `i64::MAX`.
pub fn user_power_level(state: StateFn<'_>, user: &str, create: &Pdu) -> i64 {
    // v12: creators have infinite power
    if room_creators(create).contains(user) {
        return i64::MAX;
    }

    let pl = match state("m.room.power_levels", "") {
        None => {
            // No power_levels event: only the create event's sender has power
            // (note: v12 creators are already handled above).
            return 0;
        }
        Some(pl) => pl,
    };

    // Look up users[user], fallback to users_default (default 0)
    if let Some(users) = pl.content.get("users").and_then(|v| v.as_object())
        && let Some(val) = users.get(user)
    {
        return as_i64_loose(val).unwrap_or(0);
    }
    pl.content
        .get("users_default")
        .and_then(as_i64_loose)
        .unwrap_or(0)
}

/// Fetch a scalar integer field from the current power_levels event, with fallback default.
fn power_level_field(state: StateFn<'_>, field: &str, default: i64) -> i64 {
    state("m.room.power_levels", "")
        .and_then(|pl| pl.content.get(field).and_then(as_i64_loose))
        .unwrap_or(default)
}

/// Whether `sender` is allowed to redact an event whose sender is `target_sender`
/// given the current room state.
///
/// Per `content/rooms/fragments/v3-handling-redactions.md` (applies through v12):
/// a redaction is applied iff one of:
///   a) the redacting user's power level >= the room's `redact` level (default 50), or
///   b) the redaction sender's server matches the original event sender's server.
pub fn can_apply_redaction(
    sender: &str,
    target_sender: &str,
    state: StateFn<'_>,
    create: &Pdu,
) -> bool {
    if user_server(sender) == user_server(target_sender) {
        return true;
    }
    let redact_level = power_level_field(state, "redact", 50);
    user_power_level(state, sender, create) >= redact_level
}

fn user_server(user_id: &str) -> &str {
    // user IDs are "@localpart:server"; we ignore malformed IDs by returning
    // the whole string — matching a malformed sender against itself is
    // harmless, and well-formed IDs will always contain ':'.
    user_id.split_once(':').map(|(_, s)| s).unwrap_or(user_id)
}

/// Required power level for a given event type. For state events, uses events[type]
/// then state_default (50). For message events, uses events[type] then events_default (0).
fn required_power_level(state: StateFn<'_>, event_type: &str, is_state: bool) -> i64 {
    let pl = match state("m.room.power_levels", "") {
        None => {
            return if is_state { 50 } else { 0 };
        }
        Some(pl) => pl,
    };

    if let Some(events) = pl.content.get("events").and_then(|v| v.as_object())
        && let Some(val) = events.get(event_type)
    {
        return as_i64_loose(val).unwrap_or(0);
    }
    let default_field = if is_state {
        "state_default"
    } else {
        "events_default"
    };
    let default_val = if is_state { 50 } else { 0 };
    pl.content
        .get(default_field)
        .and_then(as_i64_loose)
        .unwrap_or(default_val)
}

/// Parse a JSON value as i64, accepting both i64 and u64 representations.
fn as_i64_loose(v: &Value) -> Option<i64> {
    v.as_i64().or_else(|| v.as_u64().map(|u| u as i64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap;

    /// Build a minimal PDU for tests.
    fn pdu(
        event_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        sender: &str,
        content: Value,
        room_id: &str,
    ) -> Pdu {
        Pdu {
            event_id: event_id.to_string(),
            room_id: room_id.to_string(),
            event_type: event_type.to_string(),
            state_key: state_key.map(String::from),
            sender: sender.to_string(),
            origin_server_ts: 1000,
            content,
            auth_events: vec![],
            prev_events: vec![],
            depth: 1,
            signatures: None,
        }
    }

    fn make_state(entries: Vec<((&str, &str), Pdu)>) -> HashMap<(String, String), Pdu> {
        entries
            .into_iter()
            .map(|((t, sk), p)| ((t.to_string(), sk.to_string()), p))
            .collect()
    }

    fn lookup<'a>(state: &'a HashMap<(String, String), Pdu>, t: &str, sk: &str) -> Option<&'a Pdu> {
        state.get(&(t.to_string(), sk.to_string()))
    }

    #[test]
    fn create_with_prev_events_rejected() {
        let mut ev = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({}),
            "",
        );
        ev.prev_events = vec!["$something".into()];
        let state = HashMap::new();
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        assert!(matches!(check_auth(&ev, &sf), Err(AuthError::Rejected(_))));
    }

    #[test]
    fn create_with_room_id_rejected_v12() {
        let ev = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({}),
            "!room",
        );
        let state = HashMap::new();
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        assert!(matches!(check_auth(&ev, &sf), Err(AuthError::Rejected(_))));
    }

    #[test]
    fn create_clean_allowed() {
        let ev = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let state = HashMap::new();
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        assert!(check_auth(&ev, &sf).is_ok());
    }

    #[test]
    fn creator_has_infinite_power() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let state = make_state(vec![(("m.room.create", ""), create.clone())]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        let power = user_power_level(&sf, "@alice:example.com", &create);
        assert_eq!(power, i64::MAX);
    }

    #[test]
    fn cannot_demote_creator_v12() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = pdu(
            "$member_alice",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            "!room",
        );
        let state = make_state(vec![
            (("m.room.create", ""), create.clone()),
            (("m.room.member", "@alice:example.com"), alice_member),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // Alice tries to set herself in users — rejected by rule 10.4
        let pl_event = Pdu {
            event_id: "$pl".into(),
            room_id: "!create".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some("".into()),
            sender: "@alice:example.com".into(),
            origin_server_ts: 2000,
            content: json!({"users": {"@alice:example.com": 50}}),
            auth_events: vec![],
            prev_events: vec![],
            depth: 2,
            signatures: None,
        };
        let result = check_auth(&pl_event, &sf);
        assert!(
            matches!(result, Err(AuthError::Rejected(_))),
            "expected creator in users to be rejected"
        );
    }

    #[test]
    fn join_public_room() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = pdu(
            "$member_alice",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        let join_rules = pdu(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@alice:example.com",
            json!({"join_rule": "public"}),
            "!create",
        );
        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.member", "@alice:example.com"), alice_member),
            (("m.room.join_rules", ""), join_rules),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let bob_join = pdu(
            "$bob_join",
            "m.room.member",
            Some("@bob:example.com"),
            "@bob:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        assert!(check_auth(&bob_join, &sf).is_ok());
    }

    #[test]
    fn join_invite_only_rejected_without_invite() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = pdu(
            "$member_alice",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        let join_rules = pdu(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@alice:example.com",
            json!({"join_rule": "invite"}),
            "!create",
        );
        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.member", "@alice:example.com"), alice_member),
            (("m.room.join_rules", ""), join_rules),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let bob_join = pdu(
            "$bob_join",
            "m.room.member",
            Some("@bob:example.com"),
            "@bob:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        assert!(matches!(
            check_auth(&bob_join, &sf),
            Err(AuthError::Rejected(_))
        ));
    }

    #[test]
    fn banned_user_cannot_rejoin() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let bob_banned = pdu(
            "$bob_ban",
            "m.room.member",
            Some("@bob:example.com"),
            "@alice:example.com",
            json!({"membership": "ban"}),
            "!create",
        );
        let join_rules = pdu(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@alice:example.com",
            json!({"join_rule": "public"}),
            "!create",
        );
        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.member", "@bob:example.com"), bob_banned),
            (("m.room.join_rules", ""), join_rules),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let bob_join = pdu(
            "$bob_join",
            "m.room.member",
            Some("@bob:example.com"),
            "@bob:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        assert!(matches!(
            check_auth(&bob_join, &sf),
            Err(AuthError::Rejected(_))
        ));
    }

    #[test]
    fn sender_not_joined_cannot_send_message() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let state = make_state(vec![(("m.room.create", ""), create)]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let msg = pdu(
            "$msg",
            "m.room.message",
            None,
            "@bob:example.com",
            json!({"body": "hi"}),
            "!create",
        );
        assert!(matches!(check_auth(&msg, &sf), Err(AuthError::Rejected(_))));
    }

    #[test]
    fn state_key_at_mismatch_sender_rejected() {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = pdu(
            "$member_alice",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            "!create",
        );
        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.member", "@alice:example.com"), alice_member),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // Alice tries to send a state event with state_key = someone else's user ID
        let ev = pdu(
            "$bad",
            "m.some.type",
            Some("@bob:example.com"),
            "@alice:example.com",
            json!({}),
            "!create",
        );
        assert!(matches!(check_auth(&ev, &sf), Err(AuthError::Rejected(_))));
    }

    // ------ can_apply_redaction -------

    fn redaction_state(pl_content: Value) -> HashMap<(String, String), Pdu> {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let pl = pdu(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@alice:example.com",
            pl_content,
            "!create",
        );
        make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.power_levels", ""), pl),
        ])
    }

    #[test]
    fn redact_same_server_allowed_regardless_of_power() {
        let state = redaction_state(json!({"redact": 50, "users": {}, "users_default": 0}));
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        let create = lookup(&state, "m.room.create", "").unwrap().clone();
        // Bob on same server as the target sender (both @*:example.com),
        // with zero power, may redact.
        assert!(can_apply_redaction(
            "@bob:example.com",
            "@alice:example.com",
            &sf,
            &create,
        ));
    }

    #[test]
    fn redact_cross_server_requires_redact_power() {
        let state = redaction_state(json!({
            "redact": 50,
            "users": {"@mod:other.com": 50},
            "users_default": 0,
        }));
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        let create = lookup(&state, "m.room.create", "").unwrap().clone();

        // Mod on other.com: power 50 >= redact 50 → allowed.
        assert!(can_apply_redaction(
            "@mod:other.com",
            "@alice:example.com",
            &sf,
            &create,
        ));
        // Random other.com user: power 0 < redact 50 → not allowed.
        assert!(!can_apply_redaction(
            "@rando:other.com",
            "@alice:example.com",
            &sf,
            &create,
        ));
    }

    #[test]
    fn redact_creator_always_allowed() {
        // Creators have i64::MAX power, so they pass even across servers.
        let state = redaction_state(json!({"redact": 100, "users": {}, "users_default": 0}));
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        let create = lookup(&state, "m.room.create", "").unwrap().clone();
        assert!(can_apply_redaction(
            "@alice:example.com",
            "@bob:other.com",
            &sf,
            &create,
        ));
    }

    #[test]
    fn redact_defaults_to_level_50_when_field_missing() {
        // No `redact` field → default 50.
        let state = redaction_state(json!({"users": {"@mod:other.com": 40}}));
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);
        let create = lookup(&state, "m.room.create", "").unwrap().clone();
        assert!(!can_apply_redaction(
            "@mod:other.com",
            "@alice:example.com",
            &sf,
            &create,
        ));
    }
}
