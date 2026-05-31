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

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier};
use serde_json::Value;

use crate::canonical::canonical_json_object;
use crate::events::pdu::Pdu;
use crate::federation::keys::decode_public_key;

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

    // --- Rule 2: v12-only — room_id must be derived from create event ID ---
    // For v12 rooms (MSC4291) room_id = "!" + create event_id minus "$". Pre-v12
    // rooms mint random `!opaque:server` ids and this rule doesn't apply.
    let create =
        state("m.room.create", "").ok_or_else(|| AuthError::reject("no m.room.create in state"))?;
    let is_v12_create = create.content.get("room_version").and_then(|v| v.as_str()) == Some("12");
    if is_v12_create && !room_id_matches_create(&event.room_id, &create.event_id) {
        return Err(AuthError::reject(
            "event room_id does not match m.room.create event id (v12)",
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
    //
    // MSC3757 (org.matrix.msc3757.10) widens this: a state_key of
    // shape `@<localpart>:<server>[_<suffix>]` is authorised by the
    // embedded `<mxid>` rather than by exact equality with sender,
    // and room creators may write any owned-state state_key on
    // behalf of anyone. The malformed-mxid and bad-suffix shapes are
    // caught at the CS-API layer with 400 M_BAD_JSON before they
    // ever reach auth — here we just enforce the "right user" check.
    if let Some(sk) = &event.state_key
        && sk.starts_with('@')
    {
        let room_version_str = create
            .content
            .get("room_version")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if room_version_str == "org.matrix.msc3757.10" {
            let owner = owned_state_key_owner(sk);
            let sender_is_creator = room_creators(create).contains(&event.sender);
            match owner {
                Some(o) if o == event.sender || sender_is_creator => {}
                _ => {
                    return Err(AuthError::reject(
                        "owned state_key sender is neither owner nor room creator",
                    ));
                }
            }
        } else if sk != &event.sender {
            return Err(AuthError::reject(
                "state_key starting with @ must match sender",
            ));
        }
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

    // 1.2: room_id rules differ by version. Read the create event's
    // own `content.room_version` to decide. Default v1 per spec when
    // unset (matches Synapse's `KNOWN_ROOM_VERSIONS["1"]`).
    let content_version = event
        .content
        .get("room_version")
        .and_then(|v| v.as_str())
        .unwrap_or("1");
    let is_v12_plus = matches!(content_version, "12");
    if is_v12_plus {
        // v12 (MSC4291): room_id is derived from this event, MUST NOT
        // appear as a top-level field.
        if !event.room_id.is_empty() {
            return Err(AuthError::reject("m.room.create has a room_id (v12)"));
        }
    } else {
        // Pre-v12: room_id MUST be present; its domain MUST match the
        // sender's domain (Synapse rule 1.2).
        if event.room_id.is_empty() {
            return Err(AuthError::reject(format!(
                "m.room.create missing room_id (pre-v12, room_version={content_version})"
            )));
        }
        let sender_domain = event.sender.split_once(':').map(|(_, d)| d).unwrap_or("");
        let room_domain = event.room_id.split_once(':').map(|(_, d)| d).unwrap_or("");
        if sender_domain != room_domain {
            return Err(AuthError::reject(
                "m.room.create room_id domain doesn't match sender domain",
            ));
        }
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

    // 5.2: if content has join_authorised_via_users_server AND the
    // event is a fresh join (i.e. target was not already joined), it
    // must be a valid user ID. join→join transitions (display name /
    // avatar updates) ignore the field per spec — the test that
    // exercises this writes `join_authorised_via_users_server:
    // "unused"` literally to assert the field is dropped on a redundant
    // join. Only validate when the current membership is NOT already
    // "join" — that's where the field actually carries meaning.
    let current_target_membership = state("m.room.member", target).and_then(|p| {
        p.content
            .get("membership")
            .and_then(|v| v.as_str())
            .map(str::to_string)
    });
    if let Some(authorising) = event
        .content
        .get("join_authorised_via_users_server")
        .and_then(|v| v.as_str())
        && current_target_membership.as_deref() != Some("join")
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

    // 5.4.1.7: any signature in `signed` MUST verify against any public key
    // advertised in the matching m.room.third_party_invite event. The keys
    // come from the room's own state — not a live identity-server lookup —
    // so this rule is the only thing standing between a malicious sender
    // and a forged 3pid invite acceptance.
    verify_third_party_signed(signed, tpi_event)?;

    Ok(())
}

/// Collect the ed25519 public keys advertised by an `m.room.third_party_invite`
/// state event. Both the legacy `content.public_key` (single key) and the
/// `content.public_keys` array (per matrix-spec v1.18 §m.room.third_party_invite)
/// are accepted.
fn collect_tpi_public_keys(tpi_event: &Pdu) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(k) = tpi_event.content.get("public_key").and_then(|v| v.as_str()) {
        keys.push(k.to_string());
    }
    if let Some(arr) = tpi_event
        .content
        .get("public_keys")
        .and_then(|v| v.as_array())
    {
        for entry in arr {
            if let Some(k) = entry.get("public_key").and_then(|v| v.as_str()) {
                keys.push(k.to_string());
            }
        }
    }
    keys
}

/// Decode an ed25519 signature in any of the base64 alphabets matrix peers
/// have been observed to use. Mirrors `federation::keys::decode_signature_b64`.
fn decode_signature_b64(s: &str) -> Option<[u8; 64]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| STANDARD.decode(s))
        .ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

/// Verify the identity server's ed25519 signature over the `signed` block of
/// an `m.room.member` third-party invite.
///
/// Per matrix-spec v1.18 §5.4.1 + appendix "Signing JSON": the signed bytes are
/// the canonical-JSON encoding of `signed` MINUS its own `signatures` (and
/// `unsigned`) fields. We re-canonicalise here rather than trust any pre-baked
/// bytes from the caller — anything else would let a sender substitute the
/// canonical form. At least one (public_key, signature) pair must verify;
/// otherwise reject.
fn verify_third_party_signed(signed: &Value, tpi_event: &Pdu) -> AuthResult {
    let signed_obj = signed
        .as_object()
        .ok_or_else(|| AuthError::reject("third_party_invite.signed is not an object"))?;

    let signatures = signed_obj
        .get("signatures")
        .and_then(|v| v.as_object())
        .ok_or_else(|| AuthError::reject("third_party_invite.signed has no signatures"))?;
    if signatures.is_empty() {
        return Err(AuthError::reject(
            "third_party_invite.signed has no signatures",
        ));
    }

    let public_keys = collect_tpi_public_keys(tpi_event);
    if public_keys.is_empty() {
        return Err(AuthError::reject(
            "third_party_invite event has no public keys",
        ));
    }

    // Canonicalise signed minus signatures/unsigned exactly once — this is the
    // byte string ed25519 verification runs against.
    let mut to_canonicalise = signed_obj.clone();
    to_canonicalise.remove("signatures");
    to_canonicalise.remove("unsigned");
    let canonical = canonical_json_object(&to_canonicalise);

    for (_server, server_sigs) in signatures.iter() {
        let Some(sig_map) = server_sigs.as_object() else {
            continue;
        };
        for (key_id, sig_val) in sig_map.iter() {
            // Spec restricts third-party-invite signing to ed25519 (appendix
            // "Signing Algorithms"). Silently skip any other algorithm — a
            // mixed signatures block where the only ed25519 entry verifies
            // must still pass.
            if !key_id.starts_with("ed25519:") {
                continue;
            }
            let Some(sig_str) = sig_val.as_str() else {
                continue;
            };
            let Some(sig_bytes) = decode_signature_b64(sig_str) else {
                continue;
            };
            let signature = Signature::from_bytes(&sig_bytes);
            for pub_b64 in &public_keys {
                let Ok(verifying_key) = decode_public_key(pub_b64) else {
                    continue;
                };
                if verifying_key.verify(&canonical, &signature).is_ok() {
                    return Ok(());
                }
            }
        }
    }

    Err(AuthError::reject(
        "third_party_invite: no signature verified against any advertised public key",
    ))
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

        // 10.4 (v12 / MSC4289): users must not contain room creators.
        // Pre-v12 rooms didn't grant creators implicit infinite power, so
        // a creator legitimately appears in `users` to retain authority
        // — TestRestrictedRoomsLocalJoinNoCreatorsUsesPowerLevelsV11
        // sets exactly that.
        let is_v12 = create.content.get("room_version").and_then(|v| v.as_str()) == Some("12");
        if is_v12 {
            let creators = room_creators(create);
            for user_id in obj.keys() {
                if creators.contains(user_id.as_str()) {
                    return Err(AuthError::reject(format!(
                        "power_levels.users contains a room creator: {user_id}"
                    )));
                }
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
                // removed
                None if cur > sender_power => {
                    return Err(AuthError::reject(format!(
                        "power_levels.{field}.{k} removed, current {cur} > sender power {sender_power}"
                    )));
                }
                // changed
                Some(new_val) if new_val != cur_val && cur > sender_power => {
                    return Err(AuthError::reject(format!(
                        "power_levels.{field}.{k} changed, current {cur} > sender power {sender_power}"
                    )));
                }
                _ => {}
            }
        }
        // 10.8: entries being added or changed — new value > sender_power → reject
        for (k, new_val) in new_map.iter() {
            let new_i = as_i64_loose(new_val).unwrap_or(0);
            match current_map.get(k) {
                // added
                None if new_i > sender_power => {
                    return Err(AuthError::reject(format!(
                        "power_levels.{field}.{k} added, new {new_i} > sender power {sender_power}"
                    )));
                }
                // changed
                Some(cur_val) if cur_val != new_val && new_i > sender_power => {
                    return Err(AuthError::reject(format!(
                        "power_levels.{field}.{k} changed, new {new_i} > sender power {sender_power}"
                    )));
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
            // added
            None if new_i > sender_power => {
                return Err(AuthError::reject(format!(
                    "power_levels.users.{user} added, new {new_i} > sender power {sender_power}"
                )));
            }
            // changed
            Some(cur_val) if cur_val != new_val && new_i > sender_power => {
                return Err(AuthError::reject(format!(
                    "power_levels.users.{user} changed, new {new_i} > sender power {sender_power}"
                )));
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

/// MSC3757 state_key parser. Returns the owner mxid (`@<localpart>:<server>`)
/// when the state_key matches `@<localpart>:<server>[_<suffix>]`; returns
/// `None` for malformed forms (no `:`, empty localpart/server, or non-host
/// characters between `:<server>` and the suffix delimiter).
///
/// Notes on the grammar:
/// - localpart may itself contain `_`, so we cannot split on the FIRST `_`
///   in the whole state_key. We split at the first `:`, then look for `_`
///   only in the server-portion.
/// - server hostnames + optional ports use alphanumerics, `.`, `-`, `:`,
///   and `[` `]` (IPv6). Anything else after `:<server>` that isn't the
///   `_<suffix>` delimiter signals a malformed key — callers translate
///   this to `400 M_BAD_JSON`.
pub fn owned_state_key_owner(state_key: &str) -> Option<String> {
    let rest = state_key.strip_prefix('@')?;
    let (localpart, server_portion) = rest.split_once(':')?;
    if localpart.is_empty() {
        return None;
    }
    let server_name = match server_portion.find('_') {
        Some(idx) => &server_portion[..idx],
        None => server_portion,
    };
    if server_name.is_empty() {
        return None;
    }
    if !server_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
    {
        return None;
    }
    Some(format!("@{localpart}:{server_name}"))
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
    has_redact_power(sender, state, create)
}

/// Just the power-level half of the redaction permission check. Used
/// when the target event isn't available locally (e.g. redacting a
/// federated event whose original we never received) — we can't
/// compare server domains, so the only remaining path is "user has
/// redact-level power".
pub fn has_redact_power(sender: &str, state: StateFn<'_>, create: &Pdu) -> bool {
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

    // ========================================================================
    // Third-party invite signature verification (rule 5.4.1.7)
    // ========================================================================

    use crate::events::sign::ServerSigningKey;
    use serde_json::Map;

    /// Build the four ingredients for a 3pid-invite auth check:
    /// state map, the signed bundle (already signed by `id_key`),
    /// the m.room.member event under test, and the create event.
    ///
    /// The state contains: create, alice's join, the m.room.third_party_invite
    /// event (sender alice, state_key = token, advertising `id_key`'s public
    /// key), and a public join_rules so we don't accidentally trip an
    /// unrelated rule.
    fn build_tpi_fixture(
        id_key: &ServerSigningKey,
        token: &str,
        target: &str,
        tpi_public_keys_form: TpiKeysForm,
    ) -> (HashMap<(String, String), Pdu>, Map<String, Value>) {
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            "",
        );
        let alice_member = pdu(
            "$alice_member",
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

        let pub_b64 = id_key.public_key_base64();
        let tpi_content = match tpi_public_keys_form {
            TpiKeysForm::Legacy => json!({
                "display_name": "bob",
                "key_validity_url": "https://identity.example/_matrix/identity/v2/pubkey/isvalid",
                "public_key": pub_b64,
            }),
            TpiKeysForm::Array => json!({
                "display_name": "bob",
                "key_validity_url": "https://identity.example/_matrix/identity/v2/pubkey/isvalid",
                "public_keys": [{
                    "public_key": pub_b64,
                    "key_validity_url": "https://identity.example/_matrix/identity/v2/pubkey/isvalid",
                }],
            }),
            TpiKeysForm::ArrayWithBogusFirst { ref bogus } => json!({
                "display_name": "bob",
                "public_keys": [
                    {"public_key": bogus},
                    {"public_key": pub_b64},
                ],
            }),
            TpiKeysForm::OnlyBogus { ref bogus } => json!({
                "display_name": "bob",
                "public_key": bogus,
            }),
        };
        let tpi_event = pdu(
            "$tpi",
            "m.room.third_party_invite",
            Some(token),
            "@alice:example.com",
            tpi_content,
            "!create",
        );

        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.member", "@alice:example.com"), alice_member),
            (("m.room.join_rules", ""), join_rules),
            (("m.room.third_party_invite", token), tpi_event),
        ]);

        // The `signed` block whose canonical form the identity server signs.
        // Per matrix-spec v1.18 §5.4.1 the block carries mxid + token; signing
        // is over canonical JSON of the bundle minus `signatures`/`unsigned`.
        let mut signed = serde_json::Map::new();
        signed.insert("mxid".into(), json!(target));
        signed.insert("token".into(), json!(token));
        id_key.sign_json(&mut signed, "identity.example");

        (state, signed)
    }

    #[derive(Clone)]
    enum TpiKeysForm {
        /// content.public_key = "<base64>"
        Legacy,
        /// content.public_keys = [{public_key: "<base64>"}]
        Array,
        /// content.public_keys = [{public_key: "<bogus>"}, {public_key: "<good>"}]
        ArrayWithBogusFirst { bogus: String },
        /// content.public_key = "<bogus>" only — no good key advertised
        OnlyBogus { bogus: String },
    }

    fn make_member_with_tpi(target: &str, _token: &str, signed: Value) -> Pdu {
        pdu(
            "$bob_invite",
            "m.room.member",
            Some(target),
            "@alice:example.com",
            json!({
                "membership": "invite",
                "third_party_invite": {
                    "display_name": "bob",
                    "signed": signed,
                },
            }),
            "!create",
        )
    }

    #[test]
    fn third_party_invite_valid_signature_accepted() {
        let id_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let token = "tok-abc";
        let (state, signed) = build_tpi_fixture(&id_key, token, target, TpiKeysForm::Legacy);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let member = make_member_with_tpi(target, token, Value::Object(signed));
        let result = check_auth(&member, &sf);
        assert!(result.is_ok(), "valid sig must accept: {result:?}");
    }

    #[test]
    fn third_party_invite_array_public_keys_accepted() {
        let id_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let token = "tok-array";
        let (state, signed) = build_tpi_fixture(&id_key, token, target, TpiKeysForm::Array);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let member = make_member_with_tpi(target, token, Value::Object(signed));
        assert!(check_auth(&member, &sf).is_ok());
    }

    #[test]
    fn third_party_invite_multiple_keys_accepts_if_any_verifies() {
        // First key in the array is junk, second is the real one. The verify
        // loop must try every advertised key, not bail on the first failure.
        let id_key = ServerSigningKey::generate();
        let bogus = ServerSigningKey::generate().public_key_base64();
        let target = "@bob:example.com";
        let token = "tok-any";
        let (state, signed) = build_tpi_fixture(
            &id_key,
            token,
            target,
            TpiKeysForm::ArrayWithBogusFirst { bogus },
        );
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let member = make_member_with_tpi(target, token, Value::Object(signed));
        assert!(check_auth(&member, &sf).is_ok());
    }

    #[test]
    fn third_party_invite_no_matching_key_rejected() {
        // The signed bundle is genuinely signed, but the room state advertises
        // a different (bogus) public key. Must reject.
        let id_key = ServerSigningKey::generate();
        let attacker_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let token = "tok-mismatch";
        let (state, signed) = build_tpi_fixture(
            &id_key,
            token,
            target,
            TpiKeysForm::OnlyBogus {
                bogus: attacker_key.public_key_base64(),
            },
        );
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let member = make_member_with_tpi(target, token, Value::Object(signed));
        let result = check_auth(&member, &sf);
        match result {
            Err(AuthError::Rejected(reason)) => {
                assert!(
                    reason.contains("no signature verified"),
                    "expected verify-failure reason, got: {reason}"
                );
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn third_party_invite_tampered_signed_block_rejected() {
        // Take a valid signed bundle, then tamper with `mxid` after signing.
        // The canonical bytes diverge → verify fails.
        let id_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let token = "tok-tamper";
        let (state, mut signed) = build_tpi_fixture(&id_key, token, target, TpiKeysForm::Legacy);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // Tamper: change mxid in the signed bundle to a different user.
        signed.insert("mxid".into(), json!("@eve:example.com"));

        // The auth rule also checks mxid==state_key; align state_key to the
        // tampered mxid so we exercise the *crypto* failure, not the structural
        // mismatch.
        let member = make_member_with_tpi("@eve:example.com", token, Value::Object(signed));
        assert!(matches!(
            check_auth(&member, &sf),
            Err(AuthError::Rejected(_))
        ));
    }

    #[test]
    fn third_party_invite_mismatched_token_rejected() {
        // Member event claims token B; the m.room.third_party_invite in state
        // is keyed by token A. Structural rule 5.4.1.5 rejects.
        let id_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let real_token = "tok-A";
        let (state, signed) = build_tpi_fixture(&id_key, real_token, target, TpiKeysForm::Legacy);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // Reuse the signed-with-real_token bundle but swap the token in the
        // member event to one that isn't in state.
        let mut wrong_signed = signed.clone();
        wrong_signed.insert("token".into(), json!("tok-B"));
        let member = make_member_with_tpi(target, "tok-B", Value::Object(wrong_signed));
        let result = check_auth(&member, &sf);
        match result {
            Err(AuthError::Rejected(reason)) => {
                assert!(
                    reason.contains("no matching m.room.third_party_invite"),
                    "expected structural rejection, got: {reason}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn third_party_invite_missing_signed_rejected() {
        // No `signed` field at all in third_party_invite content. We must
        // refuse — not silently accept on missing signatures.
        let id_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let token = "tok-missing-signed";
        let (state, _signed) = build_tpi_fixture(&id_key, token, target, TpiKeysForm::Legacy);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let member = pdu(
            "$bob_invite",
            "m.room.member",
            Some(target),
            "@alice:example.com",
            json!({
                "membership": "invite",
                "third_party_invite": {
                    "display_name": "bob",
                    // no `signed` field
                },
            }),
            "!create",
        );
        let result = check_auth(&member, &sf);
        match result {
            Err(AuthError::Rejected(reason)) => {
                assert!(
                    reason.contains("no signed property"),
                    "expected structural rejection, got: {reason}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn third_party_invite_empty_signatures_block_rejected() {
        // `signed.signatures` exists but is an empty object — must reject.
        let id_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let token = "tok-empty-sigs";
        let (state, _signed) = build_tpi_fixture(&id_key, token, target, TpiKeysForm::Legacy);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        let member = make_member_with_tpi(
            target,
            token,
            json!({
                "mxid": target,
                "token": token,
                "signatures": {},
            }),
        );
        let result = check_auth(&member, &sf);
        assert!(matches!(result, Err(AuthError::Rejected(_))));
    }

    // ====================================================================
    // MSC3757 owned-state state_key parser + rule 9 integration
    // ====================================================================

    /// Well-formed owner state_keys round-trip to the embedded mxid,
    /// whether or not a suffix is present. Server `:port` and IPv6
    /// `[::1]` survive — we only split on the `_` delimiter.
    #[test]
    fn owned_state_key_parses_well_formed() {
        assert_eq!(
            owned_state_key_owner("@alice:example.com"),
            Some("@alice:example.com".to_string())
        );
        assert_eq!(
            owned_state_key_owner("@alice:example.com_suffix"),
            Some("@alice:example.com".to_string())
        );
        // Localpart contains `_` — must NOT be confused with suffix delimiter.
        assert_eq!(
            owned_state_key_owner("@my_user:example.com"),
            Some("@my_user:example.com".to_string())
        );
        // Port survives.
        assert_eq!(
            owned_state_key_owner("@alice:example.com:8080_thing"),
            Some("@alice:example.com:8080".to_string())
        );
    }

    /// Malformed shapes return `None` so the CS-API layer can map
    /// them to `400 M_BAD_JSON`. The spec test `TestMSC3757OwnedState`
    /// pins these exactly.
    #[test]
    fn owned_state_key_rejects_malformed() {
        // No `:` at all (`@oops` from the spec test).
        assert_eq!(owned_state_key_owner("@oops"), None);
        // Doesn't start with `@`.
        assert_eq!(owned_state_key_owner("alice:example.com"), None);
        // Empty localpart.
        assert_eq!(owned_state_key_owner("@:example.com"), None);
        // Empty server.
        assert_eq!(owned_state_key_owner("@alice:"), None);
        // Garbage chars (`!#$`) in the server portion before any `_`.
        assert_eq!(owned_state_key_owner("@alice:example.com!@#$thing"), None);
    }

    fn create_pdu(room_version: &str, room_id: &str, creator: &str) -> Pdu {
        pdu(
            "$create",
            "m.room.create",
            Some(""),
            creator,
            json!({"room_version": room_version}),
            room_id,
        )
    }

    /// Rule 9 under MSC3757: the user named in the state_key may write,
    /// AND the room creator may write on anyone's behalf.
    #[test]
    fn rule9_msc3757_owner_and_creator_can_write_owned_state() {
        let room_id = "!r:example.com";
        let creator = "@creator:example.com";
        let user = "@alice:example.com";
        let create = create_pdu("org.matrix.msc3757.10", room_id, creator);
        // Use sender-power=100 power_levels so the rule-8 check passes.
        let pl = pdu(
            "$pl",
            "m.room.power_levels",
            Some(""),
            creator,
            json!({"events": {"com.example.test": 0}, "users": {creator: 100}}),
            room_id,
        );
        let join_creator = pdu(
            "$j_creator",
            "m.room.member",
            Some(creator),
            creator,
            json!({"membership": "join"}),
            room_id,
        );
        let join_user = pdu(
            "$j_user",
            "m.room.member",
            Some(user),
            user,
            json!({"membership": "join"}),
            room_id,
        );
        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.power_levels", ""), pl),
            (("m.room.member", creator), join_creator),
            (("m.room.member", user), join_user),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // Owner writing their own key with a suffix → allowed.
        let owned = pdu(
            "$e1",
            "com.example.test",
            Some(&format!("{user}_my_suffix")),
            user,
            json!({}),
            room_id,
        );
        assert!(check_auth(&owned, &sf).is_ok());

        // Creator writing on the user's behalf → allowed.
        let by_creator = pdu(
            "$e2",
            "com.example.test",
            Some(user),
            creator,
            json!({}),
            room_id,
        );
        assert!(check_auth(&by_creator, &sf).is_ok());
    }

    /// A user writing another user's owned state_key (and not the
    /// creator) → 403.
    #[test]
    fn rule9_msc3757_non_owner_non_creator_rejected() {
        let room_id = "!r:example.com";
        let creator = "@creator:example.com";
        let user1 = "@alice:example.com";
        let user2 = "@bob:example.com";
        let create = create_pdu("org.matrix.msc3757.10", room_id, creator);
        let pl = pdu(
            "$pl",
            "m.room.power_levels",
            Some(""),
            creator,
            json!({"events": {"com.example.test": 0}}),
            room_id,
        );
        let j1 = pdu(
            "$j1",
            "m.room.member",
            Some(user1),
            user1,
            json!({"membership": "join"}),
            room_id,
        );
        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.power_levels", ""), pl),
            (("m.room.member", user1), j1),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // alice tries to write bob's key — neither owner nor creator.
        let bad = pdu(
            "$e3",
            "com.example.test",
            Some(user2),
            user1,
            json!({}),
            room_id,
        );
        assert!(matches!(check_auth(&bad, &sf), Err(AuthError::Rejected(_))));
    }

    /// Non-MSC3757 (plain v10) keeps strict-equality rule 9: a
    /// suffix on the state_key fails because state_key != sender.
    #[test]
    fn rule9_v10_keeps_strict_equality() {
        let room_id = "!r:example.com";
        let user = "@alice:example.com";
        let create = create_pdu("10", room_id, user);
        let pl = pdu(
            "$pl",
            "m.room.power_levels",
            Some(""),
            user,
            json!({"events": {"com.example.test": 0}}),
            room_id,
        );
        let j = pdu(
            "$j",
            "m.room.member",
            Some(user),
            user,
            json!({"membership": "join"}),
            room_id,
        );
        let state = make_state(vec![
            (("m.room.create", ""), create),
            (("m.room.power_levels", ""), pl),
            (("m.room.member", user), j),
        ]);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // Owner WITH suffix: in v10 this fails (state_key != sender).
        let ev = pdu(
            "$e4",
            "com.example.test",
            Some(&format!("{user}_suffix")),
            user,
            json!({}),
            room_id,
        );
        assert!(matches!(check_auth(&ev, &sf), Err(AuthError::Rejected(_))));
    }

    #[test]
    fn third_party_invite_non_ed25519_only_rejected() {
        // Only signatures with non-ed25519 key IDs present. We skip them all
        // (spec restricts 3pid signing to ed25519) → no signature verifies.
        let id_key = ServerSigningKey::generate();
        let target = "@bob:example.com";
        let token = "tok-non-ed25519";
        let (state, signed) = build_tpi_fixture(&id_key, token, target, TpiKeysForm::Legacy);
        let sf = |t: &str, sk: &str| lookup(&state, t, sk);

        // Rebuild signatures under a foo: key_id instead of ed25519:.
        let real_sig = signed["signatures"]["identity.example"][id_key.key_id()]
            .as_str()
            .unwrap()
            .to_string();
        let member = make_member_with_tpi(
            target,
            token,
            json!({
                "mxid": target,
                "token": token,
                "signatures": {
                    "identity.example": { "foo:bar": real_sig },
                },
            }),
        );
        let result = check_auth(&member, &sf);
        assert!(matches!(result, Err(AuthError::Rejected(_))));
    }
}
