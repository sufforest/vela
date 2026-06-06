//! Shared federation state helpers.
//!
//! Used by:
//! - `federation_receive` — check #5 (state-at-event).
//! - `federation_fetch` — `/state` and `/state_ids` handlers.
//! - `federation_join` — building the `state` and `auth_chain` fields of a
//!   `send_join` response.
//!
//! All helpers take `&Database` and are synchronous. State resolution is
//! CPU-bound, so async callers should wrap in `tokio::task::spawn_blocking`
//! when operating on a large room.

use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::{Map, Value};
use vela_core::events::pdu::Pdu;
use vela_core::state_res::{self, StateMap};
use vela_store::db::Database;

/// Cap on auth-chain BFS (protect against pathological graphs).
pub const AUTH_CHAIN_MAX: usize = 10_000;

/// Resolve a Pdu from its event_nid.
pub fn load_pdu_by_nid(db: &Database, event_nid: u64) -> Option<Pdu> {
    let (_header, json_bytes) = db.get_event(event_nid).ok().flatten()?;
    let event_id = db.get_event_id_by_nid(event_nid).ok().flatten()?;
    let json: Map<String, Value> = serde_json::from_slice::<Value>(&json_bytes)
        .ok()?
        .as_object()?
        .clone();
    Pdu::from_json(event_id, &json)
}

pub fn load_pdu_by_event_id(db: &Database, event_id: &str) -> Option<Pdu> {
    let nid = db.get_event_nid_by_id(event_id).ok().flatten()?;
    load_pdu_by_nid(db, nid)
}

/// Load a state event by (room_nid, event_type, state_key) from current
/// room state. Used to inject `m.room.create` into auth state views for
/// v12+ rooms where the create is absent from `auth_events`.
pub fn load_state_pdu(
    db: &Database,
    room_nid: u64,
    event_type: &str,
    state_key: &str,
) -> Option<Pdu> {
    let type_nid = db.get_nid(event_type).ok().flatten()?;
    let skey_nid = db.get_nid(state_key).ok().flatten()?;
    let event_nid = db
        .get_state_event_nid(room_nid, type_nid, skey_nid)
        .ok()
        .flatten()?;
    load_pdu_by_nid(db, event_nid)
}

/// Insert `m.room.create` into a state map from persisted state if it's
/// not already present (v12/MSC4291: create is excluded from auth_events).
///
/// Skips synthetic stripped placeholders (`$invite-stripped:…`) — those
/// come from `invite_room_state` and have a manufactured event_id that
/// won't match the room_id under the v12 `room_id == create_event_id`
/// rule. Using them as auth context would cascade-reject every fetched
/// event for an invited-but-not-yet-joined room until the real create
/// event arrives via send_join; better to leave the slot empty and let
/// `check_auth` surface "no m.room.create in state", which the fetched-
/// event path treats as a transient gap rather than a permanent reject.
pub fn ensure_create_in_state(
    db: &Database,
    room_nid: u64,
    state: &mut HashMap<(String, String), Pdu>,
) {
    let key = ("m.room.create".to_string(), String::new());
    if let std::collections::hash_map::Entry::Vacant(e) = state.entry(key)
        && let Some(create) = load_state_pdu(db, room_nid, "m.room.create", "")
        && !create.event_id.starts_with("$invite-stripped:")
    {
        e.insert(create);
    }
}

/// MSC3706 partial-state safety net. When the room is still
/// filling and the resolved state-at-event doesn't include the
/// sender's `m.room.member` (we haven't pulled it from the
/// resident yet), inject it from the event's `auth_events`. The
/// spec requires every non-state PDU to list its sender's
/// membership in `auth_events`, so this is always a known-good
/// substitute when our local view is genuinely incomplete.
///
/// Safe in the non-partial case too: when the state already has
/// the sender's member entry, this is a no-op. We only fill the
/// hole; we never overwrite (so a later leave/ban present in
/// state is respected).
/// True if any event in `auth_events` is an m.room.member event for
/// `sender` declaring membership ∈ {join, invite, knock}. Used by
/// the Check 5 self-leave exemption: when state-at-event has been
/// poisoned by an upstream optimistically-accepted bad-kick, the
/// real self-leave's auth_events still carry proof of the sender's
/// actual prior membership. The auth rule requires invite/join/knock;
/// if the auth chain shows one of those, the leave is consistent with
/// the sender's authoritative-but-not-yet-resynced view.
pub fn auth_events_declare_prior_membership_allowing_leave(
    db: &Database,
    sender: &str,
    auth_events: &[String],
) -> bool {
    for aid in auth_events {
        let Some(json) = load_event_json_by_event_id(db, aid) else {
            continue;
        };
        let Some(obj) = json.as_object() else {
            continue;
        };
        let ty = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let sk = obj.get("state_key").and_then(|v| v.as_str()).unwrap_or("");
        if ty != "m.room.member" || sk != sender {
            continue;
        }
        let mem = obj
            .get("content")
            .and_then(|c| c.get("membership"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if matches!(mem, "join" | "invite" | "knock") {
            return true;
        }
    }
    false
}

pub fn ensure_sender_member_in_state(
    db: &Database,
    sender: &str,
    auth_events: &[String],
    state: &mut HashMap<(String, String), Pdu>,
) {
    let key = ("m.room.member".to_string(), sender.to_string());
    if state.contains_key(&key) {
        return;
    }
    for aid in auth_events {
        let Some(json) = load_event_json_by_event_id(db, aid) else {
            continue;
        };
        let Some(obj) = json.as_object() else {
            continue;
        };
        let ty = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let sk = obj.get("state_key").and_then(|v| v.as_str()).unwrap_or("");
        if ty != "m.room.member" || sk != sender {
            continue;
        }
        if let Some(pdu) = Pdu::from_json(aid.clone(), obj) {
            state.insert(key, pdu);
            return;
        }
    }
}

/// Load the raw canonical JSON for an event by its event_id string.
pub fn load_event_json_by_event_id(db: &Database, event_id: &str) -> Option<Value> {
    let nid = db.get_event_nid_by_id(event_id).ok().flatten()?;
    let (_header, json_bytes) = db.get_event(nid).ok().flatten()?;
    serde_json::from_slice::<Value>(&json_bytes).ok()
}

pub type StateError = String;

/// Compute the state immediately *before* `event_id` — the state that the
/// event's `prev_events` collectively resolve to. Returns `None` if the
/// event has no recorded `prev_events` (only valid for `m.room.create`).
pub fn state_before_event(
    db: &Database,
    event_id: &str,
) -> Result<Option<HashMap<(String, String), Pdu>>, StateError> {
    let nid = db
        .get_event_nid_by_id(event_id)
        .map_err(|e| format!("db: {e}"))?
        .ok_or_else(|| format!("unknown event {event_id}"))?;

    let prev_nids = db.get_prev_events(nid).map_err(|e| format!("db: {e}"))?;
    if prev_nids.is_empty() {
        return Ok(None);
    }

    // Build state sets from each prev_event's snapshot.
    let mut state_sets: Vec<StateMap> = Vec::new();
    for prev_nid in &prev_nids {
        let snapshot = db
            .get_state_at_event(*prev_nid)
            .map_err(|e| format!("db: {e}"))?
            .unwrap_or_default();

        let mut sm: StateMap = StateMap::new();
        for snid in &snapshot {
            let eid = db
                .get_event_id_by_nid(*snid)
                .map_err(|e| format!("db: {e}"))?
                .ok_or_else(|| format!("state snapshot references missing event_nid {snid}"))?;
            let (header, _) = db
                .get_event(*snid)
                .map_err(|e| format!("db: {e}"))?
                .ok_or_else(|| format!("state snapshot references missing event_nid {snid}"))?;
            let et = db
                .resolve_nid(header.type_nid)
                .map_err(|e| format!("db: {e}"))?
                .ok_or_else(|| format!("unknown type_nid {}", header.type_nid))?;
            let sk = db
                .resolve_nid(header.state_key_nid)
                .map_err(|e| format!("db: {e}"))?
                .unwrap_or_default();
            sm.insert((et, sk), eid);
        }
        state_sets.push(sm);
    }

    let event_fn = |id: &str| -> Option<Pdu> { load_pdu_by_event_id(db, id) };
    let auth_chain_fn = |id: &str| -> HashSet<String> {
        let mut out = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(id.to_string());
        while let Some(n) = queue.pop_front() {
            let Some(p) = event_fn(&n) else { continue };
            for a in p.auth_events {
                if out.insert(a.clone()) {
                    queue.push_back(a);
                }
            }
        }
        out
    };
    let resolved = state_res::resolve(&state_sets, &event_fn, &auth_chain_fn);

    let mut out: HashMap<(String, String), Pdu> = HashMap::new();
    for (key, eid) in &resolved {
        if let Some(pdu) = load_pdu_by_event_id(db, eid) {
            out.insert(key.clone(), pdu);
        }
    }
    Ok(Some(out))
}

/// Same as `state_before_event` but returns only event_ids.
pub fn state_before_event_ids(
    db: &Database,
    event_id: &str,
) -> Result<Option<HashMap<(String, String), String>>, StateError> {
    let Some(pdus) = state_before_event(db, event_id)? else {
        return Ok(None);
    };
    Ok(Some(
        pdus.into_iter().map(|(k, p)| (k, p.event_id)).collect(),
    ))
}

/// Compute the full auth chain for `event_id`. Returns event_id strings.
pub fn auth_chain_event_ids(db: &Database, event_id: &str) -> Result<Vec<String>, StateError> {
    let nid = db
        .get_event_nid_by_id(event_id)
        .map_err(|e| format!("db: {e}"))?
        .ok_or_else(|| format!("unknown event {event_id}"))?;
    let chain_nids = db
        .get_auth_chain(nid, AUTH_CHAIN_MAX)
        .map_err(|e| format!("db: {e}"))?;
    let mut out = Vec::with_capacity(chain_nids.len());
    for n in chain_nids {
        let Some(eid) = db.get_event_id_by_nid(n).map_err(|e| format!("db: {e}"))? else {
            continue;
        };
        out.push(eid);
    }
    Ok(out)
}

/// Compute the auth chain as full PDU JSON.
pub fn auth_chain_pdu_json(db: &Database, event_id: &str) -> Result<Vec<Value>, StateError> {
    let ids = auth_chain_event_ids(db, event_id)?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(json) = load_event_json_by_event_id(db, &id) {
            out.push(json);
        }
    }
    Ok(out)
}

/// Walk the union of auth chains starting from `roots` (event_id strings).
/// Single shared `seen` set — O(V+E) over the union of all reachable auth
/// events, rather than O(roots × per-root-chain) for separate walks.
///
/// **Excludes roots themselves** — returns only ancestors (the auth chain OF
/// the roots). Roots must be events already persisted in the DB.
///
/// Compare with [`auth_chain_including_seeds`] which walks from an event's
/// `auth_events` list and INCLUDES them in the output.
pub fn auth_chain_union_event_ids(
    db: &Database,
    roots: &[&str],
) -> Result<Vec<String>, StateError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    let mut out: Vec<String> = Vec::new();

    // Seed with roots themselves so we don't re-emit them as ancestors.
    for r in roots {
        seen.insert((*r).to_string());
    }

    // Enqueue immediate auth_events of each root.
    for r in roots {
        let nid = match db.get_event_nid_by_id(r).map_err(|e| format!("db: {e}"))? {
            Some(n) => n,
            None => continue, // root not known locally
        };
        let auths = db.get_auth_events(nid).map_err(|e| format!("db: {e}"))?;
        for a_nid in auths {
            if let Some(a_eid) = db
                .get_event_id_by_nid(a_nid)
                .map_err(|e| format!("db: {e}"))?
                && seen.insert(a_eid.clone())
            {
                out.push(a_eid.clone());
                queue.push_back(a_eid);
                if out.len() >= AUTH_CHAIN_MAX {
                    return Ok(out);
                }
            }
        }
    }

    while let Some(eid) = queue.pop_front() {
        let nid = match db
            .get_event_nid_by_id(&eid)
            .map_err(|e| format!("db: {e}"))?
        {
            Some(n) => n,
            None => continue,
        };
        let auths = db.get_auth_events(nid).map_err(|e| format!("db: {e}"))?;
        for a_nid in auths {
            if let Some(a_eid) = db
                .get_event_id_by_nid(a_nid)
                .map_err(|e| format!("db: {e}"))?
                && seen.insert(a_eid.clone())
            {
                out.push(a_eid.clone());
                queue.push_back(a_eid);
                if out.len() >= AUTH_CHAIN_MAX {
                    return Ok(out);
                }
            }
        }
    }

    Ok(out)
}

/// Walk the auth chain starting from a list of seed event_ids. The seeds are
/// the caller-provided `auth_events` of some event that is NOT itself in the
/// DB (e.g. an event we're building a send_join response for).
///
/// **Includes the seeds** in the output, plus their transitive ancestors.
/// Seeds must already exist in the DB (they're the event's declared auth_events,
/// and we only reach this code path if auth check already validated them).
///
/// Compare with [`auth_chain_union_event_ids`] which starts from already-persisted
/// events and EXCLUDES the roots from the output.
pub fn auth_chain_including_seeds(
    db: &Database,
    seeds: &[String],
) -> Result<Vec<String>, StateError> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    // Include the seeds themselves.
    for aev in seeds {
        if seen.insert(aev.clone()) {
            out.push(aev.clone());
            queue.push_back(aev.clone());
        }
    }

    while let Some(eid) = queue.pop_front() {
        let nid = match db
            .get_event_nid_by_id(&eid)
            .map_err(|e| format!("db: {e}"))?
        {
            Some(n) => n,
            None => continue, // unknown event in chain — skip
        };
        let ancestors = db.get_auth_events(nid).map_err(|e| format!("db: {e}"))?;
        for a_nid in ancestors {
            if let Some(a_eid) = db
                .get_event_id_by_nid(a_nid)
                .map_err(|e| format!("db: {e}"))?
                && seen.insert(a_eid.clone())
            {
                out.push(a_eid.clone());
                queue.push_back(a_eid);
                if out.len() >= AUTH_CHAIN_MAX {
                    return Ok(out);
                }
            }
        }
    }

    Ok(out)
}

/// PDU JSON variant of [`auth_chain_union_event_ids`]. Skips events not in the DB.
pub fn auth_chain_union_pdu_json(db: &Database, roots: &[&str]) -> Result<Vec<Value>, StateError> {
    let ids = auth_chain_union_event_ids(db, roots)?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(json) = load_event_json_by_event_id(db, &id) {
            out.push(json);
        }
    }
    Ok(out)
}
