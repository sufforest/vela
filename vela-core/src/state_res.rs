//! Matrix State Resolution algorithm v2, with the Room Version 12 variant
//! (state-res v2.1) selected per room version.
//!
//! Reference: `content/rooms/v12.md` §State resolution and
//! `content/rooms/fragments/v2-state-res.md`.
//!
//! `resolve` takes the room version and branches where v12 differs from v2:
//! 1. Iterative auth checks on power events start from an **empty** state map
//!    in v12, versus the **unconflicted** state map in classic v2.
//! 2. v12 defines the **conflicted state subgraph** — the subgraph formed by
//!    paths between conflicted state events via `auth_events` edges — and
//!    folds it into the full conflicted set. Classic v2 does not.
//!
//! Everything else (both ordering algorithms, the auth rules invoked, the
//! final unconflicted overlay) is identical across versions. The auth-rule
//! differences that do exist are handled inside `check_auth`, which reads the
//! room version from the create event, not here.
//!
//! The algorithm is a pure function: no I/O, no async. Callers wrap it in
//! `tokio::task::spawn_blocking` to isolate CPU usage from the async runtime.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use crate::auth_rules::{check_auth, user_power_level};
use crate::events::pdu::Pdu;
use crate::events::room_version::RoomVersion;

/// (event_type, state_key) → event_id.
pub type StateMap = HashMap<(String, String), String>;

/// Lookup: event_id → Pdu (if known).
pub type EventFn<'a> = &'a dyn Fn(&str) -> Option<Pdu>;

/// Lookup: event_id → full auth chain (set of event_ids). The chain
/// excludes the event itself.
pub type AuthChainFn<'a> = &'a dyn Fn(&str) -> HashSet<String>;

/// Resolve a set of state maps into a single resolved state map.
///
/// `room_version` selects the algorithm variant: v12+ uses state-res v2.1
/// (empty initial state + conflicted state subgraph), pre-v12 uses classic
/// state-res v2 (unconflicted initial state, no subgraph). See
/// `RoomVersion::uses_state_res_v21`. Passing the wrong version for the room
/// can diverge resolved state on a fork.
///
/// Per spec: resolution(state_sets) → resolved_state_map
///
/// Arguments:
/// - `room_version`: the room's version (selects the algorithm variant)
/// - `state_sets`: state maps from each prev_event
/// - `event_fn`: resolves event_id → Pdu
/// - `auth_chain_fn`: resolves event_id → auth chain (transitive auth_events ancestors)
pub fn resolve(
    room_version: RoomVersion,
    state_sets: &[StateMap],
    event_fn: EventFn<'_>,
    auth_chain_fn: AuthChainFn<'_>,
) -> StateMap {
    // Edge cases
    if state_sets.is_empty() {
        return StateMap::new();
    }
    if state_sets.len() == 1 {
        return state_sets[0].clone();
    }

    let v21 = room_version.uses_state_res_v21();

    // --- Phase 1: split into unconflicted and conflicted ---
    let (unconflicted, conflicted_events) = split_conflicted(state_sets);

    // --- Phase 2: auth difference ---
    let auth_diff = auth_difference(state_sets, auth_chain_fn);

    // --- Phase 3+4: full conflicted set = conflicted ∪ auth_diff, plus the
    // conflicted state subgraph in v12 (state-res v2.1) only. In classic
    // state-res v2 (pre-v12) the subgraph is not part of the full set. ---
    let mut full_conflicted: HashSet<String> = HashSet::new();
    full_conflicted.extend(conflicted_events.iter().cloned());
    if v21 {
        full_conflicted.extend(conflicted_state_subgraph(&conflicted_events, event_fn));
    }
    full_conflicted.extend(auth_diff);

    // --- Phase 5: select power events and sort by reverse topological power ordering ---
    let power_event_list = select_and_sort_power_events(&full_conflicted, event_fn);

    // --- Phase 6: iterative auth checks on power events. v12 starts from an
    // EMPTY state map; classic v2 starts from the unconflicted state map. ---
    let initial_state = if v21 {
        StateMap::new()
    } else {
        unconflicted.clone()
    };
    let partial_state =
        iterative_auth_checks(room_version, &initial_state, &power_event_list, event_fn);

    // --- Phase 7: order remaining events by mainline ordering ---
    let remaining: Vec<String> = full_conflicted
        .iter()
        .filter(|id| !power_event_list.contains(id))
        .cloned()
        .collect();
    let remaining_sorted = mainline_sort(&remaining, &partial_state, event_fn);

    // --- Phase 8: iterative auth checks on remaining events ---
    let resolved = iterative_auth_checks(room_version, &partial_state, &remaining_sorted, event_fn);

    // --- Phase 9: overlay unconflicted state ---
    let mut final_state = resolved;
    for (key, event_id) in unconflicted {
        final_state.insert(key, event_id);
    }

    final_state
}

// ========================================================================
// Unconflicted / conflicted split
// ========================================================================

/// Split state sets into unconflicted map and conflicted event IDs.
/// A key is unconflicted iff every state set has the same event for it.
fn split_conflicted(state_sets: &[StateMap]) -> (StateMap, HashSet<String>) {
    // Gather all keys
    let mut all_keys: HashSet<(String, String)> = HashSet::new();
    for s in state_sets {
        for k in s.keys() {
            all_keys.insert(k.clone());
        }
    }

    let mut unconflicted = StateMap::new();
    let mut conflicted_events = HashSet::new();

    for key in all_keys {
        let mut values: HashSet<&String> = HashSet::new();
        let mut all_have = true;
        for s in state_sets {
            match s.get(&key) {
                Some(v) => {
                    values.insert(v);
                }
                None => {
                    all_have = false;
                }
            }
        }

        if all_have && values.len() == 1 {
            // Unconflicted
            let v = values.into_iter().next().unwrap().clone();
            unconflicted.insert(key, v);
        } else {
            // Conflicted — every value seen goes into the conflicted event set
            for v in values {
                conflicted_events.insert(v.clone());
            }
        }
    }

    (unconflicted, conflicted_events)
}

// ========================================================================
// Auth difference
// ========================================================================

/// Auth difference = ∪ C_i − ∩ C_i where C_i is the union of auth chains
/// for each event in state set i.
fn auth_difference(state_sets: &[StateMap], auth_chain_fn: AuthChainFn<'_>) -> HashSet<String> {
    let full_chains: Vec<HashSet<String>> = state_sets
        .iter()
        .map(|s| {
            let mut chain = HashSet::new();
            for event_id in s.values() {
                chain.insert(event_id.clone());
                chain.extend(auth_chain_fn(event_id));
            }
            chain
        })
        .collect();

    if full_chains.is_empty() {
        return HashSet::new();
    }

    // Intersection
    let mut intersection: HashSet<String> = full_chains[0].clone();
    for c in &full_chains[1..] {
        intersection.retain(|e| c.contains(e));
    }

    // Union
    let mut union: HashSet<String> = HashSet::new();
    for c in &full_chains {
        union.extend(c.iter().cloned());
    }

    // Difference
    union.difference(&intersection).cloned().collect()
}

// ========================================================================
// Conflicted state subgraph (v12)
// ========================================================================

/// The conflicted state subgraph: the subgraph formed by paths between any
/// pair of events in the conflicted state set, following `auth_events` edges.
///
/// A node X is on such a path iff X is reachable from some conflicted c1 by
/// walking auth_events (X is an ancestor of c1) AND X reaches some conflicted
/// c2 by walking auth_events (c2 is an ancestor of X). Therefore:
///
///   subgraph = ancestors(conflicted) ∩ (descendants-of-conflicted within that set)
///
/// We compute this in O(|V| + |E|) using two passes:
///
///   Pass 1 — forward BFS from conflicted following `auth_events`: visits all
///     ancestors (including conflicted as seeds). While traversing each edge
///     `event → auth_event`, record a reverse edge `auth_event → event`.
///   Pass 2 — BFS from conflicted following the reverse edges built in Pass 1.
///     By construction every visited node is in A, and is on a path to the
///     conflicted seed that produced the edge.
///
/// The result is Pass-2-visited, which includes the conflicted endpoints.
fn conflicted_state_subgraph(
    conflicted: &HashSet<String>,
    event_fn: EventFn<'_>,
) -> HashSet<String> {
    if conflicted.is_empty() {
        return HashSet::new();
    }

    // --- Pass 1: forward BFS from conflicted via auth_events ---
    let mut visited_a: HashSet<String> = HashSet::with_capacity(conflicted.len() * 4);
    let mut reverse_edges: HashMap<String, Vec<String>> = HashMap::new();
    let mut queue: VecDeque<String> = VecDeque::with_capacity(conflicted.len());
    for c in conflicted {
        if visited_a.insert(c.clone()) {
            queue.push_back(c.clone());
        }
    }
    while let Some(n) = queue.pop_front() {
        let pdu = match event_fn(&n) {
            Some(p) => p,
            None => continue,
        };
        for ae in &pdu.auth_events {
            // Record reverse edge auth_event → n
            reverse_edges.entry(ae.clone()).or_default().push(n.clone());
            // Visit the ancestor if new
            if visited_a.insert(ae.clone()) {
                queue.push_back(ae.clone());
            }
        }
    }

    // --- Pass 2: BFS from conflicted via reverse_edges, restricted to A ---
    let mut subgraph: HashSet<String> = HashSet::with_capacity(conflicted.len() * 2);
    let mut queue: VecDeque<String> = VecDeque::with_capacity(conflicted.len());
    for c in conflicted {
        if subgraph.insert(c.clone()) {
            queue.push_back(c.clone());
        }
    }
    while let Some(n) = queue.pop_front() {
        if let Some(descendants) = reverse_edges.get(&n) {
            for d in descendants {
                // Every d is in A by construction (it was visited in Pass 1), so
                // this check is defensive/redundant but makes the invariant explicit.
                if visited_a.contains(d) && subgraph.insert(d.clone()) {
                    queue.push_back(d.clone());
                }
            }
        }
    }

    subgraph
}

// ========================================================================
// Power events + reverse topological power ordering
// ========================================================================

fn is_power_event(pdu: &Pdu) -> bool {
    if pdu.event_type == "m.room.power_levels" || pdu.event_type == "m.room.join_rules" {
        return true;
    }
    if pdu.event_type == "m.room.member" {
        let membership = pdu.content.get("membership").and_then(|v| v.as_str());
        if matches!(membership, Some("leave") | Some("ban"))
            && Some(pdu.sender.as_str()) != pdu.state_key.as_deref()
        {
            return true;
        }
    }
    false
}

/// Select all power events in the full conflicted set, add their auth chain
/// members (also in full conflicted set), and sort by reverse topological
/// power ordering.
fn select_and_sort_power_events(
    full_conflicted: &HashSet<String>,
    event_fn: EventFn<'_>,
) -> Vec<String> {
    // Materialise PDUs once
    let pdus: HashMap<String, Pdu> = full_conflicted
        .iter()
        .filter_map(|id| event_fn(id).map(|p| (id.clone(), p)))
        .collect();

    // Power events within full_conflicted
    let mut x: HashSet<String> = pdus
        .iter()
        .filter(|(_, p)| is_power_event(p))
        .map(|(id, _)| id.clone())
        .collect();

    // Enlarge X by adding auth-chain members of each power event that are in full_conflicted.
    // We do this transitively within full_conflicted by walking auth_events pointers.
    let mut queue: VecDeque<String> = x.iter().cloned().collect();
    while let Some(id) = queue.pop_front() {
        if let Some(p) = pdus.get(&id) {
            for ae in &p.auth_events {
                if full_conflicted.contains(ae) && x.insert(ae.clone()) {
                    queue.push_back(ae.clone());
                }
            }
        }
    }

    // Sort by reverse topological power ordering (Kahn's with comparator)
    topological_power_sort(&x, event_fn)
}

/// Reverse topological power ordering via Kahn's algorithm.
/// Comparison: x < y iff
///   1. x's sender has greater power than y's sender (at respective auth events), OR
///   2. same power, x.origin_server_ts < y.origin_server_ts, OR
///   3. same, x.event_id < y.event_id.
fn topological_power_sort(events: &HashSet<String>, event_fn: EventFn<'_>) -> Vec<String> {
    // Materialise
    let pdus: HashMap<String, Pdu> = events
        .iter()
        .filter_map(|id| event_fn(id).map(|p| (id.clone(), p)))
        .collect();

    // Build reverse-topo graph: edges from auth_event → event (auth_events come first)
    // In-degree = number of incoming edges within the event set.
    // Edge: for each event e, for each auth_event a in e.auth_events that is in `events`,
    //   a → e in the topo order (a must come before e).
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut children: HashMap<String, Vec<String>> = HashMap::new();
    for id in events {
        in_degree.entry(id.clone()).or_insert(0);
    }
    for (id, p) in &pdus {
        for ae in &p.auth_events {
            if events.contains(ae) {
                *in_degree.entry(id.clone()).or_insert(0) += 1;
                children.entry(ae.clone()).or_default().push(id.clone());
            }
        }
    }

    // Compute sender power at respective auth_events.
    // For the purposes of ordering, we look up the event's auth_events, find any power_levels
    // event there, and compute the sender's power using that state snapshot. If no power_levels
    // is in auth_events, the sender's power is derived from the create event (creator rules
    // apply: creator = infinite; else 0).
    //
    // Callers that want perfect accuracy (e.g. when the sender's power depends on the create
    // event's additional_creators) must populate event_fn to return those events.
    let sender_power = |id: &str| -> i64 {
        let pdu = match pdus.get(id) {
            Some(p) => p,
            None => return 0,
        };
        // Build a tiny state from this event's auth_events
        let mut local_state: HashMap<(String, String), Pdu> = HashMap::new();
        for ae_id in &pdu.auth_events {
            if let Some(ae_pdu) = event_fn(ae_id)
                && let Some(ref sk) = ae_pdu.state_key
            {
                local_state.insert((ae_pdu.event_type.clone(), sk.clone()), ae_pdu);
            }
        }
        let sf = |t: &str, sk: &str| local_state.get(&(t.to_string(), sk.to_string()));

        // Need a create event for creator checks
        let create_pdu = match sf("m.room.create", "") {
            Some(c) => c.clone(),
            None => {
                // No create event in auth_events — fall back to 0 power
                return 0;
            }
        };
        user_power_level(&sf, &pdu.sender, &create_pdu)
    };

    // Start with nodes of in-degree 0
    // Pop the "smallest" (per comparison relation) at each step
    let mut ready: BTreeSet<KahnKey> = BTreeSet::new();
    for (id, &deg) in &in_degree {
        if deg == 0 {
            ready.insert(KahnKey::from_pdu(id, pdus.get(id), sender_power(id)));
        }
    }

    let mut result = Vec::with_capacity(events.len());
    let mut in_degree_mut = in_degree;
    while let Some(node) = ready.pop_first() {
        let id = node.event_id.clone();
        result.push(id.clone());
        if let Some(kids) = children.get(&id) {
            for child in kids {
                if let Some(d) = in_degree_mut.get_mut(child) {
                    *d -= 1;
                    if *d == 0 {
                        ready.insert(KahnKey::from_pdu(
                            child,
                            pdus.get(child),
                            sender_power(child),
                        ));
                    }
                }
            }
        }
    }

    result
}

/// Ordering key for Kahn's algorithm with the spec comparator.
/// x < y iff:
///   1. x.sender_power > y.sender_power, OR  (reverse — more power first)
///   2. same power, x.origin_server_ts < y.origin_server_ts, OR
///   3. same ts, x.event_id < y.event_id.
#[derive(Debug, Clone)]
struct KahnKey {
    event_id: String,
    sender_power: i64,
    origin_server_ts: u64,
}

impl KahnKey {
    fn from_pdu(id: &str, pdu: Option<&Pdu>, sender_power: i64) -> Self {
        let origin_server_ts = pdu.map(|p| p.origin_server_ts).unwrap_or(0);
        Self {
            event_id: id.to_string(),
            sender_power,
            origin_server_ts,
        }
    }
}

impl PartialEq for KahnKey {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
    }
}
impl Eq for KahnKey {}
impl Ord for KahnKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Smaller = earlier in topo order.
        // 1. Greater sender power → smaller (comes first)
        match other.sender_power.cmp(&self.sender_power) {
            Ordering::Equal => {}
            ord => return ord,
        }
        // 2. Smaller ts → smaller
        match self.origin_server_ts.cmp(&other.origin_server_ts) {
            Ordering::Equal => {}
            ord => return ord,
        }
        // 3. Smaller event_id → smaller
        self.event_id.cmp(&other.event_id)
    }
}
impl PartialOrd for KahnKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ========================================================================
// Iterative auth checks
// ========================================================================

/// Apply the iterative auth checks algorithm.
///
/// For each event in order:
/// - If the (type, state_key) key required for auth checking is not present in current state,
///   pull the corresponding event from the event's auth_events (if not rejected).
/// - Run the authorization rules.
/// - If allowed, update the state with this event.
/// - Otherwise, skip.
fn iterative_auth_checks(
    room_version: RoomVersion,
    initial: &StateMap,
    events_in_order: &[String],
    event_fn: EventFn<'_>,
) -> StateMap {
    // Maintain state as a HashMap<(type, state_key), Pdu> for auth checks,
    // but also carry the event_id map for the return value.
    let mut state_pdus: HashMap<(String, String), Pdu> = HashMap::new();
    let mut state_ids: StateMap = StateMap::new();

    // Prime state from initial
    for (key, id) in initial {
        if let Some(p) = event_fn(id) {
            state_pdus.insert(key.clone(), p);
            state_ids.insert(key.clone(), id.clone());
        }
    }

    // v12 (MSC4291) omits m.room.create from auth_events — it's identified by
    // room_id instead. The per-event augmentation below only pulls auth_events,
    // so without this the create event is absent during the auth checks and
    // every conflicted event is rejected ("no m.room.create in state"),
    // silently dropping ALL conflicted state on a genuine fork. In v12 the
    // room_id is the create event's hash (`!<hash>` ↔ `$<hash>`), so we can
    // derive and seed create from any event's room_id. This is correct because
    // every event in one `resolve` call shares a room (the algorithm's
    // invariant), and a cross-room/forged event is still rejected by auth rule
    // 2 (`room_id_matches_create`).
    //
    // Gated to v12: every pre-v12 room (v6–v11) carries create in
    // auth_events — only v12/MSC4291 dropped it — and classic-v2 starts its
    // iterative pass from the unconflicted state map where create sits
    // anyway. So the seed is unnecessary pre-v12, and its `!x → $x`
    // derivation wouldn't resolve against an opaque (non-hash) room_id
    // regardless. (An event whose auth_events omit create in a ≤v11 room is
    // itself malformed — pre-fix vela emitted such events — but tolerating
    // it on read costs nothing here.)
    let create_seed: Option<((String, String), Pdu)> = if room_version.uses_state_res_v21() {
        events_in_order
            .iter()
            .find_map(|id| event_fn(id))
            .and_then(|p| p.room_id.strip_prefix('!').map(|rest| format!("${rest}")))
            .and_then(|cid| event_fn(&cid))
            .filter(|c| c.event_type == "m.room.create")
            .map(|c| (("m.room.create".to_string(), String::new()), c))
    } else {
        None
    };

    for event_id in events_in_order {
        let ev = match event_fn(event_id) {
            Some(p) => p,
            None => continue,
        };

        // Augment state with auth_events entries for keys not already present.
        // Per spec: "If a (event_type, state_key) key that is required for checking
        // the authorization rules is not present in the state, then the appropriate
        // state event from the event's auth_events is used if the auth event is not rejected."
        //
        // We augment eagerly for all auth_events types (simpler and equivalent since
        // those types are exactly the ones auth rules consult).
        let mut augmented_pdus = state_pdus.clone();
        // Seed the create event (v12 omits it from auth_events; see above).
        if let Some((key, create_pdu)) = &create_seed {
            augmented_pdus
                .entry(key.clone())
                .or_insert_with(|| create_pdu.clone());
        }
        for ae_id in &ev.auth_events {
            if let Some(ae_pdu) = event_fn(ae_id)
                && let Some(sk) = ae_pdu.state_key.as_deref()
            {
                let key = (ae_pdu.event_type.clone(), sk.to_string());
                augmented_pdus.entry(key).or_insert(ae_pdu);
            }
        }
        let sf = |t: &str, sk: &str| augmented_pdus.get(&(t.to_string(), sk.to_string()));

        if check_auth(&ev, &sf).is_ok()
            && let Some(sk) = ev.state_key.as_deref()
        {
            let key = (ev.event_type.clone(), sk.to_string());
            state_pdus.insert(key.clone(), ev.clone());
            state_ids.insert(key, event_id.clone());
        }
        // rejected → skip
    }

    state_ids
}

// ========================================================================
// Mainline ordering
// ========================================================================

/// Sort events by mainline ordering based on the power_levels event in the
/// partially resolved state.
fn mainline_sort(
    events: &[String],
    partial_state: &StateMap,
    event_fn: EventFn<'_>,
) -> Vec<String> {
    // Mainline starts at the m.room.power_levels in partial_state (if any), then follows
    // auth_events' power_levels references to the root.
    let mainline = match partial_state
        .get(&("m.room.power_levels".to_string(), String::new()))
        .cloned()
    {
        Some(pl_id) => build_mainline(&pl_id, event_fn),
        None => Vec::new(),
    };
    let mainline_index: HashMap<String, usize> = mainline
        .iter()
        .enumerate()
        .map(|(i, id)| (id.clone(), i))
        .collect();

    // Compute (position, ts, event_id) for each event
    let mut keyed: Vec<(MainlineKey, String)> = events
        .iter()
        .filter_map(|id| {
            let pos = mainline_position(id, &mainline_index, event_fn);
            let pdu = event_fn(id)?;
            Some((
                MainlineKey {
                    position: pos,
                    origin_server_ts: pdu.origin_server_ts,
                    event_id: id.clone(),
                },
                id.clone(),
            ))
        })
        .collect();

    // Sort by mainline ordering (smallest first)
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.into_iter().map(|(_, id)| id).collect()
}

/// Build the mainline starting from a power_levels event, following the
/// m.room.power_levels reference in its auth_events until it terminates.
fn build_mainline(start_pl: &str, event_fn: EventFn<'_>) -> Vec<String> {
    let mut mainline = Vec::new();
    let mut current = Some(start_pl.to_string());
    while let Some(id) = current.take() {
        mainline.push(id.clone());
        let pdu = match event_fn(&id) {
            Some(p) => p,
            None => break,
        };
        // Find a power_levels event in this pdu's auth_events
        let next = pdu.auth_events.iter().find_map(|ae_id| {
            event_fn(ae_id).and_then(|ae| {
                if ae.event_type == "m.room.power_levels" {
                    Some(ae.event_id)
                } else {
                    None
                }
            })
        });
        current = next;
    }
    mainline
}

/// Compute the mainline position of an event e relative to mainline P.
/// Returns usize::MAX as the ∞ sentinel when e has no connection to the mainline.
fn mainline_position(
    event_id: &str,
    mainline_index: &HashMap<String, usize>,
    event_fn: EventFn<'_>,
) -> usize {
    // Walk e's own power-levels chain: e_1, e_2, ... where e_j+1 is the power_levels
    // in auth_events of e_j. Note: e_0 = event_id itself is NOT included in this list
    // per spec, but if e_0 IS a power_levels in the mainline, then the walk is empty
    // and position = ∞ per the spec (since j must be ≥ 1). Wait — re-read spec...
    //
    // Actually: the spec says "find smallest j ≥ 1 for which e_j belongs to the mainline".
    // e_0 is not included. So if event_id itself is a power_levels on the mainline, that
    // doesn't count; we look at its auth_events' power_levels.
    //
    // HOWEVER — the mainline ordering is used for NON-power events in our algorithm,
    // so event_id won't be a power_levels in practice. We still implement correctly.
    let mut current = event_fn(event_id);
    loop {
        let pdu = match current {
            Some(p) => p,
            None => return usize::MAX,
        };
        // Find power_levels in pdu's auth_events
        let next = pdu
            .auth_events
            .iter()
            .find_map(|ae_id| event_fn(ae_id).filter(|ae| ae.event_type == "m.room.power_levels"));
        match next {
            Some(pl) => {
                if let Some(&idx) = mainline_index.get(&pl.event_id) {
                    return idx;
                }
                current = Some(pl);
            }
            None => return usize::MAX,
        }
    }
}

/// Comparison key for mainline ordering.
/// x < y iff:
///   1. x.position > y.position (reversed — greater position = earlier in chain = smaller)
///   2. same position, x.origin_server_ts < y.origin_server_ts
///   3. same ts, x.event_id < y.event_id
#[derive(Debug, Clone)]
struct MainlineKey {
    position: usize,
    origin_server_ts: u64,
    event_id: String,
}

impl PartialEq for MainlineKey {
    fn eq(&self, other: &Self) -> bool {
        self.event_id == other.event_id
    }
}
impl Eq for MainlineKey {}
impl Ord for MainlineKey {
    fn cmp(&self, other: &Self) -> Ordering {
        // Greater position → smaller (comes first)
        match other.position.cmp(&self.position) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.origin_server_ts.cmp(&other.origin_server_ts) {
            Ordering::Equal => {}
            ord => return ord,
        }
        self.event_id.cmp(&other.event_id)
    }
}
impl PartialOrd for MainlineKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// ========================================================================
// Async wrapper for tokio runtime isolation
// ========================================================================

// CPU isolation: callers that need async execution should wrap `resolve` in
// `tokio::task::spawn_blocking`. We don't provide a built-in async wrapper to
// keep vela-core free of tokio dependency; the wrapper is trivial at the call
// site and keeps vela-core purely algorithmic.

// ========================================================================
// Tests
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pdu(
        event_id: &str,
        event_type: &str,
        state_key: Option<&str>,
        sender: &str,
        content: serde_json::Value,
        auth_events: &[&str],
        ts: u64,
    ) -> Pdu {
        Pdu {
            event_id: event_id.to_string(),
            room_id: "!create".to_string(),
            event_type: event_type.to_string(),
            state_key: state_key.map(String::from),
            sender: sender.to_string(),
            origin_server_ts: ts,
            content,
            auth_events: auth_events.iter().map(|s| s.to_string()).collect(),
            prev_events: vec![],
            depth: 1,
            signatures: None,
        }
    }

    #[test]
    fn single_state_set_returns_itself() {
        let state: StateMap = vec![(
            ("m.room.create".to_string(), String::new()),
            "$c".to_string(),
        )]
        .into_iter()
        .collect();
        let pdus: HashMap<String, Pdu> = HashMap::new();
        let event_fn = |id: &str| pdus.get(id).cloned();
        let auth_chain_fn = |_: &str| HashSet::new();
        let result = resolve(
            RoomVersion::V12,
            std::slice::from_ref(&state),
            &event_fn,
            &auth_chain_fn,
        );
        assert_eq!(result, state);
    }

    #[test]
    fn unconflicted_state_merges() {
        let s1: StateMap = vec![(
            ("m.room.create".to_string(), String::new()),
            "$c".to_string(),
        )]
        .into_iter()
        .collect();
        let s2: StateMap = vec![(
            ("m.room.create".to_string(), String::new()),
            "$c".to_string(),
        )]
        .into_iter()
        .collect();
        let pdus: HashMap<String, Pdu> = HashMap::new();
        let event_fn = |id: &str| pdus.get(id).cloned();
        let auth_chain_fn = |_: &str| HashSet::new();
        let result = resolve(RoomVersion::V12, &[s1, s2], &event_fn, &auth_chain_fn);
        assert_eq!(
            result
                .get(&("m.room.create".to_string(), String::new()))
                .unwrap(),
            "$c"
        );
    }

    #[test]
    fn conflicted_create_resolves_with_rules() {
        // Two state sets conflict on the topic event. Build a small room:
        //   $create → $alice_member → $topic1
        //                         \→ $topic2 (competing)
        // Both topic events sent by alice (the creator, infinite power).
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            &[],
            0,
        );
        let alice_join = pdu(
            "$alice_join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            &["$create"],
            1,
        );
        let topic1 = pdu(
            "$topic1",
            "m.room.topic",
            Some(""),
            "@alice:example.com",
            json!({"topic": "hello"}),
            &["$create", "$alice_join"],
            2,
        );
        let topic2 = pdu(
            "$topic2",
            "m.room.topic",
            Some(""),
            "@alice:example.com",
            json!({"topic": "world"}),
            &["$create", "$alice_join"],
            3,
        );

        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&create, &alice_join, &topic1, &topic2] {
            pdus.insert(p.event_id.clone(), p.clone());
        }

        let s1: StateMap = [
            (
                ("m.room.create".to_string(), String::new()),
                "$create".to_string(),
            ),
            (
                (
                    "m.room.member".to_string(),
                    "@alice:example.com".to_string(),
                ),
                "$alice_join".to_string(),
            ),
            (
                ("m.room.topic".to_string(), String::new()),
                "$topic1".to_string(),
            ),
        ]
        .iter()
        .cloned()
        .collect();
        let s2: StateMap = [
            (
                ("m.room.create".to_string(), String::new()),
                "$create".to_string(),
            ),
            (
                (
                    "m.room.member".to_string(),
                    "@alice:example.com".to_string(),
                ),
                "$alice_join".to_string(),
            ),
            (
                ("m.room.topic".to_string(), String::new()),
                "$topic2".to_string(),
            ),
        ]
        .iter()
        .cloned()
        .collect();

        let pdus_ref = pdus.clone();
        let event_fn = move |id: &str| pdus_ref.get(id).cloned();
        let auth_chain_fn = |_: &str| HashSet::new();

        let result = resolve(RoomVersion::V12, &[s1, s2], &event_fn, &auth_chain_fn);

        // Both topic events are valid; mainline ordering by origin_server_ts means
        // topic2 (later ts) wins.
        assert_eq!(
            result
                .get(&("m.room.topic".to_string(), String::new()))
                .unwrap(),
            "$topic2"
        );
    }

    #[test]
    fn v12_fork_resolves_without_create_in_auth_events() {
        // Faithful v12 (MSC4291): the create event is OMITTED from auth_events
        // and identified by room_id instead. A fork with two competing topic
        // events must still resolve. Before the fix, the iterative auth checks
        // had no m.room.create in scope (neither in auth_events nor seeded), so
        // every conflicted event failed auth and the key vanished entirely.
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            &[],
            0,
        );
        // Even the creator's join omits create from auth_events in v12.
        let alice_join = pdu(
            "$alice_join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            &[],
            1,
        );
        // The conflicting topic events list ONLY the member event — NOT $create.
        let topic1 = pdu(
            "$topic1",
            "m.room.topic",
            Some(""),
            "@alice:example.com",
            json!({"topic": "hello"}),
            &["$alice_join"],
            2,
        );
        let topic2 = pdu(
            "$topic2",
            "m.room.topic",
            Some(""),
            "@alice:example.com",
            json!({"topic": "world"}),
            &["$alice_join"],
            3,
        );

        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&create, &alice_join, &topic1, &topic2] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let state_set = |topic: &str| -> StateMap {
            [
                (
                    ("m.room.create".to_string(), String::new()),
                    "$create".to_string(),
                ),
                (
                    (
                        "m.room.member".to_string(),
                        "@alice:example.com".to_string(),
                    ),
                    "$alice_join".to_string(),
                ),
                (
                    ("m.room.topic".to_string(), String::new()),
                    topic.to_string(),
                ),
            ]
            .iter()
            .cloned()
            .collect()
        };

        let pdus_ref = pdus.clone();
        let event_fn = move |id: &str| pdus_ref.get(id).cloned();
        let auth_chain_fn = |_: &str| HashSet::new();
        let result = resolve(
            RoomVersion::V12,
            &[state_set("$topic1"), state_set("$topic2")],
            &event_fn,
            &auth_chain_fn,
        );

        // The fork resolves to one topic (the later by ordering), not dropped.
        assert_eq!(
            result
                .get(&("m.room.topic".to_string(), String::new()))
                .map(String::as_str),
            Some("$topic2"),
            "v12 fork must keep a topic; create comes from room_id, not auth_events"
        );
    }

    #[test]
    fn power_event_ordering_prefers_higher_power_sender() {
        // Creator alice bans bob, and then bob (before being banned) sets topic.
        // Alice's ban is a power event, ordered before non-power events regardless.
        // Testing sorting: alice (creator = infinite power) should come before
        // charlie (default power 0) in reverse topological power ordering.

        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@alice:example.com",
            json!({"room_version": "12"}),
            &[],
            0,
        );
        let alice_join = pdu(
            "$alice_join",
            "m.room.member",
            Some("@alice:example.com"),
            "@alice:example.com",
            json!({"membership": "join"}),
            &["$create"],
            1,
        );
        // No power_levels event — so default power for everyone except alice
        let alice_event = pdu(
            "$alice_ev",
            "m.room.member",
            Some("@charlie:example.com"),
            "@alice:example.com",
            json!({"membership": "ban"}),
            &["$create", "$alice_join"],
            5,
        );
        let charlie_event = pdu(
            "$charlie_ev",
            "m.room.member",
            Some("@dave:example.com"),
            "@charlie:example.com",
            json!({"membership": "leave"}),
            &["$create"],
            2,
        );

        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&create, &alice_join, &alice_event, &charlie_event] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let pdus_ref = pdus.clone();
        let event_fn = |id: &str| pdus_ref.get(id).cloned();

        let full_conflicted: HashSet<String> = ["$alice_ev".to_string(), "$charlie_ev".to_string()]
            .iter()
            .cloned()
            .collect();
        let sorted = select_and_sort_power_events(&full_conflicted, &event_fn);

        // Alice (creator = infinite power) comes first
        assert_eq!(sorted[0], "$alice_ev");
        assert_eq!(sorted[1], "$charlie_ev");
    }

    #[test]
    fn empty_state_sets_returns_empty() {
        let pdus: HashMap<String, Pdu> = HashMap::new();
        let event_fn = |id: &str| pdus.get(id).cloned();
        let auth_chain_fn = |_: &str| HashSet::new();
        let result = resolve(RoomVersion::V12, &[], &event_fn, &auth_chain_fn);
        assert!(result.is_empty());
    }

    #[test]
    fn is_power_event_classification() {
        let pl = pdu(
            "$pl",
            "m.room.power_levels",
            Some(""),
            "@a:x",
            json!({}),
            &[],
            0,
        );
        assert!(is_power_event(&pl));

        let jr = pdu(
            "$jr",
            "m.room.join_rules",
            Some(""),
            "@a:x",
            json!({}),
            &[],
            0,
        );
        assert!(is_power_event(&jr));

        let self_leave = pdu(
            "$sl",
            "m.room.member",
            Some("@a:x"),
            "@a:x",
            json!({"membership": "leave"}),
            &[],
            0,
        );
        assert!(!is_power_event(&self_leave));

        let kick = pdu(
            "$kick",
            "m.room.member",
            Some("@b:x"),
            "@a:x",
            json!({"membership": "leave"}),
            &[],
            0,
        );
        assert!(is_power_event(&kick));

        let join = pdu(
            "$j",
            "m.room.member",
            Some("@a:x"),
            "@a:x",
            json!({"membership": "join"}),
            &[],
            0,
        );
        assert!(!is_power_event(&join));

        let msg = pdu("$m", "m.room.message", None, "@a:x", json!({}), &[], 0);
        assert!(!is_power_event(&msg));
    }

    #[test]
    fn mainline_sort_uses_ts_tiebreak() {
        // Two events with same mainline position sort by ts.
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@a:x",
            json!({"room_version": "12"}),
            &[],
            0,
        );
        let ev1 = pdu(
            "$ev1",
            "m.room.message",
            None,
            "@a:x",
            json!({}),
            &["$create"],
            5,
        );
        let ev2 = pdu(
            "$ev2",
            "m.room.message",
            None,
            "@a:x",
            json!({}),
            &["$create"],
            10,
        );

        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&create, &ev1, &ev2] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let event_fn = |id: &str| pdus.get(id).cloned();

        // Empty partial state → no mainline → both get position ∞, sort by ts, then event_id
        let result = mainline_sort(
            &["$ev2".to_string(), "$ev1".to_string()],
            &StateMap::new(),
            &event_fn,
        );
        // ev1 (ts=5) < ev2 (ts=10) in mainline ordering
        assert_eq!(result, vec!["$ev1", "$ev2"]);
    }

    #[test]
    fn conflicted_state_subgraph_includes_path_nodes() {
        // $a (conflicted) → auth_events → $m (not conflicted but on path) → $b (conflicted)
        // Subgraph should include {$a, $m, $b}.
        let a = pdu(
            "$a",
            "m.room.topic",
            Some(""),
            "@x:y",
            json!({}),
            &["$m"],
            1,
        );
        let m = pdu(
            "$m",
            "m.room.member",
            Some("@x:y"),
            "@x:y",
            json!({"membership": "join"}),
            &["$b"],
            0,
        );
        let b = pdu(
            "$b",
            "m.room.create",
            Some(""),
            "@x:y",
            json!({"room_version": "12"}),
            &[],
            0,
        );
        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&a, &m, &b] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let event_fn = |id: &str| pdus.get(id).cloned();

        let conflicted: HashSet<String> = ["$a".to_string(), "$b".to_string()]
            .iter()
            .cloned()
            .collect();
        let sub = conflicted_state_subgraph(&conflicted, &event_fn);
        assert!(sub.contains("$a"));
        assert!(sub.contains("$b"));
        assert!(
            sub.contains("$m"),
            "intermediate node should be in subgraph: {sub:?}"
        );
    }

    #[test]
    fn conflicted_state_subgraph_excludes_unrelated_branch() {
        // $a and $b conflicted, chain $a → $m → $b.
        // $x is an ancestor of $a but NOT an ancestor of $b — not on a path between
        // conflicted events, must be excluded.
        let a = pdu(
            "$a",
            "m.room.topic",
            Some(""),
            "@x:y",
            json!({}),
            &["$m", "$x"],
            1,
        );
        let m = pdu(
            "$m",
            "m.room.member",
            Some("@x:y"),
            "@x:y",
            json!({"membership": "join"}),
            &["$b"],
            0,
        );
        let b = pdu(
            "$b",
            "m.room.create",
            Some(""),
            "@x:y",
            json!({"room_version": "12"}),
            &[],
            0,
        );
        let x = pdu("$x", "m.room.other", Some(""), "@x:y", json!({}), &[], 0);
        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&a, &m, &b, &x] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let event_fn = |id: &str| pdus.get(id).cloned();

        let conflicted: HashSet<String> = ["$a".to_string(), "$b".to_string()]
            .iter()
            .cloned()
            .collect();
        let sub = conflicted_state_subgraph(&conflicted, &event_fn);
        assert!(sub.contains("$a"));
        assert!(sub.contains("$b"));
        assert!(sub.contains("$m"));
        assert!(
            !sub.contains("$x"),
            "$x is not on a path between conflicted events: {sub:?}"
        );
    }

    #[test]
    fn conflicted_state_subgraph_scales_linearly() {
        // Build a long ancestry chain: $n0 ← $n1 ← $n2 ← ... ← $n999.
        // Conflicted = {$n0, $n999}. Subgraph should be the entire chain, and
        // the algorithm must not regress to O(V²) behaviour.
        const N: usize = 1000;
        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for i in 0..N {
            let id = format!("$n{i}");
            let auth = if i == 0 {
                vec![]
            } else {
                vec![format!("$n{}", i - 1)]
            };
            let p = Pdu {
                event_id: id.clone(),
                room_id: "!r".into(),
                event_type: "m.room.msg".into(),
                state_key: Some("".into()),
                sender: "@x:y".into(),
                origin_server_ts: i as u64,
                content: json!({}),
                auth_events: auth,
                prev_events: vec![],
                depth: i as u64,
                signatures: None,
            };
            pdus.insert(id, p);
        }
        let event_fn = |id: &str| pdus.get(id).cloned();

        let conflicted: HashSet<String> = ["$n0".to_string(), format!("$n{}", N - 1)]
            .into_iter()
            .collect();

        let t0 = std::time::Instant::now();
        let sub = conflicted_state_subgraph(&conflicted, &event_fn);
        let elapsed = t0.elapsed();

        assert_eq!(sub.len(), N, "subgraph should contain the whole chain");
        // Loose upper bound: the old O(V²) version would take ~500ms–seconds on
        // N=1000 in release mode; our new linear version completes in micros.
        // We assert a generous 500ms ceiling to catch order-of-magnitude regressions
        // without being flaky on CI.
        assert!(
            elapsed.as_millis() < 500,
            "conflicted_state_subgraph too slow on N={N}: {elapsed:?}"
        );
    }

    /// The room version passed to `resolve` selects the algorithm variant,
    /// and the choice changes the resolved state on a fork. Here a state event
    /// (`$m`, an `m.room.name`) sits on the `auth_events` path *between* the
    /// two conflicted topic events but is in neither state set, so it belongs
    /// to the conflicted state subgraph only. With an empty `auth_chain_fn`
    /// the auth difference reduces to the conflicted set itself (each state
    /// event seeds its own id) and adds nothing new, so the subgraph is the
    /// sole difference between the variants: v12 (state-res v2.1) folds it into
    /// the full conflicted set and resolves the name key, while classic v2 (v6)
    /// does not consider it at all. Both outcomes are spec-correct for their
    /// version; the bug this guards against is applying one room's algorithm
    /// to another's fork.
    #[test]
    fn subgraph_node_resolved_only_under_v12_variant() {
        // create → a_join → $b(topic) → $m(name) → $a(topic)
        let create = pdu(
            "$create",
            "m.room.create",
            Some(""),
            "@a:x",
            json!({"room_version": "12"}),
            &[],
            0,
        );
        let a_join = pdu(
            "$a_join",
            "m.room.member",
            Some("@a:x"),
            "@a:x",
            json!({"membership": "join"}),
            &["$create"],
            1,
        );
        let b = pdu(
            "$b",
            "m.room.topic",
            Some(""),
            "@a:x",
            json!({"topic": "old"}),
            &["$create", "$a_join"],
            2,
        );
        let m = pdu(
            "$m",
            "m.room.name",
            Some(""),
            "@a:x",
            json!({"name": "mid"}),
            &["$create", "$a_join", "$b"],
            3,
        );
        let a = pdu(
            "$a",
            "m.room.topic",
            Some(""),
            "@a:x",
            json!({"topic": "new"}),
            &["$create", "$a_join", "$m"],
            4,
        );
        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&create, &a_join, &b, &m, &a] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let event_fn = move |id: &str| pdus.get(id).cloned();
        let auth_chain_fn = |_: &str| HashSet::new();

        let base: Vec<((String, String), String)> = vec![
            (("m.room.create".into(), String::new()), "$create".into()),
            (("m.room.member".into(), "@a:x".into()), "$a_join".into()),
        ];
        let mut s1: StateMap = base.iter().cloned().collect();
        s1.insert(("m.room.topic".into(), String::new()), "$a".into());
        let mut s2: StateMap = base.iter().cloned().collect();
        s2.insert(("m.room.topic".into(), String::new()), "$b".into());

        let name_key = &("m.room.name".to_string(), String::new());

        let v12 = resolve(
            RoomVersion::V12,
            &[s1.clone(), s2.clone()],
            &event_fn,
            &auth_chain_fn,
        );
        assert_eq!(
            v12.get(name_key).map(String::as_str),
            Some("$m"),
            "v12 (state-res v2.1) must fold the conflicted-subgraph node into resolution"
        );

        let v6 = resolve(RoomVersion::V6, &[s1, s2], &event_fn, &auth_chain_fn);
        assert!(
            !v6.contains_key(name_key),
            "classic v2 (v6) has no conflicted state subgraph, so the subgraph-only \
             node must not appear: {v6:?}"
        );
    }

    /// Pins the *initial-state* half of the version branch (the empty vs
    /// unconflicted starting map for the iterative auth checks), which the
    /// subgraph test above does not exercise.
    ///
    /// Models an opaque-room_id (pre-v12) room whose topics' `auth_events`
    /// omit `m.room.create`. That shape is malformed for ≤v11 (create
    /// belongs in auth_events through v11 — a boundary vela once got wrong)
    /// but is exactly what pre-fix vela and lenient peers produced, so the
    /// robustness matters. `create` is unconflicted. Under classic v2 the iterative
    /// checks start from the unconflicted map, so `create` is present and the
    /// topics authorise; under v2.1 they start from empty and `create_seed`
    /// cannot derive `create` from the opaque room_id, so the topics are
    /// rejected for want of a create event. Both are the spec-correct outcome
    /// for their algorithm — the point is that the branch is load-bearing and
    /// a real v11 fork must not be run through v2.1.
    #[test]
    fn initial_state_map_differs_by_version() {
        let mk = |id: &str,
                  ty: &str,
                  sk: Option<&str>,
                  content: serde_json::Value,
                  auth: &[&str],
                  ts: u64| Pdu {
            event_id: id.into(),
            room_id: "!room:srv".into(),
            event_type: ty.into(),
            state_key: sk.map(String::from),
            sender: "@a:srv".into(),
            origin_server_ts: ts,
            content,
            auth_events: auth.iter().map(|s| s.to_string()).collect(),
            prev_events: vec![],
            depth: ts,
            signatures: None,
        };
        let create = mk(
            "$create",
            "m.room.create",
            Some(""),
            json!({"room_version": "11"}),
            &[],
            0,
        );
        let a_join = mk(
            "$a_join",
            "m.room.member",
            Some("@a:srv"),
            json!({"membership": "join"}),
            &["$create"],
            1,
        );
        // Topics omit create from auth_events (malformed-for-≤v11 shape,
        // as pre-fix vela emitted) — so create is only reachable via the
        // unconflicted initial state map.
        let t1 = mk(
            "$t1",
            "m.room.topic",
            Some(""),
            json!({"topic": "one"}),
            &["$a_join"],
            2,
        );
        let t2 = mk(
            "$t2",
            "m.room.topic",
            Some(""),
            json!({"topic": "two"}),
            &["$a_join"],
            3,
        );
        let mut pdus: HashMap<String, Pdu> = HashMap::new();
        for p in [&create, &a_join, &t1, &t2] {
            pdus.insert(p.event_id.clone(), p.clone());
        }
        let event_fn = move |id: &str| pdus.get(id).cloned();
        let auth_chain_fn = |_: &str| HashSet::new();

        let base: Vec<((String, String), String)> = vec![
            (("m.room.create".into(), String::new()), "$create".into()),
            (("m.room.member".into(), "@a:srv".into()), "$a_join".into()),
        ];
        let mut s1: StateMap = base.iter().cloned().collect();
        s1.insert(("m.room.topic".into(), String::new()), "$t1".into());
        let mut s2: StateMap = base.iter().cloned().collect();
        s2.insert(("m.room.topic".into(), String::new()), "$t2".into());
        let topic_key = &("m.room.topic".to_string(), String::new());

        let v11 = resolve(
            RoomVersion::V11,
            &[s1.clone(), s2.clone()],
            &event_fn,
            &auth_chain_fn,
        );
        assert!(
            v11.contains_key(topic_key),
            "classic v2 starts from the unconflicted map (create present), so the \
             topics must resolve: {v11:?}"
        );

        let v12 = resolve(RoomVersion::V12, &[s1, s2], &event_fn, &auth_chain_fn);
        assert!(
            !v12.contains_key(topic_key),
            "v2.1 starts from empty and cannot seed create from an opaque room_id, \
             so the topics are rejected: {v12:?}"
        );
    }
}
