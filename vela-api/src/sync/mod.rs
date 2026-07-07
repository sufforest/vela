//! Client read paths: classic `/sync`, sliding sync (MSC4186), the
//! filter store, and the ephemeral surfaces (receipts, typing,
//! thread subscriptions) that ride alongside timeline + state.

pub mod filters;
pub mod receipts;
pub mod sliding_sync;
pub mod thread_subscriptions;
pub mod typing;

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use crate::middleware::json::Json;
use axum::extract::{Query, State};
use serde::Deserialize;
use serde_json::{Value, json};
use vela_core::error::VelaError;
use vela_core::events::view::EventView;
use vela_core::identifiers::Nid;

use crate::middleware::auth::AuthenticatedUser;
use crate::middleware::error::ApiError;
use crate::room::messages::load_client_event;
use crate::router::AppState;
use crate::sync::typing::get_typing_users;

const DEFAULT_TIMELINE_LIMIT: usize = 30;

#[derive(Deserialize)]
pub struct SyncQuery {
    pub since: Option<String>,
    pub timeout: Option<u64>,
    #[allow(dead_code)]
    pub full_state: Option<bool>,
    /// Either a previously-uploaded `filter_id` (POST /user/{}/filter) or
    /// inline JSON starting with `{`.
    pub filter: Option<String>,
    /// Per c2s spec: clients pass `set_presence=offline|unavailable` to
    /// suppress the implicit "online" mark that polling /sync otherwise
    /// triggers. Omitted → caller goes online.
    pub set_presence: Option<String>,
    /// MSC4222 (stable in Matrix 1.16). When `true`, the room state in
    /// the response is emitted under `state_after` instead of `state`,
    /// reflecting state at the **end** of the timeline rather than at
    /// the start. Clients without this opt-in keep the legacy `state`
    /// field shape.
    #[serde(rename = "use_state_after")]
    pub use_state_after: Option<bool>,
    /// The pre-stabilisation MSC4222 spelling, still sent by current Element
    /// builds (`org.matrix.msc4222.use_state_after`). Either name opts in;
    /// without this, Element is silently downgraded to the legacy `state`
    /// shape, which also mis-routes lazy-loaded member state.
    #[serde(rename = "org.matrix.msc4222.use_state_after")]
    pub use_state_after_unstable: Option<bool>,
}

/// GET /_matrix/client/v3/sync
pub async fn sync(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(query): Query<SyncQuery>,
) -> Result<Json<Value>, ApiError> {
    let since: Option<u64> = query
        .since
        .as_deref()
        .and_then(|s| s.strip_prefix('s'))
        .and_then(|s| s.parse().ok());

    let timeout_ms = query.timeout.unwrap_or(0);

    // Apply set_presence per spec (default: online). Touch
    // last_active_ms on every poll; only rewrite the `presence` field
    // and federate when the value actually changes — repeated /sync
    // calls with the same effective presence (e.g. polling clients
    // staying online) shouldn't fan out fresh m.presence EDUs.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let want_presence = query.set_presence.as_deref().unwrap_or("online");
    let current_presence = state
        .db
        .get_presence(user.user_nid)
        .ok()
        .flatten()
        .and_then(|v| {
            v.get("presence")
                .and_then(|p| p.as_str())
                .map(str::to_owned)
        });
    if current_presence.as_deref() != Some(want_presence) {
        let mut rec = serde_json::Map::new();
        rec.insert("presence".into(), serde_json::json!(want_presence));
        rec.insert("last_active_ms".into(), serde_json::json!(now));
        let _ = state
            .db
            .set_local_presence(user.user_nid, &Value::Object(rec));
        state
            .federation_sender
            .notify_user_subscribers(user.user_nid);
    } else {
        // No state change — just refresh the activity timestamp.
        let _ = state.db.touch_presence(user.user_nid, now);
    }

    let joined_room_nids = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Subscribe to room channels BEFORE checking DB to avoid the race where
    // a message arrives between "check DB" and "subscribe". If we find events
    // in the DB, we return immediately and the subscriptions are dropped.
    let (notify_tx, mut notify_rx) = tokio::sync::mpsc::channel::<()>(1);
    let should_longpoll = timeout_ms > 0 && since.is_some();

    let mut task_handles = Vec::new();

    if should_longpoll {
        for &room_nid in &joined_room_nids {
            let mut rx = {
                let sender = state.room_senders.entry(Nid(room_nid)).or_insert_with(|| {
                    let (tx, _) = tokio::sync::broadcast::channel(64);
                    tx
                });
                sender.value().subscribe()
            };
            let tx = notify_tx.clone();
            let handle = tokio::spawn(async move {
                // Lagged also counts as a wake — the channel buffer
                // overflowed (64 broadcasts in this room while the
                // listener was still being scheduled), but the events
                // ARE in the DB. The main task re-reads on wake, so
                // letting Lagged signal here is the correct recovery:
                // turn the lag into a single coalesced wake, drop the
                // backlog, exit. Only `Closed` (sender dropped) means
                // no further work for this listener.
                use tokio::sync::broadcast::error::RecvError;
                if !matches!(rx.recv().await, Err(RecvError::Closed)) {
                    let _ = tx.send(()).await;
                }
            });
            task_handles.push(handle);
        }

        // Also subscribe to the per-user channel so the long-poll wakes
        // when the user's room list changes (invite accepted, DM created,
        // knock, leave, ban). Without this a pending /sync only learns
        // about new rooms after its 30s timeout.
        let mut user_rx = {
            let sender = state.user_senders.entry(user.user_nid).or_insert_with(|| {
                let (tx, _) = tokio::sync::broadcast::channel(64);
                tx
            });
            sender.value().subscribe()
        };
        let tx = notify_tx.clone();
        let handle = tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            if !matches!(user_rx.recv().await, Err(RecvError::Closed)) {
                let _ = tx.send(()).await;
            }
        });
        task_handles.push(handle);
    }
    drop(notify_tx);

    let filter = resolve_filter(&state, &user, query.filter.as_deref())?;
    let full_state = query.full_state.unwrap_or(false);
    let use_state_after = query
        .use_state_after
        .or(query.use_state_after_unstable)
        .unwrap_or(false);
    // MSC4222: the response state field must use the SAME spelling the client
    // opted in with — the stable `state_after` for `use_state_after`, the
    // unstable `org.matrix.msc4222.state_after` for the unstable param. We
    // build under the stable name internally and rename to this on the way out.
    // (sync.yaml: a client detects support from the presence of `state_after`;
    // if its key is missing it MUST behave as if it never opted in. So a client
    // sending the unstable param and reading the unstable key never finds a
    // stable-keyed response, falls back to the timeline, and a room whose create
    // event has scrolled past the timeline window then renders as "version 1".)
    let state_after_key = if query.use_state_after == Some(true) {
        "state_after"
    } else if query.use_state_after_unstable == Some(true) {
        "org.matrix.msc4222.state_after"
    } else {
        "state_after"
    };

    // Now check the DB — any events broadcast after our subscribe() call
    // will be caught by the spawned listener tasks.
    let mut response = build_sync_response_inner(
        &state,
        &user,
        &joined_room_nids,
        since,
        filter.as_ref(),
        full_state,
        use_state_after,
    )?;
    rename_state_after_for_client(&mut response, state_after_key);

    // A joined room appears in `rooms.join` only when it has new
    // content (timeline / state / ephemeral / account_data) per the
    // unchanged-room rule. So "any joined room is present" is itself
    // the signal that there's new data to deliver — no need to crack
    // open the timeline. This catches typing/receipt-only changes
    // that previously left long-polls hanging until timeout.
    let has_events = response
        .get("rooms")
        .and_then(|r| r.get("join"))
        .and_then(|j| j.as_object())
        .is_some_and(|rooms| !rooms.is_empty());
    let has_invites = response
        .get("rooms")
        .and_then(|r| r.get("invite"))
        .and_then(|i| i.as_object())
        .is_some_and(|m| !m.is_empty());
    let has_leaves = response
        .get("rooms")
        .and_then(|r| r.get("leave"))
        .and_then(|l| l.as_object())
        .is_some_and(|m| !m.is_empty());
    let has_to_device = response
        .get("to_device")
        .and_then(|td| td.get("events"))
        .and_then(|e| e.as_array())
        .is_some_and(|a| !a.is_empty());
    let has_account_data = response
        .get("account_data")
        .and_then(|ad| ad.get("events"))
        .and_then(|e| e.as_array())
        .is_some_and(|a| !a.is_empty());
    let has_device_list_changes = response
        .pointer("/device_lists/changed")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty())
        || response
            .pointer("/device_lists/left")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
    let has_new_data = has_events
        || has_invites
        || has_leaves
        || has_to_device
        || has_account_data
        || has_device_list_changes;

    if has_new_data || !should_longpoll {
        for h in task_handles {
            h.abort();
        }
        return Ok(Json(response));
    }

    // Long-poll: wait for notification or timeout
    let timeout = Duration::from_millis(timeout_ms.min(30_000));

    tokio::select! {
        _ = notify_rx.recv() => {},
        _ = tokio::time::sleep(timeout) => {},
    }

    // Abort all listener tasks regardless of wake reason
    for h in task_handles {
        h.abort();
    }

    // Re-fetch joined rooms: the user_senders wake often fires because the
    // user's membership changed (invite accepted, room created). The
    // snapshot captured before the long-poll is stale in that case; using
    // it would drop the newly-joined room from the response, leaving
    // Element stuck on the old view until a hard refresh.
    let joined_room_nids = state
        .db
        .get_user_joined_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut response = build_sync_response_inner(
        &state,
        &user,
        &joined_room_nids,
        since,
        filter.as_ref(),
        full_state,
        use_state_after,
    )?;
    rename_state_after_for_client(&mut response, state_after_key);
    Ok(Json(response))
}

/// MSC4222: rename the canonical `state_after` field in `rooms.join.*` to the
/// key spelling the client opted in with. The unstable param
/// `org.matrix.msc4222.use_state_after` pairs with the unstable response key
/// `org.matrix.msc4222.state_after`; the stable `use_state_after` uses
/// `state_after`. (Unstable-prefix is the Matrix convention for a feature still
/// on an MSC; the stable names are spec since v1.16.) We build under the stable
/// name internally and rename here, so the field name matches what the client
/// looks for — a client reading the unstable key never finds a stable-keyed
/// response and, per the spec, behaves as if it never opted in. No-op for the
/// stable spelling.
fn rename_state_after_for_client(response: &mut Value, key: &str) {
    if key == "state_after" {
        return;
    }
    let Some(join) = response
        .pointer_mut("/rooms/join")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };
    for room_data in join.values_mut() {
        if let Some(obj) = room_data.as_object_mut()
            && let Some(state_after) = obj.remove("state_after")
        {
            obj.insert(key.to_string(), state_after);
        }
    }
}

#[allow(dead_code)]
pub(crate) fn build_sync_response(
    state: &AppState,
    user: &AuthenticatedUser,
    joined_room_nids: &[u64],
    since: Option<u64>,
) -> Result<Value, ApiError> {
    build_sync_response_with_filter(state, user, joined_room_nids, since, None, false)
}

pub(crate) fn build_sync_response_with_filter(
    state: &AppState,
    user: &AuthenticatedUser,
    joined_room_nids: &[u64],
    since: Option<u64>,
    filter: Option<&Value>,
    full_state: bool,
) -> Result<Value, ApiError> {
    build_sync_response_inner(
        state,
        user,
        joined_room_nids,
        since,
        filter,
        full_state,
        false,
    )
}

pub(crate) fn build_sync_response_inner(
    state: &AppState,
    user: &AuthenticatedUser,
    joined_room_nids: &[u64],
    since: Option<u64>,
    filter: Option<&Value>,
    full_state: bool,
    use_state_after: bool,
) -> Result<Value, ApiError> {
    // Safe watermark: largest pos such that EVERY pos ≤ it has committed.
    // Used wherever a returned pos becomes a future /sync's `since` —
    // next_batch, the timeline upper bound, and the device-list upper
    // bound. If a device_lists.changed entry at pos B > safe_pos slips
    // in, next_batch=safe_pos lands below B and the next /sync's
    // `since`-keyed scan re-delivers B as a duplicate change.
    let safe_pos = state.db.safe_stream_position();
    let ignored = load_ignored_users(state, user.user_nid)?;
    let mut join_rooms = serde_json::Map::new();

    let room_filter = filter.and_then(|f| f.get("room"));
    let state_filter = room_filter.and_then(|r| r.get("state"));
    let timeline_filter = room_filter.and_then(|r| r.get("timeline"));
    let lazy_load = crate::sync::filters::lazy_load_members_enabled(state_filter, timeline_filter)
        && !crate::sync::filters::include_redundant_members(state_filter);
    for &room_nid in joined_room_nids {
        // The caller passed a snapshot of joined rooms taken at request
        // start. A long-poll wake on a ban / kick / leave races that
        // snapshot — the user is no longer joined by the time we build
        // the response, but the stale snapshot still includes the room
        // here while `get_user_left_rooms` below also includes it. The
        // room then shows up in BOTH `rooms.join` and `rooms.leave`
        // (TestUnbanViaInvite). Re-check current membership and skip
        // when it isn't still `join`.
        if state
            .db
            .get_membership(room_nid, user.user_nid)
            .ok()
            .flatten()
            != Some(1)
        {
            continue;
        }

        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        if let Some(rf) = room_filter
            && !crate::sync::filters::room_passes_filter(&room_id, rf)
        {
            continue;
        }

        // MSC3902 / MSC3706 eager-sync gating. Eager clients (no
        // `lazy_load_members`) MUST NOT see partial-state rooms — the
        // member set is incomplete and the client would render mention
        // autocomplete + DM grouping off the wrong roster. Skip them
        // while partial; once the filler clears, force a full-state
        // response on the first poll that crosses the clearance pos
        // (`since < cleared_at`). Lazy clients keep the existing
        // partial_state-true behaviour at the bottom of this loop.
        let (partial, _servers) = state
            .db
            .get_partial_state_info(room_nid)
            .unwrap_or((false, Vec::new()));
        let cleared_at = state.db.get_partial_cleared_at(room_nid).unwrap_or(None);
        if !lazy_load && partial {
            continue;
        }
        // First eager /sync past clearance: pretend `since=None` so
        // build_room_sync_for_user emits a full-state snapshot
        // (not a state delta). The filler's merged events landed as
        // `StateBundleOnly` without their own stream_pos, so the
        // delta scan can't see them. Without this branch the eager
        // client would carry the partial roster into perpetuity.
        let force_full_state =
            !lazy_load && !partial && cleared_at.is_some_and(|c| since.is_none_or(|s| s < c));
        let effective_since = if force_full_state { None } else { since };

        // Fast path: on an incremental sync, skip the whole per-room build
        // for rooms with nothing new since the caller's cursor. A typical
        // poll leaves most joined rooms quiet, and without this each one
        // still ran the full builder (timeline + state + receipts + unread
        // scans) only for `room_is_unchanged` to discard it afterwards —
        // O(all joined rooms) wasted work per poll. `room_has_changes_since`
        // is conservative (any doubt → build), and the authoritative
        // `room_is_unchanged` gate still runs below for whatever passes, so
        // this can only save work, never drop an update.
        if let Some(since_pos) = since
            && !full_state
            && !force_full_state
            && !room_has_changes_since(state, room_nid, user.user_nid, since_pos)
        {
            continue;
        }

        // Honour the filter's timeline.limit at DB query time so
        // prev_batch is computed from the trimmed batch (not the
        // pre-trim one — that breaks /messages backward pagination).
        // Cap at DEFAULT_TIMELINE_LIMIT to match the spec-suggested
        // ceiling.
        let timeline_limit = timeline_filter
            .and_then(|tf| tf.get("limit"))
            .and_then(|v| v.as_u64())
            .map(|n| (n as usize).min(DEFAULT_TIMELINE_LIMIT))
            .unwrap_or(DEFAULT_TIMELINE_LIMIT);
        // Per MSC3773 / spec: `unread_thread_notifications` opts the
        // sync into per-thread counts. Without it, threaded events count
        // toward the room's main `unread_notifications`.
        let unread_thread_notifications = timeline_filter
            .and_then(|tf| tf.get("unread_thread_notifications"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let mut room_data = build_room_sync_for_user(
            state,
            room_nid,
            &room_id,
            effective_since,
            Some(user.user_nid),
            Some(&user.device_id),
            timeline_limit,
            unread_thread_notifications,
            safe_pos,
            use_state_after,
        )?;
        if !ignored.is_empty() {
            filter_room_timeline_by_ignored(&mut room_data, &ignored);
        }
        if let Some(tf) = timeline_filter {
            crate::sync::filters::apply_timeline_filter(&mut room_data, tf);
        }
        // Apply the state filter before lazy-loading so lazy-loaded member
        // events (added next) are never stripped by a `not_types` / `types`
        // that omits `m.room.member` — lazy loading is its own opt-in.
        if let Some(sf) = state_filter {
            crate::sync::filters::apply_state_filter(&mut room_data, sf);
        }
        // Per-room `ephemeral` (typing / receipts) and `account_data`
        // sub-filters — accepted-but-ignored until now.
        if let Some(rf) = room_filter {
            for (sub, ptr) in [
                ("ephemeral", "/ephemeral/events"),
                ("account_data", "/account_data/events"),
            ] {
                if let Some(sub_filter) = rf.get(sub)
                    && let Some(arr) = room_data.pointer_mut(ptr).and_then(|v| v.as_array_mut())
                {
                    crate::sync::filters::apply_event_filter(arr, sub_filter);
                }
            }
        }
        // Spec: on incremental sync, joined rooms that have no new content
        // since `since` MUST be omitted from `rooms.join` — sending them back
        // wastes bandwidth and confuses clients into thinking the timeline
        // restarted. `full_state=true` overrides this; the post-clearance
        // force-full path is also exempt.
        //
        // ── INVARIANT (do not break) ────────────────────────────────────────
        // This decision MUST be made on the room's real, `since`-bounded
        // CHANGES only. Anything that is *presentation* — lazy-loaded member
        // state, summary/heroes, the partial_state marker, the next such field
        // — MUST be applied AFTER this gate, never before it. Injecting
        // presentation into a checked section (timeline/state/state_after/
        // ephemeral/account_data) of a quiet room makes every room reappear on
        // every /sync, so the long-poll never sleeps and clients busy-loop at
        // ~10 syncs/sec. This has bitten receipts, typing, and lazy-load.
        // `quiet_incremental_sync_omits_rooms_across_options` guards it.
        // ────────────────────────────────────────────────────────────────────
        if since.is_some() && !full_state && !force_full_state && room_is_unchanged(&room_data) {
            continue;
        }

        if lazy_load {
            ensure_lazy_load_member_state(
                state,
                room_nid,
                &room_id,
                &mut room_data,
                user,
                use_state_after,
            )?;
            crate::sync::filters::apply_lazy_load_state(
                &mut room_data,
                &user.user_id,
                use_state_after,
            );
        }
        // MSC3706 client signal: surface `partial_state: true` so the
        // lazy client knows the membership list is incomplete and can
        // soft-fail features that depend on full state (e.g. mention
        // autocomplete) until the filler catches up. Eager clients
        // never reach this point with `partial=true` (gated above).
        if partial && let Some(obj) = room_data.as_object_mut() {
            obj.insert("partial_state".into(), json!(true));
        }
        join_rooms.insert(room_id, room_data);
    }

    let invited_room_nids = state
        .db
        .get_user_invited_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut invite_rooms = serde_json::Map::new();
    for &room_nid in &invited_room_nids {
        if !membership_changed_since(state, user.user_nid, room_nid, since)? {
            continue;
        }
        // Skip invites where the inviter (sender of the recipient's
        // m.room.member invite event) is on the ignored list.
        if !ignored.is_empty()
            && invite_sender_is_ignored(state, room_nid, user.user_nid, &ignored)?
        {
            continue;
        }
        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        let invite_data = build_invite_sync(state, room_nid, &room_id)?;
        invite_rooms.insert(room_id, invite_data);
    }

    let left_room_nids = state
        .db
        .get_user_left_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let include_leave = room_filter
        .and_then(|rf| rf.get("include_leave"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mut leave_rooms = serde_json::Map::new();
    for &room_nid in &left_room_nids {
        // A room whose membership changed within this sync window (the leave
        // itself) is always surfaced so the client learns of the leave. A
        // historical left room is surfaced only on a full view of the account
        // — an initial sync or a full_state sync — and only when the filter
        // opts in via include_leave (spec default false). This is what stops
        // include_leave from re-surfacing an already-reported leave on every
        // incremental sync (Complement's TestOlderLeftRoomsNotInLeaveSection).
        let newly_left =
            since.is_some() && membership_changed_since(state, user.user_nid, room_nid, since)?;
        let full_sync = since.is_none() || full_state;
        let show = newly_left || (full_sync && include_leave);
        if !show {
            continue;
        }
        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        let timeline_limit = timeline_filter
            .and_then(|tf| tf.get("limit"))
            .and_then(|v| v.as_u64())
            .map(|n| (n as usize).min(DEFAULT_TIMELINE_LIMIT))
            .unwrap_or(DEFAULT_TIMELINE_LIMIT);

        let mut leave_data = build_leave_sync(
            state,
            room_nid,
            &room_id,
            user.user_nid,
            &user.user_id,
            since,
            timeline_limit,
        )?;
        if let Some(tf) = timeline_filter {
            crate::sync::filters::apply_timeline_filter(&mut leave_data, tf);
        }
        if let Some(sf) = state_filter {
            crate::sync::filters::apply_state_filter(&mut leave_data, sf);
        }
        leave_rooms.insert(room_id, leave_data);
    }

    let knocked_room_nids = state
        .db
        .get_user_knocked_rooms(user.user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let mut knock_rooms = serde_json::Map::new();
    for &room_nid in &knocked_room_nids {
        if !membership_changed_since(state, user.user_nid, room_nid, since)? {
            continue;
        }
        let room_id = state
            .db
            .resolve_nid(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();

        let knock_data = build_knock_sync(state, room_nid, &room_id)?;
        knock_rooms.insert(room_id, knock_data);
    }

    // Global account data. On initial sync we return everything except
    // MSC3391-tombstoned entries (empty `{}` content represents a
    // deletion — a fresh device shouldn't see them at all). On
    // incremental sync we stream every change including the empty-
    // content event, so other devices catch up on the delete.
    let mut global_account_data: Vec<Value> = match since {
        None => state
            .db
            .get_all_account_data(user.user_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .into_iter()
            .filter(|(_, content)| !content.as_object().is_some_and(|o| o.is_empty()))
            .map(|(dtype, content)| json!({"type": dtype, "content": content}))
            .collect(),
        Some(since_pos) => state
            .db
            .get_account_data_since(user.user_nid, since_pos, safe_pos + 1)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .into_iter()
            .map(|(dtype, content)| json!({"type": dtype, "content": content}))
            .collect(),
    };

    // Synthesise an `m.push_rules` event on initial sync if the user
    // hasn't customised. Spec mandates the rules always appear in
    // account_data; clients (Element, ESS) rely on this to show
    // notification settings without a separate /pushrules round-trip.
    // For incremental sync we leave this alone — the rules don't
    // change unless the user wrote, in which case the write already
    // produced an account_data event with a stream position past
    // `since`.
    if since.is_none()
        && !global_account_data
            .iter()
            .any(|e| e.get("type").and_then(|v| v.as_str()) == Some("m.push_rules"))
    {
        let global = vela_core::push_rules::default_global_rules();
        global_account_data.push(json!({
            "type": "m.push_rules",
            "content": { "global": global },
        }));
    }

    // To-device messages are delivered delete-on-ACK, not delete-on-read:
    // the client acknowledges a message by syncing past it (presenting a
    // `since` at or beyond its stream id). Drop everything ≤ `since` now
    // (the client has seen it), then return the (since, safe_pos] window —
    // each message stays in the store until a later `since` acks it. A
    // dropped or failed sync response therefore can't permanently lose an
    // `m.key.verification.*` event the way the old delete-on-read did.
    let since_pos = since.unwrap_or(0);
    state
        .db
        .ack_to_device_messages(user.user_nid, &user.device_id, since_pos)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let to_device_events = state
        .db
        .get_to_device_messages_window(user.user_nid, &user.device_id, since_pos, safe_pos)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // E2EE key counts for this device
    let otk_counts = state
        .db
        .count_one_time_keys(user.user_nid, &user.device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let unused_fallback_key_types = state
        .db
        .unused_fallback_key_algorithms(user.user_nid, &user.device_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    state
        .db
        .set_sync_position(user.user_nid, &user.device_id, safe_pos)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut presence_events = collect_presence_events(state, user.user_nid, joined_room_nids)?;
    // Top-level `presence` and `account_data` sub-filters (types / not_types /
    // senders / limit). Accepted-but-ignored until now.
    if let Some(pf) = filter.and_then(|f| f.get("presence")) {
        crate::sync::filters::apply_event_filter(&mut presence_events, pf);
    }
    if let Some(af) = filter.and_then(|f| f.get("account_data")) {
        crate::sync::filters::apply_event_filter(&mut global_account_data, af);
    }

    // device_lists.changed: users whose device/cross-signing keys changed
    // since `since` (or since 0 on initial sync). Element uses this to
    // decide when to re-query /keys/query; without it, self-signature
    // uploads don't surface and the device stays "unverified".
    // `since` is the highest position already returned to the client
    // (next_batch from the prior /sync). The rest of sync treats it
    // as exclusive — strictly newer events. Match that here by
    // starting one position past `since`, otherwise the long-poll
    // re-serves a change that was already in the prior response.
    let dl_from = since.map(|s| s.saturating_add(1)).unwrap_or(0);
    let device_lists_changed: Vec<String> = {
        // Shared fall-behind guard: when `dl_from` predates the retained
        // device-list window, this over-reports all shared-room users so
        // the client re-queries everyone rather than missing pruned changes.
        let nids = crate::e2ee::keys::device_list_changed_nids(
            state,
            user.user_nid,
            dl_from,
            safe_pos + 1,
        )?;
        let mut out = Vec::new();
        for nid in nids {
            if let Some(uid) = state
                .db
                .resolve_nid(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                out.push(uid);
            }
        }
        out
    };
    // device_lists.left: users we no longer share any room with since
    // `since`. Post-filter the raw "departed from a room I was in"
    // events against current shared-room state — bob may have left
    // the room that triggered the entry but still share another room
    // with us, in which case we do NOT report him as "left".
    let device_lists_left: Vec<String> = {
        let raw = state
            .db
            .get_device_list_left(user.user_nid, dl_from, safe_pos + 1)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        let our_rooms: HashSet<u64> = state
            .db
            .get_user_joined_rooms(user.user_nid)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut out = Vec::new();
        for nid in raw {
            // Drop the change-side dedup: a user may appear in both
            // changed and left within the same window. Spec says left
            // wins for the "no longer shares" semantic.
            //
            // One get_user_joined_rooms + set intersect per changed
            // user, vs O(our_rooms) get_membership calls previously.
            let their_rooms = state.db.get_user_joined_rooms(nid).unwrap_or_default();
            let still_sharing = their_rooms.iter().any(|r| our_rooms.contains(r));
            if still_sharing {
                continue;
            }
            if let Some(uid) = state
                .db
                .resolve_nid(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                out.push(uid);
            }
        }
        out
    };
    // O(1) lookup per element vs the previous O(N) Vec::contains.
    let left_set: HashSet<&str> = device_lists_left.iter().map(String::as_str).collect();
    let device_lists_changed: Vec<String> = device_lists_changed
        .into_iter()
        .filter(|u| !left_set.contains(u.as_str()))
        .collect();

    // Per spec, each rooms.{join,invite,leave,knock} section is
    // optional. Emit only those that have entries so consumers that
    // test `JSONKeyMissing` (e.g. MSC4155 invite-filter coverage)
    // see the section disappear when filtering blocked an invite.
    let mut rooms = serde_json::Map::new();
    if !join_rooms.is_empty() {
        rooms.insert("join".into(), Value::Object(join_rooms));
    }
    if !invite_rooms.is_empty() {
        rooms.insert("invite".into(), Value::Object(invite_rooms));
    }
    if !leave_rooms.is_empty() {
        rooms.insert("leave".into(), Value::Object(leave_rooms));
    }
    if !knock_rooms.is_empty() {
        rooms.insert("knock".into(), Value::Object(knock_rooms));
    }
    Ok(json!({
        "next_batch": format!("s{safe_pos}"),
        "rooms": rooms,
        "presence": {"events": presence_events},
        "account_data": {"events": global_account_data},
        "to_device": {"events": to_device_events},
        "device_lists": {"changed": device_lists_changed, "left": device_lists_left},
        "device_one_time_keys_count": otk_counts,
        "device_unused_fallback_key_types": unused_fallback_key_types,
    }))
}

/// MSC4115: annotate `unsigned.membership` on `ev` with the requesting
/// user's `m.room.member` value as it stood at `event_nid`. Default
/// `"leave"` when the user had no member event yet. No-op when
/// `user_nid` is `None`.
fn attach_membership_for_user(
    state: &AppState,
    ev: &mut Value,
    user_nid: Option<u64>,
    event_nid: u64,
) {
    let Some(uid) = user_nid else { return };
    let membership = crate::room::messages::membership_at_event(state, 0, uid, event_nid)
        .ok()
        .flatten()
        .unwrap_or_else(|| "leave".to_string());
    let Some(obj) = ev.as_object_mut() else {
        return;
    };
    let unsigned = obj
        .entry("unsigned".to_string())
        .or_insert_with(|| json!({}));
    let Some(unsigned_obj) = unsigned.as_object_mut() else {
        return;
    };
    unsigned_obj.insert("membership".to_string(), json!(membership));
}

/// Attach `unsigned.transaction_id` to `ev` when the requesting
/// `(user_nid, device_id)` matches the originating sender. Used on
/// the local-echo path for /sync timeline events; matches the
/// behaviour of `load_client_event_with_relations` for /event,
/// /messages, and /relations.
fn attach_txn_id_for_user(
    state: &AppState,
    ev: &mut Value,
    user_nid: Option<u64>,
    device_id: Option<&str>,
    event_nid: u64,
) {
    let (Some(uid), Some(did)) = (user_nid, device_id) else {
        return;
    };
    let Ok(Some(txn)) = state.db.get_event_txn_id_for_user(event_nid, uid, did) else {
        return;
    };
    let Some(obj) = ev.as_object_mut() else {
        return;
    };
    let unsigned = obj
        .entry("unsigned".to_string())
        .or_insert_with(|| json!({}));
    let Some(unsigned_obj) = unsigned.as_object_mut() else {
        return;
    };
    unsigned_obj.insert("transaction_id".to_string(), json!(txn));
}

/// Load a timeline event with bundled aggregations (reactions, edits,
/// thread summary), membership-at-event, and local-echo txn_id all
/// attached. Lifts the per-call-site boilerplate for /sync timelines.
fn load_timeline_event(
    state: &AppState,
    event_nid: u64,
    room_id: &str,
    user_nid: Option<u64>,
    device_id: Option<&str>,
) -> Result<Option<Value>, ApiError> {
    let caller = match (user_nid, device_id) {
        (Some(u), Some(d)) => Some((u, d)),
        _ => None,
    };
    crate::room::messages::load_client_event_with_relations(state, event_nid, room_id, caller)
}

/// Per spec, `/sync`'s `state` field on incremental sync is the delta
/// between the client's last sync position and the start of the
/// returned timeline batch. Vela walks `room_timeline` in
/// `(since_exclusive, upper_exclusive)` (so the caller passes
/// `since_pos + 1` and `first_timeline_pos`), keeps only state events,
/// dedupes on `(type, state_key)` keeping the latest position, and
/// loads them as client events.
///
/// Capped at `DELTA_STATE_SCAN_LIMIT` events scanned to keep wide gap
/// catch-ups from doing an unbounded walk. Beyond the cap the client
/// keeps any stale state until they do a full sync — strictly worse
/// than current behaviour (which always returns empty) but in line
/// with how Synapse treats deeply-stale clients.
fn compute_state_delta(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    since_exclusive: u64,
    upper_exclusive: u64,
    user_nid: Option<u64>,
    device_id: Option<&str>,
) -> Result<Vec<Value>, ApiError> {
    const DELTA_STATE_SCAN_LIMIT: usize = 500;
    if since_exclusive >= upper_exclusive {
        return Ok(Vec::new());
    }
    let entries = state
        .db
        .get_timeline_range(
            room_nid,
            since_exclusive,
            upper_exclusive,
            DELTA_STATE_SCAN_LIMIT,
        )
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let mut latest_by_slot: HashMap<(String, String), (u64, u64)> = HashMap::new();
    for (pos, nid) in &entries {
        // The event header has type_nid + state_key_nid as u64; a
        // state event has a non-zero state_key_nid in the events CF
        // header. Re-fetch just enough to decide.
        let (header, _) = match state
            .db
            .get_event(*nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        {
            Some(h) => h,
            None => continue,
        };
        if header.state_key_nid == 0 {
            continue;
        }
        let etype = state
            .db
            .resolve_nid(header.type_nid)
            .ok()
            .flatten()
            .unwrap_or_default();
        let skey = state
            .db
            .resolve_nid(header.state_key_nid)
            .ok()
            .flatten()
            .unwrap_or_default();
        latest_by_slot
            .entry((etype, skey))
            .and_modify(|cur| {
                if *pos > cur.0 {
                    *cur = (*pos, *nid);
                }
            })
            .or_insert((*pos, *nid));
    }
    let mut out = Vec::with_capacity(latest_by_slot.len());
    for (_, (_, nid)) in latest_by_slot {
        if let Some(mut ev) = load_client_event(state, nid, room_id)? {
            attach_membership_for_user(state, &mut ev, user_nid, nid);
            attach_txn_id_for_user(state, &mut ev, user_nid, device_id, nid);
            out.push(ev);
        }
    }
    Ok(out)
}

/// Lazy-loading completion: ensure the room's `state.events` carries a
/// `m.room.member` event for every sender appearing in `timeline.events`
/// (plus the requesting user themselves). The state delta in
/// `compute_state_delta` only includes member events that *transitioned*
/// inside the (since, first_pos) window — for remote senders whose
/// membership state landed via federation (partial-state filler, or the
/// inbound-event "promote sender member" path) without a stream_pos,
/// the delta misses them entirely and the client can't render the
/// timeline with the right display names. Pull the missing entries
/// from current room state and prepend them to `state.events`.
///
/// `apply_lazy_load_state` runs *after* this to trim non-relevant
/// member events; this function only ADDS, never removes.
fn ensure_lazy_load_member_state(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    room_data: &mut Value,
    user: &AuthenticatedUser,
    use_state_after: bool,
) -> Result<(), ApiError> {
    use std::collections::HashSet;

    // Lazy-loading supplies membership context for the SENDERS of the timeline
    // events being delivered, so clients can render them. With no timeline
    // events there is nothing to contextualise — inject NOTHING. Injecting on a
    // quiet sync (e.g. the caller's own membership) would make an otherwise-
    // unchanged room look changed, so `room_is_unchanged` keeps returning it on
    // every /sync and the long-poll busy-loops. That is the root cause of the
    // hammer; `quiet_incremental_sync_omits_rooms_across_options` guards it.
    let mut needed: HashSet<String> = room_data
        .pointer("/timeline/events")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("sender").and_then(|x| x.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if needed.is_empty() {
        return Ok(());
    }
    // The caller's own membership goes alongside the senders — clients expect
    // their own member event in a room they're actively receiving events in.
    needed.insert(user.user_id.clone());
    let state_pointer = if use_state_after {
        "/state_after/events"
    } else {
        "/state/events"
    };
    let already: HashSet<String> = room_data
        .pointer(state_pointer)
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| {
                    let ty = e.get("type").and_then(|v| v.as_str())?;
                    if ty != "m.room.member" {
                        return None;
                    }
                    e.get("state_key")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();
    let Ok(Some(type_member_nid)) = state.db.get_nid("m.room.member") else {
        return Ok(());
    };
    let mut to_add: Vec<Value> = Vec::new();
    for sender in &needed {
        if already.contains(sender) {
            continue;
        }
        let Ok(Some(sender_nid)) = state.db.get_nid(sender) else {
            continue;
        };
        let Ok(Some(member_nid)) =
            state
                .db
                .get_state_event_nid(room_nid, type_member_nid, sender_nid)
        else {
            continue;
        };
        if let Some(ev) = crate::room::messages::load_client_event(state, member_nid, room_id)? {
            to_add.push(ev);
        }
    }
    if to_add.is_empty() {
        return Ok(());
    }
    // Ensure the state object exists, then prepend the missing
    // members (order isn't spec-significant, but keeping new entries
    // at the front mirrors what state-delta callers expect to find).
    let state_obj = match room_data.as_object_mut() {
        Some(o) => o,
        None => return Ok(()),
    };
    let state_key = if use_state_after {
        "state_after"
    } else {
        "state"
    };
    let state_field = state_obj
        .entry(state_key.to_string())
        .or_insert_with(|| serde_json::json!({"events": []}));
    if let Some(events) = state_field
        .as_object_mut()
        .and_then(|obj| obj.get_mut("events"))
        .and_then(|v| v.as_array_mut())
    {
        let mut prepended = to_add;
        prepended.extend(std::mem::take(events));
        *events = prepended;
    }
    Ok(())
}

/// Apply the `filter_sync_event` read hook to one timeline event. Returns `true`
/// (show) when there's no viewer — i.e. the point is unbound or the viewer's id
/// couldn't be resolved — so it's a cheap no-op off the filter path. Serializing
/// the event to JSON happens only when a viewer is set (a plugin is bound).
fn sync_filter_shows(
    rt: &vela_extensions::Runtime,
    viewer: Option<&str>,
    room_id: &str,
    ev: &Value,
) -> bool {
    let Some(viewer) = viewer else {
        return true;
    };
    let event_type = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
    let sender = ev.get("sender").and_then(|s| s.as_str()).unwrap_or("");
    let event_json = ev.to_string();
    rt.filter_sync_event(&vela_extensions::SyncEvent {
        viewer,
        room_id,
        event: &event_json,
        event_type,
        sender,
    })
}

/// History-visibility gate for /sync timelines.
///
/// `/messages`, `/event` and `/context` gate every event through
/// `history_visibility_permits`, but the sync timeline builders used to
/// return raw `get_timeline_latest` / `get_timeline_range` slices, so a
/// user who joined a `history_visibility: joined` (or `invited`) room
/// could read pre-join messages on their first sync. This applies the
/// same per-event check.
///
/// Returns `Some((user_nid, visibility))` only when filtering is
/// required, i.e. the room is `joined`/`invited`. The sync timeline
/// builders are invoked for rooms the caller is (or was) a member of,
/// and a member sees the full history under `world_readable` (rule 1)
/// and `shared` (rule 3), so those return `None` — keeping the common
/// case (and the unchanged-room long-poll path) free of any per-event
/// work. `None` when there's no authenticated viewer (fail-open: we
/// can't run a per-viewer check without a viewer, and the event is
/// still gated by /messages).
fn hv_timeline_gate(
    state: &AppState,
    room_nid: u64,
    user_nid: Option<u64>,
) -> Result<Option<(u64, String)>, ApiError> {
    let Some(uid) = user_nid else {
        return Ok(None);
    };
    let visibility = crate::room::messages::current_history_visibility(state, room_nid)?;
    Ok(matches!(visibility.as_str(), "joined" | "invited").then_some((uid, visibility)))
}

/// True iff `event_nid` is hidden from `user_nid` under the room's
/// history-visibility, given a precomputed [`hv_timeline_gate`] result.
/// `None` gate (world_readable / shared / no viewer) never hides.
///
/// The `membership` passed to `history_visibility_permits` is fixed to
/// `join`: the gate only fires for `joined`/`invited` visibility, and
/// neither of those branches consults the membership argument (they key
/// off the membership *at the event*), so the nominal value is correct
/// for every caller (join, leave and ban sections alike).
fn hv_hides_event(
    state: &AppState,
    room_nid: u64,
    gate: &Option<(u64, String)>,
    event_nid: u64,
) -> Result<bool, ApiError> {
    let Some((uid, visibility)) = gate else {
        return Ok(false);
    };
    Ok(!crate::room::messages::history_visibility_permits(
        state,
        room_nid,
        *uid,
        Some(1),
        visibility,
        event_nid,
    )?)
}

fn build_room_sync_for_user(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    since: Option<u64>,
    user_nid: Option<u64>,
    device_id: Option<&str>,
    timeline_limit: usize,
    unread_thread_notifications: bool,
    safe_pos: u64,
    use_state_after: bool,
) -> Result<Value, ApiError> {
    // Read-path sync filter: if a plugin binds `filter_sync_event`, resolve the
    // viewer once and drop any timeline event the plugin hides from them. No-op
    // (and no viewer lookup) when unbound, so an operator who doesn't use it pays
    // nothing. An unresolved viewer (no nid, or a resolve error) leaves
    // `sync_viewer = None`, which shows everything — a fail-open we accept because
    // we can't run a per-viewer filter without a viewer; the filter is a view
    // shaper, not an access boundary (the event is still served by /messages).
    let sync_rt = state.extensions.load();
    let sync_viewer = if sync_rt.binds_filter_sync_event() {
        user_nid.and_then(|nid| state.db.resolve_nid(nid).ok().flatten())
    } else {
        None
    };

    let (state_events, timeline_events, limited, prev_batch) = match since {
        None => {
            let state_nids = state
                .db
                .get_all_state_event_nids(room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

            let mut state_events = Vec::new();
            for nid in &state_nids {
                if let Some(mut ev) = load_client_event(state, *nid, room_id)? {
                    attach_membership_for_user(state, &mut ev, user_nid, *nid);
                    attach_txn_id_for_user(state, &mut ev, user_nid, device_id, *nid);
                    state_events.push(ev);
                }
            }

            let timeline_entries = state
                .db
                .get_timeline_latest(room_nid, timeline_limit)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

            let hv_gate = if timeline_entries.is_empty() {
                None
            } else {
                hv_timeline_gate(state, room_nid, user_nid)?
            };
            let mut timeline_events = Vec::new();
            for (_, enid) in &timeline_entries {
                if hv_hides_event(state, room_nid, &hv_gate, *enid)? {
                    continue;
                }
                if let Some(ev) = load_timeline_event(state, *enid, room_id, user_nid, device_id)?
                    && sync_filter_shows(&sync_rt, sync_viewer.as_deref(), room_id, &ev)
                {
                    timeline_events.push(ev);
                }
            }
            // prev_batch points at the LATEST event in the batch. /members?at
            // and other "state at this point" queries expect this token to
            // represent the state INCLUDING all events delivered in the
            // batch — the client uses prev_batch as "the position I'm at in
            // this room right now". (Per-room next_batch isn't a spec
            // concept; clients re-purpose prev_batch.) /messages?from=
            // backward will return events with pos < prev_batch, which
            // overlaps the timeline batch by all-but-one events; clients
            // dedupe on event_id, so the redundancy is harmless.
            // TestGetRoomMembersAtPoint locks this semantic in.
            let last_pos = timeline_entries.last().map(|(p, _)| *p);
            let prev_batch = last_pos.map(|p| format!("s{p}"));
            (state_events, timeline_events, true, prev_batch)
        }
        Some(since_pos) => {
            // If the user's membership transitioned to `join` *within* this
            // sync window (membership_pos > since), the client has never
            // seen this room before — returning timeline-only would leave
            // them with no state to render (Element then fetches
            // /rooms/{id}/state per event, which can add seconds to the
            // perceived latency after accepting an invite). Treat it like
            // an initial join: return full current state + latest timeline.
            let fresh_join = user_nid
                .and_then(|uid| {
                    state
                        .db
                        .get_user_room_membership_pos(uid, room_nid)
                        .ok()
                        .flatten()
                })
                .map(|pos| pos > since_pos)
                .unwrap_or(false);

            if fresh_join {
                let state_nids = state
                    .db
                    .get_all_state_event_nids(room_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                let mut state_events = Vec::new();
                for nid in &state_nids {
                    if let Some(ev) = load_client_event(state, *nid, room_id)? {
                        state_events.push(ev);
                    }
                }
                let timeline_entries = state
                    .db
                    .get_timeline_latest(room_nid, timeline_limit)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
                let hv_gate = if timeline_entries.is_empty() {
                    None
                } else {
                    hv_timeline_gate(state, room_nid, user_nid)?
                };
                let mut timeline_events = Vec::new();
                let mut first_pos = None;
                for (pos, enid) in &timeline_entries {
                    if first_pos.is_none() {
                        first_pos = Some(*pos);
                    }
                    if hv_hides_event(state, room_nid, &hv_gate, *enid)? {
                        continue;
                    }
                    if let Some(ev) =
                        load_timeline_event(state, *enid, room_id, user_nid, device_id)?
                        && sync_filter_shows(&sync_rt, sync_viewer.as_deref(), room_id, &ev)
                    {
                        timeline_events.push(ev);
                    }
                }
                let prev_batch = first_pos.map(|p| format!("s{p}"));
                (state_events, timeline_events, true, prev_batch)
            } else {
                let timeline_entries = state
                    .db
                    // Spec on /sync timeline filter limit: when the
                    // client supplies one, we must use it both to bound
                    // the events returned AND to compute prev_batch
                    // accurately. Loading 30 events then trimming in a
                    // post-filter pass leaves prev_batch pointing at
                    // the pre-trim batch start, which makes
                    // /messages?from=prev_batch walk past the events
                    // the client already saw and into older state.
                    // get_timeline_range walks ascending — to honour
                    // "most recent N events since `since`", we instead
                    // walk *backwards* from now to the first
                    // `timeline_limit` events strictly newer than
                    // since.
                    .get_timeline_before(room_nid, u64::MAX, timeline_limit.max(1))
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

                // Drop entries at or before `since_pos`; those are
                // already on the client. Also cap at `safe_pos`: events
                // with `p > safe_pos` belong to allocations whose
                // WriteBatch is still in flight in some other room — if
                // we deliver them here while next_batch=safe_pos, the
                // next /sync's `p > since` would re-include them as
                // duplicates. The capped events come back on the next
                // iteration after safe_pos advances.
                let timeline_entries: Vec<(u64, u64)> = timeline_entries
                    .into_iter()
                    .filter(|(p, _)| *p > since_pos && *p <= safe_pos)
                    .collect();
                // limited covers two cases: batch was truncated by
                // the filter limit, OR the room had a federation gap
                // fill (`/get_missing_events`, `/state_ids`) at a
                // stream position the user hasn't seen yet — in that
                // case the timeline events alone are inadequate to
                // render the room state at the start of the batch
                // (per spec) and the client needs to know to refetch
                // state.
                let gap_fill_pos = state
                    .last_gap_fill_pos
                    .get(&room_nid)
                    .map(|v| *v)
                    .unwrap_or(0);
                // When the user's since predates a federation gap fill,
                // drop pre-gap events from this batch. Spec
                // TestSyncTimelineGap requires that a `limited:true`
                // batch contains only post-gap events: clients use
                // `limited` as the trigger to fetch state via /messages
                // backfill, and including pre-gap events under it
                // confuses where the gap actually lies. Pre-gap events
                // remain reachable via prev_batch + /messages.
                //
                // Restricted to fetch_missing_events triggers (the
                // /state_ids fallback no longer sets gap_fill_pos)
                // because /state_ids fetches outliers only and the
                // wider trigger dropped legitimate post-fallback live
                // events in unrelated federation tests.
                let timeline_entries: Vec<(u64, u64)> = if since_pos < gap_fill_pos {
                    timeline_entries
                        .into_iter()
                        .filter(|(p, _)| *p > gap_fill_pos)
                        .collect()
                } else {
                    timeline_entries
                };
                let limited = timeline_entries.len() >= timeline_limit || since_pos < gap_fill_pos;

                let hv_gate = if timeline_entries.is_empty() {
                    None
                } else {
                    hv_timeline_gate(state, room_nid, user_nid)?
                };
                let mut timeline_events = Vec::new();
                let mut first_pos = None;
                for (pos, enid) in &timeline_entries {
                    if first_pos.is_none() {
                        first_pos = Some(*pos);
                    }
                    if hv_hides_event(state, room_nid, &hv_gate, *enid)? {
                        continue;
                    }
                    if let Some(ev) =
                        load_timeline_event(state, *enid, room_id, user_nid, device_id)?
                        && sync_filter_shows(&sync_rt, sync_viewer.as_deref(), room_id, &ev)
                    {
                        timeline_events.push(ev);
                    }
                }

                // State delta. The legacy `state` field is the delta between
                // the client's last sync and the START of the timeline
                // (first_pos): state events IN the timeline are carried by
                // the timeline itself and must not be duplicated here.
                //
                // MSC4222 `state_after` is instead the room state at the END
                // of the timeline, so its delta extends to the sync point
                // (safe_pos) and DOES include state events in the batch.
                // Without this split a state event that's the only new event
                // sits in the timeline and never reaches `state_after` — the
                // msc4140 delayed-state-event regression.
                let delta_upper = if use_state_after {
                    safe_pos + 1
                } else {
                    first_pos.unwrap_or(safe_pos + 1)
                };
                let state_events = compute_state_delta(
                    state,
                    room_nid,
                    room_id,
                    since_pos + 1,
                    delta_upper,
                    user_nid,
                    device_id,
                )?;

                let prev_batch = first_pos.map(|p| format!("s{p}"));
                (state_events, timeline_events, limited, prev_batch)
            }
        }
    };

    // Ephemeral: typing + receipts
    let mut ephemeral_events = Vec::new();

    // Typing.
    //
    // m.typing is current-state-style: clients want the latest list of
    // typers, not a stream of deltas. But emitting it on every /sync
    // would conflict with the "skip unchanged room" rule (every room
    // would always look "changed") and flood clients with redundant
    // events. Compromise: emit on initial sync, then on incremental
    // sync only when the typing set transitioned (start or stop) at
    // a stream position newer than `since`. The transition pos is
    // bumped by the /typing handler.
    let last_typing_change = state.typing_change_pos.get(&room_nid).map(|v| *v);
    let typing_changed_since = match (since, last_typing_change) {
        (None, _) => true,           // initial sync — always carry the snapshot
        (Some(_), None) => false,    // never transitioned in this process
        (Some(s), Some(p)) => p > s, // a transition happened since the last sync
    };
    // Also (re-)emit the typing snapshot when the room has new timeline
    // events to deliver: clients running tests like TestACLsForEDUs
    // expect a typing event to coexist with the message that woke the
    // sync. Without this, the typing transition fires once on Response
    // #1, the message arrives in Response #N, and no single response
    // ever carries both.
    let timeline_has_new = !timeline_events.is_empty();
    if typing_changed_since || timeline_has_new {
        let typing_user_nids = get_typing_users(state, room_nid);
        let mut user_ids = Vec::new();
        for nid in &typing_user_nids {
            if let Some(uid) = state
                .db
                .resolve_nid(*nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            {
                user_ids.push(Value::String(uid));
            }
        }
        // Emit empty user_ids only when this is incremental sync AND a
        // typing transition fired (typically an explicit stop), per
        // TestTyping/Typing_can_be_explicitly_stopped. On initial sync
        // we'd otherwise inject an empty typing event into every room —
        // TestACLsForEDUs asserts the ACL'd room has zero ephemeral
        // events, and the empty snapshot would count. Re-emitting solely
        // because timeline has new events doesn't need an empty snapshot
        // — just skip when nobody's typing.
        let emit_empty_is_ok = since.is_some() && typing_changed_since;
        if !user_ids.is_empty() || emit_empty_is_ok {
            ephemeral_events.push(json!({
                "type": "m.typing",
                "content": {"user_ids": user_ids}
            }));
        }
    }

    // Receipts. MSC4102/TestThreadReceiptsInSyncMSC4102 contract lives
    // inside the shared helper (unthreaded entry wins for clients).
    // Skip emit on incremental sync when no receipt has been written
    // since the client's cursor — without this, every /sync re-emits
    // the full receipt snapshot regardless of whether anything changed,
    // and the unchanged-room skip rule never fires (rooms.join always
    // contains every joined room, has_new_data is always true, the
    // long-poll never sleeps, clients hammer at ~0.5s).
    let receipts_changed = match (since, user_nid) {
        (Some(since_pos), Some(_)) => state
            .db
            .get_room_receipts_max_pos(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .is_some_and(|max| max > since_pos),
        _ => true, // initial sync OR unauthenticated: always emit the snapshot
    };
    // Same coalescing rule as typing above: if the room is going to
    // appear in this response because of a fresh timeline event, ride
    // the current receipt snapshot along so test contracts that wait
    // for `timeline + ephemeral.m.receipt` in one response succeed
    // without depending on transition timing.
    let receipts_changed = receipts_changed || timeline_has_new;
    if receipts_changed
        && let Some(uid) = user_nid
        && let Some(receipts_event) = build_receipts_event(state, room_nid, uid)?
    {
        ephemeral_events.push(receipts_event);
    }

    let joined_count = state
        .db
        .count_room_members_by_membership(room_nid, 1)
        .unwrap_or(1);
    let invited_count = state
        .db
        .count_room_members_by_membership(room_nid, 2)
        .unwrap_or(0);

    // "Heroes" — up to HEROES_CAP joined-or-invited members (excluding
    // the requesting user) clients use to render a room name when
    // m.room.name and m.room.canonical_alias are both unset. Spec says
    // "Required if the room's `m.room.name` or `m.room.canonical_alias`
    // state events are unset or empty" — when either is set the field
    // is optional, so we skip the membership scan to keep /sync cheap
    // for named rooms (the common case in normal use). Spec orders by
    // "stream ordering"; we pick alphabetically on user_id since the
    // membership index doesn't preserve insertion order and replicas
    // need to agree on which prefix shows up.
    const HEROES_CAP: usize = 5;
    let has_room_name_or_alias = {
        let name_set = crate::membership::read_state_value_pub(state, room_nid, "m.room.name", "")
            .ok()
            .flatten()
            .and_then(|v| v.get("content").cloned())
            .and_then(|c| c.get("name").and_then(|v| v.as_str()).map(str::to_string))
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        let alias_set =
            crate::membership::read_state_value_pub(state, room_nid, "m.room.canonical_alias", "")
                .ok()
                .flatten()
                .and_then(|v| v.get("content").cloned())
                .and_then(|c| c.get("alias").and_then(|v| v.as_str()).map(str::to_string))
                .map(|s| !s.is_empty())
                .unwrap_or(false);
        name_set || alias_set
    };
    let heroes: Vec<String> = if has_room_name_or_alias {
        Vec::new()
    } else {
        let pick = |membership: u8| -> Vec<u64> {
            state
                .db
                .get_room_members_by_membership(room_nid, membership)
                .unwrap_or_default()
        };
        let mut nids = pick(1);
        nids.extend(pick(2));
        // Per sync.yaml: "When no joined or invited members are
        // available, this should consist of the banned and left
        // users." Mostly a degenerate case (e.g. the user is left in
        // a room that's since emptied) but still spec-required.
        if nids.iter().all(|&n| Some(n) == user_nid) {
            nids.extend(pick(0)); // leave
            nids.extend(pick(3)); // ban
        }
        let mut user_ids: Vec<String> = nids
            .into_iter()
            .filter(|nid| user_nid != Some(*nid))
            .filter_map(|nid| state.db.resolve_nid(nid).ok().flatten())
            .collect();
        user_ids.sort();
        user_ids.dedup();
        user_ids.truncate(HEROES_CAP);
        user_ids
    };

    // Same delta-skip as receipts above: on incremental sync, skip the
    // room_account_data snapshot when nothing has changed in the
    // `(user, room)` slot since the client's `since` cursor.
    let room_account_data_changed = match (since, user_nid) {
        (Some(since_pos), Some(uid)) => state
            .db
            .get_room_account_data_max_pos(uid, room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .is_some_and(|max| max > since_pos),
        _ => true,
    };
    let room_account_data = match (user_nid, room_account_data_changed) {
        (Some(uid), true) => {
            let all = state
                .db
                .get_all_room_account_data(uid, room_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            // MSC3391: on initial sync (no `since`) skip tombstoned
            // entries (empty `{}` content). Incremental sync keeps them
            // so other devices catch up on the deletion.
            all.into_iter()
                .filter(|(_, content)| {
                    since.is_some() || !content.as_object().is_some_and(|o| o.is_empty())
                })
                .map(|(dtype, content)| json!({"type": dtype, "content": content}))
                .collect::<Vec<_>>()
        }
        _ => Vec::new(),
    };

    // Approximate unread_notifications by counting non-state events
    // newer than the user's m.read receipt that aren't from the user
    // themselves. Highlights run the full push-rule evaluator and
    // flag any event whose matched rule emits a `highlight` tweak —
    // covers display-name mentions, custom content/keyword rules, and
    // user-defined overrides.
    //
    // When `unread_thread_notifications` is requested via the timeline
    // filter, also produce per-thread counts keyed by thread root
    // event_id. An event is "in a thread" iff its `m.relates_to`
    // points at a root with `rel_type=m.thread`. The thread root
    // itself counts toward the main timeline, not its own thread.
    let (notification_count, highlight_count, thread_counts) = match user_nid {
        Some(uid) => compute_unread_counts(state, room_nid, uid, unread_thread_notifications)?,
        None => (0, 0, std::collections::BTreeMap::new()),
    };

    let mut payload = serde_json::Map::new();
    // MSC4222: emit `state_after` (state at end of timeline) when the
    // client opted in, otherwise the legacy `state` field (state at
    // start of timeline). For initial sync these collapse to the same
    // content — current state IS state-at-end. For incremental sync
    // vela doesn't compute delta state today, so `state_after.events`
    // is the same empty list as `state.events` would be.
    let state_field = if use_state_after {
        "state_after"
    } else {
        "state"
    };
    payload.insert(state_field.to_string(), json!({"events": state_events}));
    payload.insert(
        "timeline".to_string(),
        json!({
            "events": timeline_events,
            "limited": limited,
            "prev_batch": prev_batch.unwrap_or_default(),
        }),
    );
    payload.insert(
        "summary".to_string(),
        json!({
            "m.heroes": heroes,
            "m.joined_member_count": joined_count,
            "m.invited_member_count": invited_count,
        }),
    );
    payload.insert("ephemeral".to_string(), json!({"events": ephemeral_events}));
    payload.insert(
        "account_data".to_string(),
        json!({"events": room_account_data}),
    );
    payload.insert(
        "unread_notifications".to_string(),
        json!({
            "highlight_count": highlight_count,
            "notification_count": notification_count,
        }),
    );
    // MSC3773: emit `unread_thread_notifications` ONLY when both the
    // filter requested it and there's at least one thread with non-zero
    // counts. Emitting an empty map confuses clients that branch on
    // field presence (TestThreadedReceipts asserts `!t.Exists()` once
    // the user has read everything in every thread).
    if unread_thread_notifications && !thread_counts.is_empty() {
        let mut threads = serde_json::Map::new();
        for (root, (count, highlights)) in &thread_counts {
            threads.insert(
                root.clone(),
                json!({
                    "highlight_count": *highlights,
                    "notification_count": *count,
                }),
            );
        }
        payload.insert(
            "unread_thread_notifications".to_string(),
            Value::Object(threads),
        );
    }
    Ok(Value::Object(payload))
}

/// Compute `(notification_count, highlight_count, thread_counts)` for a
/// timeline batch the user is about to see.
///
/// Highlights run the user's merged push-rule set (server defaults plus
/// any `m.push_rules` account_data) through `vela_core::push_rules` and
/// flag any event whose first matching rule emits a `highlight` tweak —
/// covers `.m.rule.contains_display_name`, custom content/keyword rules,
/// and any user override. The evaluator context (rules + displayname +
/// joined_member_count) is built once per call; the per-event hot loop
/// only does the evaluate.
///
/// Counts the room TOTAL unread since the user's read receipt — a scan over
/// `room_timeline` from the receipt position to now, NOT a per-`/sync`-batch
/// delta (the old batch-local count read as zero whenever the receipt sat
/// before the delivered batch).
///
/// MSC3771/3773 receipt scoping: each `m.read`/`m.read.private` receipt is
/// bucketed by `thread_id` — unthreaded covers all threads, `"main"` covers
/// main-timeline events only, a thread id covers just that thread. An event at
/// stream position P is "read" iff an in-scope receipt sits at a position >= P.
/// The scan is bounded below by the unthreaded receipt (the only one that
/// covers every scope) and the caller's membership position, and capped to the
/// newest `UNREAD_SCAN_CAP` events above that floor.
pub(crate) fn compute_unread_counts(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
    unread_thread_notifications: bool,
) -> Result<(u64, u64, std::collections::BTreeMap<String, (u64, u64)>), ApiError> {
    let mut thread_counts: std::collections::BTreeMap<String, (u64, u64)> =
        std::collections::BTreeMap::new();

    // Map the user's read receipts to stream POSITIONS. An event at position P
    // is "read" if an in-scope receipt sits at a position >= P. We count over
    // the whole room since the receipt — not just the delivered /sync batch —
    // so the count is the spec's room-total unread, not a per-batch delta.
    // Both m.read and m.read.private advance the owner's own read position.
    // thread_id: None = unthreaded (covers every scope); "main" = the main
    // timeline only; otherwise a specific thread root.
    let receipts: Vec<(Option<String>, u64)> = state
        .db
        .get_room_receipts(room_nid)
        .ok()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(rt, un, tid, val)| {
            if un != user_nid || (rt != "m.read" && rt != "m.read.private") {
                return None;
            }
            let eid = val.get("event_id").and_then(|v| v.as_str())?;
            let pos = state.db.event_stream_pos(room_nid, eid).ok().flatten()?;
            Some((tid, pos))
        })
        .collect();

    // Highest receipt position that marks `scope` (the event's thread root, or
    // None for the main timeline) read.
    let scope_read_pos = |scope: Option<&str>| -> u64 {
        receipts
            .iter()
            .filter(|(rt, _)| match (rt.as_deref(), scope) {
                (None, _) => true,            // unthreaded covers every scope
                (Some("main"), None) => true, // main receipt covers main-timeline events
                (Some(t), Some(s)) => t == s, // thread receipt covers its own thread
                _ => false,
            })
            .map(|(_, p)| *p)
            .max()
            .unwrap_or(0)
    };
    // The unthreaded receipt is the only one guaranteed to cover all scopes, so
    // it's the safe lower bound for the scan; events at/below it are all read.
    let unthreaded_pos = receipts
        .iter()
        .filter(|(rt, _)| rt.is_none())
        .map(|(_, p)| *p)
        .max()
        .unwrap_or(0);
    // Don't count events from before the caller joined.
    let join_pos = state
        .db
        .get_user_room_membership_pos(user_nid, room_nid)
        .ok()
        .flatten()
        .unwrap_or(0);
    let scan_from = join_pos.max(unthreaded_pos);
    let to = state.db.current_stream_position().saturating_add(1);
    // Caught up to the safe floor → nothing to count, skip the scan entirely.
    if scan_from.saturating_add(1) >= to {
        return Ok((0, 0, thread_counts));
    }
    // Scan the NEWEST events above the floor, not the oldest: the count must
    // reflect the freshest unread and saturate older overflow at the cap. A
    // forward scan would, for a client with only a "main"/thread receipt (no
    // unthreaded floor) and more than `UNREAD_SCAN_CAP` events, examine only
    // the oldest (already-read) window and wrongly report zero.
    let events = state
        .db
        .get_timeline_range_newest(room_nid, scan_from.saturating_add(1), to, UNREAD_SCAN_CAP)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut main_count = 0u64;
    let mut main_highlights = 0u64;
    let user_id_str = state
        .db
        .resolve_nid(user_nid)
        .ok()
        .flatten()
        .unwrap_or_default();

    // Build the push-rule evaluator inputs once. The hot loop calls
    // `evaluate` per event, which is cheap, but rule loading and member-
    // state lookups are not — keep them out of the loop.
    let rules = crate::push::pushrules::load_user_rules(state, user_nid)
        .unwrap_or_else(|_| vela_core::push_rules::default_global_rules());
    let displayname = recipient_room_displayname(state, room_nid, user_nid, &user_id_str);
    let joined_member_count = state
        .db
        .count_room_members_by_membership(room_nid, 1)
        .unwrap_or(0);
    // notifications.room threshold (default 50) is constant per room; the
    // sender's power level is set per event in the loop below (MSC3952
    // @room highlight gate).
    let notifications_room_level = crate::membership::notifications_room_level(state, room_nid);
    let mut push_ctx = vela_core::push_rules::RoomContext {
        joined_member_count,
        recipient_display_name: displayname,
        recipient_user_id: user_id_str.clone(),
        sender_power_level: 0,
        notifications_room_level,
    };

    for (pos, event_nid) in events {
        let Some((_, body)) = state.db.get_event(event_nid).ok().flatten() else {
            continue;
        };
        let Ok(ev) = serde_json::from_slice::<Value>(&body) else {
            continue;
        };
        let ev_type = ev.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let sender = ev.get("sender").and_then(|v| v.as_str()).unwrap_or("");
        if ev.get("state_key").is_some() || sender == user_id_str {
            continue;
        }
        if !matches!(ev_type, "m.room.message" | "m.room.encrypted") {
            continue;
        }

        let thread_root = ev
            .pointer("/content/m.relates_to")
            .filter(|rel| rel.get("rel_type").and_then(|v| v.as_str()) == Some("m.thread"))
            .and_then(|rel| rel.get("event_id"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Read if an in-scope receipt sits at or after this event's position.
        if scope_read_pos(thread_root.as_deref()) >= pos {
            continue;
        }

        push_ctx.sender_power_level =
            crate::membership::user_power(state, room_nid, sender).unwrap_or(0);
        let action = vela_core::push_rules::evaluate(&ev, &rules, &push_ctx);
        let highlights = action
            .tweaks
            .get("highlight")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if unread_thread_notifications && let Some(root) = thread_root {
            let entry = thread_counts.entry(root).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(1);
            if highlights {
                entry.1 = entry.1.saturating_add(1);
            }
        } else {
            main_count = main_count.saturating_add(1);
            if highlights {
                main_highlights = main_highlights.saturating_add(1);
            }
        }
    }
    Ok((main_count, main_highlights, thread_counts))
}

/// Cap on how many room events `compute_unread_counts` scans behind the read
/// receipt. Bounds the per-room cost for a caller far behind; the reported
/// count saturates here (clients render large counts as "99+"). The common
/// case — a recent unthreaded receipt — scans only the events since it, so
/// this ceiling is rarely approached.
const UNREAD_SCAN_CAP: usize = 1000;

/// Resolve the recipient's display name for use in `contains_display_name`
/// push-rule evaluation. Prefer the per-room `m.room.member` event (so
/// per-room nicknames like "alice (oncall)" highlight when called by name),
/// then fall back to the user's profile. Returns `None` when neither is
/// set, which skips the rule rather than risk a false positive on empty.
fn recipient_room_displayname(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
    user_id_str: &str,
) -> Option<String> {
    let type_nid = state.db.get_nid("m.room.member").ok().flatten();
    let skey_nid = if !user_id_str.is_empty() {
        state.db.get_nid(user_id_str).ok().flatten()
    } else {
        None
    };
    if let (Some(tn), Some(sn)) = (type_nid, skey_nid)
        && let Ok(Some(event_nid)) = state.db.get_state_event_nid(room_nid, tn, sn)
        && let Ok(Some((_, bytes))) = state.db.get_event(event_nid)
        && let Ok(ev) = serde_json::from_slice::<Value>(&bytes)
        && let Some(name) = ev
            .pointer("/content/displayname")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
    {
        return Some(name.to_string());
    }
    if let Some(profile_name) = state
        .db
        .get_user(user_nid)
        .ok()
        .flatten()
        .and_then(|u| {
            u.get("displayname")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .filter(|s| !s.is_empty())
    {
        return Some(profile_name);
    }
    // Spec doesn't mandate a default display name, but every server
    // in the ecosystem (Synapse, Dendrite) treats the localpart as the
    // de-facto display name when the user hasn't customised. Without
    // this fallback, `.m.rule.contains_display_name` can never fire
    // for fresh users — a message body containing `@bob:hs1` would
    // need a literal "bob" display_name to highlight, which most test
    // and integration setups never set (TestThreadedReceipts).
    user_id_str
        .strip_prefix('@')
        .and_then(|s| s.split_once(':').map(|(local, _)| local.to_string()))
        .filter(|s| !s.is_empty())
}

/// Build the `m.receipt` ephemeral event for a single room, or `None` if
/// the room has no receipts. MSC4102: when a user has both an unthreaded
/// and threaded receipt on the same event, the unthreaded entry wins
/// (clients use it as the room-wide anchor).
pub(crate) fn build_receipts_event(
    state: &AppState,
    room_nid: u64,
    for_user_nid: u64,
) -> Result<Option<Value>, ApiError> {
    let receipts = state
        .db
        .get_room_receipts(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    if receipts.is_empty() {
        return Ok(None);
    }
    let mut sorted: Vec<&(String, u64, Option<String>, Value)> = receipts.iter().collect();
    sorted.sort_by_key(|r| r.2.is_none());
    let mut content_map = serde_json::Map::new();
    for (receipt_type, user_nid, thread_id, receipt_val) in sorted {
        // Spec: `m.read.private` is visible ONLY to the user who set
        // it — never to other room members, never to remote servers.
        // Without this filter Element shows two "seen by" entries for
        // the same reader (their public + private receipts both leak
        // into other users' sync responses).
        if receipt_type == "m.read.private" && *user_nid != for_user_nid {
            continue;
        }
        if let (Some(event_id), Some(ts)) = (
            receipt_val.get("event_id").and_then(|v| v.as_str()),
            receipt_val.get("ts").and_then(|v| v.as_u64()),
        ) {
            let user_id = state
                .db
                .resolve_nid(*user_nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .unwrap_or_default();

            let event_entry = content_map
                .entry(event_id.to_string())
                .or_insert_with(|| json!({}));
            let type_entry = event_entry
                .as_object_mut()
                .unwrap()
                .entry(receipt_type.clone())
                .or_insert_with(|| json!({}));
            let mut user_entry = serde_json::Map::new();
            user_entry.insert("ts".into(), json!(ts));
            if let Some(tid) = thread_id {
                user_entry.insert("thread_id".into(), json!(tid));
            }
            type_entry
                .as_object_mut()
                .unwrap()
                .insert(user_id, Value::Object(user_entry));
        }
    }
    if content_map.is_empty() {
        return Ok(None);
    }
    Ok(Some(json!({
        "type": "m.receipt",
        "content": content_map
    })))
}

/// Gather `m.presence` EDUs for users the caller shares a room with,
/// **including the caller themselves**. We emit one event per
/// distinct peer that has a stored record (users with no record are
/// skipped — `format_status` would fabricate `offline` but flooding
/// sync with offlines for everyone serves no purpose).
///
/// Self-inclusion is essential: clients (Element X in particular)
/// build their own profile presence indicator from the /sync feed,
/// not from local state. Filtering self out left clients showing
/// the user as offline even when they were actively sync'ing —
/// fixed here.
fn collect_presence_events(
    state: &AppState,
    self_nid: u64,
    joined_room_nids: &[u64],
) -> Result<Vec<Value>, ApiError> {
    let mut peers: HashSet<u64> = HashSet::new();
    // The caller's own presence belongs in their /sync. Insert first
    // so it's always considered even for users in zero rooms.
    peers.insert(self_nid);
    for &room_nid in joined_room_nids {
        let members = state
            .db
            .get_room_members(room_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
        for m in members {
            peers.insert(m);
        }
    }

    let mut events = Vec::new();
    for peer_nid in peers {
        let Some(rec) = state
            .db
            .get_presence(peer_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        else {
            continue;
        };
        let user_id = state
            .db
            .resolve_nid(peer_nid)
            .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
            .unwrap_or_default();
        events.push(json!({
            "type": "m.presence",
            "sender": user_id,
            "content": crate::presence::format_status(&rec, &state.config.presence),
        }));
    }
    Ok(events)
}

/// Resolve a `?filter=` parameter into the JSON definition. Accepts inline
/// JSON (`{...}`) or a previously-uploaded filter id. Returns `None` for
/// missing/unknown filters; sync proceeds unfiltered rather than 4xx,
/// since clients in the wild rely on this lenient behaviour.
fn resolve_filter(
    state: &AppState,
    user: &AuthenticatedUser,
    raw: Option<&str>,
) -> Result<Option<Value>, ApiError> {
    let Some(s) = raw else { return Ok(None) };
    if s.starts_with('{') {
        return Ok(serde_json::from_str(s).ok());
    }
    let f = state
        .db
        .get_filter(user.user_nid, s)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    Ok(f)
}

/// Load the user's `m.ignored_user_list` global account data and return
/// the set of ignored user IDs (empty when the account data is absent).
fn load_ignored_users(state: &AppState, user_nid: u64) -> Result<HashSet<String>, ApiError> {
    let mut out = HashSet::new();
    let raw = state
        .db
        .get_account_data(user_nid, "m.ignored_user_list")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let Some(v) = raw else { return Ok(out) };
    if let Some(map) = v.get("ignored_users").and_then(|x| x.as_object()) {
        for k in map.keys() {
            out.insert(k.clone());
        }
    }
    Ok(out)
}

/// Drop timeline events whose `sender` is on the ignored list. State,
/// ephemeral, and account_data are untouched — only timeline message
/// events are filtered, which is the behaviour clients expect.
fn filter_room_timeline_by_ignored(room_data: &mut Value, ignored: &HashSet<String>) {
    let Some(events) = room_data
        .pointer_mut("/timeline/events")
        .and_then(|v| v.as_array_mut())
    else {
        return;
    };
    events.retain(|e| e.sender().map(|s| !ignored.contains(s)).unwrap_or(true));
}

/// Check whether the most recent invite for `user_nid` in `room_nid` was
/// sent by an ignored user. Looks at the current `m.room.member` state
/// event for the user.
fn invite_sender_is_ignored(
    state: &AppState,
    room_nid: u64,
    user_nid: u64,
    ignored: &HashSet<String>,
) -> Result<bool, ApiError> {
    let user_id = state
        .db
        .resolve_nid(user_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_default();
    let type_nid = state
        .db
        .get_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let skey_nid = state
        .db
        .get_nid(&user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let (Some(tn), Some(sn)) = (type_nid, skey_nid) else {
        return Ok(false);
    };
    let Some(event_nid) = state
        .db
        .get_state_event_nid(room_nid, tn, sn)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(false);
    };
    let Some((header, _)) = state
        .db
        .get_event(event_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    else {
        return Ok(false);
    };
    let sender = state
        .db
        .resolve_nid(header.sender_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
        .unwrap_or_default();
    Ok(ignored.contains(&sender))
}

/// True if the user's membership in `room_nid` should be surfaced in this
/// sync response. On initial sync (`since.is_none()`) always true; on
/// incremental sync, only when the last recorded transition happened after
/// the client's `since` token. Rooms with no recorded transition (possible
/// for entries predating the index, or for incoming federation member events
/// that bypass `set_membership`) are treated as "always include" — a minor
/// over-report that the client can dedupe, better than silently dropping.
fn membership_changed_since(
    state: &AppState,
    user_nid: u64,
    room_nid: u64,
    since: Option<u64>,
) -> Result<bool, ApiError> {
    let since = match since {
        Some(s) => s,
        None => return Ok(true),
    };
    match state
        .db
        .get_user_room_membership_pos(user_nid, room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
    {
        Some(pos) => Ok(pos > since),
        None => Ok(true),
    }
}

/// Build the `rooms.invite.{room_id}` payload with stripped state events.
fn build_invite_sync(state: &AppState, room_nid: u64, room_id: &str) -> Result<Value, ApiError> {
    Ok(json!({
        "invite_state": {
            "events": collect_invite_or_knock_stripped(state, room_nid, room_id)?,
        },
    }))
}

/// Build the `rooms.knock.{room_id}` payload with stripped state events.
/// Spec: `rooms.knock.{roomId}.knock_state.events` mirrors `invite_state`.
fn build_knock_sync(state: &AppState, room_nid: u64, room_id: &str) -> Result<Value, ApiError> {
    Ok(json!({
        "knock_state": {
            "events": collect_invite_or_knock_stripped(state, room_nid, room_id)?,
        },
    }))
}

/// Stripped state events that go into `invite_state` / `knock_state`.
///
/// Per MSC4311 (room version 12), the `m.room.create` event MUST be
/// included in full — it carries the data needed to verify the
/// room_id (which v12 derives from a hash of the create event). All
/// other state events are stripped to `type/state_key/sender/content`.
fn collect_invite_or_knock_stripped(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
) -> Result<Vec<Value>, ApiError> {
    let state_nids = state
        .db
        .get_all_state_event_nids(room_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut out = Vec::new();
    for nid in state_nids {
        let Some(ev) = load_client_event(state, nid, room_id)? else {
            continue;
        };
        let etype = ev.event_type().unwrap_or("");
        if !vela_core::events::INVITE_STRIPPED_STATE_TYPES.contains(&etype) {
            continue;
        }
        if etype == "m.room.create" {
            // MSC4311: full create event, not stripped.
            out.push(ev);
        } else {
            out.push(json!({
                "type": ev.get("type"),
                "state_key": ev.get("state_key"),
                "sender": ev.get("sender"),
                "content": ev.get("content"),
            }));
        }
    }
    Ok(out)
}

/// True when the room sync block has no content to deliver: empty
/// timeline, empty state delta, no ephemeral events, no per-room
/// account data. Such rooms must be omitted from `rooms.join` on
/// incremental sync per spec.
/// Cheap "does this room have anything new for the caller since `since_pos`?"
/// check, used to skip the full per-room build for quiet rooms on an
/// incremental sync (a few point-gets vs. the whole builder).
///
/// CONSERVATIVE: returns `true` (build the room) whenever a change source
/// can't be cheaply ruled out — a DB error, or any tracked position past the
/// cursor. It therefore can only ever SAVE work, never drop an update; the
/// authoritative `room_is_unchanged` gate still runs after the build for
/// anything this lets through. The change sources mirror what the builder
/// actually emits: new timeline/state events (both carry a stream_pos), new
/// room receipts, new per-(user,room) account data, and a typing transition.
fn room_has_changes_since(state: &AppState, room_nid: u64, user_nid: u64, since_pos: u64) -> bool {
    // New timeline (or state — state events are timelined) events.
    match state.db.get_room_latest_timeline_pos(room_nid) {
        Ok(Some(p)) if p > since_pos => return true,
        Err(_) => return true, // uncertain → build
        _ => {}
    }
    // New receipts anywhere in the room.
    match state.db.get_room_receipts_max_pos(room_nid) {
        Ok(Some(p)) if p > since_pos => return true,
        Err(_) => return true,
        _ => {}
    }
    // New per-(user, room) account data.
    match state.db.get_room_account_data_max_pos(user_nid, room_nid) {
        Ok(Some(p)) if p > since_pos => return true,
        Err(_) => return true,
        _ => {}
    }
    // A typing transition since the cursor (in-memory, per-room).
    if state
        .typing_change_pos
        .get(&room_nid)
        .is_some_and(|p| *p > since_pos)
    {
        return true;
    }
    false
}

fn room_is_unchanged(room: &Value) -> bool {
    let arr_empty = |ptr: &str| {
        room.pointer(ptr)
            .and_then(|v| v.as_array())
            .is_none_or(|a| a.is_empty())
    };
    arr_empty("/timeline/events")
        && arr_empty("/state/events")
        && arr_empty("/state_after/events")
        && arr_empty("/ephemeral/events")
        && arr_empty("/account_data/events")
}

/// Build the `rooms.leave.{room_id}` payload.
///
/// Per spec, a left user's view of the room is **frozen at their leave**:
/// they must not see events sent (or state changed) after that point. The
/// state we expose anchors at the user's leave event, and the timeline
/// stops there too.
///
/// Layout:
/// - `timeline.events` — events up to and including the user's leave,
///   newest-first capped to `timeline_limit`, returned chronologically.
///   For incremental sync, events at or before `since` are also dropped.
/// - `state.events` — state at the start of the timeline (or state at
///   the leave event itself when timeline_limit==0). For incremental
///   sync, the delta against `state-at-since` is emitted instead.
/// - `state.events` excludes events that already appear in
///   `timeline.events` (spec rule: don't duplicate).
///
/// `timeline_limit` is the post-filter cap requested by the client; the
/// caller still applies `timeline_filter`/`state_filter` on top of what
/// we return, which can shrink either array further.
const LEAVE_SCAN_WINDOW: usize = 10_000;

fn build_leave_sync(
    state: &AppState,
    room_nid: u64,
    room_id: &str,
    user_nid: u64,
    user_id: &str,
    since: Option<u64>,
    timeline_limit: usize,
) -> Result<Value, ApiError> {
    // Locate the user's leave event. Because the user is currently in the
    // "left" set, the live state entry for `(m.room.member, user_id)` IS
    // the leave event — any subsequent rejoin would have moved them to
    // the joined set.
    let member_type_nid = state
        .db
        .get_or_create_nid("m.room.member")
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let user_skey_nid = state
        .db
        .get_or_create_nid(user_id)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
    let leave_event_nid = state
        .db
        .get_state_event_nid(room_nid, member_type_nid, user_skey_nid)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    // Walk room timeline backwards from the latest position, skipping
    // events that were sent AFTER the user left (those belong to other
    // members and must not be visible). Once we hit the leave event we
    // include it and continue collecting older events up to the limit.
    let scan = state
        .db
        .get_timeline_before(room_nid, u64::MAX, LEAVE_SCAN_WINDOW)
        .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;

    let mut timeline_newest_first: Vec<(u64, u64)> = Vec::new();
    let mut found_leave = leave_event_nid.is_none();
    let mut more_before_first = false;
    for (pos, enid) in scan.iter().rev() {
        let is_leave_event = Some(*enid) == leave_event_nid;
        if !found_leave {
            if is_leave_event {
                found_leave = true;
            } else {
                continue;
            }
        }
        // The leave/ban event itself is the membership transition; emit
        // it regardless of `since`. `set_membership` burns a fresh
        // stream_pos AFTER persist_event, so the user's membership_pos
        // (and therefore a /sync `since` derived from
        // `current_stream_position()`) routinely sits one position
        // PAST the leave event. Without this carve-out, the leave
        // event is `pos <= since` and the since-cap below skips it,
        // leaving `rooms.leave.<room>.timeline` and
        // `rooms.leave.<room>.state` empty for the very sync that
        // surfaces the transition (TestUnbanViaInvite).
        if !is_leave_event
            && let Some(s) = since
            && *pos <= s
        {
            break;
        }
        if timeline_newest_first.len() >= timeline_limit {
            more_before_first = true;
            break;
        }
        timeline_newest_first.push((*pos, *enid));
    }
    let first_pos = timeline_newest_first.last().map(|(p, _)| *p);
    let prev_batch = first_pos.map(|p| format!("s{p}")).unwrap_or_default();

    // State at the start of the timeline (chronologically). When the
    // timeline is empty we fall back to state-at-leave so the client
    // still sees the room as it was at the moment of departure.
    let state_at_anchor: Vec<u64> = match first_pos {
        Some(p) => {
            // Find the event immediately preceding the timeline's first
            // event in the same room and read its persisted state
            // snapshot. If our timeline starts at the room's create
            // event there's no predecessor — pre-state is empty.
            let predecessor = state
                .db
                .get_timeline_before(room_nid, p, 1)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            match predecessor.last() {
                Some((_, pred_nid)) => state
                    .db
                    .get_state_at_event(*pred_nid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    .unwrap_or_default(),
                None => Vec::new(),
            }
        }
        None => match leave_event_nid {
            Some(nid) => state
                .db
                .get_state_at_event(nid)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                .unwrap_or_default(),
            None => Vec::new(),
        },
    };

    // For incremental sync, emit only the delta against state-at-since
    // (events that became state between `since` and the timeline start).
    let state_to_emit: Vec<u64> = match since {
        Some(since_pos) => {
            let at_since_event = state
                .db
                .get_timeline_before(room_nid, since_pos.saturating_add(1), 1)
                .map_err(|e| ApiError(VelaError::Store(e.to_string())))?;
            let state_at_since = match at_since_event.last() {
                Some((_, snid)) => state
                    .db
                    .get_state_at_event(*snid)
                    .map_err(|e| ApiError(VelaError::Store(e.to_string())))?
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            let since_set: std::collections::HashSet<u64> = state_at_since.into_iter().collect();
            state_at_anchor
                .into_iter()
                .filter(|n| !since_set.contains(n))
                .collect()
        }
        None => state_at_anchor,
    };

    // Don't duplicate state events that are already in the timeline.
    let timeline_set: std::collections::HashSet<u64> =
        timeline_newest_first.iter().map(|(_, n)| *n).collect();

    let mut state_events = Vec::new();
    for nid in &state_to_emit {
        if timeline_set.contains(nid) {
            continue;
        }
        if let Some(ev) = load_client_event(state, *nid, room_id)? {
            state_events.push(ev);
        }
    }

    // History-visibility also bounds the *start* of an archived view:
    // under `joined`/`invited`, a user who joined then left must not see
    // events from before they joined (the leave-cap above only bounds the
    // recent end). Same per-event gate as /messages and the live sync.
    let hv_gate = if timeline_newest_first.is_empty() {
        None
    } else {
        hv_timeline_gate(state, room_nid, Some(user_nid))?
    };
    let mut timeline_events = Vec::new();
    for (_, enid) in timeline_newest_first.iter().rev() {
        if hv_hides_event(state, room_nid, &hv_gate, *enid)? {
            continue;
        }
        if let Some(ev) = load_client_event(state, *enid, room_id)? {
            timeline_events.push(ev);
        }
    }

    Ok(json!({
        "state": {"events": state_events},
        "timeline": {
            "events": timeline_events,
            "limited": more_before_first,
            "prev_batch": prev_batch,
        },
        "account_data": {"events": []},
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::build_test_state;

    #[test]
    fn invited_rooms_appear_in_sync_query() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let user_nid = db.get_or_create_nid("@bob:example.com").unwrap();
        let room_nid = db.get_or_create_nid("!room1").unwrap();

        // Before invite: no invited rooms.
        let invited = db.get_user_invited_rooms(user_nid).unwrap();
        assert!(invited.is_empty(), "no invites yet");

        // Set membership to invite (2).
        db.set_membership(room_nid, user_nid, 2).unwrap();

        // Now should appear.
        let invited = db.get_user_invited_rooms(user_nid).unwrap();
        assert_eq!(invited, vec![room_nid], "room should appear after invite");

        // Joined rooms should still be empty.
        let joined = db.get_user_joined_rooms(user_nid).unwrap();
        assert!(joined.is_empty(), "not joined");
    }

    fn fake_user(state: &AppState, user_id: &str) -> AuthenticatedUser {
        let user_nid = state.db.get_or_create_nid(user_id).unwrap();
        AuthenticatedUser {
            user_nid,
            user_id: user_id.to_string(),
            device_id: "DEV".into(),
            appservice_nid: None,
        }
    }

    /// To-device messages must be redelivered until the client syncs past
    /// them (delete-on-ACK), not dropped the moment they're first returned.
    /// Guards the verification-request-lost regression end to end through
    /// the sync handler (ack `since`, then return the (since, safe_pos]
    /// window).
    #[test]
    fn to_device_redelivered_until_synced_past() {
        let (state, _tmp) = build_test_state();
        let user = fake_user(&state, "@bob:example.com");
        state
            .db
            .queue_to_device(
                user.user_nid,
                "DEV",
                "m.key.verification.request",
                "@bob:example.com",
                &json!({"transaction_id": "t1"}),
            )
            .unwrap();

        let td = |resp: &Value| -> usize {
            resp.pointer("/to_device/events")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        };

        // Initial sync delivers it.
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        assert_eq!(td(&resp), 1, "verification to-device must be delivered");
        let pos: u64 = resp["next_batch"]
            .as_str()
            .unwrap()
            .strip_prefix('s')
            .unwrap()
            .parse()
            .unwrap();

        // A client that did not advance its token still sees it — the old
        // delete-on-read would have dropped it after the first response.
        let resp2 = build_sync_response(&state, &user, &[], None).unwrap();
        assert_eq!(td(&resp2), 1, "must redeliver until acked");

        // Syncing past it (since = next_batch) acks and clears it.
        let resp3 = build_sync_response(&state, &user, &[], Some(pos)).unwrap();
        assert_eq!(td(&resp3), 0, "acked message must not reappear");

        // And it's actually gone from the store, not just filtered out.
        assert!(
            state
                .db
                .get_to_device_messages_window(user.user_nid, "DEV", 0, pos)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn invite_appears_on_initial_and_disappears_on_incremental_after_pos() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;

        let room_nid = db.get_or_create_nid("!room:example.com").unwrap();
        let user = fake_user(&state, "@bob:example.com");
        db.set_membership(room_nid, user.user_nid, 2).unwrap();

        // Initial sync: invite present.
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        let invites = resp.pointer("/rooms/invite").unwrap().as_object().unwrap();
        assert!(
            invites.contains_key("!room:example.com"),
            "invite missing on initial sync: {invites:?}"
        );

        // Stream pos of the invite.
        let pos = db
            .get_user_room_membership_pos(user.user_nid, room_nid)
            .unwrap()
            .expect("invite transition indexed");

        // Incremental sync from the exact pos of the invite: should
        // be excluded. With the MSC4155-driven sparse rooms emission,
        // an empty invite slot causes `rooms.invite` to be absent
        // entirely, which is equally "no stale invite".
        let resp = build_sync_response(&state, &user, &[], Some(pos)).unwrap();
        let has_stale_invite = resp
            .pointer("/rooms/invite")
            .and_then(|v| v.as_object())
            .is_some_and(|o| o.contains_key("!room:example.com"));
        assert!(!has_stale_invite, "stale invite should not reappear");

        // Incremental sync from before pos: invite reappears.
        let resp = build_sync_response(&state, &user, &[], Some(pos - 1)).unwrap();
        let invites = resp.pointer("/rooms/invite").unwrap().as_object().unwrap();
        assert!(invites.contains_key("!room:example.com"));
    }

    /// Persist a state event, allocate a fresh stream pos, and update
    /// the room's snapshot so `get_state_at_event` returns it.
    #[allow(clippy::too_many_arguments)]
    fn persist_state(
        db: &vela_store::db::Database,
        nid: u64,
        eid: &str,
        room_nid: u64,
        room_id: &str,
        type_name: &str,
        sender_nid: u64,
        sender_id: &str,
        state_key: &str,
        content: serde_json::Value,
        ts: u64,
        depth: u64,
        prev: &[u64],
    ) -> u64 {
        let type_nid = db.get_or_create_nid(type_name).unwrap();
        let skey_nid = db.get_or_create_nid(state_key).unwrap();
        let body = serde_json::json!({
            "type": type_name,
            "sender": sender_id,
            "state_key": state_key,
            "room_id": room_id,
            "content": content,
            "origin_server_ts": ts, "depth": depth,
            "prev_events": [], "auth_events": [],
        });
        let pos = db
            .persist_event(
                nid,
                eid,
                room_nid,
                type_nid,
                sender_nid,
                skey_nid,
                ts,
                depth,
                &serde_json::to_vec(&body).unwrap(),
                prev,
                &[],
                true,
                false,
            )
            .unwrap();
        db.promote_state_event(room_nid, nid, type_nid, skey_nid)
            .unwrap();
        pos
    }

    /// Like `persist_message` but with explicit `prev_events`, so the
    /// message inherits a per-event state snapshot. History-visibility
    /// keys off `get_state_at_event`, which is populated by snapshot
    /// inheritance through `prev_events` — `persist_message` passes none,
    /// so it can't exercise the gate. Returns the stream position.
    #[allow(clippy::too_many_arguments)]
    fn persist_msg_prev(
        db: &vela_store::db::Database,
        nid: u64,
        eid: &str,
        room_nid: u64,
        room_id: &str,
        sender_nid: u64,
        sender_id: &str,
        body: &str,
        ts: u64,
        depth: u64,
        prev: &[u64],
    ) -> u64 {
        let type_nid = db.get_or_create_nid("m.room.message").unwrap();
        let event = serde_json::json!({
            "event_id": eid,
            "type": "m.room.message",
            "sender": sender_id,
            "room_id": room_id,
            "content": {"msgtype": "m.text", "body": body},
            "origin_server_ts": ts, "depth": depth,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            nid,
            eid,
            room_nid,
            type_nid,
            sender_nid,
            0,
            ts,
            depth,
            &serde_json::to_vec(&event).unwrap(),
            prev,
            &[],
            false,
            false,
        )
        .unwrap()
    }

    /// Build a room with a given `m.room.history_visibility`, a message
    /// sent BEFORE bob joins, bob's join, and a message sent AFTER. All
    /// events are prev-chained so per-event state snapshots resolve (what
    /// the history-visibility gate reads). bob ends up joined. Returns
    /// `(state, tmp, bob, room_id, pre_join_pos, bob_membership_pos)`:
    /// `pre_join_pos` is a `since` that falls before bob's join (triggers
    /// the fresh-join branch), `bob_membership_pos` is bob's join
    /// transition pos (a `since` for steady-state incremental).
    fn build_hv_scenario(
        visibility: &str,
    ) -> (
        AppState,
        tempfile::TempDir,
        AuthenticatedUser,
        String,
        u64,
        u64,
    ) {
        let (state, tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!hvroom:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let bob = fake_user(&state, "@bob:example.com");

        persist_state(
            &db,
            300,
            "$hv_create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            301,
            "$hv_alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[300],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();
        persist_state(
            &db,
            302,
            "$hv_vis",
            room_nid,
            &room_id,
            "m.room.history_visibility",
            alice_nid,
            alice,
            "",
            serde_json::json!({ "history_visibility": visibility }),
            3,
            3,
            &[301],
        );
        // Pre-join message: bob has no member event in the snapshot here.
        let pre_join_pos = persist_msg_prev(
            &db,
            303,
            "$hv_pre",
            room_nid,
            &room_id,
            alice_nid,
            alice,
            "pre-join-secret",
            4,
            4,
            &[302],
        );
        persist_state(
            &db,
            304,
            "$hv_bob_join",
            room_nid,
            &room_id,
            "m.room.member",
            bob.user_nid,
            "@bob:example.com",
            "@bob:example.com",
            serde_json::json!({"membership": "join"}),
            5,
            5,
            &[303],
        );
        // set_membership burns a fresh pos AFTER the join event; calling it
        // here (before the post message) keeps bob's membership_pos below
        // the post message's pos, so a steady-state incremental sync from
        // `bob_membership_pos` still surfaces the post-join message.
        db.set_membership(room_nid, bob.user_nid, 1).unwrap();
        let bob_membership_pos = db
            .get_user_room_membership_pos(bob.user_nid, room_nid)
            .unwrap()
            .expect("bob join transition recorded");
        // Post-join message: snapshot includes bob's join.
        persist_msg_prev(
            &db,
            305,
            "$hv_post",
            room_nid,
            &room_id,
            alice_nid,
            alice,
            "post-join-visible",
            6,
            6,
            &[304],
        );

        (state, tmp, bob, room_id, pre_join_pos, bob_membership_pos)
    }

    /// Collect the `body` strings of every timeline message in bob's
    /// `rooms.join.<room>` section of a /sync response.
    fn join_timeline_bodies(resp: &Value, room_id: &str) -> Vec<String> {
        resp.pointer(&format!("/rooms/join/{room_id}/timeline/events"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        e.pointer("/content/body")
                            .and_then(|b| b.as_str())
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// `joined` history-visibility: a user's initial /sync MUST NOT leak
    /// messages sent before they joined, but MUST show post-join messages
    /// and their own join. Regression guard for the /sync timeline build
    /// ignoring `m.room.history_visibility` (which /messages enforces).
    #[test]
    fn sync_initial_hides_prejoin_under_joined_visibility() {
        let (state, _tmp, bob, room_id, _pre, _mp) = build_hv_scenario("joined");
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();
        let resp = build_sync_response(&state, &bob, &[room_nid], None).unwrap();

        let bodies = join_timeline_bodies(&resp, &room_id);
        assert!(
            !bodies.iter().any(|b| b == "pre-join-secret"),
            "pre-join message leaked into initial sync: {bodies:?}"
        );
        assert!(
            bodies.iter().any(|b| b == "post-join-visible"),
            "post-join message missing from initial sync: {bodies:?}"
        );
        // bob's own join event is always visible.
        let ids: Vec<String> = resp
            .pointer(&format!("/rooms/join/{room_id}/timeline/events"))
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            ids.iter().any(|i| i == "$hv_bob_join"),
            "bob's own join must be visible: {ids:?}"
        );
    }

    /// Fresh-join branch (incremental sync whose `since` predates the
    /// join): same gate as initial sync — no pre-join leak.
    #[test]
    fn sync_fresh_join_hides_prejoin_under_joined_visibility() {
        let (state, _tmp, bob, room_id, pre_join_pos, _mp) = build_hv_scenario("joined");
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();
        let resp = build_sync_response(&state, &bob, &[room_nid], Some(pre_join_pos)).unwrap();

        let bodies = join_timeline_bodies(&resp, &room_id);
        assert!(
            !bodies.iter().any(|b| b == "pre-join-secret"),
            "pre-join message leaked into fresh-join sync: {bodies:?}"
        );
        assert!(
            bodies.iter().any(|b| b == "post-join-visible"),
            "post-join message missing from fresh-join sync: {bodies:?}"
        );
    }

    /// Steady-state incremental sync after the join: a post-join message
    /// must still come through — the gate must not over-filter events the
    /// member is entitled to.
    #[test]
    fn sync_incremental_shows_postjoin_under_joined_visibility() {
        let (state, _tmp, bob, room_id, _pre, bob_membership_pos) = build_hv_scenario("joined");
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();
        let resp =
            build_sync_response(&state, &bob, &[room_nid], Some(bob_membership_pos)).unwrap();

        let bodies = join_timeline_bodies(&resp, &room_id);
        assert_eq!(
            bodies,
            vec!["post-join-visible".to_string()],
            "incremental sync should carry exactly the post-join message: {bodies:?}"
        );
    }

    /// `shared` (the spec default): a joined member sees the WHOLE
    /// history, including events from before they joined (rule 3). The
    /// gate must be a no-op here — otherwise the common case regresses.
    #[test]
    fn sync_initial_shows_prejoin_under_shared_visibility() {
        let (state, _tmp, bob, room_id, _pre, _mp) = build_hv_scenario("shared");
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();
        let resp = build_sync_response(&state, &bob, &[room_nid], None).unwrap();

        let bodies = join_timeline_bodies(&resp, &room_id);
        assert!(
            bodies.iter().any(|b| b == "pre-join-secret"),
            "shared visibility must show pre-join history: {bodies:?}"
        );
        assert!(
            bodies.iter().any(|b| b == "post-join-visible"),
            "post-join message missing: {bodies:?}"
        );
    }

    /// `world_readable`: everything is visible regardless of membership.
    #[test]
    fn sync_initial_shows_prejoin_under_world_readable() {
        let (state, _tmp, bob, room_id, _pre, _mp) = build_hv_scenario("world_readable");
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();
        let resp = build_sync_response(&state, &bob, &[room_nid], None).unwrap();

        let bodies = join_timeline_bodies(&resp, &room_id);
        assert!(
            bodies.iter().any(|b| b == "pre-join-secret"),
            "world_readable must show pre-join history: {bodies:?}"
        );
    }

    /// The archived (rooms.leave) view is bounded at BOTH ends under
    /// `joined` visibility: the leave-cap hides post-leave events, and the
    /// history-visibility gate hides pre-join events. The user still sees
    /// the messages from while they were joined plus their own
    /// join/leave.
    #[test]
    fn leave_sync_hides_prejoin_under_joined_visibility() {
        let (state, _tmp, bob, room_id, _pre, _mp) = build_hv_scenario("joined");
        let db = state.db.clone();
        let room_nid = db.get_nid(&room_id).unwrap().unwrap();

        // bob leaves after the post-join message.
        persist_state(
            &db,
            306,
            "$hv_bob_leave",
            room_nid,
            &room_id,
            "m.room.member",
            bob.user_nid,
            "@bob:example.com",
            "@bob:example.com",
            serde_json::json!({"membership": "leave"}),
            7,
            7,
            &[305],
        );
        db.set_membership(room_nid, bob.user_nid, 0).unwrap();

        let leave = build_leave_sync(
            &state,
            room_nid,
            &room_id,
            bob.user_nid,
            &bob.user_id,
            None,
            10,
        )
        .unwrap();
        let events = leave
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .unwrap();
        let bodies: Vec<&str> = events
            .iter()
            .filter_map(|e| e.pointer("/content/body").and_then(|b| b.as_str()))
            .collect();
        let ids: Vec<&str> = events
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();

        assert!(
            !bodies.contains(&"pre-join-secret"),
            "pre-join message leaked into archived view: {bodies:?}"
        );
        assert!(
            bodies.contains(&"post-join-visible"),
            "while-joined message missing from archived view: {bodies:?}"
        );
        assert!(
            ids.contains(&"$hv_bob_leave"),
            "bob's own leave must appear: {ids:?}"
        );
    }

    /// Setup that mirrors the Complement TestArchivedRoomsHistory shape:
    /// alice + bob in a room, both joined, alice writes a custom state
    /// `a.madeup.state` with my_key=before, bob leaves, then alice writes
    /// the same state with my_key=after.
    fn build_archive_scenario() -> (AppState, tempfile::TempDir, AuthenticatedUser, String) {
        let (state, tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!leaveroom:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let bob = fake_user(&state, "@bob:example.com");

        persist_state(
            &db,
            100,
            "$create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            101,
            "$alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[100],
        );
        persist_state(
            &db,
            102,
            "$bob_join",
            room_nid,
            &room_id,
            "m.room.member",
            bob.user_nid,
            "@bob:example.com",
            "@bob:example.com",
            serde_json::json!({"membership": "join"}),
            3,
            3,
            &[101],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();
        db.set_membership(room_nid, bob.user_nid, 1).unwrap();

        persist_state(
            &db,
            103,
            "$state_before",
            room_nid,
            &room_id,
            "a.madeup.state",
            alice_nid,
            alice,
            "",
            serde_json::json!({"my_key": "before"}),
            4,
            4,
            &[102],
        );
        persist_state(
            &db,
            104,
            "$bob_leave",
            room_nid,
            &room_id,
            "m.room.member",
            bob.user_nid,
            "@bob:example.com",
            "@bob:example.com",
            serde_json::json!({"membership": "leave"}),
            5,
            5,
            &[103],
        );
        db.set_membership(room_nid, bob.user_nid, 0).unwrap();
        persist_state(
            &db,
            105,
            "$state_after",
            room_nid,
            &room_id,
            "a.madeup.state",
            alice_nid,
            alice,
            "",
            serde_json::json!({"my_key": "after"}),
            6,
            6,
            &[104],
        );

        (state, tmp, bob, room_id)
    }

    /// With timeline_limit=0 the leave room shows state-AT-LEAVE in
    /// `state.events`. The post-leave `$state_after` must not appear.
    #[test]
    fn leave_sync_with_empty_timeline_returns_state_at_leave() {
        let (state, _tmp, bob, room_id) = build_archive_scenario();
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();

        let leave = build_leave_sync(
            &state,
            room_nid,
            &room_id,
            bob.user_nid,
            &bob.user_id,
            None,
            0,
        )
        .unwrap();
        let state_events = leave
            .pointer("/state/events")
            .and_then(|v| v.as_array())
            .unwrap();

        let madeup = state_events
            .iter()
            .find(|e| e.get("type").and_then(|t| t.as_str()) == Some("a.madeup.state"))
            .expect("madeup state event present");
        assert_eq!(
            madeup.pointer("/content/my_key").and_then(|v| v.as_str()),
            Some("before"),
            "state must be at-leave, not current"
        );

        let bob_member = state_events
            .iter()
            .find(|e| {
                e.get("type").and_then(|t| t.as_str()) == Some("m.room.member")
                    && e.get("state_key").and_then(|s| s.as_str()) == Some("@bob:example.com")
            })
            .expect("bob's member event present in state");
        assert_eq!(
            bob_member
                .pointer("/content/membership")
                .and_then(|v| v.as_str()),
            Some("leave"),
        );

        let timeline = leave
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(timeline.is_empty(), "timeline_limit=0 → empty timeline");
    }

    /// With a non-zero limit, the leave room timeline ends at the user's
    /// leave event — events sent after the leave must NOT appear, even if
    /// they're newer than the leave in the room timeline.
    #[test]
    fn leave_sync_timeline_ends_at_leave_event() {
        let (state, _tmp, bob, room_id) = build_archive_scenario();
        let room_nid = state.db.get_nid(&room_id).unwrap().unwrap();

        let leave = build_leave_sync(
            &state,
            room_nid,
            &room_id,
            bob.user_nid,
            &bob.user_id,
            None,
            10,
        )
        .unwrap();
        let timeline = leave
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .unwrap();

        let last_id = timeline
            .last()
            .and_then(|e| e.get("event_id").and_then(|v| v.as_str()))
            .expect("timeline non-empty");
        assert_eq!(last_id, "$bob_leave", "timeline must end at bob's leave");
        assert!(
            !timeline
                .iter()
                .any(|e| e.get("event_id").and_then(|v| v.as_str()) == Some("$state_after")),
            "post-leave events must not appear in bob's timeline"
        );
    }

    /// Incremental sync where `since` falls just before the leave event:
    /// timeline should be exactly the leave event, and state.events
    /// should be empty (the only state delta is the leave event itself,
    /// which already appears in the timeline).
    #[test]
    fn leave_sync_incremental_emits_leave_in_timeline_and_no_duplicate_state() {
        let (state, _tmp, bob, room_id) = build_archive_scenario();
        let db = &state.db;
        let room_nid = db.get_nid(&room_id).unwrap().unwrap();

        // Find the stream pos of `$state_before` and use it as `since`.
        // The leave event was persisted right after it, so events after
        // that point are exactly the leave + the post-leave state change.
        let scan = db.get_timeline_before(room_nid, u64::MAX, 100).unwrap();
        let state_before_pos = scan
            .iter()
            .find_map(|(pos, nid)| {
                let eid = db.get_event_id_by_nid(*nid).unwrap().unwrap_or_default();
                if eid == "$state_before" {
                    Some(*pos)
                } else {
                    None
                }
            })
            .expect("found $state_before");

        let leave = build_leave_sync(
            &state,
            room_nid,
            &room_id,
            bob.user_nid,
            &bob.user_id,
            Some(state_before_pos),
            10,
        )
        .unwrap();

        let timeline = leave
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .unwrap();
        let ids: Vec<&str> = timeline
            .iter()
            .filter_map(|e| e.get("event_id").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(ids, vec!["$bob_leave"], "timeline only the leave event");

        let state_events = leave
            .pointer("/state/events")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(
            state_events.is_empty(),
            "state delta should be empty (leave is in timeline already): {state_events:?}"
        );
    }

    /// Per spec, an incremental /sync MUST omit joined rooms with no new
    /// content since `since`. The `full_state=true` form bypasses this.
    #[test]
    fn unchanged_joined_room_omitted_from_incremental_sync() {
        let (state, _tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!quietroom:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let alice_user = AuthenticatedUser {
            user_nid: alice_nid,
            user_id: alice.into(),
            device_id: "DEV".into(),
            appservice_nid: None,
        };

        persist_state(
            &db,
            200,
            "$create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            201,
            "$alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[200],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        let cur = db.current_stream_position();

        // Initial sync: room must appear (even if "empty" state, alice
        // has never seen it before).
        let resp =
            build_sync_response_with_filter(&state, &alice_user, &[room_nid], None, None, false)
                .unwrap();
        assert!(
            resp.pointer(&format!("/rooms/join/{room_id}")).is_some(),
            "initial sync must include joined rooms"
        );

        // Incremental sync from a token equal to current pos: nothing
        // happened since, so the room must be omitted. Sparse rooms
        // emission means `rooms.join` itself may be absent — that's
        // also "room not present".
        let resp = build_sync_response_with_filter(
            &state,
            &alice_user,
            &[room_nid],
            Some(cur),
            None,
            false,
        )
        .unwrap();
        let has_room = resp
            .pointer("/rooms/join")
            .and_then(|v| v.as_object())
            .is_some_and(|o| o.contains_key(&room_id));
        assert!(
            !has_room,
            "unchanged room must not appear on incremental sync"
        );

        // full_state=true forces the room to be present even when nothing
        // has happened since.
        let resp = build_sync_response_with_filter(
            &state,
            &alice_user,
            &[room_nid],
            Some(cur),
            None,
            true,
        )
        .unwrap();
        assert!(
            resp.pointer(&format!("/rooms/join/{room_id}")).is_some(),
            "full_state=true must always include joined rooms"
        );
    }

    /// Regression for the /sync busy-loop: a quiet room must be omitted from an
    /// incremental sync even when the client requested **lazy-loading**.
    /// Lazy-load injects the caller's own `m.room.member` into the room state
    /// for rendering context; that must not be counted as a change, or every
    /// room reappears on every /sync, `has_new_data` is always true, and the
    /// long-poll busy-loops (~10 syncs/sec).
    #[test]
    fn lazy_loaded_unchanged_room_omitted_from_incremental_sync() {
        let (state, _tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!llquiet:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let alice_user = AuthenticatedUser {
            user_nid: alice_nid,
            user_id: alice.into(),
            device_id: "DEV".into(),
            appservice_nid: None,
        };

        persist_state(
            &db,
            200,
            "$create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            201,
            "$alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[200],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        let cur = db.current_stream_position();
        let lazy_filter = serde_json::json!({"room": {"state": {"lazy_load_members": true}}});

        let resp = build_sync_response_with_filter(
            &state,
            &alice_user,
            &[room_nid],
            Some(cur),
            Some(&lazy_filter),
            false,
        )
        .unwrap();

        let has_room = resp
            .pointer("/rooms/join")
            .and_then(|v| v.as_object())
            .is_some_and(|o| o.contains_key(&room_id));
        assert!(
            !has_room,
            "lazy-loaded quiet room must be omitted on incremental sync (injected own-membership must not count as a change)"
        );
    }

    /// MSC4222: when a client opts in with the UNSTABLE param
    /// (`org.matrix.msc4222.use_state_after`), the response's state field must
    /// be renamed from the canonical `state_after` to the unstable key the
    /// client reads (`org.matrix.msc4222.state_after`). vela emitted the stable
    /// key for the unstable param, so Element never found it, treated
    /// `state_after` as absent (per spec) and fell back to the timeline — long
    /// rooms then rendered as "version 1" with no name.
    #[test]
    fn rename_state_after_uses_unstable_key_for_unstable_param() {
        let mut resp = serde_json::json!({
            "rooms": {"join": {"!r:s": {
                "state_after": {"events": [
                    {"type": "m.room.create", "content": {"room_version": "12"}}
                ]},
                "timeline": {"events": []}
            }}}
        });
        rename_state_after_for_client(&mut resp, "org.matrix.msc4222.state_after");
        let room = resp
            .pointer("/rooms/join/!r:s")
            .and_then(|v| v.as_object())
            .unwrap();
        assert!(
            !room.contains_key("state_after"),
            "the stable `state_after` key must be gone (spec: client reads its own spelling)"
        );
        assert!(
            room.contains_key("org.matrix.msc4222.state_after"),
            "state must move under the unstable key the unstable-param client reads"
        );
    }

    /// The stable spelling (`use_state_after` → `state_after`) is a no-op:
    /// the canonical field stays under `state_after`.
    #[test]
    fn rename_state_after_noop_for_stable_key() {
        let mut resp = serde_json::json!({
            "rooms": {"join": {"!r:s": {"state_after": {"events": []}}}}
        });
        rename_state_after_for_client(&mut resp, "state_after");
        assert!(
            resp.pointer("/rooms/join/!r:s/state_after").is_some(),
            "stable spelling must leave `state_after` in place"
        );
    }

    /// Class-level invariant guard against the /sync busy-loop: a *quiet*
    /// incremental sync — nothing changed since `since` — must omit every
    /// joined room, for EVERY combination of sync options. Phrasing it as a
    /// property (not per-source) means a future content source that injects
    /// unconditionally fails this test regardless of which source it is or
    /// which option combination triggers it — the per-source tests catch the
    /// sources we thought of; this catches the ones we didn't.
    #[test]
    fn quiet_incremental_sync_omits_rooms_across_options() {
        let (state, _tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!quietmatrix:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let alice_user = AuthenticatedUser {
            user_nid: alice_nid,
            user_id: alice.into(),
            device_id: "DEV".into(),
            appservice_nid: None,
        };
        persist_state(
            &db,
            200,
            "$create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            201,
            "$alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[200],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();

        let cur = db.current_stream_position();
        let lazy = serde_json::json!({"room": {"state": {"lazy_load_members": true}}});
        let timeline = serde_json::json!({"room": {"timeline": {"limit": 20}}});

        for (label, filter) in [
            ("no filter", None),
            ("lazy-load", Some(&lazy)),
            ("timeline filter", Some(&timeline)),
        ] {
            for &use_state_after in &[false, true] {
                let resp = build_sync_response_inner(
                    &state,
                    &alice_user,
                    &[room_nid],
                    Some(cur),
                    filter,
                    false,
                    use_state_after,
                )
                .unwrap();
                let empty = resp
                    .pointer("/rooms/join")
                    .and_then(|v| v.as_object())
                    .is_none_or(|o| o.is_empty());
                assert!(
                    empty,
                    "quiet incremental sync must omit all rooms [{label}, use_state_after={use_state_after}], got {:?}",
                    resp.pointer("/rooms/join")
                );
            }
        }
    }

    /// The converse — the lost-update guard. A room with a *real* change MUST
    /// still appear on an incremental lazy-load sync, carrying the timeline
    /// sender's membership. Pairs with the omit invariant so a future
    /// over-eager gate that dropped genuine updates is caught too.
    #[test]
    fn changed_room_appears_with_lazy_load_on_incremental_sync() {
        let (state, _tmp) = build_test_state();
        let db = state.db.clone();

        let room_id = "!llchanged:example.com".to_string();
        let room_nid = db.get_or_create_nid(&room_id).unwrap();
        let alice = "@alice:example.com";
        let alice_nid = db.get_or_create_nid(alice).unwrap();
        let bob = "@bob:example.com";
        let bob_nid = db.get_or_create_nid(bob).unwrap();
        let alice_user = AuthenticatedUser {
            user_nid: alice_nid,
            user_id: alice.into(),
            device_id: "DEV".into(),
            appservice_nid: None,
        };
        persist_state(
            &db,
            200,
            "$create",
            room_nid,
            &room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            201,
            "$alice_join",
            room_nid,
            &room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[200],
        );
        persist_state(
            &db,
            202,
            "$bob_join",
            room_nid,
            &room_id,
            "m.room.member",
            bob_nid,
            bob,
            bob,
            serde_json::json!({"membership": "join"}),
            3,
            3,
            &[201],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();
        db.set_membership(room_nid, bob_nid, 1).unwrap();

        let cur = db.current_stream_position();
        // Bob sends a message after `cur` — a genuine change.
        persist_message(
            &db, 203, "$bobmsg", room_nid, &room_id, bob_nid, bob, "hi", 100, 4,
        );

        let lazy = serde_json::json!({"room": {"state": {"lazy_load_members": true}}});
        let resp = build_sync_response_inner(
            &state,
            &alice_user,
            &[room_nid],
            Some(cur),
            Some(&lazy),
            false,
            false,
        )
        .unwrap();

        let room = resp.pointer(&format!("/rooms/join/{room_id}")).expect(
            "a changed room must appear on an incremental lazy-load sync (lost-update guard)",
        );
        let timeline = room
            .pointer("/timeline/events")
            .and_then(|v| v.as_array())
            .expect("timeline events");
        assert!(
            timeline
                .iter()
                .any(|e| e.get("event_id").and_then(|v| v.as_str()) == Some("$bobmsg")),
            "the changed room's timeline must carry bob's message"
        );
        let state_events = room
            .pointer("/state/events")
            .and_then(|v| v.as_array())
            .expect("state events");
        assert!(
            state_events
                .iter()
                .any(
                    |e| e.get("type").and_then(|v| v.as_str()) == Some("m.room.member")
                        && e.get("state_key").and_then(|v| v.as_str()) == Some(bob)
                ),
            "lazy-load must inject the timeline sender (bob)'s membership"
        );
    }

    /// The unstable MSC4222 query param spelling must opt in just like the
    /// stable one — otherwise current Element builds are silently downgraded.
    #[test]
    fn unstable_msc4222_use_state_after_param_is_recognised() {
        let q: SyncQuery =
            serde_urlencoded::from_str("org.matrix.msc4222.use_state_after=true").unwrap();
        assert_eq!(q.use_state_after, None);
        assert_eq!(q.use_state_after_unstable, Some(true));
        let merged = q
            .use_state_after
            .or(q.use_state_after_unstable)
            .unwrap_or(false);
        assert!(merged, "the unstable spelling must opt into state_after");
    }

    #[test]
    fn historical_leave_is_gated_by_include_leave() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!leftroom:example.com").unwrap();
        let user = fake_user(&state, "@carol:example.com");
        db.set_membership(room_nid, user.user_nid, 0).unwrap();

        let has_leave = |r: &Value| {
            r.pointer("/rooms/leave")
                .and_then(|v| v.as_object())
                .is_some_and(|o| o.contains_key("!leftroom:example.com"))
        };

        // Initial sync, no filter: include_leave defaults to false, so a room
        // left before the (nonexistent) window must NOT appear.
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        assert!(
            !has_leave(&resp),
            "historical left room must not appear on an initial sync without include_leave"
        );

        // Same initial sync with include_leave=true → it appears.
        let filter = json!({"room": {"include_leave": true}});
        let resp = build_sync_response_with_filter(&state, &user, &[], None, Some(&filter), false)
            .unwrap();
        assert!(
            has_leave(&resp),
            "include_leave=true must surface the historical left room"
        );

        // Incremental sync past the leave position, no filter → no stale leave.
        let pos = db
            .get_user_room_membership_pos(user.user_nid, room_nid)
            .unwrap()
            .unwrap();
        let resp = build_sync_response(&state, &user, &[], Some(pos)).unwrap();
        assert!(!has_leave(&resp), "stale leave should not reappear");

        // Crucially, include_leave must NOT re-surface an already-reported
        // historical leave on an incremental sync — the room was left before
        // the window, so it appears once (on the leave) and never again.
        let resp =
            build_sync_response_with_filter(&state, &user, &[], Some(pos), Some(&filter), false)
                .unwrap();
        assert!(
            !has_leave(&resp),
            "include_leave must not re-surface a historical leave on incremental sync"
        );

        // A full-state sync, by contrast, behaves like an initial sync: the
        // historical leave reappears when include_leave is set.
        let resp =
            build_sync_response_with_filter(&state, &user, &[], Some(pos), Some(&filter), true)
                .unwrap();
        assert!(
            has_leave(&resp),
            "a full-state sync with include_leave should surface historical left rooms"
        );
    }

    #[test]
    fn ignored_user_invite_is_dropped_from_sync() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!room12").unwrap();
        let user = fake_user(&state, "@bob:example.com");
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();

        // Persist a create + alice's join + alice-invites-bob member event.
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();
        let bob_skey = db.get_or_create_nid("@bob:example.com").unwrap();

        db.persist_event(
            10,
            "$room12",
            room_nid,
            type_create,
            alice_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.create",
                "sender": "@alice:example.com",
                "state_key": "",
                "room_id": "!room12",
                "content": {"room_version": "12"},
                "origin_server_ts": 1, "depth": 1,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            11,
            "$alice",
            room_nid,
            type_member,
            alice_nid,
            alice_nid,
            2,
            2,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.member",
                "sender": "@alice:example.com", "state_key": "@alice:example.com",
                "room_id": "!room12",
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": ["$room12"], "auth_events": ["$room12"],
            }))
            .unwrap(),
            &[10],
            &[10],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            12,
            "$bob_invite",
            room_nid,
            type_member,
            alice_nid,
            bob_skey,
            3,
            3,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.member",
                "sender": "@alice:example.com", "state_key": "@bob:example.com",
                "room_id": "!room12",
                "content": {"membership": "invite"},
                "origin_server_ts": 3, "depth": 3,
                "prev_events": ["$alice"], "auth_events": ["$alice"],
            }))
            .unwrap(),
            &[11],
            &[11],
            true,
            false,
        )
        .unwrap();
        db.set_membership(room_nid, user.user_nid, 2).unwrap();

        // Without ignoring alice, the invite shows up.
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        assert!(
            resp.pointer("/rooms/invite/!room12").is_some(),
            "invite present pre-ignore"
        );

        // Now bob ignores alice.
        db.set_account_data(
            user.user_nid,
            "m.ignored_user_list",
            &serde_json::json!({
                "ignored_users": {"@alice:example.com": {}}
            }),
        )
        .unwrap();

        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        assert!(
            resp.pointer("/rooms/invite/!room12").is_none(),
            "invite from ignored user should be filtered: {resp:?}"
        );
    }

    #[test]
    fn new_invite_after_since_surfaces_on_incremental() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!fresh:example.com").unwrap();
        let user = fake_user(&state, "@dan:example.com");

        // Client's since token is "now", captured before the invite arrives.
        let since = db.current_stream_position();

        // Now the invite comes in.
        db.set_membership(room_nid, user.user_nid, 2).unwrap();

        let resp = build_sync_response(&state, &user, &[], Some(since)).unwrap();
        let invites = resp.pointer("/rooms/invite").unwrap().as_object().unwrap();
        assert!(
            invites.contains_key("!fresh:example.com"),
            "fresh invite must appear after since={since}"
        );
    }

    // ---- highlight_count via push-rule evaluation ----
    //
    // Scenario: alice + bob in a room, both joined. Bob sends one or more
    // messages; we check what alice's `compute_unread_counts` says about
    // notification_count and highlight_count.

    /// Build the minimal world: create+joins for alice & bob, return their
    /// nids and the room_nid. Caller decides what messages to add.
    fn build_alice_bob_room(
        state: &AppState,
    ) -> (u64, u64, u64, &'static str, &'static str, &'static str) {
        let db = state.db.clone();
        let room_id = "!hl:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice = "@alice:example.com";
        let bob = "@bob:example.com";
        let alice_nid = db.create_user(alice, "x").unwrap();
        let bob_nid = db.create_user(bob, "x").unwrap();

        persist_state(
            &db,
            100,
            "$create",
            room_nid,
            room_id,
            "m.room.create",
            alice_nid,
            alice,
            "",
            serde_json::json!({"room_version": "12"}),
            1,
            1,
            &[],
        );
        persist_state(
            &db,
            101,
            "$alice_join",
            room_nid,
            room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join"}),
            2,
            2,
            &[100],
        );
        persist_state(
            &db,
            102,
            "$bob_join",
            room_nid,
            room_id,
            "m.room.member",
            bob_nid,
            bob,
            bob,
            serde_json::json!({"membership": "join"}),
            3,
            3,
            &[101],
        );
        db.set_membership(room_nid, alice_nid, 1).unwrap();
        db.set_membership(room_nid, bob_nid, 1).unwrap();
        (room_nid, alice_nid, bob_nid, room_id, alice, bob)
    }

    /// Persist a non-state `m.room.message` from `sender` with `body`,
    /// then return the same JSON shape `build_sync_response` would emit
    /// in the timeline (a `Value` with `type`/`sender`/`content`/etc).
    fn persist_message(
        db: &vela_store::db::Database,
        nid: u64,
        eid: &str,
        room_nid: u64,
        room_id: &str,
        sender_nid: u64,
        sender_id: &str,
        body: &str,
        ts: u64,
        depth: u64,
    ) -> serde_json::Value {
        let type_nid = db.get_or_create_nid("m.room.message").unwrap();
        let event = serde_json::json!({
            "event_id": eid,
            "type": "m.room.message",
            "sender": sender_id,
            "room_id": room_id,
            "content": {"msgtype": "m.text", "body": body},
            "origin_server_ts": ts, "depth": depth,
            "prev_events": [], "auth_events": [],
        });
        db.persist_event(
            nid,
            eid,
            room_nid,
            type_nid,
            sender_nid,
            0,
            ts,
            depth,
            &serde_json::to_vec(&event).unwrap(),
            &[],
            &[],
            false,
            false,
        )
        .unwrap();
        event
    }

    #[test]
    fn highlight_count_fires_on_room_member_displayname_mention() {
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, alice, bob) = build_alice_bob_room(&state);

        // Alice's per-room displayname: "Alice Wonder". Push-rule
        // contains_display_name should match a body containing it.
        persist_state(
            &state.db,
            110,
            "$alice_profile",
            room_nid,
            room_id,
            "m.room.member",
            alice_nid,
            alice,
            alice,
            serde_json::json!({"membership": "join", "displayname": "Alice Wonder"}),
            10,
            10,
            &[102],
        );

        let _ev = persist_message(
            &state.db,
            200,
            "$m1",
            room_nid,
            room_id,
            bob_nid,
            bob,
            "hey Alice Wonder",
            20,
            20,
        );

        let (notif, hl, _) = compute_unread_counts(&state, room_nid, alice_nid, false).unwrap();
        assert_eq!(notif, 1, "underride rule should count bob's message");
        assert_eq!(hl, 1, "displayname mention should highlight");
    }

    #[test]
    fn highlight_count_fires_on_custom_content_rule() {
        // Mirrors the spec's `.m.rule.contains_user_name`: user has a
        // content rule whose pattern is their MXID, action notify+highlight.
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, _alice, bob) = build_alice_bob_room(&state);

        // Install a user-level content rule on top of the defaults.
        state
            .db
            .set_account_data(
                alice_nid,
                "m.push_rules",
                &serde_json::json!({
                    "global": {
                        "content": [{
                            "rule_id": ".m.rule.contains_user_name",
                            "default": true,
                            "enabled": true,
                            // Matrix content rules glob-match; users
                            // wrap their MXID with wildcards so the
                            // pattern fires anywhere in the body.
                            "pattern": "*@alice:example.com*",
                            "actions": ["notify", {"set_tweak": "highlight"}],
                        }],
                    }
                }),
            )
            .unwrap();

        let _ev = persist_message(
            &state.db,
            201,
            "$m2",
            room_nid,
            room_id,
            bob_nid,
            bob,
            "hey @alice:example.com",
            21,
            21,
        );

        let (notif, hl, _) = compute_unread_counts(&state, room_nid, alice_nid, false).unwrap();
        assert_eq!(notif, 1);
        assert_eq!(hl, 1, "MXID mention via content rule should highlight");
    }

    #[test]
    fn highlight_count_zero_for_plain_message() {
        // No displayname set, no custom rules. Bob's plain message
        // should bump notification_count via the default underride
        // .m.rule.message but NOT highlight.
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, _alice, bob) = build_alice_bob_room(&state);

        let _ev = persist_message(
            &state.db,
            202,
            "$m3",
            room_nid,
            room_id,
            bob_nid,
            bob,
            "good morning",
            22,
            22,
        );

        let (notif, hl, _) = compute_unread_counts(&state, room_nid, alice_nid, false).unwrap();
        assert_eq!(notif, 1, "plain message still notifies under defaults");
        assert_eq!(hl, 0, "no rule emits highlight → highlight_count = 0");
    }

    #[test]
    fn highlight_count_falls_back_to_profile_displayname() {
        // No per-room member displayname, but a global profile one.
        // contains_display_name should still match.
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, _alice, bob) = build_alice_bob_room(&state);
        state
            .db
            .update_user_profile(alice_nid, Some("Alice Profile"), None)
            .unwrap();

        let _ev = persist_message(
            &state.db,
            203,
            "$m4",
            room_nid,
            room_id,
            bob_nid,
            bob,
            "ping Alice Profile please",
            23,
            23,
        );

        let (_notif, hl, _) = compute_unread_counts(&state, room_nid, alice_nid, false).unwrap();
        assert_eq!(hl, 1, "profile displayname should still drive highlight");
    }

    #[test]
    fn unread_count_reflects_messages_after_read_receipt() {
        // The regression this fixes: the old per-batch count returned 0
        // whenever the read receipt sat before the delivered timeline batch.
        // Now we count the room total since the receipt — alice reads m1, bob
        // sends m2 + m3, so the count is 2 regardless of any /sync batch.
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, _alice, bob) = build_alice_bob_room(&state);

        persist_message(
            &state.db, 200, "$u1", room_nid, room_id, bob_nid, bob, "one", 20, 20,
        );
        state
            .db
            .set_receipt(room_nid, "m.read", alice_nid, "$u1", 100, None)
            .unwrap();
        persist_message(
            &state.db, 201, "$u2", room_nid, room_id, bob_nid, bob, "two", 21, 21,
        );
        persist_message(
            &state.db, 202, "$u3", room_nid, room_id, bob_nid, bob, "three", 22, 22,
        );

        let (notif, _hl, _) = compute_unread_counts(&state, room_nid, alice_nid, false).unwrap();
        assert_eq!(notif, 2, "two messages after the read receipt are unread");
    }

    #[test]
    fn unread_count_zero_when_caught_up() {
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, _alice, bob) = build_alice_bob_room(&state);
        persist_message(
            &state.db, 200, "$c1", room_nid, room_id, bob_nid, bob, "one", 20, 20,
        );
        persist_message(
            &state.db, 201, "$c2", room_nid, room_id, bob_nid, bob, "two", 21, 21,
        );
        state
            .db
            .set_receipt(room_nid, "m.read", alice_nid, "$c2", 100, None)
            .unwrap();
        let (notif, _, _) = compute_unread_counts(&state, room_nid, alice_nid, false).unwrap();
        assert_eq!(notif, 0, "reading the latest event clears the count");
    }

    #[test]
    fn private_read_receipt_advances_unread_count() {
        // m.read.private marks events read for the owner's own unread count.
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, _alice, bob) = build_alice_bob_room(&state);
        persist_message(
            &state.db, 200, "$p1", room_nid, room_id, bob_nid, bob, "one", 20, 20,
        );
        state
            .db
            .set_receipt(room_nid, "m.read.private", alice_nid, "$p1", 100, None)
            .unwrap();
        let (notif, _, _) = compute_unread_counts(&state, room_nid, alice_nid, false).unwrap();
        assert_eq!(
            notif, 0,
            "a private read receipt also marks the message read"
        );
    }

    #[test]
    fn main_receipt_does_not_clear_thread_unread() {
        // A "main"-scoped receipt covers only the main timeline; a reply in a
        // thread it doesn't cover stays unread under its own thread bucket.
        let (state, _tmp) = build_test_state();
        let (room_nid, alice_nid, bob_nid, room_id, _alice, bob) = build_alice_bob_room(&state);

        persist_message(
            &state.db, 200, "$mt1", room_nid, room_id, bob_nid, bob, "main", 20, 20,
        );
        state
            .db
            .set_receipt(room_nid, "m.read", alice_nid, "$mt1", 100, Some("main"))
            .unwrap();

        // A threaded reply (rel_type m.thread) the "main" receipt does not cover.
        let type_nid = state.db.get_or_create_nid("m.room.message").unwrap();
        let thread_ev = serde_json::json!({
            "event_id": "$mt2", "type": "m.room.message", "sender": bob, "room_id": room_id,
            "content": {
                "msgtype": "m.text", "body": "in thread",
                "m.relates_to": {"rel_type": "m.thread", "event_id": "$root"},
            },
            "origin_server_ts": 21, "depth": 21, "prev_events": [], "auth_events": [],
        });
        state
            .db
            .persist_event(
                201,
                "$mt2",
                room_nid,
                type_nid,
                bob_nid,
                0,
                21,
                21,
                &serde_json::to_vec(&thread_ev).unwrap(),
                &[],
                &[],
                false,
                false,
            )
            .unwrap();

        let (main_count, _hl, threads) =
            compute_unread_counts(&state, room_nid, alice_nid, true).unwrap();
        assert_eq!(
            main_count, 0,
            "main receipt clears the main-timeline message"
        );
        assert_eq!(
            threads.get("$root").map(|(c, _)| *c),
            Some(1),
            "the thread reply stays unread under its thread bucket"
        );
    }

    /// `compute_state_delta` returns the most-recent state event for
    /// each `(type, state_key)` slot that changed between
    /// `since_exclusive` and `upper_exclusive`. Non-state events in
    /// the same range are ignored.
    #[test]
    fn state_delta_picks_latest_per_slot() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!delta:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let bob_nid = db.get_or_create_nid("@bob:example.com").unwrap();
        let _ = (alice_nid, bob_nid);

        // Pos 1: alice writes m.room.name = "v1".
        let p1 = persist_state(
            db,
            1001,
            "$n1",
            room_nid,
            room_id,
            "m.room.name",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"name": "v1"}),
            10,
            1,
            &[],
        );
        // Pos 2: alice writes a regular m.room.message (NOT a state event).
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();
        let body = json!({
            "type": "m.room.message",
            "sender": "@alice:example.com",
            "room_id": room_id,
            "content": {"body": "hi"},
            "origin_server_ts": 11, "depth": 2,
            "prev_events": [], "auth_events": [],
        });
        let _p2 = db
            .persist_event(
                1002,
                "$m1",
                room_nid,
                type_msg,
                alice_nid,
                0,
                11,
                2,
                &serde_json::to_vec(&body).unwrap(),
                &[],
                &[],
                false,
                false,
            )
            .unwrap();
        // Pos 3: alice updates m.room.name = "v2" — supersedes p1.
        let p3 = persist_state(
            db,
            1003,
            "$n2",
            room_nid,
            room_id,
            "m.room.name",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"name": "v2"}),
            12,
            3,
            &[],
        );
        assert!(p3 > p1, "stream pos must advance");

        let out = compute_state_delta(&state, room_nid, room_id, 1, p3 + 1, None, None).unwrap();
        let by_slot: std::collections::HashMap<String, String> = out
            .iter()
            .map(|ev| {
                let key = format!(
                    "{}|{}",
                    ev.get("type").and_then(|v| v.as_str()).unwrap_or(""),
                    ev.get("state_key").and_then(|v| v.as_str()).unwrap_or("")
                );
                let name = ev
                    .pointer("/content/name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                (key, name)
            })
            .collect();
        assert_eq!(by_slot.len(), 1, "one slot, latest only: {by_slot:?}");
        assert_eq!(by_slot.get("m.room.name|").map(String::as_str), Some("v2"));
    }

    /// `since_exclusive >= upper_exclusive` means the client is
    /// up-to-date with everything we'd emit; the delta is empty.
    #[test]
    fn state_delta_empty_when_range_inverted_or_collapsed() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!noop:example.com").unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        persist_state(
            db,
            2001,
            "$x",
            room_nid,
            "!noop:example.com",
            "m.room.name",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"name": "x"}),
            1,
            1,
            &[],
        );
        assert!(
            compute_state_delta(&state, room_nid, "!noop:example.com", 10, 10, None, None)
                .unwrap()
                .is_empty()
        );
        assert!(
            compute_state_delta(&state, room_nid, "!noop:example.com", 11, 10, None, None)
                .unwrap()
                .is_empty()
        );
    }

    /// State events in disjoint slots all come back (one per slot).
    #[test]
    fn state_delta_returns_one_event_per_slot() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!multi:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();

        let p1 = persist_state(
            db,
            3001,
            "$pl",
            room_nid,
            room_id,
            "m.room.power_levels",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"users_default": 0}),
            1,
            1,
            &[],
        );
        let p2 = persist_state(
            db,
            3002,
            "$jr",
            room_nid,
            room_id,
            "m.room.join_rules",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"join_rule": "public"}),
            2,
            2,
            &[],
        );
        assert!(p2 > p1);

        let out = compute_state_delta(&state, room_nid, room_id, 1, p2 + 1, None, None).unwrap();
        let types: std::collections::HashSet<String> = out
            .iter()
            .filter_map(|ev| ev.get("type").and_then(|v| v.as_str()).map(String::from))
            .collect();
        assert!(types.contains("m.room.power_levels"));
        assert!(types.contains("m.room.join_rules"));
        assert_eq!(out.len(), 2);
    }

    /// Non-state events (`state_key_nid == 0`) inside the range must
    /// NOT contribute to the delta. This is the test that catches a
    /// regression where compute_state_delta treats every event as
    /// state.
    #[test]
    fn state_delta_skips_non_state_events_in_range() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!noisy:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();
        let type_msg = db.get_or_create_nid("m.room.message").unwrap();

        // Three plain timeline messages.
        for (nid, eid) in &[(4001u64, "$m1"), (4002, "$m2"), (4003, "$m3")] {
            let body = json!({
                "type": "m.room.message",
                "sender": "@alice:example.com",
                "room_id": room_id,
                "content": {"body": "x"},
                "origin_server_ts": 1, "depth": 1,
                "prev_events": [], "auth_events": [],
            });
            db.persist_event(
                *nid,
                eid,
                room_nid,
                type_msg,
                alice_nid,
                0,
                1,
                1,
                &serde_json::to_vec(&body).unwrap(),
                &[],
                &[],
                false,
                false,
            )
            .unwrap();
        }
        let out = compute_state_delta(&state, room_nid, room_id, 1, 99999, None, None).unwrap();
        assert!(
            out.is_empty(),
            "non-state events shouldn't contribute: {out:#?}"
        );
    }

    /// A room with no events in the range returns an empty delta.
    /// Distinct from the "inverted range" test — here the range is
    /// valid but the room genuinely has nothing in it.
    #[test]
    fn state_delta_empty_for_empty_room() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_nid = db.get_or_create_nid("!quiet:example.com").unwrap();
        let out = compute_state_delta(&state, room_nid, "!quiet:example.com", 1, 99999, None, None)
            .unwrap();
        assert!(out.is_empty());
    }

    /// The `(since_exclusive, upper_exclusive)` window translates to
    /// the timeline scan's `[from, to)` half-open range — `from`
    /// inclusive, `to` exclusive. Callers in sync pass `since + 1` as
    /// `since_exclusive` to skip the event the client already has.
    /// Pin both boundary behaviours so a later signature change can't
    /// silently flip inclusivity.
    #[test]
    fn state_delta_window_is_half_open_lower_inclusive() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!boundary:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();

        let p = persist_state(
            db,
            5001,
            "$jr",
            room_nid,
            room_id,
            "m.room.join_rules",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"join_rule": "public"}),
            1,
            1,
            &[],
        );
        // since_exclusive == p (inclusive lower) → event INCLUDED.
        let out = compute_state_delta(&state, room_nid, room_id, p, p + 10, None, None).unwrap();
        assert_eq!(out.len(), 1, "lower bound is inclusive");

        // since_exclusive == p + 1 → event excluded.
        let out =
            compute_state_delta(&state, room_nid, room_id, p + 1, p + 10, None, None).unwrap();
        assert!(out.is_empty(), "events past lower bound are excluded");

        // upper_exclusive == p (exclusive upper) → event excluded.
        let out = compute_state_delta(&state, room_nid, room_id, 1, p, None, None).unwrap();
        assert!(out.is_empty(), "upper bound is exclusive");
    }

    /// State events with the same `(type, state_key)` slot but
    /// arriving at different positions both contribute initially, but
    /// only the latest position survives the dedupe.
    #[test]
    fn state_delta_latest_wins_when_multiple_writes_same_slot() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!races:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let alice_nid = db.get_or_create_nid("@alice:example.com").unwrap();

        let _ = persist_state(
            db,
            6001,
            "$pl1",
            room_nid,
            room_id,
            "m.room.power_levels",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"users_default": 0}),
            1,
            1,
            &[],
        );
        let _ = persist_state(
            db,
            6002,
            "$pl2",
            room_nid,
            room_id,
            "m.room.power_levels",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"users_default": 5}),
            2,
            2,
            &[],
        );
        let p3 = persist_state(
            db,
            6003,
            "$pl3",
            room_nid,
            room_id,
            "m.room.power_levels",
            alice_nid,
            "@alice:example.com",
            "",
            json!({"users_default": 10}),
            3,
            3,
            &[],
        );
        let out = compute_state_delta(&state, room_nid, room_id, 1, p3 + 1, None, None).unwrap();
        assert_eq!(out.len(), 1);
        let users_default = out[0]
            .pointer("/content/users_default")
            .and_then(|v| v.as_u64())
            .unwrap_or_default();
        assert_eq!(users_default, 10, "latest write wins: {out:#?}");
    }

    /// Spec: `next_batch` MUST be a string token; clients re-feed it
    /// as `since` and expect strict-monotonic ordering. Pin the
    /// `s{pos}` token shape so a downstream refactor can't silently
    /// switch to a different encoding (e.g. opaque base64).
    #[test]
    fn next_batch_uses_stream_position_token_shape() {
        let (state, _tmp) = build_test_state();
        let user = fake_user(&state, "@alice:example.com");
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        let next_batch = resp
            .pointer("/next_batch")
            .and_then(|v| v.as_str())
            .expect("next_batch present");
        assert!(
            next_batch.starts_with('s'),
            "expected s-prefixed pos token: {next_batch}"
        );
        let pos: u64 = next_batch[1..].parse().expect("numeric pos");
        assert!(pos >= 1, "pos >= 1, got {pos}");
    }

    /// /sync top-level response keeps the device_lists, account_data,
    /// presence, to_device, and one-time-keys count sections present
    /// even on a fresh account with nothing in any of them — clients
    /// pin on these keys existing for initial render.
    #[test]
    fn sync_top_level_sections_always_present() {
        let (state, _tmp) = build_test_state();
        let user = fake_user(&state, "@alice:example.com");
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        for key in [
            "/next_batch",
            "/account_data/events",
            "/device_lists/changed",
            "/device_lists/left",
            "/device_one_time_keys_count",
            "/device_unused_fallback_key_types",
            "/presence/events",
            "/to_device/events",
        ] {
            assert!(
                resp.pointer(key).is_some(),
                "expected {key} in /sync response: {resp:#?}"
            );
        }
    }

    /// Sparse-rooms rule: a sync with zero joined / invited / left /
    /// knocked rooms emits an EMPTY `rooms` object, not one with the
    /// section keys all populated as empty objects. Without this the
    /// MSC4155 `JSONKeyMissing` checks regress.
    #[test]
    fn sync_rooms_object_is_empty_when_no_rooms() {
        let (state, _tmp) = build_test_state();
        let user = fake_user(&state, "@bob:example.com");
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        let rooms = resp.pointer("/rooms").and_then(|v| v.as_object()).unwrap();
        assert!(
            rooms.is_empty(),
            "expected empty rooms object, got {rooms:?}"
        );
    }

    /// `m.push_rules` is synthesised on initial sync when the user
    /// hasn't customised — clients depend on it for default
    /// notification settings. Verify the shape so a refactor of the
    /// account_data path doesn't drop it.
    #[test]
    fn initial_sync_synthesises_push_rules_account_data() {
        let (state, _tmp) = build_test_state();
        let user = fake_user(&state, "@alice:example.com");
        let resp = build_sync_response(&state, &user, &[], None).unwrap();
        let events = resp
            .pointer("/account_data/events")
            .and_then(|v| v.as_array())
            .unwrap();
        let push_rules = events
            .iter()
            .find(|e| e.get("type").and_then(|v| v.as_str()) == Some("m.push_rules"))
            .expect("m.push_rules synthesised on initial sync");
        let global = push_rules
            .pointer("/content/global")
            .expect("content.global present");
        assert!(
            global.get("override").is_some(),
            "global.override missing: {push_rules:#?}"
        );
        assert!(global.get("underride").is_some());
    }

    /// Incremental sync DOESN'T re-synthesise `m.push_rules` — the
    /// rules don't change unless the user wrote, in which case the
    /// account_data event already covered it.
    #[test]
    fn incremental_sync_skips_push_rules_synthesis() {
        let (state, _tmp) = build_test_state();
        let user = fake_user(&state, "@alice:example.com");
        // Advance the stream so `since = 1` is a valid past position.
        let _ = state.db.next_stream_position();
        let resp = build_sync_response(&state, &user, &[], Some(1)).unwrap();
        let events = resp
            .pointer("/account_data/events")
            .and_then(|v| v.as_array())
            .unwrap();
        let has_push_rules = events
            .iter()
            .any(|e| e.get("type").and_then(|v| v.as_str()) == Some("m.push_rules"));
        assert!(
            !has_push_rules,
            "m.push_rules should NOT be synthesised on incremental sync"
        );
    }

    /// `typing_change_pos` is a process-local `DashMap`. A typing
    /// transition writes the room's stream position; the sync read
    /// path compares it against the client's `since`. Sanity-check the
    /// map mechanics so a future refactor catches removal.
    #[test]
    fn typing_change_pos_round_trips() {
        let (state, _tmp) = build_test_state();
        let room_nid = 42u64;
        // Empty default.
        assert!(state.typing_change_pos.get(&room_nid).is_none());

        state.typing_change_pos.insert(room_nid, 100);
        assert_eq!(
            state.typing_change_pos.get(&room_nid).map(|v| *v),
            Some(100)
        );

        // Updates overwrite.
        state.typing_change_pos.insert(room_nid, 200);
        assert_eq!(
            state.typing_change_pos.get(&room_nid).map(|v| *v),
            Some(200)
        );
    }

    /// `room_is_unchanged` returns true for a room whose join data has
    /// no timeline / state / ephemeral / account_data events. This is
    /// the predicate that controls sparse rooms emission.
    #[test]
    fn room_is_unchanged_recognises_empty_sections() {
        let empty = json!({
            "timeline": {"events": []},
            "state": {"events": []},
            "ephemeral": {"events": []},
            "account_data": {"events": []},
        });
        assert!(room_is_unchanged(&empty));

        let with_timeline = json!({
            "timeline": {"events": [{"type": "m.room.message"}]},
            "state": {"events": []},
            "ephemeral": {"events": []},
            "account_data": {"events": []},
        });
        assert!(!room_is_unchanged(&with_timeline));

        let with_state = json!({
            "timeline": {"events": []},
            "state": {"events": [{"type": "m.room.name"}]},
            "ephemeral": {"events": []},
            "account_data": {"events": []},
        });
        assert!(!room_is_unchanged(&with_state));

        let with_ephem = json!({
            "timeline": {"events": []},
            "state": {"events": []},
            "ephemeral": {"events": [{"type": "m.typing"}]},
            "account_data": {"events": []},
        });
        assert!(!room_is_unchanged(&with_ephem));

        let with_account = json!({
            "timeline": {"events": []},
            "state": {"events": []},
            "ephemeral": {"events": []},
            "account_data": {"events": [{"type": "m.tag"}]},
        });
        assert!(!room_is_unchanged(&with_account));
    }

    /// Rooms with literally no section keys (missing entirely) must
    /// still be treated as unchanged — defensive read for malformed
    /// values that future refactors might temporarily produce.
    #[test]
    fn room_is_unchanged_treats_missing_keys_as_empty() {
        let empty_object = json!({});
        assert!(room_is_unchanged(&empty_object));
        let only_summary = json!({"summary": {"m.joined_member_count": 1}});
        assert!(room_is_unchanged(&only_summary));
    }

    /// MSC3902 eager-sync gating: a partial-state room MUST NOT
    /// appear in eager (no `lazy_load_members`) /sync until the
    /// filler clears the flag. Once cleared, the room must appear on
    /// the next eager poll whose `since` is strictly less than the
    /// recorded `partial_cleared_at` — the per-room state delta
    /// can't see the filler-merged events (they're persisted as
    /// `StateBundleOnly` without their own stream_pos), so /sync
    /// forces a full-state response on that one poll.
    #[test]
    fn eager_sync_skips_partial_room_then_emits_after_clear() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!part:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let user = fake_user(&state, "@al:example.com");
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();

        // Minimal room: create + alice's join. Skip persist_state
        // snapshotting — eager-sync gating only looks at partial
        // state flags + the room's joined_room_nids set.
        db.create_room_meta(room_nid, room_id, "12").unwrap();
        db.persist_event(
            10,
            "$c",
            room_nid,
            type_create,
            user.user_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.create",
                "sender": "@al:example.com",
                "state_key": "",
                "room_id": room_id,
                "content": {"room_version": "12"},
                "origin_server_ts": 1, "depth": 1,
                "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            11,
            "$j",
            room_nid,
            type_member,
            user.user_nid,
            user.user_nid,
            2,
            2,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.member",
                "sender": "@al:example.com",
                "state_key": "@al:example.com",
                "room_id": room_id,
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2,
                "prev_events": ["$c"], "auth_events": ["$c"],
            }))
            .unwrap(),
            &[10],
            &[10],
            true,
            false,
        )
        .unwrap();
        db.set_membership(room_nid, user.user_nid, 1).unwrap();
        db.set_partial_state_join(room_nid, &["resident.example".into()], 11)
            .unwrap();

        // Eager initial sync: room must be omitted.
        let resp = build_sync_response(&state, &user, &[room_nid], None).unwrap();
        let has_room = resp
            .pointer("/rooms/join")
            .and_then(|v| v.as_object())
            .is_some_and(|o| o.contains_key(room_id));
        assert!(
            !has_room,
            "eager sync must omit partial-state room, got: {}",
            resp.pointer("/rooms/join").unwrap()
        );

        // Clear at pos=99. Subsequent eager incremental with
        // since=50 (< 99) must surface the room.
        db.clear_partial_state(room_nid, 99).unwrap();
        let resp_after = build_sync_response(&state, &user, &[room_nid], Some(50)).unwrap();
        let has_room_after = resp_after
            .pointer("/rooms/join")
            .and_then(|v| v.as_object())
            .is_some_and(|o| o.contains_key(room_id));
        assert!(
            has_room_after,
            "eager sync past clearance must include the room, got: {}",
            resp_after
                .pointer("/rooms/join")
                .unwrap_or(&serde_json::json!(null))
        );
    }

    /// End-to-end: a bound `filter_sync_event` plugin drops a flagged sender's
    /// message from the viewer's `/sync` timeline, while a normal message stays —
    /// proving the read-path hook is wired into the timeline build.
    #[cfg(feature = "extensions")]
    #[test]
    fn sync_filter_hides_flagged_sender_from_timeline() {
        let (state, _tmp) = build_test_state();
        let db = &state.db;
        let room_id = "!filt:example.com";
        let room_nid = db.get_or_create_nid(room_id).unwrap();
        let bob = fake_user(&state, "@bob:example.com");
        let evil_nid = db.get_or_create_nid("@evil:example.com").unwrap();
        let good_nid = db.get_or_create_nid("@good:example.com").unwrap();
        let type_create = db.get_or_create_nid("m.room.create").unwrap();
        let type_member = db.get_or_create_nid("m.room.member").unwrap();
        let skey_empty = db.get_or_create_nid("").unwrap();

        db.create_room_meta(room_nid, room_id, "12").unwrap();
        db.persist_event(
            10,
            "$c",
            room_nid,
            type_create,
            bob.user_nid,
            skey_empty,
            1,
            1,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.create", "sender": "@bob:example.com", "state_key": "",
                "room_id": room_id, "content": {"room_version": "12"},
                "origin_server_ts": 1, "depth": 1, "prev_events": [], "auth_events": [],
            }))
            .unwrap(),
            &[],
            &[],
            true,
            false,
        )
        .unwrap();
        db.persist_event(
            11,
            "$j",
            room_nid,
            type_member,
            bob.user_nid,
            bob.user_nid,
            2,
            2,
            &serde_json::to_vec(&serde_json::json!({
                "type": "m.room.member", "sender": "@bob:example.com",
                "state_key": "@bob:example.com", "room_id": room_id,
                "content": {"membership": "join"},
                "origin_server_ts": 2, "depth": 2, "prev_events": ["$c"], "auth_events": ["$c"],
            }))
            .unwrap(),
            &[10],
            &[10],
            true,
            false,
        )
        .unwrap();
        db.set_membership(room_nid, bob.user_nid, 1).unwrap();

        // Two timeline messages: one from a flagged `@evil` sender, one normal.
        persist_message(
            db,
            20,
            "$evil",
            room_nid,
            room_id,
            evil_nid,
            "@evil:example.com",
            "spam",
            10,
            10,
        );
        persist_message(
            db,
            21,
            "$good",
            room_nid,
            room_id,
            good_nid,
            "@good:example.com",
            "hello",
            11,
            11,
        );

        // A sync-filter plugin that hides events whose sender contains "evil".
        const SYNC: &[u8] =
            include_bytes!("../../../vela-extensions/tests/fixtures/sync_filter_guest.wasm");
        let rt = vela_extensions::Runtime::new(vec![vela_extensions::PluginConfig {
            name: "sync".into(),
            wasm: SYNC.to_vec(),
            fail_policy: vela_extensions::FailPolicy::Closed,
            fuel: 50_000_000,
            wall_ms: 0,
            memory_pages: 256,
            event_types: None,
            points: vela_extensions::Points {
                check_event: false,
                on_event: false,
                check_registration: false,
                check_media_upload: false,
                check_profile_update: false,
                check_room_create: false,
                filter_sync_event: true,
                check_login: false,
            },
            capabilities: Default::default(),
            client_ip: Default::default(),
            config: serde_json::json!({ "mode": "hide_sender" }),
        }])
        .expect("sync-filter plugin loads");
        state.extensions.store(std::sync::Arc::new(rt));

        let resp = build_sync_response(&state, &bob, &[room_nid], None).unwrap();
        let senders: Vec<String> = resp
            .pointer(&format!("/rooms/join/{room_id}/timeline/events"))
            .and_then(|v| v.as_array())
            .map(|evs| {
                evs.iter()
                    .filter_map(|e| e.get("sender").and_then(|s| s.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            senders.iter().any(|s| s == "@good:example.com"),
            "the normal message must be shown; timeline senders: {senders:?}"
        );
        assert!(
            !senders.iter().any(|s| s == "@evil:example.com"),
            "the flagged sender's message must be hidden; timeline senders: {senders:?}"
        );
    }
}
