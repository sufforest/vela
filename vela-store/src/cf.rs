/// All column family names used by Vela.
/// Adding a new CF here automatically creates it on DB open.
pub const COLUMN_FAMILIES: &[&str] = &[
    "meta",
    "nid_map",
    "nid_reverse",
    "events",
    "event_ids",
    "event_id_reverse",
    "event_depth",
    "event_edges",
    "event_auth_edges",
    "event_state",
    "state_snapshots",
    "room_timeline",
    "room_state",
    "room_meta",
    "room_extremities",
    "room_bump",
    "memberships",
    "user_rooms",
    "users",
    "tokens",
    "refresh_tokens",
    "devices",
    "sync_tokens",
    "transactions",
    "account_data",
    "account_data_pos",
    "room_account_data",
    "device_keys",
    "one_time_keys",
    "cross_signing_keys",
    "to_device_messages",
    "key_backup",
    "device_key_changes",
    // Highest m.device_list_update EDU stream_id we've persisted per
    // (user_nid, device_id). Key: `[user_nid_be:8] | device_id_bytes`.
    // Value: u64 BE. Used by `handle_device_list_update` to drop
    // redelivered EDUs (peer restarts and re-sends from an
    // unadvanced cursor) without creating a fresh
    // `device_key_changes` entry — which would leak the same change
    // into a later /sync window for the observer.
    "device_list_edu_seen",
    "media_metadata",
    "receipts",
    // Generic small-value position tracking. Keys are
    // `<purpose-prefix>:<scope-bytes>`, values are u64 BE-encoded
    // stream positions. Lets `/sync` skip emitting per-type snapshots
    // (m.receipt, m.fully_read, room tags) when the client's `since`
    // cursor already covers every update — without this every
    // incremental sync re-emits the full snapshot, bypasses the
    // unchanged-room skip rule, and clients hammer /sync. Single CF
    // so future tracking gaps don't each become a new CF.
    "stream_positions",
    "room_aliases",
    "server_keys",
    "sliding_sync_conns",
    "soft_failed_events",
    // Tracks event_ids of inbound federation events we rejected.
    // Used to cascade rejection: any event whose auth_events
    // reference one of these is itself rejected. Stores the
    // rejection reason as the value (debugging aid).
    "rejected_events",
    "event_redactions",
    "user_membership_pos",
    "event_relations",
    // O(1) count of children per (parent_event_nid, rel_type_nid).
    // Incremented on every record_relation, decremented when a
    // relation event is redacted. Reads from the m.thread / m.replace
    // aggregation path become a single point lookup instead of a
    // prefix scan.
    "relation_counts",
    // Per-room thread roots ordered by latest m.thread activity.
    // Key: (room_nid_be:8, !latest_child_sp:8, root_event_nid:8).
    // Lets /threads return the freshest threads via a single
    // ordered prefix scan instead of walking the room timeline.
    "thread_index",
    // Side lookup `(room_nid, root_nid) -> latest_child_sp` so
    // thread_index inserts can delete the prior key for the same
    // root before writing the new one. Without this, thread_index
    // would accumulate stale (latest_sp, root) tuples.
    "thread_root_latest",
    // Thread participants set: presence of `(root_nid, user_nid)`
    // means `user_nid` has at least one m.thread reply to the
    // root. Lets `current_user_participated` be a single point
    // lookup instead of a relations-prefix scan. Members are not
    // removed on reply redaction (a redacted reply still counts
    // as participation per spec).
    "thread_participants",
    "user_filters",
    "user_pushers",
    "user_presence",
    // Activity index over `user_presence`. Keyed by
    // `(last_active_ms_be:8, user_nid_be:8)`. Lets the presence
    // sweeper walk only the prefix-range of users whose activity is
    // older than the idle threshold instead of scanning every record.
    // Maintained atomically with every `user_presence` write.
    "presence_activity_index",
    "federation_outbox",
    "federation_edu_cursor",
    "receipts_stream",
    "presence_stream",
    "to_device_outbound",
    "to_device_seen_message_ids",
    "device_list_outbound",
    // Per-(destination, position) buffer of m.signing_key_update EDU
    // payloads. Drained by `SigningKeyUpdateStream` and shipped via
    // the federation sender. Same value/key shape as
    // `device_list_outbound`.
    "signing_key_update_outbound",
    // Short-lived OpenID tokens issued via /_matrix/client/v3/user/
    // {userId}/openid/request_token and validated by remote servers
    // hitting /_matrix/federation/v1/openid/userinfo. Value: 8 BE
    // bytes of `expires_at_ms` followed by the user_id string.
    "openid_tokens",
    // Per-event mapping `event_nid -> (sender_nid:8, device_id, 0xff,
    // txn_id)` for local-echo. Read by /sync, /messages, and /event
    // when the requesting user/device matches the sender — those
    // responses get `unsigned.transaction_id` attached so the
    // client can correlate.
    "event_txn_ids",
    "room_directory",
    // `event_nid -> replaced_event_nid`. Written when a state event
    // is promoted into current state; lets `load_client_event` cheap-
    // lookup `unsigned.prev_content` and `unsigned.replaces_state`
    // without walking the timeline backwards.
    "state_replaces",
    // `(observer_nid, stream_pos) -> departed_nid`. Mirror of
    // `device_key_changes` but for the "no longer share any room"
    // direction. Drives `device_lists.left` in /sync — E2EE clients
    // need to invalidate cached device keys for users who left every
    // shared room.
    "device_list_left",
    // MSC4306 thread subscriptions. Tracks whether a user has
    // (manually or automatically) subscribed to receive notifications
    // about a thread. Key layout:
    //   user_nid (8 BE) | room_nid (8 BE) | thread_root_event_id bytes
    // Value: `state` byte (1=manual, 2=automatic, 0=unsubscribed) +
    // 8 BE bytes `last_change_stream_pos`. The pos is used to
    // detect automatic-subscribe attempts whose cause event predates
    // the last unsubscribe (MSC4306 conflict check).
    "thread_subscriptions",
    // Vela admin-bot dynamic registration tokens. Key is the raw token
    // string (operators copy/paste it), value is JSON:
    //   { uses_allowed: u64, uses_used: u64, expires_at_ms: u64,
    //     created_by: u64 (user_nid), created_at_ms: u64 }
    // `uses_allowed = 0` means unlimited; `expires_at_ms = 0` means
    // never expires. The static `[registration] token` from vela.toml
    // is seeded into this CF on first boot when no admin exists, so
    // the same lookup path covers bootstrap and post-bootstrap.
    "registration_tokens",
    // Registered Matrix Application Services. One row per operator-
    // added AS. Key: `[appservice_nid_be:8]`. Value: JSON
    //   { nid, id, config: { url, hs_token_hash, as_token_hash,
    //                        sender_localpart, receive_ephemeral },
    //     namespaces: [{ scope, regex, exclusive }],
    //     enabled, owner_nid, created_at_ms }
    // Tokens are SHA-256 hashed before storage — cleartext shown to
    // the operator only at registration time. A secondary index
    // `as:<id> -> nid` lives in `nid_map` so id-keyed lookups stay
    // O(1) (admin commands, AS-token masquerade auth lookup).
    "appservices",
    // Per-AS outbound transaction queue. One persistent FIFO per
    // registered AS; one tokio task per FIFO drains and POSTs to the
    // AS's URL. Architecture mirrors federation_outbox: persistent
    // CF + per-destination task + exponential backoff + 24h dead
    // threshold + Notify wake on push.
    //
    // Key: `[appservice_nid_be:8][txn_seq_be:8]`. Forward scan within
    // an AS's prefix = chronological delivery order. Value: serialised
    // Transaction (event_nids + room_ids — event JSON loaded from
    // `events` CF on demand at delivery time).
    "appservice_outbox",
    // User-submitted abuse reports against events, rooms, or users.
    // Key: `[ts_ns_be:8][reporter_nid_be:8]` — nanosecond timestamp
    // avoids same-millisecond collisions when one user submits
    // multiple reports in quick succession. Forward scan = oldest
    // first, reverse scan = newest first (what !reports wants).
    // Value: JSON
    //   { kind: "event"|"room"|"user",
    //     room_id?: string, room_nid?: u64,
    //     event_id?: string, event_nid?: u64,
    //     target_user_id?: string, target_user_nid?: u64,
    //     reporter_user_id: string, reporter_nid: u64,
    //     reason: string, ts_ms: u64 }
    // Read by `!reports` admin bot command. We deliberately don't
    // index by room or reporter — the volume is low and a full
    // backward scan from the end is cheap at human-moderator scale.
    "event_reports",
    // Maps external identity-provider subjects (OIDC `sub` claim) to
    // local user nids. One row per `(provider, sub)` pair. Populated
    // on first-touch when an OIDC-authenticated request arrives for
    // a previously-unseen `sub`; subsequent requests with the same
    // token hit a fast `(provider, sub) -> user_nid` lookup that
    // bypasses the introspection round trip's user-provisioning logic.
    //
    // Key: `[provider_len_be:2][provider_bytes][sub_bytes]`. The
    // length prefix lets two providers share the CF without collision
    // (e.g. `("oauth-delegated", "abc")` vs `("saml", "abc")`).
    // Value: little-endian `u64` user_nid.
    //
    // `provider` is operator-controlled and stable per IdP; today the
    // only writer is the MSC3861 introspection flow with the literal
    // `"oauth-delegated"`. A future SAML/LDAP/whatever flow would use
    // its own provider string without touching this schema.
    "external_ids",
];
