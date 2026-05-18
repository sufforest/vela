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
];
