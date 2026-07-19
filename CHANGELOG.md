# Changelog

All notable changes to Vela are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely;
versioning follows [Semantic Versioning](https://semver.org/) with
the caveat that 0.x releases may make breaking changes between
minor versions.

## [Unreleased]

### Security

- **Password-path hardening.** All argon2 hashing/verification now runs in
  one module, off the async runtime and capped at core-count concurrency
  (bounds worst-case hashing memory under a login flood). Login and UIA
  rejections are uniform in error and timing: unknown users, passwordless
  accounts, and deactivated accounts all burn one argon2 verification
  against a dummy hash, closing a username-enumeration timing oracle.
  Deactivated-account login returns generic `M_FORBIDDEN` (spec-permitted
  when the password was wiped) instead of pre-auth `M_USER_DEACTIVATED`.
  Passwords are capped at 512 bytes. `!reset-password` / `!create-user`
  redact the operator's command message when it carried a plaintext
  password.
- **Resource caps.** Account-data values (including the merged `m.tag`
  blob and, growth-only, the `m.push_rules` ruleset) get a guard-rail
  cap — `[limits] max_account_data_bytes`, default 1 MiB, 0 disables;
  key backups capped at 65536 keys per version (bulk PUTs stop at the
  cap) and 64 live versions per user; user-directory search bounds its
  candidate walk at 10k rows and reports `limited: true` when truncated.

## [0.3.0] — 2026-06-27

A sandboxed WebAssembly extension platform, plus a round of federation,
end-to-end-encryption, and client-compatibility hardening.

### Added

- **Extension platform.** Sandboxed WebAssembly plugins (wasmtime + the
  Component Model) hook the server at well-defined points without forking it.
  Decision points — `check_registration`, `check_login`, `check_media_upload`,
  `check_profile_update`, `check_room_create` — allow / deny / modify a
  request; `on_event` observes events asynchronously; `filter_sync_event`
  shapes what a client sees in `/sync`; inbound federated events can be
  soft-failed by a plugin. Plugins get three capabilities — structured
  logging, an `emit-event` bot channel, and per-plugin key/value state — all
  behind a manifest whose grants are reconciled against the component's actual
  imports before it loads. Per-plugin fuel, memory, and wall-clock limits;
  hot-reload on SIGHUP. Ships an SDK and example plugins.
- **Third-party protocols + matrix-rtc transports.** `GET
  /_matrix/client/v3/thirdparty/protocols` and the MSC4143 `rtc/transports`
  discovery endpoint.

### Security

- **`/keys/query` no longer leaks other users' `user_signing_keys`** — they
  are returned only for a self-query, per spec. (Cross-user leakage corrupted
  the client trust model and showed verified users as untrusted.)
- **`/preview_url` SSRF guard.** The URL-preview fetch refuses targets that
  resolve to private/internal addresses, re-validates each redirect hop, pins
  the connection to the validated address, and caps the response body.
  Operators with internal preview targets opt out via
  `[media] url_preview_allow_private_ips`.
- **Cross-signing signature uploads are scoped to the caller** — a client can
  no longer fold signatures attributed to another user, or into another user's
  device/signing keys (cross-user signing is limited to the master key). The
  cross-signing-key UIA gate keys off key material, not signatures.
- Cap federation response bodies (key server 256 KiB, general 100 MiB).

### Fixed

- **Federation signing keys.** Refetch a remote server's keys when a signature
  references an unknown key id instead of serving a stale cached key; accept
  events signed with a server's rotated-out keys within their validity window.
- **E2EE / devices.** Preserve cross-signing signatures across a key re-upload
  (a verified device no longer reverts to unverified); track device
  `last_seen`; deliver to-device messages delete-on-ack on both `/sync` and
  sliding sync (a dropped sync can't lose a verification request); notify a
  user's other devices and room-mates when a device is deleted.
- **Client compatibility.** Stop a `/sync` busy-loop on lazy-loaded
  incremental syncs; emit the MSC4222 `state_after` under the key matching the
  client's opt-in param (rooms no longer render as "v1"/empty in Element);
  keep room heroes' membership through lazy-load (fixes "Empty room" on fresh
  login); align the `/login` `well_known` base URL with discovery; return
  `M_UNRECOGNIZED` for auth-metadata when delegated auth is off.

## [0.2.0] — 2026-06-13

Spec-maturity milestone: faster joins (MSC3706/MSC3902), delegated auth
(MSC3861), extended profiles (MSC4133), notifications history, dehydrated
devices (MSC3814), and a long tail of CS-API / federation correctness work.

### Added

- **Dehydrated devices (MSC3814).** `PUT`/`GET`/`DELETE
  /_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device` plus
  `POST .../{device_id}/events` let a client park an encrypted, offline
  device on the server and rehydrate it later to decrypt to-device room keys
  that arrived while it was away. The dehydrated device is registered like
  any other device, so `/keys/query`, `/keys/claim`, to-device routing, and
  cross-server `m.device_list_update` all work for it; the events endpoint
  drains its to-device queue with a read-ahead cursor. One per user — a new
  upload replaces and purges the previous one; `device_data` and one-time-key
  counts are bounded, and a dehydrated id may not alias an existing device.

- **Notification history.** `GET /_matrix/client/v3/notifications` returns a
  paginated list of past notifications (with `from` / `limit` / `only=highlight`).
  Rows are persisted whenever a push rule matches for a local recipient — even
  when no push gateway is registered — and the `read` flag is computed at query
  time from the user's `m.read` receipt / `m.fully_read` marker.
- **Extended profile fields (MSC4133).** `GET/PUT/DELETE
  /_matrix/client/v3/profile/{userId}/{keyName}` for arbitrary profile fields
  (timezone, pronouns, …) alongside the standard `displayname`/`avatar_url`;
  the full-profile response folds them in. Owner-only writes, size-bounded.
- **`GET /_matrix/client/v1/auth_metadata` (MSC2965).** Relays the configured
  IdP's OAuth authorization-server metadata, falling back to an issuer-only
  document if the IdP is unreachable; 404 when delegated auth is off.

- **Faster remote joins (MSC3706 + MSC3902 partial state).** Joining a
  large federated room no longer blocks on downloading its full member
  list. vela requests a join with `omit_members=true`, becomes joinable
  immediately with a partial-state hint, and a background filler
  reconciles the rest of the room state and device lists out of band.
  `/sync` surfaces `partial_state: true` so clients can soft-fail
  membership-dependent features until the room resolves; endpoints that
  need complete state (`/members`, `/joined_members`, `/state`,
  `/state_ids`, inbound `make/send_join` and `make/send_knock`) block or
  reject while a room is still partial rather than serving incomplete
  answers. The filler mirrors member transitions and the remote
  device-key cache on re-verify, replays buffered `m.device_list_update`
  EDUs once full state lands, and re-evaluates events optimistically
  accepted or soft-failed during the partial window.
- **Delegated authentication via OIDC / OAuth2 (MSC3861, phase 2).** vela
  can defer login to an external identity provider instead of managing
  passwords itself. Set `[auth.oidc].introspection_endpoint` and vela
  validates Bearer tokens by introspecting them against the IdP (RFC 7662,
  `client_secret_basic` / `client_secret_post`), caches results up to two
  minutes bounded by the token's own expiry, and provisions accounts on
  first touch from the `sub` / `username` / `device_id` claims. When
  enabled, the legacy auth surface is refused: `/login` advertises no
  password flow, `/register` rejects non-AS callers, and
  `/account/password` / `/account/deactivate` return `M_UNRECOGNIZED`.
- **Stateful sliding sync (MSC4186).** The `/sync` successor persists
  per-connection state in a new `sliding_sync_conns` column family.
  Reconnects no longer re-deliver state the client already has; the
  server emits room data only for rooms that crossed a list window,
  visibility, or state version since the last poll (DELTA ops), and
  explicit room subscriptions stay live across polls until the client
  drops them (sticky subscriptions).
- **Matrix Application Service support.** Bridges (mautrix-telegram,
  mautrix-discord, mautrix-signal, etc.) and bots can now register
  with vela. An operator pastes the AS's registration YAML into the
  admin room via `!as register <yaml>`; vela validates the
  namespaces, hashes the tokens (cleartext is shown to the operator
  once, never stored), persists to a new `appservices` CF, and
  starts a per-AS outbound delivery worker. Every event matching the
  AS's namespaces is enqueued into the new `appservice_outbox` CF;
  the worker drains it, posts to `PUT /_matrix/app/v1/transactions/
  {txnId}` with `Authorization: Bearer <hs_token>`, falls back to
  the legacy `/transactions/{txnId}` URL on 404/405, and retries
  with exponential backoff (2s → 5min cap, 24h dead threshold).
  Inbound `Bearer <as_token>` + `?user_id=` masquerades the request
  as a user in the AS's namespace — virtual users are provisioned
  on demand. Admin commands: `!as register/list/unregister/enable/
  disable`. Interest filter is wired into both the local send path
  and `federation_receive`, so federated events trigger AS delivery
  too. **Deferred to follow-ups:** `m.login.application_service`
  register/login types, `M_EXCLUSIVE` enforcement on non-AS callers,
  ping protocol, query endpoints, `?ts=` timestamp massaging,
  ephemeral passthrough (m.presence/m.typing/m.receipt under
  `receive_ephemeral`), device management UIA bypass, third-party
  protocols.
- **Delayed events (MSC4140).** Clients can schedule an event to be sent
  after a delay (self-destructing status, scheduled posts). A
  `[server] max_delay_ms` knob caps how far out a delay may be set.
- **Event relationships over federation (MSC2836).**
  `/event_relationships` walks and backfills threaded and related events
  across servers, so clients see complete relation chains for rooms whose
  history spans multiple homeservers.
- **Owned state events (MSC3757).** State events whose `state_key` is a
  user's own MXID can be set by that user regardless of power level,
  enabling per-user state without granting elevated permissions.
- **Server-side invite filtering (MSC4155).** An invitee's
  `org.matrix.msc4155.invite_permission_config` account data drives
  which invites vela accepts on their behalf, so unwanted invites are
  rejected before they ever reach the client.
- **Restricted-room joins over federation.** vela can complete the
  `send_join` happy path for restricted rooms, joining via a third
  server that vouches for the join authorisation.
- **Notary server-key proxy.** `/_matrix/key/v2/query` answers questions
  about *other* servers' keys: vela fetches the target's
  `/key/v2/server`, countersigns it, and returns the result, acting as a
  key-notary for peers.
- **Room summary (MSC3266).** `GET /_matrix/client/v1/rooms/{roomIdOrAlias}/summary`
  (and the `im.nheko.summary` unstable path) lets clients preview a room
  before joining. Resolves aliases, gates visibility via the existing
  peek rules (members/invitees always; otherwise public/knock/
  world-readable/allow-list), returns the caller's `membership`, and
  serves unauthenticated requests for world-readable rooms only. Rooms we
  don't host are summarised over federation (the hierarchy root from a
  `via` / known candidate server), so previewing a remote room works for
  authenticated callers.
- **Intentional mentions (MSC3952).** `m.mentions` is now honoured for
  push: `.m.rule.is_user_mention` notifies a user listed in
  `content.m.mentions.user_ids`, and `.m.rule.is_room_mention` handles
  `@room` — but only when the sender's power level meets the room's
  `notifications.room` threshold, so low-power users can't @room-spam.
  Highlight counts in `/sync` reflect the same rules.
- **Batch device delete.** `POST /_matrix/client/v3/delete_devices`
  with the same UIA discipline as single-device delete; ids the caller
  doesn't own are skipped instead of failing the whole batch.
- **Content reporting.** `POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`
  plus the v1.13 `/rooms/{roomId}/report` and v1.14
  `/users/{userId}/report` siblings. v1.18 semantics: optional
  `reason`, no `score`. Always returns 200 `{}` (privacy mode —
  doesn't leak whether the target exists or the reporter is in the
  room). Reports persist into a new `event_reports` CF.
- **`?server=` on `/publicRooms`.** GET/POST `/_matrix/client/v3/publicRooms`
  now accept the `server` query param. When set to a remote homeserver
  name, vela forwards the request via
  `POST /_matrix/federation/v1/publicRooms` and returns the peer's
  response. Clients can browse other homeservers' directories without
  having to talk to them directly.
- **`/.well-known/matrix/support`.** Serves admin/security contacts and
  a support page from a new `[support]` config section (MSC1929);
  returns 404 when unconfigured.
- **`m.get_login_token` capability** advertised as disabled so clients
  hide the cross-device-login affordance we don't implement.
- **`vela-admin rooms-top` and `diagnose`.** `rooms-top --limit N` lists
  rooms by most-recent activity with a relative-age column (clock-skewed
  future bumps render as `future`); `diagnose` is a one-screen operator
  health probe covering current stream position, rooms still mid
  partial-state resync, destinations with pending outbound queues, and
  24h / 7d room activity. Both read existing schema, no new state.
- **Admin bot commands** `!reports [N]` (show the last N abuse reports,
  default 20), `!reactivate <mxid>` (undo `!deactivate`'s flag), and
  `!reset-password <mxid> [password]` (atomic: fresh argon2 hash, clear
  the deactivated flag, revoke every access token; generates a random
  password when none is given).
- **Complement in CI.** The Matrix spec-compliance suite now runs on
  every PR via `.github/workflows/complement.yml`. Image build is
  cached through buildkit's GHA backend; the existing
  `tools/testing/complement/{run.sh,skiplist.txt}` runner is reused
  unmodified so local and CI behaviour stay aligned.
- `[presence]` config block: `idle_after` / `offline_after` /
  `sweep_interval`. See `tools/deploy/vela.toml.example`.

### Changed

- **Federation throughput.** Inbound `/send` transactions process
  concurrently — one task per room, with each room's PDUs still
  serialised under a per-room lock spanning the full state-at-event,
  auth-chain, and persist sequence. The outbound sender is concurrent per
  `(destination, room)` instead of one serial task per destination, so a
  busy room no longer stalls delivery to others.
- **`/members?at=` historical snapshots.** `GET /rooms/{roomId}/members`
  honors the `at=` sync-token parameter, returning membership as it stood
  at that point. `/sync`'s `prev_batch` now points past the events the
  client just received so `at=` resolves to useful state, deleting a
  canonical alias rewrites `m.room.canonical_alias` to drop the dead
  reference, and `send_join` responses carry the full `auth_chain`.
- **Race-free NID allocation.** Replaced the global event-id counter with
  a HiLo allocator handing out per-namespace counter blocks, eliminating
  a check-then-write race where two concurrent writers for the same fresh
  identifier could each consume a slot and leave one writer's state
  unreachable (seen as spurious 403 "not a member" on federated leaves).
  The `/sync` device-list watermark was aligned to the same boundary to
  stop phantom duplicate `device_lists.changed` entries.
- **Threads and relations** are served from indices maintained on write
  (`relation_counts`, `thread_index`, `thread_participants`) instead of
  prefix scans, so `/threads` and relation-count lookups are point reads.
- **Dependency bumps.** rocksdb to 0.24 and object_store to 0.13; the
  OpenTelemetry stack to 0.32 with tracing-opentelemetry 0.33.
- **`vela-api` reorganised into per-domain folders** (`auth`, `room`,
  `sync`, `federation`, …) instead of one flat module tree.

### Security

- **`/messages` could leak pre-join history.** `GET /rooms/{r}/messages`
  applied only a coarse departed-member cap, with no per-event
  history-visibility check (the gate `/event` and `/context` already use). In
  a room with `history_visibility: joined` or `invited`, a member could page
  backward and read events from before they joined/were invited. Both the
  timeline and DAG-backfill paths now gate each event by the user's
  membership at that event; `shared` / `world_readable` are unaffected.

### Fixed

- **`/sync` now honours the state, ephemeral, presence, and account_data
  sub-filters.** Only the timeline filter was applied before (and the state
  filter only on left rooms); the rest were accepted but silently ignored.
  Their `types` / `not_types` / `senders` / `limit` constraints now apply to
  each section, including the room state filter on joined rooms.
- **Device deletion is now federated.** Removing a device (logout,
  `/devices/{id}` delete, or a dehydrated-device replace) didn't tell remote
  servers, so they kept the dead device in their `/keys/query` view. It now
  emits an `m.device_list_update` with `deleted: true` to servers sharing a
  room with the user, paired with the local key reclaim below.
- **Device deletion now reclaims its keys.** Removing a device (logout,
  `/devices/{id}` delete, or a dehydrated-device replace) only dropped the
  device record, leaving its `device_keys` and `one_time_keys` behind to
  accumulate forever. `delete_device` now cascades to both, scoped to the
  one device (a device id that is a prefix of another is unaffected).
- **Outlier events now promote to live on re-delivery.** An event first
  seen as an outlier — fetched via an `/event` probe for auth/prev context
  and never timelined — was dropped by the already-seen check when it later
  arrived through `/send`, so it stayed invisible to `/sync` and never fired
  its membership/device-list side effects. It's now promoted to a live
  timeline event: the receive path re-auths it and re-persists it as live
  reusing its nid (references stay intact). Backed by a new
  `event_timeline_pos` forward index, which also retires the O(timeline)
  backward scan in `event_stream_pos`.
- **Push-rule keys with escaped dots weren't resolved.** The condition
  key parser split on every `.`, so a key like `content.m\.mentions.room`
  (whose `m.mentions` segment contains a literal dot) never matched.
  It now honours `\.` / `\\` escaping, which the MSC3952 mention rules
  depend on.
- **Federated messages didn't trigger push notifications.** The push
  dispatch path only ran on locally-sent events; when a remote user
  sent a message to a federated room, every local member's mobile
  client stayed silent. Inbound federation now calls the same
  `dispatch_for_event` after persistence, so remote-sender pushes go
  through identical rule evaluation and gateway POST as local ones.
- **`m.room.server_acl` was only enforced on inbound /send.** Banned
  origins could still hit `/make_join`, `/send_join`, `/make_knock`,
  `/send_knock`, and `/v2/invite` — i.e. join, knock, and invite
  themselves into rooms whose ACL was supposed to keep them out.
  All five handlers now run the same ACL check before doing room
  work. Leave handlers are intentionally exempt per spec: a banned
  origin must still be able to leave a room it's already in.
- **Own presence not visible in /sync.** `collect_presence_events`
  filtered the requesting user out of the emitted peer set, so
  clients that draw their own profile indicator from /sync (Element
  X among them) fell back to "offline" for the requester. Now
  always included.
- **Stored presence never decayed.** A user who set themselves
  online and closed their browser stayed "online" in every other
  client indefinitely. Effective presence is now computed at read
  time from `last_active_ms` with `idle_after` → unavailable and
  `offline_after` → offline transitions; a background sweeper
  persists those transitions and broadcasts the federation EDU so
  remote servers see the new state. Thresholds configurable under
  `[presence]` (defaults: 5min / 30min / 60s sweep).
- **Push-notification retries are bounded.** A failing pusher backs off
  with a per-pusher exponential schedule and a hard ceiling instead of
  stalling the push queue behind it.
- **Federation and sync robustness.** A long tail of correctness fixes to
  the inbound federation and `/sync` paths: lazy-fetch of unknown
  prev-events and auth-chain parents during the state-at-event check
  (transient gaps no longer cascading into permanent rejections), correct
  v12 auth context (no synthetic invite-stripped create injected), EDU
  coalescing and `m.room.server_acl` applied to room-scoped EDUs,
  split-tracked stream watermark so `next_batch` and delta scans agree,
  redaction markers for not-yet-seen targets parked and applied on
  arrival, and a localpart fallback for the display-name push rule so
  `.m.rule.contains_display_name` fires for users without a set profile
  name.

## [0.1.1] — 2026-05-17

### Fixed

- **Critical: `recover_max_nid` recovery bug.** The shared `nid_counter`
  was recovered by scanning only `nid_reverse` (string NIDs), missing
  every event NID. After a restart the counter reset below the actual
  max event NID and the next `next_nid()` allocations silently
  overwrote existing event rows in `events`, breaking every reference
  that held the original NID. User-visible symptom: 403 "sender is not
  joined" on `PUT /send` in rooms whose state-event NIDs happened to
  collide. Fix scans both `nid_reverse` and `events`. Includes
  auto-repair on `Database::open` that walks `room_state`, detects
  entries pointing at events whose actual (type, state_key) doesn't
  match, and replaces them with the latest valid event from
  `room_timeline`. (#62)
- **Verification handshake silently failed.** Element X sent
  `PUT /sendToDevice/m.key.verification.request/{txn}` without a
  `Content-Type` header; axum's stock `Json<T>` extractor rejected the
  request before the body was read. Replaced with a Bytes-then-parse
  extractor used site-wide that parses JSON regardless of header.
  Aligns with Synapse, Dendrite, and Continuwuity. (#62)
- **`/sync` polling storm.** `build_room_sync_for_user` emitted
  receipts + room account_data unconditionally, so `has_new_data` was
  always true and the long-poll never slept. Added per-room and
  per-(user, room) max-stream-position tracking in a new
  `stream_positions` CF; the two ephemeral types now emit only when
  their tracked position advanced past `since`. (#59)
- **`m.read.private` receipts visible to other users.**
  `build_receipts_event` returned every receipt to every viewer; the
  m.read.private privacy contract was broken. Now filtered to the
  receipt's owner only. (#59)
- **`/v3/createRoom` emitted duplicate state events** when
  `initial_state` overrode a preset default (e.g.
  `m.room.history_visibility`). Element rendered two state-change
  notices and the preset's event was shadowed by the override anyway.
  Preset emits are now skipped when `initial_state` contains the same
  `(type, state_key)`. (#59)
- **Admin bootstrap missed `server_name` drift.** If the admin room
  had been created under an earlier `server_name`, the
  `room_is_locally_hosted` check rejected re-bootstrap. Added
  `admin_room_create_sender_is_local`; bootstrap recreates the admin
  room when the create sender is no longer local. (#59)
- **Key backup load-mutate-save race** in `/v3/room_keys/keys`
  produced lost writes during parallel session upload. Replaced the
  account_data blob with per-row CF storage in `key_backup`; each
  session is its own row, atomic. Per-user lock guards the count/etag
  stats only. (#60)
- **Key backup blob leaked via `/sync`.** The `m.vela.key_backup`
  account_data event surfaced to the user's other devices on every
  receive. Moving the backup off account_data eliminates the leak.
  Migration drains the legacy blob into the new CF on first read after
  upgrade. (#60)
- **Bootstrap token static fallback bypassed revoke.** The
  `[registration] token` config value used to be a static fallback
  the operator could not revoke. Now single-use, allocated like any
  other registration token. (#56)
- **`well-known` published a localhost URL.** `/.well-known/matrix/*`
  emitted the bind URL (`http://0.0.0.0:8008/`) instead of the public
  `server_name` URL, breaking federation discovery for any deployment
  that wasn't bound directly on its public hostname. (#55)
- **Config parse errors silently swallowed.** `load_config` ignored
  TOML parse failures and booted with defaults, hiding the real
  problem from the operator. Errors now surface and refuse to start.
  (#58)
- **`HEALTHCHECK` hardcoded port 8008**, so containers with a
  non-default `[server] port` reported `(unhealthy)` to the
  orchestrator. Now reads `$VELA_PORT`. (#58)
- **`docker-compose` default built from source** instead of using the
  published image. (#57)
- **`/account/3pid` returned 404** instead of an empty list; Element
  rendered "Unable to load" in Settings. Now returns `{"threepids":
  []}`. (#57)

### Added

- **`vela-admin diagnose-membership <room_id> <user_id>`** — dumps
  the `memberships` and `room_state` CF entries side-by-side for one
  (room, user) pair and flags drift. Useful for confirming whether a
  "sender is not joined" rejection is the recover_max_nid corruption.
  (#62)
- **`vela-admin` bundled in the production Docker image** so the
  operator can run it via `docker compose exec vela vela-admin ...`
  without a separate install or build. (#62)
- **CI gate: real S3 wire test against MinIO** behind the
  `s3-integration` feature flag. Catches multipart-upload, signing,
  and abort-path bugs that the trait-level unit tests can't reach.
  (#61)
- **Operational `[profile.dev]` improvements** — `debug = 1` cuts
  `target/` size during local dev. (#58)

### Changed

- **Improved `m.room.topic` content shape** to include the structured
  MSC3765 representation alongside the legacy `topic` string. (Already
  present at 0.1.0; clarifying for upgraders since downstream clients
  may now consume the structured form.)

## [0.1.0] — 2026-04

Initial release. Targets Matrix Room Version 12 only.

### Added — protocol surface

- Full Matrix Client-Server API (registration with token gate,
  password + refresh-token login, /sync, sliding sync (MSC4186),
  /messages, /send, /createRoom, room presets, invites, kick/ban,
  leave/forget, redactions, profiles, devices, account_data,
  receipts, typing, presence, push rules)
- Federation in/out: PDU receive pipeline (6-check), state
  resolution v2, /get_missing_events fetch on inbound prev gaps,
  /event_auth chain backfill, signed transactions, X-Matrix
  header verification, restricted-room joins with two-server proof
- All five EDU streams (receipts, presence, typing, to-device,
  device list)
- E2EE primitives: device keys, one-time keys, cross-signing,
  signature upload, key backup with spec-compliant replacement
  rules, to-device delivery
- Threads, reactions, polls, edits, replies via `/relations`
  (both v3 and v1 paths)
- Spaces (m.space rooms)
- Knock, knock_restricted, restricted joins
- Push rules + Sygnal-compatible HTTP pushers
- Application Service basics (full polish in 0.2)
- /_matrix/client/v1/media/* legacy aliases for compatibility
- m.topic rich representation in createRoom (MSC3765)
- Lazy-loaded members in /sync state filter

### Added — operations

- `[federation] enabled = true|false` toggle
- `[registration] enabled` + `token`; UIA flow advertises
  `m.login.registration_token` when configured
- `[media] backend = "fs"|"s3"` with full S3-compatible support
  (AWS, MinIO, Cloudflare R2, Backblaze B2) via `object_store`
- `[media] max_upload_size` (default 50 MiB)
- `[backup] enabled`, scheduled in-process; `disk:/path` or
  `s3://bucket/prefix` targets; `keep` retention rotation
- `[retention] media` periodic sweeper with separate
  `local_lifetime` and `remote_lifetime`
- `[room_defaults] encrypt_by_default = "off"|"dm_only"|
  "private_only"|"all"` server-side policy for auto-injecting
  m.room.encryption when `/createRoom` doesn't include one
- `/_health` operational endpoint (status, version, schema_version,
  uptime)
- `vela --validate-config` pre-flight CLI flag
- `tools/testing/smoketest/vela.toml.example` annotated config for new deploys
- `vela-backup` CLI: point-in-time database checkpoint
- `tools/testing/smoketest/` Docker Compose: vela + Element Web at
  http://localhost:8009 for end-to-end testing
- `tools/testing/fedtest/` Docker Compose: two-vela federation smoke test
- `tools/testing/loadtest/` wrk-based perf harness
- `tools/testing/complement/` runner with skiplist for known-broken tests

### Added — durability and recovery

- Stream-position counter recovered from the embedded database's
  sequence number on startup rather than scanning every column
  family. Fixes a class of `/sync` hot-loop bugs after restart.
- Schema-version stamp; vela refuses to start on incompatible
  on-disk data with a clear error.
- SIGTERM-aware graceful shutdown with a 30 s drain window.

### Added — accounts and identity

- Server-side encryption-by-default for new private rooms (config-gated)
- Spec-compliant `/account/deactivate` with hardened cleanup:
  invalidates access + refresh tokens, drops pushers, drops device
  keys (signing + cross-signing + one-time), force-leaves all
  joined / invited / knocking rooms with reason, fans out
  m.device_list_update to peer servers, optional `erase=true`
  profile placeholder
- Alias creator tracking: `PUT /directory/room` records the
  creator; `DELETE` allows only the creator OR a user with PL ≥
  `events.m.room.aliases` (default 50)

### Added — privacy

- Federation toggle for fully-private deployments
- Encryption-by-default policy
- No telemetry, no analytics, no phone-home
- Federation refuses traffic in BOTH directions when disabled
  (route not mounted, outbound short-circuited)

### Known limitations

- No voice / video (MatrixRTC) — planned
- Not all Complement tests pass; structural incompatibilities
  (TestPowerLevels, TestKnockRoomsInPublicRoomsDirectory,
  TestIsDirectFlagFederation) are skiplisted as protocol-version
  mismatches against v12
- No multi-instance support; single-process by design
- Application Service support works for basics; not yet validated
  against third-party bridges
- Federation tested against itself; not yet against other
  implementations on the public internet
