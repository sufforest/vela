# Changelog

All notable changes to Vela are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely;
versioning follows [Semantic Versioning](https://semver.org/) with
the caveat that 0.x releases may make breaking changes between
minor versions.

## [Unreleased]

### Added

- **Complement in CI.** The Matrix spec-compliance suite now runs on
  every PR via `.github/workflows/complement.yml`. Image build is
  cached through buildkit's GHA backend; the existing
  `tools/testing/complement/{run.sh,skiplist.txt}` runner is reused
  unmodified so local and CI behaviour stay aligned.

### Fixed

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

### Added

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
- **`POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}`** plus
  the v1.13 `/rooms/{roomId}/report` and v1.14
  `/users/{userId}/report` siblings. v1.18 semantics: optional
  `reason`, no `score`. Always returns 200 `{}` (privacy mode —
  doesn't leak whether the target exists or the reporter is in the
  room). Reports persist into a new `event_reports` CF.
- **`!reports [N]` admin bot command** — show the last N abuse
  reports (default 20). Surfaces what users submit through the
  `/report` endpoints.
- **`!reactivate <mxid>` admin bot command.** Undoes `!deactivate`'s
  flag — operator must follow with `!reset-password` since
  `!deactivate` blanks the hash.
- **`!reset-password <mxid> [password]` admin bot command.**
  Atomic: sets a fresh argon2 hash, clears the `deactivated` flag,
  and deletes every existing access token. Without a password
  argument the bot generates a 16-char random one and replies with
  it. With a password argument that one is used.
- `[presence]` config block: `idle_after` / `offline_after` /
  `sweep_interval`. See `tools/deploy/vela.toml.example`.

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
