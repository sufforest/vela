# Changelog

All notable changes to Vela are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) loosely;
versioning follows [Semantic Versioning](https://semver.org/) with
the caveat that 0.x releases may make breaking changes between
minor versions.

## [Unreleased]

(Add user-visible changes here as they land. At release time,
rename to `[X.Y.Z] — YYYY-MM-DD` and start a fresh `[Unreleased]`
above.)

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
