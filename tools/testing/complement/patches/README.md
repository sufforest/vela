# Complement patches

Patches applied to the checked-out Complement tree by `run.sh` before the
tests are compiled. They carry fixes that are not yet in the pinned upstream
ref (`.github/workflows/complement.yml` → `matrix-org/complement`). Application
is idempotent and order is lexical by filename.

## 0001-msc3902-handler-race.patch

Fixes a data race in Complement's own `msc3902` partial-state-join test
(`tests/msc3902/federation_room_join_partial_state_test.go`), not in any
homeserver. The test's `server.pduHandlers` map is read by the federation
transaction goroutine while the test goroutine adds/removes handlers
concurrently with no synchronisation; `go test -race` flags it
(`test.go:72` read vs `test.go:109` write).

On top of the bare race, `WithWaitForLeave` removes its leave handler off a
`room.CurrentState` observation — which the transaction goroutine sets (via
`AddEvent`) *before* it invokes the handler — so an in-flight handler call can
find an empty handler set and report the leave as an unexpected PDU. This
surfaces as flaky `Received unexpected PDU` failures in the "incorrectly
kicked / absent servers" subtests, ~7–13% per run, whenever a homeserver
delivers the leave to both servers close together in time (vela's parallel
per-destination federation sender does, reliably). It is not a vela bug:
vela delivers each leave exactly once.

The patch:
- guards the handler maps with a mutex (snapshot under lock on dispatch); and
- reworks `WithWaitForLeave` to drain the buffered leave channel first,
  falling back to `room.CurrentState` only after a quiet period, so the
  handler is only removed once its callback has run (or no delivery is in
  flight).

Verified locally: `-race` clean, and 0 failures over 80 runs of the
previously-flaky subtest (was ~7%).

**Remove this patch** once the equivalent fix lands upstream and the pinned
ref in `.github/workflows/complement.yml` is bumped past it.
