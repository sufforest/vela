# Vela load test

Drives `wrk` against a running Vela and reports per-endpoint throughput
+ p50 / p99 latency. The goal is to give an honest single-binary
ceiling number on your hardware, and to expose where time goes when
combined with the OTel tracing spans (`--features otel`) and the
Prometheus `/_vela/metrics` snapshot.

## What we measure

Three endpoints, picked because they exercise distinct hot paths:

| Endpoint | Why |
|---|---|
| `GET /_matrix/client/v3/sync` (auth) | Steady-state read-heavy. Most user-visible. Touches user-rooms scan, timeline reads, ephemeral assembly. |
| `PUT .../rooms/{r}/send/m.room.message/{txn}` | Write-heavy. Persists event, computes hash/sig, updates extremities, fans out federation. Per-request unique txn keeps the dedup path honest. |
| `GET /_matrix/client/v3/profile/{user}/displayname` | Cheap public read. Calibrates the HTTP/middleware overhead floor — anything slower than this on auth'd reads is from auth or DB. |

Federation endpoints are intentionally skipped — they need X-Matrix
signing, which wrk can't do without C-extension Lua, and a realistic
federation stress requires a peer to drive load against. Use Complement
or a second vela instance for that.

## Run

Prerequisites:

- Vela running at `$BASE_URL` (default `http://127.0.0.1:8008`). The
  `tools/testing/smoketest` compose works.
- `wrk` installed: `brew install wrk` (mac) or
  `apt install wrk` (debian).
- `jq` for JSON setup.

```sh
# Default 30s @ 8 concurrent against localhost smoketest
bash tools/testing/loadtest/loadtest.sh

# Heavier:
DURATION=60 CONCURRENCY=64 bash tools/testing/loadtest/loadtest.sh

# Custom target (e.g. fedtest vela-a):
BASE_URL=http://127.0.0.1:8108 bash tools/testing/loadtest/loadtest.sh
```

Output is a markdown table on stdout, suitable for pasting into
notes. Numbers are NOT committed to the repo — your machine's hardware
is not everyone's, and tracking results in git invites cargo-culting
of single-machine numbers as if they were universal SLOs. The tool is
for you to measure your own deployment.

## Reading the output

- **req/s** — sustained throughput at the given concurrency. Higher is
  better. Compare across runs on the same machine, not across machines.
- **p50** — median request latency. The "feels fast" number.
- **p99** — tail latency. The "users complain" number. If p99 is
  >> 10× p50 something is queuing up; check `/_vela/metrics`
  `_request_duration_*` histograms to see which route.
- **errors** — non-2xx responses. Anything > 0 here invalidates the
  rest of the row; investigate before trusting the throughput number.

## Cross-referencing with observability

While the load test is running:

- `curl $BASE_URL/_vela/metrics | grep request` — per-route latency
  histograms from the running process. The load test gives you
  request-side numbers; metrics give you server-side. Discrepancy = HTTP
  layer / network overhead.
- If `--features otel` is enabled and an OTLP collector is wired up,
  the trace span `federation.signed_request` (and `receive_transaction`)
  fire on every cross-server request. Useful when load-testing two
  vela instances.

## What this tool deliberately doesn't do

- **Scenarios beyond a single endpoint.** wrk is single-endpoint by
  design. For multi-step user flows (register → join → send → sync),
  reach for k6 / Locust. We didn't, because per-endpoint numbers are
  more diagnostic for the "where's the bottleneck" question.
- **Track results over time in the repo.** That belongs in your own
  notes / dashboard. Single-machine numbers in git invite
  cargo-culting them as universal SLOs; they aren't.
- **Federation load.** See above; needs proper signing.
- **Long-poll sync.** wrk would just hold connections open. The
  measured `/sync` requests use `timeout=0` so they return
  immediately with whatever's available.
