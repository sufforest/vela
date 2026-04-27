#!/bin/bash
# loadtest.sh — drive `wrk` against a running Vela and emit a markdown
# perf summary. See README.md for what it measures and why.
#
# Tunables (env vars):
#   BASE_URL       target server (default: http://127.0.0.1:8008)
#   DURATION       seconds per endpoint (default: 30)
#   CONCURRENCY    open connections (default: 8)
#   THREADS        wrk worker threads (default: 2)

set -eu

BASE_URL=${BASE_URL:-http://127.0.0.1:8008}
DURATION=${DURATION:-30}
CONCURRENCY=${CONCURRENCY:-8}
THREADS=${THREADS:-2}

log() { printf '[loadtest] %s\n' "$*" >&2; }
die() { printf '[loadtest] FATAL: %s\n' "$*" >&2; exit 1; }

# ---- Prerequisites --------------------------------------------------------

command -v wrk >/dev/null || die "wrk not installed (brew install wrk / apt install wrk)"
command -v jq  >/dev/null || die "jq not installed"

if ! curl -sf "$BASE_URL/_matrix/client/versions" >/dev/null; then
    die "Vela not reachable at $BASE_URL"
fi

# ---- Setup phase ----------------------------------------------------------

# Random suffix so reruns don't collide on usernames.
SUFFIX=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8)
USER_LOCAL="loaduser_${SUFFIX}"
PASSWORD="loadtestpw1!"

log "registering @${USER_LOCAL}"
REG=$(curl -sf -X POST "$BASE_URL/_matrix/client/v3/register" \
    -H 'content-type: application/json' \
    -d "$(jq -n --arg u "$USER_LOCAL" --arg p "$PASSWORD" \
        '{username: $u, password: $p, auth: {type: "m.login.dummy"}}')")
TOKEN=$(printf '%s' "$REG" | jq -r '.access_token')
USER_ID=$(printf '%s' "$REG" | jq -r '.user_id')
[ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || die "register failed"
log "  user_id = $USER_ID"

log "creating a room"
ROOM=$(curl -sf -X POST "$BASE_URL/_matrix/client/v3/createRoom" \
    -H "authorization: Bearer $TOKEN" \
    -H 'content-type: application/json' \
    -d '{"preset":"private_chat"}' \
    | jq -r '.room_id')
[ -n "$ROOM" ] && [ "$ROOM" != "null" ] || die "createRoom failed"
log "  room_id = $ROOM"

# ---- Build per-endpoint Lua scripts in a temp dir -------------------------

LUA_DIR=$(mktemp -d -t vela-loadtest-XXXX)
cleanup() { rm -rf "$LUA_DIR"; }
trap cleanup EXIT

# /sync — GET with bearer auth, no body. timeout=0 so wrk doesn't long-poll.
cat > "$LUA_DIR/sync.lua" <<'LUA'
wrk.method = "GET"
wrk.headers["Authorization"] = "Bearer " .. os.getenv("LT_TOKEN")
function request()
    return wrk.format(nil, "/_matrix/client/v3/sync?timeout=0")
end
LUA

# /send — PUT with random txn_id per request. Body is a fixed text msg.
cat > "$LUA_DIR/send.lua" <<'LUA'
wrk.method = "PUT"
wrk.headers["Authorization"] = "Bearer " .. os.getenv("LT_TOKEN")
wrk.headers["Content-Type"] = "application/json"
wrk.body = '{"msgtype":"m.text","body":"loadtest message"}'

local room = os.getenv("LT_ROOM")
local counter = 0
-- Seed with time + PID so concurrent wrk threads (each in its own
-- coroutine but sharing this table) don't draw the same numbers. PID
-- is the same across threads but math.random sequences diverge by
-- counter; the time component reseeds across runs.
math.randomseed(os.time())
function request()
    counter = counter + 1
    local txn = string.format("lt-%d-%d-%d", os.time(), counter, math.random(1, 1e9))
    local path = "/_matrix/client/v3/rooms/" .. room
        .. "/send/m.room.message/" .. txn
    return wrk.format(nil, path)
end
LUA

# /profile/.../displayname — public read, no auth required.
cat > "$LUA_DIR/profile.lua" <<'LUA'
wrk.method = "GET"
local user = os.getenv("LT_USER_ID")
function request()
    return wrk.format(nil, "/_matrix/client/v3/profile/" .. user .. "/displayname")
end
LUA

# ---- Run wrk and parse output ---------------------------------------------

# wrk emits `Requests/sec`, `Transfer/sec`, `Latency Distribution` etc.
# Parse:
#   - throughput from 'Requests/sec:'
#   - p50 / p99 from `--latency` distribution
#   - errors from `Non-2xx or 3xx responses` (if any)
run_endpoint() {
    local label="$1" lua="$2"
    log "running: $label  (${CONCURRENCY}c × ${DURATION}s)"

    local out
    out=$(LT_TOKEN="$TOKEN" LT_ROOM="$ROOM" LT_USER_ID="$USER_ID" \
        wrk -t"$THREADS" -c"$CONCURRENCY" -d"${DURATION}s" --latency \
            -s "$lua" "$BASE_URL" 2>&1)

    local rps p50 p99 errors
    rps=$(printf '%s' "$out" | awk '/Requests\/sec:/ {print $2}')
    # Latency Distribution lines are: "    50%   1.23ms"
    p50=$(printf '%s' "$out" | awk '/^[[:space:]]+50%/ {print $2}')
    p99=$(printf '%s' "$out" | awk '/^[[:space:]]+99%/ {print $2}')
    errors=$(printf '%s' "$out" | awk '/Non-2xx or 3xx responses:/ {print $5}')
    [ -z "$errors" ] && errors=0

    printf '| %-32s | %12s | %8s | %8s | %6s |\n' \
        "$label" "${rps:-?}" "${p50:-?}" "${p99:-?}" "$errors"
}

# ---- Output table ---------------------------------------------------------

echo
echo "## Vela load test results"
echo
echo "- target: \`$BASE_URL\`"
echo "- duration: ${DURATION}s per endpoint"
echo "- concurrency: $CONCURRENCY connections × $THREADS threads"
echo "- date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo
echo "| Endpoint                         |        req/s |      p50 |      p99 | errs |"
echo "|----------------------------------|-------------:|---------:|---------:|-----:|"
run_endpoint "GET /sync"              "$LUA_DIR/sync.lua"
run_endpoint "PUT /rooms/{r}/send/..." "$LUA_DIR/send.lua"
run_endpoint "GET /profile/{u}/dispname" "$LUA_DIR/profile.lua"
echo
