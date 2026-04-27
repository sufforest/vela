#!/bin/bash
# smoke_edus.sh — two-server EDU federation smoke test.
#
# Drives the fedtest compose (`tools/testing/fedtest/docker-compose.yml`):
# Alice on vela-a, Bob on vela-b, peered over plain HTTP. Verifies
# m.typing, m.receipt, and m.presence ride the wire correctly.
#
# Run:
#   docker compose -f tools/testing/fedtest/docker-compose.yml up -d --build
#   bash tools/testing/fedtest/smoke_edus.sh
#
# Exit code 0 = all three EDUs federated; non-zero = first failure.

set -eu

A=${A:-http://127.0.0.1:8108}
B=${B:-http://127.0.0.1:8118}
A_NAME=${A_NAME:-vela-a:8008}
B_NAME=${B_NAME:-vela-b:8008}

# How long to wait for federation to deliver one EDU. Generous enough
# for cold compose start, tight enough that real bugs fail fast.
WAIT=${WAIT:-3}

PASS=$'\033[32m✓\033[0m'
FAIL=$'\033[31m✗\033[0m'

log()  { printf '[smoke] %s\n' "$*" >&2; }
pass() { printf '%s %s\n' "$PASS" "$*"; }
fail() { printf '%s %s\n' "$FAIL" "$*" >&2; exit 1; }

# --- helpers ----------------------------------------------------------------

wait_ready() {
    local base="$1" name="$2"
    log "waiting for $name at $base"
    for _ in $(seq 1 30); do
        if curl -sf "$base/_matrix/client/versions" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "$name not ready after 30s"
}

register() {
    local base="$1" user="$2"
    local body
    body=$(jq -n --arg u "$user" --arg p "smokepass1!" \
        '{username: $u, password: $p, auth: {type: "m.login.dummy"}}')
    curl -sf -X POST "$base/_matrix/client/v3/register" \
        -H 'content-type: application/json' \
        -d "$body" \
        | jq -r '.access_token'
}

create_room() {
    local base="$1" token="$2"
    curl -sf -X POST "$base/_matrix/client/v3/createRoom" \
        -H "authorization: Bearer $token" \
        -H 'content-type: application/json' \
        -d '{"preset":"public_chat"}' \
        | jq -r '.room_id'
}

invite() {
    local base="$1" token="$2" room="$3" user="$4"
    curl -sf -X POST "$base/_matrix/client/v3/rooms/$room/invite" \
        -H "authorization: Bearer $token" \
        -H 'content-type: application/json' \
        -d "$(jq -n --arg u "$user" '{user_id: $u}')" \
        > /dev/null
}

join_room() {
    local base="$1" token="$2" room="$3"
    curl -sf -X POST "$base/_matrix/client/v3/rooms/$room/join" \
        -H "authorization: Bearer $token" \
        -H 'content-type: application/json' \
        -d '{}' \
        > /dev/null
}

set_typing() {
    local base="$1" token="$2" room="$3" user="$4" typing="$5"
    curl -sf -X PUT \
        "$base/_matrix/client/v3/rooms/$room/typing/$user" \
        -H "authorization: Bearer $token" \
        -H 'content-type: application/json' \
        -d "$(jq -n --argjson t "$typing" '{typing: $t, timeout: 30000}')" \
        > /dev/null
}

send_message() {
    local base="$1" token="$2" room="$3" body="$4"
    local txn
    txn="smoketxn-$(date +%s%N)"
    curl -sf -X PUT \
        "$base/_matrix/client/v3/rooms/$room/send/m.room.message/$txn" \
        -H "authorization: Bearer $token" \
        -H 'content-type: application/json' \
        -d "$(jq -n --arg b "$body" '{msgtype: "m.text", body: $b}')" \
        | jq -r '.event_id'
}

post_receipt() {
    local base="$1" token="$2" room="$3" event_id="$4"
    curl -sf -X POST \
        "$base/_matrix/client/v3/rooms/$room/receipt/m.read/$event_id" \
        -H "authorization: Bearer $token" \
        -H 'content-type: application/json' \
        -d '{}' \
        > /dev/null
}

set_presence() {
    local base="$1" token="$2" user="$3" presence="$4" msg="$5"
    curl -sf -X PUT \
        "$base/_matrix/client/v3/presence/$user/status" \
        -H "authorization: Bearer $token" \
        -H 'content-type: application/json' \
        -d "$(jq -n --arg p "$presence" --arg m "$msg" \
            '{presence: $p, status_msg: $m}')" \
        > /dev/null
}

get_presence() {
    local base="$1" token="$2" user="$3"
    curl -sf -X GET \
        "$base/_matrix/client/v3/presence/$user/status" \
        -H "authorization: Bearer $token"
}

# /sync with a generous wait. Returns the JSON.
do_sync() {
    local base="$1" token="$2"
    curl -sf -X GET \
        "$base/_matrix/client/v3/sync?timeout=2000" \
        -H "authorization: Bearer $token"
}

# --- run --------------------------------------------------------------------

wait_ready "$A" "vela-a"
wait_ready "$B" "vela-b"

log "registering @alice on vela-a"
TOK_A=$(register "$A" "alice")
[ -n "$TOK_A" ] && [ "$TOK_A" != "null" ] || fail "register alice failed"

log "registering @bob on vela-b"
TOK_B=$(register "$B" "bob")
[ -n "$TOK_B" ] && [ "$TOK_B" != "null" ] || fail "register bob failed"

log "alice creates a room"
ROOM=$(create_room "$A" "$TOK_A")
[ -n "$ROOM" ] && [ "$ROOM" != "null" ] || fail "createRoom failed"
log "  room = $ROOM"

log "alice invites @bob:$B_NAME"
invite "$A" "$TOK_A" "$ROOM" "@bob:$B_NAME"

log "bob accepts via vela-b (federated join)"
join_room "$B" "$TOK_B" "$ROOM"

log "letting state settle"
sleep "$WAIT"

# === Test 1: m.typing federates A → B ====================================
log "test: m.typing"
set_typing "$A" "$TOK_A" "$ROOM" "@alice:$A_NAME" true
sleep "$WAIT"

SYNC=$(do_sync "$B" "$TOK_B")
typers=$(printf '%s' "$SYNC" \
    | jq -r --arg r "$ROOM" \
        '[.rooms.join[$r].ephemeral.events[]?
          | select(.type=="m.typing")
          | .content.user_ids[]?] | join(",")')

if printf '%s' "$typers" | grep -q "@alice:$A_NAME"; then
    pass "m.typing federated (Bob's /sync sees Alice typing)"
else
    fail "m.typing not received: typers=[$typers]"
fi

# Stop typing — verify the off-state federates too.
set_typing "$A" "$TOK_A" "$ROOM" "@alice:$A_NAME" false
sleep "$WAIT"
SYNC=$(do_sync "$B" "$TOK_B")
typers=$(printf '%s' "$SYNC" \
    | jq -r --arg r "$ROOM" \
        '[.rooms.join[$r].ephemeral.events[]?
          | select(.type=="m.typing")
          | .content.user_ids[]?] | join(",")')
if printf '%s' "$typers" | grep -q "@alice:$A_NAME"; then
    fail "m.typing stop not received: typers still include alice [$typers]"
else
    pass "m.typing stop federated"
fi

# === Test 2: m.receipt federates B → A ===================================
log "test: m.receipt"
EVT=$(send_message "$A" "$TOK_A" "$ROOM" "ping for receipt")
[ -n "$EVT" ] && [ "$EVT" != "null" ] || fail "send_message failed"
log "  event_id = $EVT"
sleep "$WAIT"

post_receipt "$B" "$TOK_B" "$ROOM" "$EVT"
sleep "$WAIT"

SYNC=$(do_sync "$A" "$TOK_A")
# /sync ephemeral m.receipt content shape (c2s) is:
#   { "<event_id>": { "<receipt_type>": { "<user_id>": { "ts": ... } } } }
# So we check that Bob's user_id appears under [event_id][m.read].
got_ts=$(printf '%s' "$SYNC" \
    | jq -r --arg r "$ROOM" --arg ev "$EVT" --arg u "@bob:$B_NAME" \
        '.rooms.join[$r].ephemeral.events[]?
         | select(.type=="m.receipt")
         | .content[$ev]?["m.read"]?[$u]?.ts // empty' | head -n 1)

if [ -n "$got_ts" ]; then
    pass "m.receipt federated (Alice sees Bob's m.read on \$msg, ts=$got_ts)"
else
    fail "m.receipt not received for $EVT from @bob:$B_NAME"
fi

# === Test 3: m.presence federates A → B ==================================
log "test: m.presence"
set_presence "$A" "$TOK_A" "@alice:$A_NAME" "online" "smoke test"
sleep "$WAIT"

STATUS=$(get_presence "$B" "$TOK_B" "@alice:$A_NAME")
presence=$(printf '%s' "$STATUS" | jq -r '.presence')
status_msg=$(printf '%s' "$STATUS" | jq -r '.status_msg // empty')

if [ "$presence" = "online" ] && [ "$status_msg" = "smoke test" ]; then
    pass "m.presence federated (Bob sees Alice online + status_msg)"
else
    fail "m.presence not received: presence=$presence status_msg=$status_msg"
fi

# Flip to unavailable, verify update propagates.
set_presence "$A" "$TOK_A" "@alice:$A_NAME" "unavailable" ""
sleep "$WAIT"
STATUS=$(get_presence "$B" "$TOK_B" "@alice:$A_NAME")
presence=$(printf '%s' "$STATUS" | jq -r '.presence')
if [ "$presence" = "unavailable" ]; then
    pass "m.presence update federated"
else
    fail "m.presence update not received: presence=$presence"
fi

echo
echo "all EDU smoke checks passed"
