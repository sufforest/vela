#!/bin/bash
# run.sh — run Complement against the current vela-complement image with
# our skip list applied. The skip list reclaims wall time consumed by
# tests we already know are failing on unimplemented features.
#
# Defaults assume Complement is checked out at $COMPLEMENT_DIR (or
# /Users/$USER/code/workspace/references/complement). Override per env.
#
# Retry policy (opt-in): set RETRY_FLAKES=1 to re-run any top-level
# failure in isolation. Off by default — the per-room lock, pushrule
# lock, local-authoriser poll, state-res tiebreak, and invite-rescind
# fix took multi-server federation races down to zero on local grinds.
# If CI starts flaking again that's a signal to refactor, not to mask.
#
# Usage:
#   bash tools/testing/complement/run.sh           # full suite, skiplist applied
#   bash tools/testing/complement/run.sh ./tests   # tests/ package only
#
# Output: writes to /tmp/complement-run.log (last full output).

set -u

COMPLEMENT_DIR="${COMPLEMENT_DIR:-$HOME/code/workspace/references/complement}"
TIMEOUT="${TIMEOUT:-30m}"
LOG="${LOG:-/tmp/complement-run.log}"
RETRY_LOG="${RETRY_LOG:-/tmp/complement-retry.log}"
SKIPLIST="${SKIPLIST:-$(dirname "$0")/skiplist.txt}"
RETRY_FLAKES="${RETRY_FLAKES:-0}"

[ -d "$COMPLEMENT_DIR" ] || { echo "complement dir not found at $COMPLEMENT_DIR" >&2; exit 1; }
[ -f "$SKIPLIST" ] || { echo "skiplist not found at $SKIPLIST" >&2; exit 1; }

# Build the -skip regex by joining non-comment lines with '|'.
# Empty list → don't pass -skip (regex of empty would match everything).
SKIP_REGEX=$(grep -vE '^\s*(#|$)' "$SKIPLIST" | paste -sd '|' -)

PACKAGES=("./tests/csapi" "./tests" "./tests/msc4306" "./tests/msc4222" "./tests/msc3967")
if [ $# -gt 0 ]; then
    PACKAGES=("$@")
fi

echo "[complement] image:    vela-complement:latest"
echo "[complement] timeout:  $TIMEOUT (per package)"
echo "[complement] packages: ${PACKAGES[*]}"
if [ -n "$SKIP_REGEX" ]; then
    echo "[complement] skipping: $(grep -cvE '^\s*(#|$)' "$SKIPLIST") tests"
fi
echo "[complement] log:      $LOG"
if [ "$RETRY_FLAKES" = "1" ]; then
    echo "[complement] retry:    isolated rerun for failing tests"
fi

cd "$COMPLEMENT_DIR"

run_suite() {
    local out_log="$1"
    if [ -n "$SKIP_REGEX" ]; then
        COMPLEMENT_BASE_IMAGE=vela-complement:latest \
            go test -v -count=1 -timeout "$TIMEOUT" \
            -skip "$SKIP_REGEX" \
            "${PACKAGES[@]}" \
            > "$out_log" 2>&1
    else
        COMPLEMENT_BASE_IMAGE=vela-complement:latest \
            go test -v -count=1 -timeout "$TIMEOUT" \
            "${PACKAGES[@]}" \
            > "$out_log" 2>&1
    fi
    return $?
}

# First pass: full parallel run.
run_suite "$LOG"
EXIT=$?

# Collect top-level failing tests from the first pass. Only top-level
# tests are eligible for retry — subtests are re-exercised when their
# parent is re-run, so we don't need to enumerate every failing
# subtest path separately.
FAILED_TOP_LEVEL=$(grep -E "^--- FAIL: [^/[:space:]]+( |$)" "$LOG" 2>/dev/null \
    | awk '{print $3}' \
    | sort -u || true)

RECOVERED_TESTS=()
STILL_FAILING_TESTS=()

if [ "$RETRY_FLAKES" = "1" ] && [ -n "$FAILED_TOP_LEVEL" ]; then
    echo
    echo "[complement] retrying $(echo "$FAILED_TOP_LEVEL" | wc -l | tr -d ' ') failing top-level test(s) in isolation"
    : > "$RETRY_LOG"
    for test_name in $FAILED_TOP_LEVEL; do
        # Anchor the regex so we don't accidentally re-run a sibling
        # whose name shares this prefix.
        RUN_REGEX="^${test_name}$"
        COMPLEMENT_BASE_IMAGE=vela-complement:latest \
            go test -v -count=1 -timeout "$TIMEOUT" \
            -run "$RUN_REGEX" \
            "${PACKAGES[@]}" \
            >> "$RETRY_LOG" 2>&1
        rc=$?
        if [ $rc -eq 0 ]; then
            echo "[complement] retry PASS: $test_name"
            RECOVERED_TESTS+=("$test_name")
        else
            echo "[complement] retry FAIL: $test_name"
            STILL_FAILING_TESTS+=("$test_name")
        fi
    done
fi

# Summary
echo
echo "[complement] exit=$EXIT"
PASS=$(grep -c "^--- PASS:" "$LOG" 2>/dev/null || echo 0)
FAIL=$(grep -c "^--- FAIL:" "$LOG" 2>/dev/null || echo 0)
SKIP=$(grep -c "^--- SKIP:" "$LOG" 2>/dev/null || echo 0)
echo "[complement] top-level: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
grep -E "^(FAIL|ok)\s+github" "$LOG" | sed 's/^/[complement] /'

if [ ${#RECOVERED_TESTS[@]} -gt 0 ]; then
    echo "[complement] recovered on retry (flake): ${RECOVERED_TESTS[*]}"
fi
if [ ${#STILL_FAILING_TESTS[@]} -gt 0 ]; then
    echo "[complement] real failures (failed twice): ${STILL_FAILING_TESTS[*]}"
fi

# Final exit: 0 only if all initial failures were recovered on retry.
if [ "$RETRY_FLAKES" = "1" ] \
    && [ $EXIT -ne 0 ] \
    && [ ${#STILL_FAILING_TESTS[@]} -eq 0 ] \
    && [ -n "$FAILED_TOP_LEVEL" ]; then
    EXIT=0
fi

exit $EXIT
