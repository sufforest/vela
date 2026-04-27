#!/bin/bash
# run.sh — run Complement against the current vela-complement image with
# our skip list applied. The skip list reclaims wall time consumed by
# tests we already know are failing on unimplemented features.
#
# Defaults assume Complement is checked out at $COMPLEMENT_DIR (or
# /Users/$USER/code/workspace/references/complement). Override per env.
#
# Usage:
#   bash tools/testing/complement/run.sh           # full suite, skiplist applied
#   bash tools/testing/complement/run.sh ./tests   # tests/ package only
#
# Output: writes to /tmp/complement-run.log (last full output).

set -eu

COMPLEMENT_DIR="${COMPLEMENT_DIR:-$HOME/code/workspace/references/complement}"
TIMEOUT="${TIMEOUT:-30m}"
LOG="${LOG:-/tmp/complement-run.log}"
SKIPLIST="${SKIPLIST:-$(dirname "$0")/skiplist.txt}"

[ -d "$COMPLEMENT_DIR" ] || { echo "complement dir not found at $COMPLEMENT_DIR" >&2; exit 1; }
[ -f "$SKIPLIST" ] || { echo "skiplist not found at $SKIPLIST" >&2; exit 1; }

# Build the -skip regex by joining non-comment lines with '|'.
# Empty list → don't pass -skip (regex of empty would match everything).
SKIP_REGEX=$(grep -vE '^\s*(#|$)' "$SKIPLIST" | paste -sd '|' -)

PACKAGES=("./tests/csapi" "./tests")
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

cd "$COMPLEMENT_DIR"

set +e
if [ -n "$SKIP_REGEX" ]; then
    COMPLEMENT_BASE_IMAGE=vela-complement:latest \
        go test -v -count=1 -timeout "$TIMEOUT" \
        -skip "$SKIP_REGEX" \
        "${PACKAGES[@]}" \
        > "$LOG" 2>&1
else
    COMPLEMENT_BASE_IMAGE=vela-complement:latest \
        go test -v -count=1 -timeout "$TIMEOUT" \
        "${PACKAGES[@]}" \
        > "$LOG" 2>&1
fi
EXIT=$?
set -e

# Summary
echo
echo "[complement] exit=$EXIT"
PASS=$(grep -c "^--- PASS:" "$LOG" 2>/dev/null || echo 0)
FAIL=$(grep -c "^--- FAIL:" "$LOG" 2>/dev/null || echo 0)
SKIP=$(grep -c "^--- SKIP:" "$LOG" 2>/dev/null || echo 0)
echo "[complement] top-level: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
grep -E "^(FAIL|ok)\s+github" "$LOG" | sed 's/^/[complement] /'

exit $EXIT
