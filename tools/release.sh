#!/usr/bin/env bash
#
# Cut a release. Keeps the Cargo version, CHANGELOG, and the git tag in
# lockstep so they can't drift (the way 0.3.0's number got bumped without a
# matching tag). Run this instead of hand-editing versions.
#
#   tools/release.sh <X.Y.Z>            # bump + draft changelog + sync locks
#   tools/release.sh <X.Y.Z> --dry-run # show what it would do, change nothing
#
# It does NOT commit, push, or tag — it stages the working tree and prints
# the exact commands. Review the generated CHANGELOG section (the auto draft
# is grouped from merged-PR titles; curate it before committing), then open
# the release as a normal PR and tag the merge commit.
set -euo pipefail

NEW="${1:?usage: tools/release.sh <X.Y.Z> [--dry-run]}"
DRY=""
[ "${2:-}" = "--dry-run" ] && DRY=1
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo "error: version must be X.Y.Z (got '$NEW')" >&2
    exit 1
}

cd "$(git rev-parse --show-toplevel)"

CURRENT="$(grep -m1 -E '^version = "' Cargo.toml | sed -E 's/.*"(.*)".*/\1/')"
LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
RANGE="${LAST_TAG:+$LAST_TAG..}HEAD"
TODAY="$(date +%Y-%m-%d)"

echo "current Cargo version : $CURRENT"
echo "new version           : $NEW"
echo "changelog range       : ${LAST_TAG:-<start>}..HEAD"
echo

# --- Draft the CHANGELOG section from merged-PR subjects -----------------
# Squash-merge commits read "type: subject (#NNN)". Group by conventional
# type, strip the prefix. This is a STARTING POINT to curate, not gospel.
LOG="$(git log --no-merges --pretty=format:'%s' "$RANGE")"
section() { # <header> <type-regex>
    local body
    body="$(printf '%s\n' "$LOG" | grep -E "$2" | sed -E 's/^[a-z]+(\([^)]*\))?!?: //; s/^/- /' || true)"
    [ -n "$body" ] && printf '### %s\n\n%s\n\n' "$1" "$body"
}
SECTION="$(
    printf '## [%s] — %s\n\n' "$NEW" "$TODAY"
    section Added '^feat'
    section Fixed '^fix'
    section Changed '^(perf|refactor|build|ci|docs|chore)'
)"

echo "=== generated CHANGELOG section (curate before committing) ==="
printf '%s\n' "$SECTION"
echo "============================================================"

if [ -n "$DRY" ]; then
    echo "[dry-run] would: splice the above under '## [Unreleased]' in CHANGELOG.md,"
    echo "[dry-run]        bump Cargo version $CURRENT -> $NEW, refresh lockfiles."
    exit 0
fi

# --- Splice into CHANGELOG.md under the [Unreleased] header --------------
awk -v sec="$SECTION" '
    { print }
    /^## \[Unreleased\]/ && !done { print ""; print sec; done=1 }
' CHANGELOG.md > CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md

# --- Bump the workspace version (workspace.package + path-dep anchors) ---
if [ "$CURRENT" != "$NEW" ]; then
    sed -E "s/version = \"$CURRENT\"/version = \"$NEW\"/g" Cargo.toml > Cargo.toml.tmp \
        && mv Cargo.toml.tmp Cargo.toml
    # Sync both lockfiles (main + the standalone smoketest-rs tree, which
    # path-depends on the vela crates).
    cargo update --workspace --quiet
    cargo update --workspace --quiet \
        --manifest-path tools/testing/smoketest-rs/Cargo.toml
fi

echo
echo "done. review the diff, then ship as a PR and tag the merge commit:"
echo "  git switch -c wzy/release-$NEW && git commit -am 'chore: release $NEW'"
echo "  # open PR, merge when green, then on main:"
echo "  git tag -a v$NEW -m 'v$NEW' && git push origin v$NEW"
