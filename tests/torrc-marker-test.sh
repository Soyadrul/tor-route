#!/usr/bin/env bash
# Regression test: strip_torrc_block must never delete past the tor-route
# marked block. Any malformed marker structure - a start marker without its
# end marker (partial write/crash), an end marker above its start marker, or
# nested markers - must back up torrc and abort instead of letting sed's
# range run to EOF or swallow user-owned lines (BUGS.md #4).
#
# Pure file test with a temp TORRC; no root needed.
#
# Usage: tests/torrc-marker-test.sh

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

# shellcheck disable=SC1090
source <(sed -n '/^strip_torrc_block()/,/^}/p' "$TOR_ROUTE")
declare -F strip_torrc_block >/dev/null || fail "strip_torrc_block not found in $TOR_ROUTE"

RED=''; YELLOW=''; RESET=''

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
TORRC="$TMP/torrc"

# Backups from earlier cases would make later glob assertions ambiguous.
clear_backups() { rm -f "$TORRC".tor-route-unterminated.* 2>/dev/null || true; }

# ── Case 1: well-formed block -> block removed, outside lines kept ───────────
cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
# --- tor-route.sh end ---
user-after
EOF
strip_torrc_block
grep -q '^user-before$' "$TORRC" || fail "line before the block was lost"
grep -q '^user-after$' "$TORRC" || fail "line after the block was lost"
grep -q '^# --- tor-route.sh start ---$' "$TORRC" && fail "marked block was not removed"

# ── Case 2: start marker without end marker -> abort, keep torrc, make backup ─
cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
user-owned-below
EOF
cp "$TORRC" "$TMP/original"
if ( strip_torrc_block ) 2>/dev/null; then
    fail "unterminated block must exit non-zero"
fi
cmp -s "$TORRC" "$TMP/original" || fail "torrc was modified despite the unterminated block"
grep -q '^user-owned-below$' "$TORRC" || fail "user-owned line below the marker was deleted"
compgen -G "$TORRC.tor-route-unterminated.*" >/dev/null || fail "no backup file was written"
cmp -s "$(compgen -G "$TORRC.tor-route-unterminated.*" | head -1)" "$TMP/original" \
    || fail "backup does not match the original torrc"

# ── Case 3: end marker ABOVE the start marker -> abort, keep every line ──────
# Counts are equal (1/1), so a count-only guard passes and the sed range runs
# from the start marker to EOF, deleting user-owned lines below it.
clear_backups
cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh end ---
user-middle
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
user-owned-below
EOF
cp "$TORRC" "$TMP/out-of-order"
if ( strip_torrc_block ) 2>/dev/null; then
    fail "an end marker above the start marker must exit non-zero"
fi
cmp -s "$TORRC" "$TMP/out-of-order" || fail "torrc was modified despite out-of-order markers"
grep -q '^user-owned-below$' "$TORRC" || fail "user-owned line below the mismatched start marker was deleted"
compgen -G "$TORRC.tor-route-unterminated.*" >/dev/null || fail "no backup file was written for out-of-order markers"
cmp -s "$(compgen -G "$TORRC.tor-route-unterminated.*" | head -1)" "$TMP/out-of-order" \
    || fail "backup does not match the original torrc"

# ── Case 4: nested start/end markers -> abort, keep every line ───────────────
# Counts are equal (2/2); sed deletes from the first start to the first end,
# swallowing the user-owned line in between.
clear_backups
cat > "$TORRC" <<'EOF'
# --- tor-route.sh start ---
# --- tor-route.sh start ---
user-owned
# --- tor-route.sh end ---
# --- tor-route.sh end ---
EOF
cp "$TORRC" "$TMP/nested"
if ( strip_torrc_block ) 2>/dev/null; then
    fail "nested markers must exit non-zero"
fi
cmp -s "$TORRC" "$TMP/nested" || fail "torrc was modified despite nested markers"
grep -q '^user-owned$' "$TORRC" || fail "user-owned line between nested markers was deleted"
compgen -G "$TORRC.tor-route-unterminated.*" >/dev/null || fail "no backup file was written for nested markers"
cmp -s "$(compgen -G "$TORRC.tor-route-unterminated.*" | head -1)" "$TMP/nested" \
    || fail "backup does not match the original torrc"

# ── Case 5: no markers -> untouched no-op ────────────────────────────────────
printf 'SocksPort 9050\n' > "$TORRC"
cp "$TORRC" "$TMP/no-markers"
strip_torrc_block
cmp -s "$TORRC" "$TMP/no-markers" || fail "torrc without markers was modified"

# ── Case 6: backup cannot be written -> still abort, never claim a backup ────
clear_backups
cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh start ---
user-owned-below
EOF
cp "$TORRC" "$TMP/cp-fails"
out=$( ( cp() { printf 'partial' > "$2"; return 1; }; strip_torrc_block ) 2>&1 ) && fail "backup failure must still exit non-zero"
cmp -s "$TORRC" "$TMP/cp-fails" || fail "torrc was modified while the backup was failing"
compgen -G "$TORRC.tor-route-unterminated.*" >/dev/null && fail "partial backup file was left behind after cp failed"
case "$out" in
    *"Backup written"*) fail "claimed a backup was written when cp failed" ;;
esac
case "$out" in
    *"Could not write a backup"*) : ;;
    *) fail "no clear message when the backup cannot be written" ;;
esac

# ── Case 7: marker LOOKALIKE is not part of the block ────────────────────────
# The guard matches marker lines literally, so the delete must too: with an
# unescaped sed BRE a one-character lookalike (tor-routeXsh) opens the range
# and the lines between it and the real end marker are deleted.
clear_backups
cat > "$TORRC" <<'EOF'
top
# --- tor-routeXsh start ---
user-owned-between
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
# --- tor-route.sh end ---
bottom
EOF
strip_torrc_block
grep -q '^top$' "$TORRC" || fail "line before the lookalike was lost"
grep -q '^user-owned-between$' "$TORRC" || fail "line between the lookalike and the real block was lost"
grep -q '^bottom$' "$TORRC" || fail "line after the block was lost"
grep -q 'tor-routeXsh start' "$TORRC" || fail "lookalike marker line was deleted"
grep -q '^TransPort 127.0.0.1:9040$' "$TORRC" && fail "real marked block was not removed"

echo "PASS: strip_torrc_block refuses to edit torrc with malformed markers"
