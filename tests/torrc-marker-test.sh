#!/usr/bin/env bash
# Regression test: strip_torrc_block must never delete past a missing end
# marker. With only the start marker present (partial write/crash), it must
# back up torrc and abort instead of letting the sed range run to EOF and
# destroy user-owned lines (BUGS.md #4).
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

# ── Case 3: no markers -> untouched no-op ────────────────────────────────────
printf 'SocksPort 9050\n' > "$TORRC"
cp "$TORRC" "$TMP/no-markers"
strip_torrc_block
cmp -s "$TORRC" "$TMP/no-markers" || fail "torrc without markers was modified"

echo "PASS: strip_torrc_block refuses to delete past a missing end marker"
