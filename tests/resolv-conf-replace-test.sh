#!/usr/bin/env bash
# Regression test: the resolv.conf helpers must verify that the replacement
# actually happened. A rename(2) onto a bind-mounted file fails with EBUSY;
# callers must see non-zero so they can warn instead of printing ✓
# (BUGS.md #7).
#
# Runs in a throwaway mount+user namespace (no effect on the host). Exits 77
# (skip) when unshare or mount namespaces are unavailable.
#
# Usage: tests/resolv-conf-replace-test.sh

set -u

if [[ "${CT_TEST_MNTNS:-0}" != "1" ]]; then
    command -v unshare >/dev/null 2>&1 || { echo "SKIP: 'unshare' not available"; exit 77; }
    if ! unshare -rm true 2>/dev/null; then
        echo "SKIP: unprivileged user/mount namespaces unavailable"
        exit 77
    fi
    TEST_SELF=$(readlink -f "$0")
    exec unshare -rm env CT_TEST_MNTNS=1 bash "$TEST_SELF" "$@"
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

# shellcheck disable=SC1090
source <(sed -n \
    -e '/^replace_file_verified()/,/^}/p' \
    -e '/^link_file_verified()/,/^}/p' \
    "$TOR_ROUTE")
for fn in replace_file_verified link_file_verified; do
    declare -F "$fn" >/dev/null || fail "$fn not found in $TOR_ROUTE"
done

TMP=$(mktemp -d)
trap 'umount "$TMP/bound" 2>/dev/null; umount "$TMP/bound_link" 2>/dev/null; rm -rf "$TMP"' EXIT

# ── replace_file_verified: normal file succeeds and verifies content ─────────
printf 'nameserver 9.9.9.9\n' > "$TMP/replaceable"
replace_file_verified "$TMP/replaceable" "nameserver 127.0.0.1" \
    || fail "normal replacement must succeed"
[[ "$(cat "$TMP/replaceable")" == "nameserver 127.0.0.1" ]] || fail "content not replaced"
compgen -G "$TMP/replaceable.tmp" >/dev/null && fail "leftover .tmp file"

# ── replace_file_verified: bind-mounted file fails, content untouched ────────
printf 'nameserver 9.9.9.9\n' > "$TMP/bound_src"
printf 'nameserver 1.1.1.1\n' > "$TMP/bound"
mount --bind "$TMP/bound_src" "$TMP/bound" || fail "could not set up bind mount"
if replace_file_verified "$TMP/bound" "nameserver 127.0.0.1"; then
    fail "replacement over a bind mount must fail"
fi
[[ "$(cat "$TMP/bound")" == "nameserver 9.9.9.9" ]] || fail "bind-mounted file was modified"
compgen -G "$TMP/bound.tmp" >/dev/null && fail "leftover .tmp file after failure"

# ── link_file_verified: normal symlink succeeds ──────────────────────────────
printf 'nameserver 9.9.9.9\n' > "$TMP/link_target"
link_file_verified "$TMP/mylink" "$TMP/link_target" || fail "normal symlink must succeed"
[[ "$(readlink "$TMP/mylink")" == "$TMP/link_target" ]] || fail "symlink target wrong"

# ── link_file_verified: bind-mounted target path fails ───────────────────────
printf 'nameserver 9.9.9.9\n' > "$TMP/bound_link_src"
printf 'nameserver 1.1.1.1\n' > "$TMP/bound_link"
mount --bind "$TMP/bound_link_src" "$TMP/bound_link" || fail "could not set up bind mount"
if link_file_verified "$TMP/bound_link" "$TMP/link_target"; then
    fail "symlink over a bind mount must fail"
fi

echo "PASS: resolv.conf replacement helpers detect bind-mount failures"
