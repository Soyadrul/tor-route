#!/usr/bin/env bash
# Regression test: restore_tor_service must not consume TOR_STATE_FILE before
# cleanup_torrc can abort. cleanup_torrc exits 1 on a malformed torrc (see
# strip_torrc_block); if the state file were already removed, the user's
# retry after fixing torrc would default to "Tor was not running" and leave
# a Tor that was running before `start` stopped - not "as it was found".
#
# Pure function test with stubs; no root needed.
#
# Usage: tests/restore-tor-service-test.sh

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

# shellcheck disable=SC1090
source <(sed -n '/^restore_tor_service()/,/^}/p' "$TOR_ROUTE")
declare -F restore_tor_service >/dev/null || fail "restore_tor_service not found in $TOR_ROUTE"

YELLOW=''; GREEN=''; BOLD=''; RESET=''

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
TOR_STATE_FILE="$TMP/tor-state"

# ── Case 1: cleanup aborts -> state file survives for the retry ──────────────
printf 'yes' > "$TOR_STATE_FILE"
( cleanup_torrc() { exit 1; }; service_tor_restart() { :; }; service_tor_stop() { :; }; restore_tor_service ) >/dev/null 2>&1
rc=$?
[[ "$rc" -ne 0 ]] || fail "cleanup abort must exit non-zero"
[[ -f "$TOR_STATE_FILE" ]] || fail "state file was consumed before cleanup could abort"

# ── Case 2: cleanup succeeds -> state file is consumed ───────────────────────
( cleanup_torrc() { :; }; service_tor_restart() { :; }; service_tor_stop() { :; }; restore_tor_service ) >/dev/null 2>&1
rc=$?
[[ "$rc" -eq 0 ]] || fail "successful restore must exit zero"
[[ -f "$TOR_STATE_FILE" ]] && fail "state file was not consumed after a successful restore"

echo "PASS: restore_tor_service keeps the Tor state file when torrc cleanup aborts"
