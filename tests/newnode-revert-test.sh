#!/usr/bin/env bash
# Regression test: when newnode reverts after configure_torrc (interrupt or
# failed reload), torrc and COUNTRY_FILE must be restored to the previous
# configuration instead of being stripped, so on-disk state matches the
# still-live Tor process (BUGS.md #3).
#
# Pure file test with a temp TORRC/STATE_DIR; no root, Tor or network needed.
#
# Usage: tests/newnode-revert-test.sh

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

TOR_TRANS_PORT=$(grep -m1 '^TOR_TRANS_PORT=' "$TOR_ROUTE" | cut -d= -f2)
TOR_DNS_PORT=$(grep -m1 '^TOR_DNS_PORT=' "$TOR_ROUTE" | cut -d= -f2)

# shellcheck disable=SC1090
source <(sed -n \
    -e '/^ensure_state_dir()/,/^}/p' \
    -e '/^strip_torrc_block()/,/^}/p' \
    -e '/^configure_torrc()/,/^}/p' \
    -e '/^revert_torrc_to_previous()/,/^}/p' \
    "$TOR_ROUTE")
for fn in ensure_state_dir strip_torrc_block configure_torrc revert_torrc_to_previous; do
    declare -F "$fn" >/dev/null || fail "$fn not found in $TOR_ROUTE"
done

YELLOW=''; RED=''; GREEN=''; RESET=''

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
TORRC="$TMP/torrc"
STATE_DIR="$TMP/state"
COUNTRY_FILE="$STATE_DIR/country"

seed_previous_pin() { # $1 = country code of the pre-newnode session
    mkdir -p "$STATE_DIR"
    cat > "$TORRC" <<EOF
# user-owned line
SocksPort 9050

# --- tor-route.sh start ---
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:${TOR_TRANS_PORT}
DNSPort 127.0.0.1:${TOR_DNS_PORT}
ExitNodes {$1}
StrictNodes 1
# --- tor-route.sh end ---
EOF
    printf '%s\n' "$1" > "$COUNTRY_FILE"
}

count_markers() { grep -c "^# --- tor-route.sh $1 ---$" "$TORRC"; }

# ── Case 1: previous pin was "de", newnode wrote "us", then reverts ──────────
seed_previous_pin de
configure_torrc us >/dev/null
grep -q 'ExitNodes {us}' "$TORRC" || fail "setup: new pin not written"
revert_torrc_to_previous de >/dev/null
grep -q 'ExitNodes {de}' "$TORRC" || fail "previous pin not restored"
grep -q 'ExitNodes {us}' "$TORRC" && fail "new pin still present after revert"
[[ "$(cat "$COUNTRY_FILE")" == "de" ]] || fail "COUNTRY_FILE not restored"
[[ "$(count_markers start)" -eq 1 ]] || fail "torrc block duplicated"
grep -q '^SocksPort 9050$' "$TORRC" || fail "user-owned line lost"

# ── Case 2: previous session was unpinned ("random" sentinel) ───────────────
seed_previous_pin jp
configure_torrc us >/dev/null
revert_torrc_to_previous random >/dev/null
grep -q 'ExitNodes' "$TORRC" && fail "random revert must not leave an ExitNodes pin"
[[ "$(cat "$COUNTRY_FILE")" == "random" ]] || fail "COUNTRY_FILE must be random"
grep -q '^SocksPort 9050$' "$TORRC" || fail "user-owned line lost (random case)"
[[ "$(count_markers start)" -eq 1 ]] || fail "torrc block duplicated (random case)"

echo "PASS: newnode revert restores the previous torrc and country state"
