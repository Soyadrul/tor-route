#!/usr/bin/env bash
# Regression test for stop's conntrack cleanup (cleanup_conntrack_tor_ports).
#
# Reproduces the real scenario in a throwaway network namespace: REDIRECT
# rules send new TCP/UDP flows to Tor's TransPort/DNSPort, so their conntrack
# entries carry Tor's local port as the reply SOURCE port. The test asserts
# that cleanup removes exactly those entries and leaves unrelated flows
# alone.
#
# Requires: unshare, ip, iptables, conntrack, python3. Exits 77 (skip) when a
# tool is missing or unprivileged user/network namespaces are unavailable.
#
# Usage: tests/conntrack-cleanup-test.sh

set -u

if [[ "${CT_TEST_IN_NETNS:-0}" != "1" ]]; then
    for cmd in unshare ip iptables conntrack python3 readlink; do
        command -v "$cmd" >/dev/null 2>&1 || { echo "SKIP: '$cmd' not available"; exit 77; }
    done
    if ! unshare -rn true 2>/dev/null; then
        echo "SKIP: unprivileged user/network namespaces unavailable"
        exit 77
    fi
    TEST_SELF=$(readlink -f "$0")
    exec unshare -rn env CT_TEST_IN_NETNS=1 bash "$TEST_SELF" "$@"
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"
UNRELATED_PORT=8080

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

TOR_TRANS_PORT=$(grep -m1 '^TOR_TRANS_PORT=' "$TOR_ROUTE" | cut -d= -f2)
TOR_DNS_PORT=$(grep -m1 '^TOR_DNS_PORT=' "$TOR_ROUTE" | cut -d= -f2)
[[ "$TOR_TRANS_PORT" =~ ^[0-9]+$ && "$TOR_DNS_PORT" =~ ^[0-9]+$ ]] \
    || fail "could not read TOR_TRANS_PORT/TOR_DNS_PORT from $TOR_ROUTE"

# Load the function under test (the script's top level is a dispatcher and
# cannot be sourced directly). Fail loudly if the implementation changes shape.
if ! sed -n '/^cleanup_conntrack_tor_ports()/,/^}/p' "$TOR_ROUTE" | grep -q .; then
    fail "cleanup_conntrack_tor_ports() not found in $TOR_ROUTE"
fi
# shellcheck disable=SC1090
source <(sed -n '/^cleanup_conntrack_tor_ports()/,/^}/p' "$TOR_ROUTE")
declare -F cleanup_conntrack_tor_ports >/dev/null || fail "function failed to load"
YELLOW=""; RESET=""   # function prints colour codes; colours are optional

# ── Throwaway netns setup ─────────────────────────────────────────────────────
ip link set lo up
ip link add veth0 type veth peer name veth1 || fail "could not create veth pair"
ip addr add 10.0.0.1/24 dev veth0
ip addr add 10.0.0.2/24 dev veth1
ip link set veth0 up
ip link set veth1 up

# TCP listeners: Tor's TransPort and an unrelated port.
python3 - "$TOR_TRANS_PORT" "$UNRELATED_PORT" <<'PY' &
import socket, sys, threading, time
def serve(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(8)
    while True:
        c, _ = s.accept()
        threading.Thread(target=lambda c=c: (time.sleep(20), c.close()), daemon=True).start()
for p in (int(sys.argv[1]), int(sys.argv[2])):
    threading.Thread(target=serve, args=(p,), daemon=True).start()
time.sleep(30)
PY
listener_pid=$!
sleep 1

# Exactly the rules apply_iptables installs (REDIRECT into Tor's ports).
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports "$TOR_TRANS_PORT"
iptables -t nat -A OUTPUT -p udp --dport 53  -j REDIRECT --to-ports "$TOR_DNS_PORT"

# Tor-routed TCP: 443 is rewritten to Tor's TransPort.
( exec 3<>/dev/tcp/10.0.0.2/443; sleep 15 ) &
routed_pid=$!
# Tor-routed UDP: 53 is rewritten to Tor's DNSPort.
exec 4<>/dev/udp/10.0.0.2/53
printf 'x' >&4
# Unrelated TCP flow (no REDIRECT rule matches port 8080).
( exec 5<>/dev/tcp/10.0.0.2/8080; sleep 15 ) &
unrelated_pid=$!

reply_entries() { conntrack -L -p "$1" --reply-port-src "$2" 2>/dev/null; }
wait_for_entry() {
    local i
    for i in {1..25}; do
        [[ -n "$(reply_entries "$1" "$2")" ]] && return 0
        sleep 0.2
    done
    return 1
}

wait_for_entry tcp "$TOR_TRANS_PORT" || fail "no TCP entry with reply source port $TOR_TRANS_PORT"
wait_for_entry udp "$TOR_DNS_PORT"   || fail "no UDP entry with reply source port $TOR_DNS_PORT"
wait_for_entry tcp "$UNRELATED_PORT" || fail "unrelated TCP entry (port $UNRELATED_PORT) missing"

cleanup_conntrack_tor_ports

[[ -z "$(reply_entries tcp "$TOR_TRANS_PORT")" ]] || fail "Tor TCP entry survived cleanup"
[[ -z "$(reply_entries udp "$TOR_DNS_PORT")" ]]   || fail "Tor UDP entry survived cleanup"
[[ -n "$(reply_entries tcp "$UNRELATED_PORT")" ]] || fail "cleanup deleted an unrelated TCP entry (too broad)"

kill "$routed_pid" "$unrelated_pid" "$listener_pid" 2>/dev/null
echo "PASS: conntrack cleanup removed Tor-port entries, kept unrelated ones"
exit 0
