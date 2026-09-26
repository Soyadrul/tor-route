#!/usr/bin/env bash
# Network-namespace helper for the conntrack cleanup regression (withdrawn
# BUGS.md #1, kept as a guard). Runs inside `unshare -rn` (caller-enforced)
# and must use the REAL iptables/conntrack: it reproduces a REDIRECT rewrite
# and checks that cleanup removes exactly the Tor-port entries, keeps
# unrelated ones, and prints no raw conntrack dump.

set -u

HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HELPERS_DIR/setup.bash"

fail() { echo "FAIL: $*" >&2; exit 1; }

TEST_TMP="${TEST_TMP:-$(mktemp -d)}"
export TEST_TMP
init_test_env

UNRELATED_PORT=8080

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

# cleanup's only intended output is its one-line summary: conntrack -D echoes
# every deleted flow to stdout, so a missing redirect would dump the raw
# entries at the user during stop.
cleanup_output=$(cleanup_conntrack_tor_ports 2>&1)
[[ "$cleanup_output" == *"Removed stale conntrack entries pointing at Tor's ports."* ]] \
    || fail "cleanup summary line missing from output"
case "$cleanup_output" in
    *"src="*|*"dst="*) fail "cleanup leaked raw conntrack entries to its output" ;;
esac

[[ -z "$(reply_entries tcp "$TOR_TRANS_PORT")" ]] || fail "Tor TCP entry survived cleanup"
[[ -z "$(reply_entries udp "$TOR_DNS_PORT")" ]]   || fail "Tor UDP entry survived cleanup"
[[ -n "$(reply_entries tcp "$UNRELATED_PORT")" ]] || fail "cleanup deleted an unrelated TCP entry (too broad)"

kill "$routed_pid" "$unrelated_pid" "$listener_pid" 2>/dev/null
echo "PASS: conntrack cleanup removed Tor-port entries, kept unrelated ones and stayed quiet"
exit 0
