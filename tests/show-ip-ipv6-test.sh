#!/usr/bin/env bash
# Regression test: show_ip must only label a reachable IPv6 address as
# "LEAK!" while Tor routing is active. With routing off the address is the
# host's own and must be printed without the leak banner (BUGS.md #2).
#
# Pure PATH-stub test: fake curl/iptables, no network or root needed.
#
# Usage: tests/show-ip-ipv6-test.sh

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

STUB_DIR=$(mktemp -d)
trap 'rm -rf "$STUB_DIR"' EXIT

cat > "$STUB_DIR/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *api6.ipify.org*) echo "2001:db8::dead:beef" ;;
    *api.ipify.org*)  echo "203.0.113.7" ;;
    *ipwho.is*)       echo '{"country":"Testland","country_code":"TL","isp":"Example ISP"}' ;;
esac
EOF

# Emit a Tor REDIRECT rule only when CT_TEST_ROUTING=1.
cat > "$STUB_DIR/iptables" <<'EOF'
#!/usr/bin/env bash
if [[ "${CT_TEST_ROUTING:-0}" == "1" ]]; then
    echo "-A OUTPUT -p tcp -m state --state NEW -j REDIRECT --to-ports 9040"
fi
exit 0
EOF

chmod +x "$STUB_DIR/curl" "$STUB_DIR/iptables"

# shellcheck disable=SC1090
source <(sed -n '/^is_routing_active()/,/^}/p;/^show_ip()/,/^}/p' "$TOR_ROUTE")
declare -F show_ip >/dev/null || fail "show_ip not found in $TOR_ROUTE"
declare -F is_routing_active >/dev/null || fail "is_routing_active not found in $TOR_ROUTE"

TOR_TRANS_PORT=9040
RED=''; GREEN=''; YELLOW=''; BOLD=''; RESET=''; CYAN=''

out=$(CT_TEST_ROUTING=1 PATH="$STUB_DIR:$PATH" show_ip)
grep -q 'LEAK!' <<<"$out" || fail "routing active + reachable IPv6 must flag LEAK"
grep -q '2001:db8::dead:beef' <<<"$out" || fail "IPv6 address missing (routing-active case)"

out=$(CT_TEST_ROUTING=0 PATH="$STUB_DIR:$PATH" show_ip)
grep -q 'LEAK!' <<<"$out" && fail "routing off must not claim an IPv6 leak"
grep -q '2001:db8::dead:beef' <<<"$out" || fail "IPv6 address missing (routing-off case)"

echo "PASS: show_ip flags IPv6 only as a leak while routing is active"
