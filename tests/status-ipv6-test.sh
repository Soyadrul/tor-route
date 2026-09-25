#!/usr/bin/env bash
# Regression test: on a host with no usable IPv6 stack, status must report
# IPv6 as unavailable instead of "NOT blocked - leak possible!" (BUGS.md #6).
#
# Pure PATH-stub test: fake ip6tables, no network or root needed.
#
# Usage: tests/status-ipv6-test.sh

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

# shellcheck disable=SC1090
source <(sed -n '/^ipv6_available()/,/^}/p;/^ipv6_policy_state()/,/^}/p' "$TOR_ROUTE")
declare -F ipv6_available >/dev/null || fail "ipv6_available not found in $TOR_ROUTE"
declare -F ipv6_policy_state >/dev/null || fail "ipv6_policy_state not found in $TOR_ROUTE"

STUB_DIR=$(mktemp -d)
trap 'rm -rf "$STUB_DIR"' EXIT

cat > "$STUB_DIR/ip6tables" <<'EOF'
#!/usr/bin/env bash
case "${CT_TEST_IP6:-blocked}" in
    unavailable) exit 1 ;;
    blocked)     echo "Chain OUTPUT (policy DROP)" ;;
    allowed)     echo "Chain OUTPUT (policy ACCEPT)" ;;
esac
EOF
chmod +x "$STUB_DIR/ip6tables"

state=$(CT_TEST_IP6=unavailable PATH="$STUB_DIR:$PATH" ipv6_policy_state)
[[ "$state" == "unavailable" ]] || fail "no IPv6 stack must report unavailable, got '$state'"

state=$(CT_TEST_IP6=blocked PATH="$STUB_DIR:$PATH" ipv6_policy_state)
[[ "$state" == "blocked" ]] || fail "DROP policy must report blocked, got '$state'"

state=$(CT_TEST_IP6=allowed PATH="$STUB_DIR:$PATH" ipv6_policy_state)
[[ "$state" == "allowed" ]] || fail "non-DROP policy must report allowed, got '$state'"

echo "PASS: IPv6 policy classified as unavailable/blocked/allowed"
