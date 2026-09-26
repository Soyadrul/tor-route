#!/usr/bin/env bash
# Regression test: show_ip must still display Country/ISP when the primary
# geo provider is rate-limited. ipwho.is allows 1,000 free requests/day per
# client IP; under Tor the client is a shared exit node, so busy exits get
# HTTP 429 responses. show_ip must fall back to a second keyless HTTPS
# provider (ipwhois.app) and must say so explicitly when every provider
# fails, instead of silently dropping the lines.
#
# Pure PATH-stub test: fake curl/iptables, no network or root needed.
#
# Usage: tests/show-ip-geo-test.sh

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"

STUB_DIR=$(mktemp -d)
trap 'rm -rf "$STUB_DIR"' EXIT

# CT_TEST_PRIMARY:   ok | ratelimited   (ipwho.is)
# CT_TEST_FALLBACK:  ok | fail          (ipwhois.app)
# CT_TEST_CALLS points at a file recording every geo-provider URL fetched.
cat > "$STUB_DIR/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *api6.ipify.org*)  ;;                                      # no IPv6: empty body
    *api.ipify.org*)   echo "203.0.113.7" ;;
    *ipwho.is*)
        printf '%s\n' "$*" >> "$CT_TEST_CALLS"
        case "${CT_TEST_PRIMARY:-ok}" in
            ok)          echo '{"country":"Germany","country_code":"DE","isp":"Primary ISP"}' ;;
            ratelimited) echo '{"success":false,"message":"Rate limit exceeded"}' ;;
        esac
        ;;
    *ipwhois.app*)
        printf '%s\n' "$*" >> "$CT_TEST_CALLS"
        case "${CT_TEST_FALLBACK:-fail}" in
            ok) echo '{"country":"France","country_code":"FR","isp":"Fallback ISP"}' ;;
        esac
        ;;
esac
exit 0
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

# ── 1. Primary rate-limited: fall back and print fallback Country/ISP ────────
calls="$STUB_DIR/calls-fallback"; : > "$calls"
out=$(CT_TEST_CALLS="$calls" CT_TEST_PRIMARY=ratelimited CT_TEST_FALLBACK=ok \
    CT_TEST_ROUTING=1 PATH="$STUB_DIR:$PATH" show_ip)
grep -q 'Country: France (FR)' <<<"$out" \
    || fail "rate-limited primary: fallback country missing from output"
grep -q 'ISP/Org: Fallback ISP' <<<"$out" \
    || fail "rate-limited primary: fallback ISP missing from output"
grep -q 'Germany' <<<"$out" \
    && fail "rate-limited primary: primary data leaked into output"
grep -q 'ipwhois.app' "$calls" \
    || fail "rate-limited primary: fallback provider was never queried"

# ── 2. Every provider fails: explicit message, not silence ───────────────────
calls="$STUB_DIR/calls-fail"; : > "$calls"
out=$(CT_TEST_CALLS="$calls" CT_TEST_PRIMARY=ratelimited CT_TEST_FALLBACK=fail \
    CT_TEST_ROUTING=1 PATH="$STUB_DIR:$PATH" show_ip)
grep -qi 'Country/ISP: lookup unavailable' <<<"$out" \
    || fail "all providers failed: explicit unavailable message missing"
grep -q 'Country:' <<<"$out" \
    && fail "all providers failed: empty country line printed"

# ── 3. Primary works: fallback must not be queried ───────────────────────────
calls="$STUB_DIR/calls-primary"; : > "$calls"
out=$(CT_TEST_CALLS="$calls" CT_TEST_PRIMARY=ok CT_TEST_FALLBACK=ok \
    CT_TEST_ROUTING=1 PATH="$STUB_DIR:$PATH" show_ip)
grep -q 'Country: Germany (DE)' <<<"$out" || fail "primary success: country missing"
grep -q 'ISP/Org: Primary ISP' <<<"$out" || fail "primary success: ISP missing"
grep -q 'ipwhois.app' "$calls" \
    && fail "primary success: fallback provider was queried unnecessarily"

echo "PASS: show_ip falls back to a second geo provider and warns when all fail"
exit 0
