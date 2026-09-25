#!/usr/bin/env bash
# Regression test: the DNSPort must not be 5353 (the standard mDNS port), so
# tor-route cannot collide with avahi and cannot answer loopback mDNS queries
# (BUGS.md #5). The README must document the actual port.
#
# Pure file test; no root needed.
#
# Usage: tests/dns-port-test.sh

set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "$(readlink -f "$0")")" && pwd)
TOR_ROUTE="$SCRIPT_DIR/../tor-route.sh"
README="$SCRIPT_DIR/../README.md"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -f "$TOR_ROUTE" ]] || fail "tor-route.sh not found at $TOR_ROUTE"
[[ -f "$README" ]] || fail "README.md not found at $README"

PORT=$(grep -m1 '^TOR_DNS_PORT=' "$TOR_ROUTE" | cut -d= -f2)
[[ "$PORT" =~ ^[0-9]+$ ]] || fail "could not read TOR_DNS_PORT from $TOR_ROUTE"
[[ "$PORT" != "5353" ]] || fail "TOR_DNS_PORT must not be the mDNS port 5353"
[[ "$PORT" -gt 1023 ]] || fail "DNSPort should be an unprivileged port (>1023), got $PORT"

grep -q '5353' "$README" && fail "README still documents the mDNS port 5353"
grep -q "$PORT" "$README" || fail "README does not document the DNSPort $PORT"

echo "PASS: DNSPort is $PORT, off the mDNS port, and documented"
