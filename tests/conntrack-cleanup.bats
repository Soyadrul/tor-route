#!/usr/bin/env bats
# Conntrack cleanup scoping (withdrawn BUGS.md #1, kept as a guard): cleanup
# must delete exactly the entries whose reply source port is a Tor port, keep
# unrelated flows, and print only its one-line summary. Runs against the real
# kernel in a throwaway network namespace; skips when unavailable.

load 'helpers/setup'

setup() { setup_test; }

@test "cleanup removes only Tor-port entries and stays quiet (netns)" {
    needs_netns
    needs_commands ip iptables conntrack python3

    run unshare -rn env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/conntrack-netns.sh"
    assert_success
    assert_output --partial "PASS:"
}
