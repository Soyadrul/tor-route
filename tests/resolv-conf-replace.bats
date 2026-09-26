#!/usr/bin/env bats
# resolv.conf replacement helpers against bind mounts (BUGS.md #7): a
# rename(2) onto a bind-mounted file fails with EBUSY, and callers must see
# the failure. Runs in a throwaway mount+user namespace so the bind mounts
# cannot affect the host; skips when namespaces are unavailable.

load 'helpers/setup'

setup() { setup_test; }

@test "the resolv.conf helpers detect bind-mount failures (mount namespace)" {
    needs_mountns

    run unshare -rm env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/resolv-netns.sh" replace-bind
    assert_success
    assert_output --partial "PASS:"
}
