#!/usr/bin/env bats
# DNS handling: the verified file/symlink helpers and the full
# fix_dns_start/fix_dns_stop flows (backup, masking record, restore order,
# unmask) exercised in a mount namespace so /etc/resolv.conf can be replaced
# safely.

load 'helpers/setup'

setup() { setup_test; }

# Ported from dns-port-test.sh (BUGS.md #5): the DNSPort must stay off the
# mDNS/Avahi port and the README must document the real port.
@test "DNSPort stays off the mDNS port and is documented in the README" {
    [[ "$TOR_DNS_PORT" != "5353" ]]
    [[ "$TOR_DNS_PORT" -gt 1023 ]]
    assert_file_contains "$REPO_ROOT/README.md" "$TOR_DNS_PORT"
    assert_file_not_contains "$REPO_ROOT/README.md" '5353'
}

# ── file helpers (no namespace needed) ────────────────────────────────────────

@test "replace_file_verified replaces content, verifies it and removes the .tmp" {
    printf 'nameserver 9.9.9.9\n' > "$TEST_TMP/target"

    run replace_file_verified "$TEST_TMP/target" "nameserver 127.0.0.1"
    assert_success
    assert_equal "$(cat "$TEST_TMP/target")" "nameserver 127.0.0.1"

    run bash -c "compgen -G '$TEST_TMP/target.tmp'"
    assert_failure
}

@test "replace_file_verified fails when the target cannot be written" {
    run replace_file_verified "$TEST_TMP/missing-dir/target" "nameserver 127.0.0.1"
    assert_failure

    run bash -c "compgen -G '$TEST_TMP/missing-dir/target.tmp'"
    assert_failure
}

@test "replace_file_verified verifies the content actually landed" {
    printf 'nameserver 9.9.9.9\n' > "$TEST_TMP/target"
    mv() { return 0; }   # a rename that silently does nothing must be caught

    run replace_file_verified "$TEST_TMP/target" "nameserver 127.0.0.1"
    assert_failure
}

@test "link_file_verified creates and verifies a symlink" {
    printf 'nameserver 9.9.9.9\n' > "$TEST_TMP/link_target"

    run link_file_verified "$TEST_TMP/mylink" "$TEST_TMP/link_target"
    assert_success
    assert_symlink_to "$TEST_TMP/link_target" "$TEST_TMP/mylink"
}

@test "link_file_verified fails when ln cannot create the link" {
    run link_file_verified "$TEST_TMP/missing-dir/mylink" "$TEST_TMP/link_target"
    assert_failure
}

@test "link_file_verified verifies the resulting target" {
    ln() { return 0; }   # a link() that silently does nothing must be caught

    run link_file_verified "$TEST_TMP/mylink" "$TEST_TMP/link_target"
    assert_failure
}

# ── fix_dns_start / fix_dns_stop (mount namespace) ────────────────────────────

@test "fix_dns_start backs up, records masking and verifies the swap (mount namespace)" {
    needs_mountns
    run unshare -rm env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/resolv-netns.sh" fix-dns-start
    assert_success
    assert_output --partial "PASS:"
}

@test "fix_dns_start does not claim success when resolv.conf cannot be replaced (mount namespace)" {
    needs_mountns
    run unshare -rm env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/resolv-netns.sh" fix-dns-start-bind-fail
    assert_success
    assert_output --partial "PASS:"
}

@test "fix_dns_stop guards, restores the backup and unmasks only recorded units (mount namespace)" {
    needs_mountns
    run unshare -rm env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/resolv-netns.sh" fix-dns-stop
    assert_success
    assert_output --partial "PASS:"
}

@test "status judges resolv.conf against Tor on non-systemd inits (mount namespace)" {
    needs_mountns
    run unshare -rm env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/resolv-netns.sh" status-resolv
    assert_success
    assert_output --partial "PASS:"
}
