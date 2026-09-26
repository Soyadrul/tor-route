#!/usr/bin/env bats
# Firewall behavior: rule application (apply_iptables), backups
# (save_iptables), restore guards (restore_iptables), routing detection and
# IPv6 classification. Every firewall command is a stub; no real rule is
# touched.

load 'helpers/setup'

setup() {
    setup_test
    make_firewall_stubs
    make_save_restore_stubs
    make_conntrack_stub
}

@test "apply_iptables installs the documented NAT and filter rules" {
    run apply_iptables
    assert_success
    assert_output --partial "Non-DNS UDP blocked"

    # NAT: flush, DNS redirects excluding Tor's own traffic, Tor RETURN,
    # LAN bypass, new-TCP redirect.
    assert_file_contains "$STUB_LOG" '^iptables -t nat -F OUTPUT$'
    assert_file_contains "$STUB_LOG" '^iptables -F OUTPUT$'
    assert_file_contains "$STUB_LOG" '^iptables -t nat -A OUTPUT -m owner ! --uid-owner 4242 -p udp --dport 53 -j REDIRECT --to-ports 9053$'
    assert_file_contains "$STUB_LOG" '^iptables -t nat -A OUTPUT -m owner ! --uid-owner 4242 -p tcp --dport 53 -j REDIRECT --to-ports 9053$'
    assert_file_contains "$STUB_LOG" '^iptables -t nat -A OUTPUT -m owner --uid-owner 4242 -j RETURN$'
    local addr
    for addr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        assert_file_contains "$STUB_LOG" "^iptables -t nat -A OUTPUT -d $addr -j RETURN$"
    done
    assert_file_contains "$STUB_LOG" '^iptables -t nat -A OUTPUT -p tcp -m state --state NEW -j REDIRECT --to-ports 9040$'

    # Filter: Tor's UDP, local DNS, LAN UDP, then a final DROP.
    assert_file_contains "$STUB_LOG" '^iptables -A OUTPUT -m owner --uid-owner 4242 -p udp -j ACCEPT$'
    assert_file_contains "$STUB_LOG" '^iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT$'
    for addr in 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        assert_file_contains "$STUB_LOG" "^iptables -A OUTPUT -p udp -d $addr -j ACCEPT$"
    done
    local last
    last=$(grep '^iptables -A OUTPUT' "$STUB_LOG" | tail -n1)
    assert_equal "$last" "iptables -A OUTPUT -p udp -j DROP"

    # IPv6 is denied by policy.
    assert_file_contains "$STUB_LOG" '^ip6tables -P INPUT DROP$'
    assert_file_contains "$STUB_LOG" '^ip6tables -P OUTPUT DROP$'
    assert_file_contains "$STUB_LOG" '^ip6tables -P FORWARD DROP$'
}

@test "apply_iptables refuses to run without a Tor user" {
    TOR_UID="" TOR_USER=""
    detect_tor_user() { TOR_UID=""; TOR_USER=""; }
    run apply_iptables
    assert_failure
    assert_output --partial "Tor user not found"
}

@test "apply_iptables aborts when a rule command fails" {
    export CT_TEST_FAIL_IPTABLES_ON='-j RETURN'
    run apply_iptables
    assert_failure
    assert_output --partial "Failed to apply the firewall rules"
}

@test "apply_iptables aborts when the IPv6 DROP policies do not verify" {
    export CT_TEST_IPV6_VERIFY=fail
    run apply_iptables
    assert_failure
    assert_output --partial "Could not apply IPv6 DROP policies"
}

@test "apply_iptables skips IPv6 blocking when the kernel has no IPv6 stack" {
    export CT_TEST_IPV6=unavailable
    run apply_iptables
    assert_success
    assert_output --partial "IPv6 not available"
    assert_file_not_contains "$STUB_LOG" 'ip6tables -P'
}

# ── save_iptables ─────────────────────────────────────────────────────────────

@test "save_iptables writes both backups atomically and root-only" {
    run save_iptables
    assert_success
    assert_file_exists "$IPTABLES_BACKUP"
    assert_file_exists "$IP6TABLES_BACKUP"
    assert_file_contains "$IPTABLES_BACKUP" 'PRE-TOR-V4-RULES'
    assert_file_contains "$IP6TABLES_BACKUP" 'PRE-TOR-V6-RULES'
    assert_file_permission 600 "$IPTABLES_BACKUP"
    assert_file_permission 600 "$IP6TABLES_BACKUP"

    run bash -c "compgen -G '$STATE_DIR/*.tmp'"
    assert_failure
    assert_equal "$output" ""
}

@test "save_iptables aborts cleanly when the IPv4 save fails" {
    export CT_TEST_SAVE_FAIL=v4
    run save_iptables
    assert_failure
    assert_output --partial "Firewall save failed"
    assert_file_not_exists "$IPTABLES_BACKUP"
    assert_file_not_exists "$IP6TABLES_BACKUP"
}

@test "save_iptables leaves no partial backup when the IPv6 save fails" {
    export CT_TEST_SAVE_FAIL=v6
    run save_iptables
    assert_failure
    assert_file_not_exists "$IPTABLES_BACKUP"
    assert_file_not_exists "$IP6TABLES_BACKUP"
}

@test "save_iptables skips the IPv6 backup when there is no IPv6 stack" {
    export CT_TEST_IPV6=unavailable
    run save_iptables
    assert_success
    assert_output --partial "skipping IPv6 backup"
    assert_file_exists "$IPTABLES_BACKUP"
    assert_file_not_exists "$IP6TABLES_BACKUP"
}

# ── restore_iptables ──────────────────────────────────────────────────────────

@test "restore_iptables never touches the firewall when no backup exists" {
    run restore_iptables
    assert_success
    assert_output --partial "not modified"
    assert_file_not_contains "$STUB_LOG" '^iptables -F$'
    assert_file_not_contains "$STUB_LOG" '^iptables -t nat -F$'
}

@test "restore_iptables flushes, resets IPv6 policies, restores both families and removes the backups" {
    mkdir -p "$STATE_DIR"
    printf 'PRE-TOR-V4-RULES\n' > "$IPTABLES_BACKUP"
    printf 'PRE-TOR-V6-RULES\n' > "$IP6TABLES_BACKUP"

    run restore_iptables
    assert_success
    assert_file_contains "$STUB_LOG" '^iptables -F$'
    assert_file_contains "$STUB_LOG" '^iptables -t nat -F$'
    assert_file_contains "$STUB_LOG" '^ip6tables -P INPUT ACCEPT$'
    assert_file_contains "$STUB_LOG" '^ip6tables -P OUTPUT ACCEPT$'
    assert_file_contains "$STUB_LOG" '^ip6tables -P FORWARD ACCEPT$'
    assert_file_contains "$STUB_LOG" '^iptables-restore$'
    assert_file_contains "$STUB_LOG" '^ip6tables-restore$'
    assert_file_contains "$STUB_LOG" '^conntrack -D -p tcp --reply-port-src 9040$'
    assert_file_contains "$STUB_LOG" '^conntrack -D -p udp --reply-port-src 9053$'

    assert_file_not_exists "$IPTABLES_BACKUP"
    assert_file_not_exists "$IP6TABLES_BACKUP"
}

@test "restore_iptables keeps a failing family's backup and reports failure" {
    mkdir -p "$STATE_DIR"
    printf 'PRE-TOR-V4-RULES\n' > "$IPTABLES_BACKUP"
    printf 'PRE-TOR-V6-RULES\n' > "$IP6TABLES_BACKUP"
    export CT_TEST_RESTORE_FAIL=v4

    run restore_iptables
    assert_failure
    assert_output --partial "FAILED to restore iptables rules"
    assert_file_exists "$IPTABLES_BACKUP"
    assert_file_not_exists "$IP6TABLES_BACKUP"
}

# ── routing detection and IPv6 classification ─────────────────────────────────

@test "is_routing_active handles -S output and the -L fallback" {
    run is_routing_active
    assert_failure

    export CT_TEST_ROUTING_LEGACY=1
    run is_routing_active
    assert_success

    export CT_TEST_ROUTING_LEGACY=0 CT_TEST_ROUTING=1
    run is_routing_active
    assert_success
}

@test "ipv6_policy_state classifies unavailable, blocked and allowed" {
    export CT_TEST_IPV6=unavailable
    run ipv6_available
    assert_failure
    run ipv6_policy_state
    assert_success
    assert_output "unavailable"

    export CT_TEST_IPV6=available CT_TEST_IPV6_VERIFY=ok
    run ipv6_available
    assert_success
    run ipv6_policy_state
    assert_output "blocked"

    export CT_TEST_IPV6_VERIFY=fail
    run ipv6_policy_state
    assert_output "allowed"
}
