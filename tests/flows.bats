#!/usr/bin/env bats
# Command-level control flow for start/stop/newnode: the already-active
# guard, the success-claim gate, the country-pin abort unwind, reload
# failure revert, stop no-ops and the interrupt unwind contract. Internal
# helpers that touch /etc/resolv.conf are overridden here — dns.bats covers
# them — and every external command is a stub.

load 'helpers/setup'

setup() {
    setup_test
    make_firewall_stubs
    make_save_restore_stubs
    make_systemd_stubs
    make_ss_stub
    make_journalctl_stub
    make_curl_stub
    make_conntrack_stub
    make_sleep_stub
}

# Entry guards are overridden so the command bodies run unprivileged.
allow_entry() {
    require_root() { :; }
    acquire_command_lock() { :; }
    require_init() { :; }
    check_dependencies() { :; }
    check_net_tools() { :; }
}

# Everything start needs to get past Tor bring-up and firewall apply, so the
# tests can observe the probe/success logic that follows.
reach_the_probe() {
    allow_entry
    fix_dns_start() { return 0; }
    export CT_TEST_TOR_RUNNING=1 CT_TEST_PORTS=1 CT_TEST_BOOTSTRAPPED=1
}

@test "start refuses to re-apply while routing is already active" {
    allow_entry
    export CT_TEST_ROUTING=1

    run cmd_start start
    assert_success
    assert_output --partial "already active"
    assert_file_not_exists "$TORRC"
    assert_file_not_contains "$STUB_LOG" '^iptables -t nat -F OUTPUT$'
    assert_file_not_contains "$STUB_LOG" '^systemctl restart tor$'
}

@test "start claims success only after the traffic probe passes" {
    reach_the_probe
    probe_traffic() { return 0; }
    export CT_TEST_IPV4=203.0.113.7

    run cmd_start start
    assert_success
    assert_output --partial "All traffic is now routed through Tor!"
    assert_file_contains "$STUB_LOG" '^iptables -t nat -A OUTPUT -p tcp -m state --state NEW -j REDIRECT --to-ports 9040$'
}

@test "start warns instead of claiming success when traffic does not flow (no pin)" {
    reach_the_probe
    probe_traffic() { return 1; }
    prompt_country_fallback() { echo "PROMPT-CALLED"; return 1; }
    export CT_TEST_IPV4=203.0.113.7

    run cmd_start start
    assert_success
    assert_output --partial "not flowing yet"
    refute_output --partial "PROMPT-CALLED"
}

@test "start unwinds completely when a country pin is unusable and the user aborts" {
    reach_the_probe
    probe_traffic() { return 1; }
    prompt_country_fallback() { return 1; }
    export CT_TEST_IPV4=203.0.113.7

    run cmd_start start de
    assert_failure
    assert_output --partial "Aborted - restoring normal internet"
    assert_file_contains "$STUB_LOG" '^iptables-restore$'
    assert_file_contains "$STUB_LOG" '^systemctl restart tor$'
    assert_file_not_contains "$TORRC" 'tor-route.sh start'
    assert_file_not_exists "$COUNTRY_FILE"
    assert_file_not_exists "$TOR_STATE_FILE"
    assert_file_not_exists "$IPTABLES_BACKUP"
    assert_file_not_exists "$IP6TABLES_BACKUP"
}

@test "start falls back to a random exit when the pin is unusable and the user agrees" {
    reach_the_probe
    local calls="$TEST_TMP/probe-calls"
    probe_traffic() { printf 'probe\n' >> "$calls"; [[ "$(wc -l < "$calls")" -ge 2 ]]; }
    prompt_country_fallback() { return 0; }
    export CT_TEST_IPV4=203.0.113.7

    run cmd_start start de
    assert_success
    assert_output --partial "All traffic is now routed through Tor!"
    assert_file_not_contains "$TORRC" 'ExitNodes'
    assert_equal "$(cat "$COUNTRY_FILE")" "random"
}

@test "start falls back to random and warns when the fallback reload fails" {
    reach_the_probe
    probe_traffic() { return 1; }
    prompt_country_fallback() { return 0; }
    export CT_TEST_RELOAD_FAIL=1 CT_TEST_IPV4=203.0.113.7

    run cmd_start start de
    assert_success
    assert_output --partial "reload failed - traffic will use a random exit node"
    assert_file_not_contains "$TORRC" 'ExitNodes'
}

@test "newnode refuses when Tor is not running" {
    allow_entry
    run cmd_newnode newnode
    assert_failure
    assert_output --partial "Tor is not running"
}

@test "newnode refuses when routing is not active" {
    allow_entry
    export CT_TEST_TOR_RUNNING=1 CT_TEST_ROUTING=0
    run cmd_newnode newnode
    assert_failure
    assert_output --partial "Tor routing is not active"
}

@test "newnode reverts torrc and country state when the reload fails" {
    allow_entry
    export CT_TEST_TOR_RUNNING=1 CT_TEST_ROUTING=1 CT_TEST_RELOAD_FAIL=1

    run configure_torrc de
    assert_success

    run cmd_newnode newnode us
    assert_failure
    assert_output --partial "Tor reload failed - torrc reverted"
    assert_file_contains "$TORRC" '^ExitNodes {de}$'
    assert_file_not_contains "$TORRC" 'ExitNodes {us}'
    assert_equal "$(cat "$COUNTRY_FILE")" "de"
}

@test "stop with no prior session leaves the firewall and DNS untouched" {
    allow_entry
    export CT_TEST_CURL_OK=1

    run cmd_stop stop
    assert_success
    assert_output --partial "Firewall was not modified"
    assert_output --partial "DNS was not modified"
    assert_output --partial "Normal internet restored"
    assert_file_not_contains "$STUB_LOG" '^iptables -F$'
    assert_file_not_contains "$STUB_LOG" '^iptables -t nat -F$'
    assert_file_not_contains "$STUB_LOG" '^iptables-restore$'
    assert_file_contains "$STUB_LOG" '^systemctl stop tor$'
}

@test "stop aborts with manual recovery steps when the rules survive the restore" {
    allow_entry
    mkdir -p "$STATE_DIR"
    printf 'PRE-TOR-V4-RULES\n' > "$IPTABLES_BACKUP"
    is_routing_active() { return 0; }

    run cmd_stop stop
    assert_failure
    assert_output --partial "firewall backups are missing"
    assert_output --partial "iptables -t nat -F OUTPUT"
    assert_file_not_contains "$STUB_LOG" '^systemctl stop tor$'
}

@test "interrupt_unwind is safe before anything was saved" {
    export CT_TEST_TOR_RUNNING=1

    run interrupt_unwind
    assert_failure
    assert_output --partial "Interrupted"
    assert_file_not_contains "$STUB_LOG" '^iptables -F$'
    assert_file_not_contains "$STUB_LOG" '^iptables -t nat -F$'
    assert_file_contains "$STUB_LOG" '^systemctl stop tor$'
}
