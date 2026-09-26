#!/usr/bin/env bats
# `status` and `check` output plus the dependency gates. Guard functions are
# overridden so the command bodies run without root; every external command
# is a stub.

load 'helpers/setup'

setup() {
    setup_test
    make_firewall_stubs
    make_systemd_stubs
    make_ss_stub
    make_curl_stub
    make_journalctl_stub
}

allow_command_guards() {
    require_root() { :; }
    require_init() { :; }
    check_net_tools() { :; }
}

# Version-reporting stubs for every binary cmd_check probes.
make_check_stubs() {
    local c
    for c in tor iptables ip6tables iptables-save ip6tables-save curl ss; do
        make_stub "$c" <<STUB
#!/usr/bin/env bash
if [[ "\${1:-}" == "--version" ]]; then echo "$c version 1.0"; exit 0; fi
printf '%s %s\\n' "$c" "\$*" >> "\$STUB_LOG"
exit 0
STUB
    done
}

# ── status ────────────────────────────────────────────────────────────────────

@test "status reports active routing, blocking and masking state" {
    allow_command_guards
    RESOLVED_UNITS=(unit-a.service unit-b.socket)
    mkdir -p "$STATE_DIR"
    printf 'us\n' > "$COUNTRY_FILE"
    export CT_TEST_ROUTING=1 CT_TEST_UDP_BLOCKED=1 CT_TEST_IPV6=available \
        CT_TEST_IPV6_VERIFY=ok CT_TEST_TOR_RUNNING=1 CT_TEST_PORTS=1 \
        CT_TEST_MASKED_UNITS="unit-a.service unit-b.socket" CT_TEST_IPV4=203.0.113.7

    run cmd_status status
    assert_success
    assert_output --partial "Tor service:       Running"
    assert_output --partial "TCP routing:       Through Tor"
    assert_output --partial "UDP / WebRTC:      Blocked"
    assert_output --partial "IPv6:              Blocked"
    assert_output --partial "All units masked"
    assert_output --partial "Exit node country: US (pinned)"
    assert_output --partial "TransPort 9040: Listening"
    assert_output --partial "DNSPort   9053:  Listening"
}

@test "status reports a missing UDP DROP rule as a possible leak" {
    allow_command_guards
    export CT_TEST_ROUTING=1 CT_TEST_UDP_BLOCKED=0 CT_TEST_IPV4=203.0.113.7

    run cmd_status status
    assert_success
    assert_output --partial "NOT blocked - leak possible!"
}

@test "status distinguishes unavailable, blocked and leaking IPv6" {
    allow_command_guards
    export CT_TEST_ROUTING=1 CT_TEST_IPV4=203.0.113.7

    export CT_TEST_IPV6=unavailable
    run cmd_status status
    assert_output --partial "Not available (no IPv6 stack)"

    export CT_TEST_IPV6=available CT_TEST_IPV6_VERIFY=fail
    run cmd_status status
    assert_output --partial "NOT blocked - leak possible!"
}

@test "status with routing off shows direct routing and the country sentinel" {
    allow_command_guards
    export CT_TEST_ROUTING=0 CT_TEST_IPV4=203.0.113.7

    run cmd_status status
    assert_success
    assert_output --partial "Direct (not through Tor)"
    assert_output --partial "Not blocked (routing is off)"
    assert_output --partial "Exit node country: Unknown"

    mkdir -p "$STATE_DIR"
    printf 'random\n' > "$COUNTRY_FILE"
    run cmd_status status
    assert_output --partial "Exit node country: Random (no country filter)"
}

# ── check ─────────────────────────────────────────────────────────────────────

@test "check reports all checks passed when every dependency exists" {
    allow_command_guards
    make_check_stubs
    make_id_stub
    printf 'SocksPort 9050\n' > "$TORRC"

    run cmd_check
    assert_success
    assert_output --partial "── System ─"
    assert_output --partial "── Firewall ─"
    assert_output --partial "All checks passed"
}

@test "check reports failures when a dependency is missing" {
    allow_command_guards
    make_check_stubs
    make_id_stub
    hide_commands iptables
    printf 'SocksPort 9050\n' > "$TORRC"

    run cmd_check
    assert_success
    assert_output --partial "Some checks failed"
    assert_output --partial "(missing)"
}

# ── dependency gates ──────────────────────────────────────────────────────────

@test "check_dependencies names every missing tool" {
    local c
    for c in tor iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore ss; do
        make_stub "$c" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    done
    hide_commands curl

    run check_dependencies
    assert_failure
    assert_output --partial "Missing: curl"
}

@test "check_dependencies passes with tor, firewall tools and the Tor user present" {
    local c
    for c in tor iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore curl ss; do
        make_stub "$c" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    done
    run check_dependencies
    assert_success
}

@test "check_net_tools only demands the tools it is asked for (stop survives a tor uninstall)" {
    make_stub iptables <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    make_stub ip6tables <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    hide_commands curl ss

    run check_net_tools iptables ip6tables
    assert_success

    run check_net_tools
    assert_failure
    assert_output --partial "Missing: curl ss"
}

@test "check_dependencies refuses to run without a Tor user" {
    local c
    for c in tor iptables ip6tables iptables-save ip6tables-save iptables-restore ip6tables-restore curl ss; do
        make_stub "$c" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
    done
    detect_tor_user() { TOR_UID=""; TOR_USER=""; }
    TOR_UID="" TOR_USER=""

    run check_dependencies
    assert_failure
    assert_output --partial "Tor system user not found"
}

# ── check: display branches ───────────────────────────────────────────────────

@test "check reports a running Tor service, our torrc block and existing state" {
    allow_command_guards
    make_check_stubs
    make_id_stub
    export CT_TEST_TOR_RUNNING=1 CT_TEST_BOOTSTRAPPED=1
    mkdir -p "$STATE_DIR"
    : > "$COUNTRY_FILE"
    cat > "$TORRC" <<'EOF'
SocksPort 9050
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
# --- tor-route.sh end ---
EOF

    run cmd_check
    assert_success
    assert_output --partial "Status:    Running"
    assert_output --partial "Our block: present"
    assert_output --partial "    TransPort 127.0.0.1:9040"
    assert_output --partial "Bootstrapped 100%"
    assert_output --partial "COUNTRY_FILE:  $COUNTRY_FILE  (exists)"
}

@test "check fails its verdict when torrc and the Tor user are missing" {
    allow_command_guards
    make_check_stubs
    detect_tor_user() { TOR_UID=""; TOR_USER=""; }
    rm -f "$TORRC"

    run cmd_check
    assert_success
    assert_output --partial "Exists:    no"
    assert_output --partial "Found:     none"
    assert_output --partial "Some checks failed"
}

@test "check tolerates missing tor while routing stays active" {
    allow_command_guards
    make_check_stubs
    make_firewall_stubs
    hide_commands tor
    detect_tor_user() { TOR_UID=""; TOR_USER=""; }
    export CT_TEST_ROUTING=1 CT_TEST_IPV6=available CT_TEST_IPV6_VERIFY=ok
    printf 'SocksPort 9050\n' > "$TORRC"

    run cmd_check
    assert_success
    assert_output --partial "missing but routing active — stop still works"
    assert_output --partial "none (routing active — stop still works)"
    assert_output --partial "NAT OUTPUT:"
    assert_output --partial "Filter OUTPUT:"
    assert_output --partial "IPv6 policy:  Blocked"
}

@test "check reports allowed and unavailable IPv6 policies" {
    allow_command_guards
    make_check_stubs
    make_firewall_stubs
    make_id_stub
    export CT_TEST_ROUTING=1 CT_TEST_IPV6=available CT_TEST_IPV6_VERIFY=fail
    printf 'SocksPort 9050\n' > "$TORRC"

    run cmd_check
    assert_output --partial "IPv6 policy:  Not blocked (policy ACCEPT)"

    hide_commands ip6tables
    run cmd_check
    assert_output --partial "ip6tables: not available"
}

@test "check tails TOR_LOG_FILE on non-systemd inits" {
    allow_command_guards
    INIT=openrc
    TOR_LOG_FILE="$TEST_TMP/tor.log"
    printf 'boot line\nlast line\n' > "$TOR_LOG_FILE"
    make_check_stubs
    make_id_stub
    printf 'SocksPort 9050\n' > "$TORRC"

    run cmd_check
    assert_success
    assert_output --partial "Source:    $TOR_LOG_FILE (tail, last 5 lines)"
    assert_output --partial "last line"

    : > "$TOR_LOG_FILE"
    run cmd_check
    assert_success
    assert_output --partial "(empty)"

    rm -f "$TOR_LOG_FILE"
    run cmd_check
    assert_success
    assert_output --partial "not found - not required"
}

# ── status: remaining branches ────────────────────────────────────────────────

@test "status flags a resolver unit that is not masked" {
    allow_command_guards
    RESOLVED_UNITS=(unit-a.service unit-b.socket)
    export CT_TEST_ROUTING=1 CT_TEST_IPV4=203.0.113.7 CT_TEST_MASKED_UNITS="unit-b.socket"

    run cmd_status status
    assert_success
    assert_output --partial "DNS (unit-a.service): NOT masked - may leak!"
    refute_output --partial "All units masked"
}

@test "status with routing off reports an active systemd-resolved as normal" {
    allow_command_guards
    export CT_TEST_ROUTING=0 CT_TEST_IPV4=203.0.113.7 CT_TEST_RESOLVED_RUNNING=1

    run cmd_status status
    assert_success
    assert_output --partial "systemd-resolved active (normal, not routed)"
}

@test "check reports resolv.conf type and pre-start resolver state (mount namespace)" {
    needs_mountns
    run unshare -rm env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/resolv-netns.sh" check-resolv
    assert_success
    assert_output --partial "PASS:"
}
