#!/usr/bin/env bats
# Service/resolver dispatch per init system and the restore_tor_service
# lifecycle, including the "keep tor-state until torrc cleanup succeeds"
# hardening (ba8d58f). SysVinit's absolute /etc/init.d/tor path is exercised
# in a mount namespace by helpers/service-sysvinit-netns.sh.

load 'helpers/setup'

setup() {
    setup_test
    make_systemd_stubs
}

@test "service_tor_* dispatches to systemd commands" {
    run service_tor_start
    assert_success
    run service_tor_stop
    assert_success
    run service_tor_restart
    assert_success
    run service_tor_reload
    assert_success

    run service_tor_running
    assert_failure
    export CT_TEST_TOR_RUNNING=1
    run service_tor_running
    assert_success

    export CT_TEST_RELOAD_FAIL=1
    run service_tor_reload
    assert_failure

    assert_file_contains "$STUB_LOG" '^systemctl start tor$'
    assert_file_contains "$STUB_LOG" '^systemctl stop tor$'
    assert_file_contains "$STUB_LOG" '^systemctl restart tor$'
    assert_file_contains "$STUB_LOG" '^systemctl kill --signal=SIGHUP tor$'
}

@test "service_tor_* dispatches to OpenRC commands" {
    INIT=openrc
    make_stub rc-service <<'STUB'
#!/usr/bin/env bash
printf 'rc-service %s\n' "$*" >> "$STUB_LOG"
[[ "$*" == "tor status" ]] && exit "${CT_TEST_OPENRC_STATUS:-0}"
exit 0
STUB

    run service_tor_start
    assert_success
    run service_tor_reload
    assert_success
    run service_tor_running
    assert_success
    export CT_TEST_OPENRC_STATUS=3
    run service_tor_running
    assert_failure

    assert_file_contains "$STUB_LOG" '^rc-service tor start$'
    assert_file_contains "$STUB_LOG" '^rc-service tor reload$'
    assert_file_contains "$STUB_LOG" '^rc-service tor status$'
}

@test "service_tor_* dispatches to Runit commands" {
    INIT=runit
    make_stub sv <<'STUB'
#!/usr/bin/env bash
printf 'sv %s\n' "$*" >> "$STUB_LOG"
[[ "$*" == "status tor" ]] && exit "${CT_TEST_RUNIT_STATUS:-0}"
exit 0
STUB

    run service_tor_start
    assert_success
    run service_tor_reload
    assert_success
    run service_tor_running
    assert_success
    export CT_TEST_RUNIT_STATUS=1
    run service_tor_running
    assert_failure

    assert_file_contains "$STUB_LOG" '^sv start tor$'
    assert_file_contains "$STUB_LOG" '^sv reload tor$'
    assert_file_contains "$STUB_LOG" '^sv status tor$'
}

@test "an unknown init system fails loudly instead of guessing" {
    INIT="weirdinit"
    run service_tor_start
    assert_failure
    assert_output --partial "not supported"
}

@test "service_tor_log tails TOR_LOG_FILE on OpenRC instead of using journalctl" {
    INIT=openrc
    TOR_LOG_FILE="$TEST_TMP/tor.log"
    printf 'boot line\nlast line\n' > "$TOR_LOG_FILE"

    run service_tor_log
    assert_success
    assert_output --partial "last line"
    assert_file_not_contains "$STUB_LOG" 'journalctl'
}

@test "resolver_running is systemd-only" {
    run resolver_running
    assert_failure
    export CT_TEST_RESOLVED_RUNNING=1
    run resolver_running
    assert_success

    INIT=openrc
    export CT_TEST_RESOLVED_RUNNING=1
    run resolver_running
    assert_failure
}

@test "restore_tor_service stops Tor and removes the block when Tor was not running" {
    printf 'SocksPort 9050\n' > "$TORRC"
    run configure_torrc us
    assert_success
    printf 'no\n' > "$TOR_STATE_FILE"

    run restore_tor_service
    assert_success
    assert_output --partial "Tor stopped"
    assert_file_contains "$STUB_LOG" '^systemctl stop tor$'
    assert_file_not_contains "$TORRC" 'tor-route.sh start'
    assert_file_contains "$TORRC" '^SocksPort 9050$'
    assert_file_not_exists "$TOR_STATE_FILE"
    assert_file_not_exists "$COUNTRY_FILE"
}

@test "restore_tor_service cleans torrc and restarts Tor when it was running" {
    printf 'SocksPort 9050\n' > "$TORRC"
    run configure_torrc de
    assert_success
    printf 'yes\n' > "$TOR_STATE_FILE"

    run restore_tor_service
    assert_success
    assert_output --partial "Tor service restored"
    assert_file_contains "$STUB_LOG" '^systemctl restart tor$'
    assert_file_not_contains "$TORRC" 'tor-route.sh start'
    assert_file_contains "$TORRC" '^SocksPort 9050$'
    assert_file_not_exists "$TOR_STATE_FILE"
}

@test "restore_tor_service keeps the state file when torrc cleanup aborts (retry stays correct)" {
    cat > "$TORRC" <<'EOF'
# --- tor-route.sh start ---
user-owned-below
EOF
    mkdir -p "$STATE_DIR"
    printf 'yes\n' > "$TOR_STATE_FILE"

    run restore_tor_service
    assert_failure
    assert_output --partial "refusing to edit"
    assert_file_exists "$TOR_STATE_FILE"
    assert_file_not_contains "$STUB_LOG" '^systemctl restart tor$'
}

@test "restore_tor_service defaults to stopping Tor when no state file exists" {
    printf 'SocksPort 9050\n' > "$TORRC"
    rm -f "$TOR_STATE_FILE"

    run restore_tor_service
    assert_success
    assert_file_contains "$STUB_LOG" '^systemctl stop tor$'
    assert_file_not_contains "$TORRC" 'tor-route.sh start'
}

@test "detect_tor_user picks the first existing account from TOR_USERS" {
    TOR_UID="" TOR_USER=""
    make_id_stub

    detect_tor_user
    assert_equal "$TOR_UID" "4242"
    assert_equal "$TOR_USER" "tor"
}

@test "_banner_commit prints STABLE or the short commit" {
    COMMIT="STABLE"
    run _banner_commit
    assert_output "(STABLE)"

    COMMIT="abc1234"
    run _banner_commit
    assert_output "(abc1234)"
}

@test "SysVinit dispatch uses /etc/init.d/tor (mount namespace)" {
    needs_mountns
    run unshare -rm env TEST_TMP="$TEST_TMP" TOR_ROUTE_UNDER_TEST="$TOR_ROUTE_UNDER_TEST" \
        bash "$HELPERS_DIR/service-sysvinit-netns.sh"
    assert_success
    assert_output --partial "PASS:"
}
