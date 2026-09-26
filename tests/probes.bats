#!/usr/bin/env bats
# show_ip reporting (IPv4/IPv6 labelling, geo-provider fallback), the traffic
# probes and the country-pin fallback default.

load 'helpers/setup'

setup() {
    setup_test
    make_curl_stub
    make_firewall_stubs
    make_sleep_stub
}

# ── show_ip ───────────────────────────────────────────────────────────────────

@test "show_ip flags an IPv6 address as a leak while routing is active" {
    export CT_TEST_IPV4=203.0.113.7 CT_TEST_IPV6_ADDR=2001:db8::1 CT_TEST_ROUTING=1
    run show_ip
    assert_success
    assert_output --partial "IPv4: 203.0.113.7"
    assert_output --partial "IPv6: 2001:db8::1"
    assert_output --partial "LEAK!"
}

@test "show_ip prints the host's own IPv6 address without an alarm when routing is off" {
    export CT_TEST_IPV4=203.0.113.7 CT_TEST_IPV6_ADDR=2001:db8::1 CT_TEST_ROUTING=0
    run show_ip
    assert_success
    assert_output --partial "IPv6: 2001:db8::1"
    refute_output --partial "LEAK!"
}

@test "show_ip reports IPv6 as blocked while routing is active with no reachable address" {
    export CT_TEST_IPV4=203.0.113.7 CT_TEST_ROUTING=1 CT_TEST_IPV6_ADDR=""
    run show_ip
    assert_success
    assert_output --partial "Blocked"
    refute_output --partial "LEAK!"
}

@test "show_ip reports IPv6 as unreachable when routing is off" {
    export CT_TEST_IPV4=203.0.113.7 CT_TEST_ROUTING=0 CT_TEST_IPV6_ADDR=""
    run show_ip
    assert_success
    assert_output --partial "not configured / unreachable"
}

@test "show_ip warns when the IPv4 address cannot be fetched" {
    export CT_TEST_IPV4="" CT_TEST_CURL_OK=0
    run show_ip
    assert_success
    assert_output --partial "could not fetch"
}

@test "show_ip uses the primary geo provider when it answers" {
    export CT_TEST_IPV4=203.0.113.7 CT_TEST_GEO_PRIMARY=ok CT_TEST_GEO_FALLBACK=ok
    run show_ip
    assert_success
    assert_output --partial "Country: Germany (DE)"
    assert_output --partial "ISP/Org: Primary ISP"
    assert_file_contains "$STUB_LOG" 'ipwho.is/203.0.113.7'
    assert_file_not_contains "$STUB_LOG" 'ipwhois.app'
}

@test "show_ip falls back to the second geo provider when the first is rate-limited" {
    export CT_TEST_IPV4=203.0.113.7 CT_TEST_GEO_PRIMARY=ratelimited CT_TEST_GEO_FALLBACK=ok
    run show_ip
    assert_success
    assert_output --partial "Country: France (FR)"
    assert_output --partial "ISP/Org: Fallback ISP"
    refute_output --partial "Germany"
    assert_file_contains "$STUB_LOG" 'ipwhois.app/json/203.0.113.7'
}

@test "show_ip says the lookup is unavailable when every geo provider fails" {
    export CT_TEST_IPV4=203.0.113.7 CT_TEST_GEO_PRIMARY=ratelimited CT_TEST_GEO_FALLBACK=fail
    run show_ip
    assert_success
    assert_output --partial "Country/ISP: lookup unavailable"
    refute_output --partial "Country:"
}

# ── probe_traffic / wait_for_new_ip ───────────────────────────────────────────

@test "probe_traffic returns success as soon as a request succeeds" {
    export CT_TEST_CURL_OK=1
    run probe_traffic
    assert_success
    assert_output --partial "."
}

@test "probe_traffic gives up after its bounded retries" {
    export CT_TEST_CURL_OK=0 CT_TEST_IPV4=""
    run probe_traffic
    assert_failure
    refute_output --partial "success"
}

@test "wait_for_new_ip succeeds when the exit IP changes" {
    printf '%s\n' "198.51.100.1" "198.51.100.2" > "$TEST_TMP/ips"
    export CT_TEST_IPV4_FILE="$TEST_TMP/ips"
    run wait_for_new_ip "198.51.100.1"
    assert_success
}

@test "wait_for_new_ip fails when the IP never changes" {
    printf '%s\n' "198.51.100.1" > "$TEST_TMP/ips"
    export CT_TEST_IPV4_FILE="$TEST_TMP/ips"
    run wait_for_new_ip "198.51.100.1"
    assert_failure
}

# ── prompt_country_fallback ───────────────────────────────────────────────────

@test "prompt_country_fallback defaults to abort with no usable terminal" {
    needs_commands setsid

    # setsid detaches the controlling terminal, so opening /dev/tty fails and
    # the function cannot ask: EOF/timeout must resolve to "abort".
    run setsid bash -c "
        source '$HELPERS_DIR/setup.bash'
        TEST_TMP='$TEST_TMP' init_test_env
        prompt_country_fallback de
    " </dev/null
    assert_failure
    assert_output --partial "Traffic is not flowing with the exit node pinned to DE"
}
