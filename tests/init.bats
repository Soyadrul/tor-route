#!/usr/bin/env bats
# Init-system detection and configuration (detect_init/require_init). Every
# other test file presets INIT or overrides require_init, so this is the only
# place the real detection paths run.

load 'helpers/setup'

setup() { setup_test; }

# detect_init reads /proc/1/comm via cat; override cat only for that path and
# delegate every other invocation to the real binary.
stub_pid1() {
    TOR_ROUTE_TEST_PID1="$1"
    cat() {
        if [[ "${1:-}" == "/proc/1/comm" ]]; then printf '%s\n' "$TOR_ROUTE_TEST_PID1"; return 0; fi
        command cat "$@"
    }
}

@test "detect_init maps known pid1 names" {
    stub_pid1 systemd
    run detect_init
    assert_success
    assert_output "systemd"

    stub_pid1 openrc-init
    run detect_init
    assert_output "openrc"

    stub_pid1 openrc
    run detect_init
    assert_output "openrc"

    stub_pid1 runit
    run detect_init
    assert_output "runit"
}

@test "detect_init treats pid1 'init' without OpenRC as SysVinit" {
    stub_pid1 init
    hide_commands openrc

    run detect_init
    assert_success
    assert_output "sysvinit"
}

@test "detect_init treats pid1 'init' with the openrc command as OpenRC" {
    stub_pid1 init
    make_stub openrc <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

    run detect_init
    assert_success
    assert_output "openrc"
}

@test "detect_init falls back to systemctl for an unknown pid1" {
    stub_pid1 weird
    make_stub systemctl <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

    run detect_init
    assert_success
    assert_output "systemd"
}

@test "detect_init falls back to rc-service when systemctl is absent" {
    stub_pid1 weird
    hide_commands systemctl
    make_stub rc-service <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

    run detect_init
    assert_success
    assert_output "openrc"
}

@test "detect_init falls back to runsvdir when systemctl and rc-service are absent" {
    stub_pid1 weird
    hide_commands systemctl rc-service
    make_stub runsvdir <<'STUB'
#!/usr/bin/env bash
exit 0
STUB

    run detect_init
    assert_success
    assert_output "runit"
}

@test "detect_init fails when no init system can be identified" {
    stub_pid1 weird
    hide_commands systemctl rc-service runsvdir

    run detect_init
    assert_failure
    assert_output ""
}

@test "require_init configures the systemd unit list and log source" {
    stub_pid1 systemd

    run require_init
    assert_success
    assert_output --partial "Init system:"
    assert_output --partial "systemd"

    # Variable assignments need the direct call: `run` uses a subshell.
    require_init
    assert_equal "$INIT" "systemd"
    assert_equal "${RESOLVED_UNITS[*]}" \
        "systemd-resolved-varlink.socket systemd-resolved-monitor.socket systemd-resolved.service"
    assert_equal "$TOR_LOG_FILE" ""
}

@test "require_init configures log paths for non-systemd inits" {
    stub_pid1 openrc
    require_init
    assert_equal "$INIT" "openrc"
    assert_equal "$TOR_LOG_FILE" "/var/log/tor/log"
    assert_equal "${#RESOLVED_UNITS[@]}" "0"

    stub_pid1 runit
    require_init
    assert_equal "$INIT" "runit"
    assert_equal "$TOR_LOG_FILE" "/var/log/tor/current"
    assert_equal "${#RESOLVED_UNITS[@]}" "0"

    # A SysVinit host reports pid1 as "init" without the openrc command.
    hide_commands openrc
    stub_pid1 init
    require_init
    assert_equal "$INIT" "sysvinit"
    assert_equal "$TOR_LOG_FILE" "/var/log/tor/log"
}

@test "require_init rejects an unknown init system value" {
    detect_init() { echo "weirdinit"; }

    run require_init
    assert_failure
    assert_output --partial "Not supported"
    assert_output --partial "weirdinit"
}

@test "require_init fails when detection fails" {
    stub_pid1 weird
    hide_commands systemctl rc-service runsvdir

    run require_init
    assert_failure
    assert_output --partial "Could not detect init system"
}
