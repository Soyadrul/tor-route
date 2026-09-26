#!/usr/bin/env bats
# Command dispatcher: usage output, root gates and argument validation.
# These tests never reach the mutating parts of start/stop/newnode: the root
# gate or the argument checks stop first, and where the flow continues the
# entry guards are overridden.

load 'helpers/setup'

setup() { setup_test; }

@test "no arguments prints usage and exits 1" {
    run /bin/bash "$TOR_ROUTE_UNDER_TEST"
    assert_failure
    assert_output --partial "Usage:"
    assert_output --partial "start|stop|status|newnode|countries|check"
}

@test "an unknown command prints usage and exits 1" {
    run /bin/bash "$TOR_ROUTE_UNDER_TEST" bogus
    assert_failure
    assert_output --partial "Usage:"
}

@test "root-only commands refuse to run as a normal user" {
    skip_if_root
    local cmd
    for cmd in start stop status newnode check; do
        run /bin/bash "$TOR_ROUTE_UNDER_TEST" "$cmd"
        assert_failure
        assert_output --partial "Must be run as root"
    done
}

# The guards are overridden so the help/validation branches are reachable
# without root; nothing mutating is reached in these tests.
override_entry_guards() {
    require_root() { :; }
    acquire_command_lock() { :; }
    require_init() { :; }
    check_dependencies() { :; }
    is_routing_active() { return 1; }
}

@test "start --help prints usage and exits 0" {
    override_entry_guards
    run cmd_start start --help
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "start [CC]"
}

@test "newnode -h prints usage and exits 0" {
    require_root() { :; }
    acquire_command_lock() { :; }
    require_init() { :; }
    check_net_tools() { :; }
    service_tor_running() { return 0; }
    is_routing_active() { return 0; }
    run cmd_newnode newnode -h
    assert_success
    assert_output --partial "Usage:"
    assert_output --partial "newnode [CC]"
}

@test "start rejects extra arguments before touching anything" {
    require_root() { :; }
    acquire_command_lock() { :; }
    run cmd_start start us extra
    assert_failure
    assert_output --partial "Unexpected argument(s): extra"
}

@test "newnode rejects extra arguments before touching anything" {
    require_root() { :; }
    acquire_command_lock() { :; }
    run cmd_newnode newnode us extra
    assert_failure
    assert_output --partial "Unexpected argument(s): extra"
}

@test "start rejects an unknown country code" {
    override_entry_guards
    run cmd_start start zz
    assert_failure
    assert_output --partial "Unknown country code: 'ZZ'"
}
