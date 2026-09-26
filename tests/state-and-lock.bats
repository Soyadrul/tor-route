#!/usr/bin/env bats
# State directory and advisory lock hardening: permissions, symlink refusals
# and mutual exclusion for the mutating commands.

load 'helpers/setup'

setup() { setup_test; }

@test "ensure_state_dir creates a 0700 directory" {
    run ensure_state_dir
    assert_success
    assert_dir_exists "$STATE_DIR"
    assert_file_permission 700 "$STATE_DIR"
}

@test "ensure_state_dir refuses a symlinked state directory" {
    ln -s "$TEST_TMP/elsewhere" "$STATE_DIR"

    run ensure_state_dir
    assert_failure
    assert_output --partial "symlink - refusing"
}

@test "ensure_state_dir refuses a state path that is not a directory" {
    printf 'not a dir\n' > "$STATE_DIR"

    run ensure_state_dir
    assert_failure
    assert_output --partial "not a directory"
}

@test "acquire_command_lock creates a 0600 lock file and succeeds" {
    run acquire_command_lock
    assert_success
    assert_file_exists "$COMMAND_LOCK_FILE"
    assert_file_permission 600 "$COMMAND_LOCK_FILE"
}

@test "acquire_command_lock refuses a symlinked lock file" {
    run ensure_state_dir
    assert_success
    ln -s /etc/passwd "$COMMAND_LOCK_FILE"

    run acquire_command_lock
    assert_failure
    assert_output --partial "symlink - refusing"
}

@test "acquire_command_lock fails fast while another process holds the lock" {
    run ensure_state_dir
    assert_success

    exec 8>>"$COMMAND_LOCK_FILE"
    flock -n 8

    run acquire_command_lock
    assert_failure
    assert_output --partial "Another tor-route command is already running"

    exec 8>&-
}

@test "read-only commands ignore a held advisory lock" {
    run ensure_state_dir
    assert_success
    exec 8>>"$COMMAND_LOCK_FILE"
    flock -n 8

    run /bin/bash "$TOR_ROUTE_UNDER_TEST" countries
    assert_success

    exec 8>&-
}
