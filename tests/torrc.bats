#!/usr/bin/env bats
# torrc management: strip_torrc_block's marker guards (BUGS.md #4),
# configure_torrc's marked block, cleanup_torrc and the newnode revert path
# (BUGS.md #3).

load 'helpers/setup'

setup() {
    setup_test
}

# count_markers start|end -> number of literal marker lines in $TORRC
count_markers() {
    local n
    n=$(grep -c "^# --- tor-route.sh $1 ---$" "$TORRC" 2>/dev/null || true)
    printf '%s' "${n:-0}"
}

# ── strip_torrc_block: well-formed and no-op cases ────────────────────────────

@test "strip removes only the marked block and keeps surrounding lines" {
    cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
# --- tor-route.sh end ---
user-after
EOF
    run strip_torrc_block
    assert_success
    assert_file_contains "$TORRC" '^user-before$'
    assert_file_contains "$TORRC" '^user-after$'
    assert_file_not_contains "$TORRC" 'tor-route.sh start'
    assert_file_not_contains "$TORRC" '^TransPort'
}

@test "strip is a no-op when torrc has no markers" {
    printf 'SocksPort 9050\n' > "$TORRC"
    cp "$TORRC" "$TEST_TMP/original"
    run strip_torrc_block
    assert_success
    assert_files_equal "$TORRC" "$TEST_TMP/original"
}

@test "strip is a no-op when torrc does not exist" {
    rm -f "$TORRC"
    run strip_torrc_block
    assert_success
}

# ── strip_torrc_block: malformed structures abort with a backup ───────────────

@test "start marker without end marker aborts, keeps torrc and writes a backup" {
    cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
user-owned-below
EOF
    cp "$TORRC" "$TEST_TMP/original"

    run strip_torrc_block
    assert_failure
    assert_output --partial "refusing to edit"
    assert_files_equal "$TORRC" "$TEST_TMP/original"
    assert_file_contains "$TORRC" '^user-owned-below$'

    run bash -c "compgen -G '$TORRC.tor-route-unterminated.*'"
    assert_success
    backup=$(printf '%s' "$output" | head -n1)
    assert_files_equal "$backup" "$TEST_TMP/original"
}

@test "end marker above the start marker aborts, keeps every line and writes a backup" {
    cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh end ---
user-middle
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
user-owned-below
EOF
    cp "$TORRC" "$TEST_TMP/out-of-order"

    run strip_torrc_block
    assert_failure
    assert_output --partial "out of order or nested"
    assert_files_equal "$TORRC" "$TEST_TMP/out-of-order"
    assert_file_contains "$TORRC" '^user-owned-below$'

    run bash -c "compgen -G '$TORRC.tor-route-unterminated.*'"
    assert_success
    backup=$(printf '%s' "$output" | head -n1)
    assert_files_equal "$backup" "$TEST_TMP/out-of-order"
}

@test "nested markers abort, keep every line and write a backup" {
    cat > "$TORRC" <<'EOF'
# --- tor-route.sh start ---
# --- tor-route.sh start ---
user-owned
# --- tor-route.sh end ---
# --- tor-route.sh end ---
EOF
    cp "$TORRC" "$TEST_TMP/nested"

    run strip_torrc_block
    assert_failure
    assert_output --partial "out of order or nested"
    assert_files_equal "$TORRC" "$TEST_TMP/nested"
    assert_file_contains "$TORRC" '^user-owned$'

    run bash -c "compgen -G '$TORRC.tor-route-unterminated.*'"
    assert_success
    backup=$(printf '%s' "$output" | head -n1)
    assert_files_equal "$backup" "$TEST_TMP/nested"
}

@test "a failing backup does not claim success and leaves no partial file" {
    cat > "$TORRC" <<'EOF'
user-before
# --- tor-route.sh start ---
user-owned-below
EOF
    cp "$TORRC" "$TEST_TMP/cp-fails"

    cp() { printf 'partial' > "$2"; return 1; }
    run strip_torrc_block
    assert_failure
    assert_output --partial "Could not write a backup"
    refute_output --partial "Backup written"
    assert_files_equal "$TORRC" "$TEST_TMP/cp-fails"

    run bash -c "compgen -G '$TORRC.tor-route-unterminated.*'"
    assert_failure
    assert_equal "$output" ""
}

@test "a marker lookalike (tor-routeXsh) is not treated as part of the block" {
    cat > "$TORRC" <<'EOF'
top
# --- tor-routeXsh start ---
user-owned-between
# --- tor-route.sh start ---
TransPort 127.0.0.1:9040
# --- tor-route.sh end ---
bottom
EOF
    run strip_torrc_block
    assert_success
    assert_file_contains "$TORRC" '^top$'
    assert_file_contains "$TORRC" '^user-owned-between$'
    assert_file_contains "$TORRC" '^bottom$'
    assert_file_contains "$TORRC" 'tor-routeXsh start'
    assert_file_not_contains "$TORRC" '^TransPort'
}

# ── configure_torrc / cleanup_torrc / revert ──────────────────────────────────

@test "configure_torrc writes the marked block, the pin and the country file" {
    printf 'SocksPort 9050\n' > "$TORRC"

    run configure_torrc us
    assert_success

    assert_file_contains "$TORRC" '^# --- tor-route\.sh start ---$'
    assert_file_contains "$TORRC" "^TransPort 127.0.0.1:${TOR_TRANS_PORT}$"
    assert_file_contains "$TORRC" "^DNSPort 127.0.0.1:${TOR_DNS_PORT}$"
    assert_file_contains "$TORRC" '^VirtualAddrNetworkIPv4 10\.192\.0\.0/10$'
    assert_file_contains "$TORRC" '^AutomapHostsOnResolve 1$'
    assert_file_contains "$TORRC" '^ExitNodes {us}$'
    assert_file_contains "$TORRC" '^StrictNodes 1$'
    assert_file_contains "$TORRC" '^SocksPort 9050$'
    assert_equal "$(count_markers start)" "1"
    assert_equal "$(count_markers end)" "1"

    assert_file_exists "$COUNTRY_FILE"
    assert_equal "$(cat "$COUNTRY_FILE")" "us"
    assert_file_permission 600 "$COUNTRY_FILE"
}

@test "configure_torrc with no country writes a random block and state" {
    printf 'SocksPort 9050\n' > "$TORRC"

    run configure_torrc ""
    assert_success

    assert_file_contains "$TORRC" "^TransPort 127.0.0.1:${TOR_TRANS_PORT}$"
    assert_file_not_contains "$TORRC" 'ExitNodes'
    assert_equal "$(cat "$COUNTRY_FILE")" "random"
}

@test "configure_torrc is idempotent: reapplying never duplicates the block" {
    printf 'SocksPort 9050\n' > "$TORRC"

    run configure_torrc us
    assert_success
    run configure_torrc de
    assert_success

    assert_equal "$(count_markers start)" "1"
    assert_equal "$(count_markers end)" "1"
    assert_equal "$(grep -c '^ExitNodes' "$TORRC" || true)" "1"
    assert_file_contains "$TORRC" '^ExitNodes {de}$'
    assert_file_not_contains "$TORRC" 'ExitNodes \{us\}'
    assert_file_contains "$TORRC" '^SocksPort 9050$'
}

@test "configure_torrc refuses to write through a symlinked country file" {
    run ensure_state_dir
    assert_success
    ln -s /etc/passwd "$COUNTRY_FILE"

    run configure_torrc us
    assert_failure
    assert_output --partial "symlink - refusing"
}

@test "cleanup_torrc removes the block and the country file, keeps user lines" {
    printf 'SocksPort 9050\n' > "$TORRC"
    run configure_torrc jp
    assert_success

    run cleanup_torrc
    assert_success
    assert_file_not_contains "$TORRC" 'tor-route.sh start'
    assert_file_contains "$TORRC" '^SocksPort 9050$'
    assert_file_not_exists "$COUNTRY_FILE"
}

@test "revert_torrc_to_previous restores the previous pin without duplicating" {
    printf 'SocksPort 9050\n' > "$TORRC"
    run configure_torrc de
    assert_success
    run configure_torrc us
    assert_success

    run revert_torrc_to_previous de
    assert_success
    assert_file_contains "$TORRC" '^ExitNodes {de}$'
    assert_file_not_contains "$TORRC" 'ExitNodes \{us\}'
    assert_equal "$(cat "$COUNTRY_FILE")" "de"
    assert_equal "$(count_markers start)" "1"
    assert_file_contains "$TORRC" '^SocksPort 9050$'
}

@test "revert_torrc_to_previous random clears the pin instead of pinning random" {
    printf 'SocksPort 9050\n' > "$TORRC"
    run configure_torrc jp
    assert_success

    run revert_torrc_to_previous random
    assert_success
    assert_file_not_contains "$TORRC" 'ExitNodes'
    assert_file_not_contains "$TORRC" 'StrictNodes'
    assert_equal "$(cat "$COUNTRY_FILE")" "random"
    assert_equal "$(count_markers start)" "1"
    assert_file_contains "$TORRC" '^SocksPort 9050$'
}
