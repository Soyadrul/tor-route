#!/usr/bin/env bats
# Country-code validation and the `countries` command.

load 'helpers/setup'

setup() { setup_test; }

@test "VALID_COUNTRIES holds the 249 ISO 3166-1 alpha-2 codes, unique and lowercase" {
    assert_equal "${#VALID_COUNTRIES[@]}" "249"
    local -A seen=()
    local cc
    for cc in "${VALID_COUNTRIES[@]}"; do
        [[ "$cc" =~ ^[a-z]{2}$ ]] || fail "not a lowercase 2-letter code: '$cc'"
        [[ -z "${seen[$cc]:-}" ]] || fail "duplicate code: $cc"
        seen[$cc]=1
    done
}

@test "validate_country normalizes case and prints the accepted code" {
    run validate_country us
    assert_success
    assert_output "us"

    run validate_country US
    assert_success
    assert_output "us"

    run validate_country De
    assert_success
    assert_output "de"
}

@test "validate_country rejects unknown, malformed and empty input" {
    run validate_country zz
    assert_failure

    run validate_country usa
    assert_failure

    run validate_country u
    assert_failure

    run validate_country 12
    assert_failure

    run validate_country ""
    assert_failure
}

@test "countries command prints every code and works with an empty PATH (no root, no deps)" {
    run env PATH="$STUB_DIR" /bin/bash "$TOR_ROUTE_UNDER_TEST" countries
    assert_success

    local clean count
    clean=$(printf '%s' "$output" | sed 's/\x1b\[[0-9;]*m//g')
    count=$(printf '%s\n' "$clean" | grep -oE '\b[A-Z]{2}\b' | sort -u | wc -l)
    assert_equal "$count" "249"

    assert_output --partial "AD"
    assert_output --partial "ZW"
    assert_output --partial "Usage examples"
}
