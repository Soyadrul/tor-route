#!/usr/bin/env bash
# Namespace helper for the DNS and status tests. Runs inside `unshare -rm`
# (caller-enforced) so it can replace /etc with a private tmpfs or
# bind-mount a file over /etc/resolv.conf without touching the host.
#
# Usage: unshare -rm env TEST_TMP=... TOR_ROUTE_UNDER_TEST=... \
#            bash tests/helpers/resolv-netns.sh <mode>
# Modes: replace-bind | fix-dns-start | fix-dns-start-bind-fail |
#        fix-dns-stop | status-resolv

set -u

HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HELPERS_DIR/setup.bash"

fail() { echo "FAIL: $*" >&2; exit 1; }

TEST_TMP="${TEST_TMP:-$(mktemp -d)}"
export TEST_TMP
init_test_env

MODE="${1:-}"
[[ -n "$MODE" ]] || fail "no mode given"

isolate_etc() {
    mount -t tmpfs tmpfs /etc || fail "could not mount tmpfs over /etc"
}

write_resolv() {
    printf '%s\n' "$1" > /etc/resolv.conf || fail "could not write /etc/resolv.conf"
}

case "$MODE" in
replace-bind)
    # Ported from resolv-conf-replace-test.sh (BUGS.md #7): the helpers must
    # report failure (and leave no .tmp) when rename(2) cannot replace the
    # file because it is a bind mount.
    tmp="$TEST_TMP/replace"
    mkdir -p "$tmp"

    printf 'nameserver 9.9.9.9\n' > "$tmp/replaceable"
    replace_file_verified "$tmp/replaceable" "nameserver 127.0.0.1" \
        || fail "normal replacement must succeed"
    [[ "$(cat "$tmp/replaceable")" == "nameserver 127.0.0.1" ]] || fail "content not replaced"
    compgen -G "$tmp/replaceable.tmp" >/dev/null && fail "leftover .tmp file"

    printf 'nameserver 9.9.9.9\n' > "$tmp/bound_src"
    printf 'nameserver 1.1.1.1\n' > "$tmp/bound"
    mount --bind "$tmp/bound_src" "$tmp/bound" || fail "could not set up bind mount"
    if replace_file_verified "$tmp/bound" "nameserver 127.0.0.1"; then
        fail "replacement over a bind mount must fail"
    fi
    [[ "$(cat "$tmp/bound")" == "nameserver 9.9.9.9" ]] || fail "bind-mounted file was modified"
    compgen -G "$tmp/bound.tmp" >/dev/null && fail "leftover .tmp file after failure"

    printf 'nameserver 9.9.9.9\n' > "$tmp/link_target"
    link_file_verified "$tmp/mylink" "$tmp/link_target" || fail "normal symlink must succeed"
    [[ "$(readlink "$tmp/mylink")" == "$tmp/link_target" ]] || fail "symlink target wrong"

    printf 'nameserver 9.9.9.9\n' > "$tmp/bound_link_src"
    printf 'nameserver 1.1.1.1\n' > "$tmp/bound_link"
    mount --bind "$tmp/bound_link_src" "$tmp/bound_link" || fail "could not set up link bind mount"
    if link_file_verified "$tmp/bound_link" "$tmp/link_target"; then
        fail "symlink over a bind mount must fail"
    fi

    echo "PASS: resolv.conf replacement helpers detect bind-mount failures"
    ;;

fix-dns-start)
    # Success path: backup, masking record and the verified swap to Tor.
    isolate_etc
    write_resolv "nameserver 198.51.100.53"
    INIT=systemd
    RESOLVED_UNITS=(unit-a.service unit-b.socket)
    make_systemd_stubs
    export CT_TEST_RESOLVED_RUNNING=1 CT_TEST_MASKED_UNITS="unit-b.socket"

    out=$(fix_dns_start 2>&1) || fail "fix_dns_start failed: $out"
    [[ "$(cat /etc/resolv.conf)" == "nameserver 127.0.0.1" ]] || fail "resolv.conf not pointed at Tor"
    [[ -f "$RESOLV_BACKUP" ]] || fail "no resolv.conf backup"
    [[ "$(cat "$RESOLV_BACKUP")" == "nameserver 198.51.100.53" ]] || fail "backup content wrong"
    [[ "$(stat -c %a "$RESOLV_BACKUP")" == "600" ]] || fail "backup is not 0600"
    [[ "$(cat "$RESOLVED_STATE_FILE")" == "yes" ]] || fail "resolved-state not recorded as yes"
    grep -qx 'unit-a.service' "$RESOLVED_MASK_STATE_FILE" || fail "newly masked unit not recorded"
    grep -qx 'unit-b.socket' "$RESOLVED_MASK_STATE_FILE" \
        && fail "already-masked unit must not be recorded for unmasking"
    grep -q '^systemctl mask --now unit-a.service$' "$STUB_LOG" || fail "unit-a was not masked"
    grep -q '^systemctl mask --now unit-b.socket$' "$STUB_LOG" || fail "unit-b was not masked"
    grep -q '/etc/resolv.conf → 127.0.0.1' <<<"$out" || fail "success message missing"

    # Second run with the resolver stopped: it must be recorded as not running.
    rm -rf "$STATE_DIR"
    : > "$STUB_LOG"
    export CT_TEST_RESOLVED_RUNNING=0
    out=$(fix_dns_start 2>&1) || fail "fix_dns_start failed without a resolver: $out"
    [[ "$(cat "$RESOLVED_STATE_FILE")" == "no" ]] || fail "resolved-state not recorded as no"

    echo "PASS: fix_dns_start backs up, records and verifies"
    ;;

fix-dns-start-bind-fail)
    # BUGS.md #7: when the swap cannot happen (bind mount), fix_dns_start must
    # return non-zero and must not claim the resolver was repointed.
    isolate_etc
    write_resolv "nameserver 198.51.100.53"
    printf 'nameserver 203.0.113.9\n' > "$TEST_TMP/bound"
    mount --bind "$TEST_TMP/bound" /etc/resolv.conf || fail "could not bind mount resolv.conf"

    INIT=systemd
    RESOLVED_UNITS=(unit-a.service)
    make_systemd_stubs

    if out=$(fix_dns_start 2>&1); then
        fail "fix_dns_start must fail on a bind-mounted resolv.conf"
    fi
    grep -q 'NOT repointed' <<<"$out" || fail "no explicit failure message"
    grep -q '→ 127.0.0.1' <<<"$out" && fail "claimed success over a failed swap"
    [[ "$(cat /etc/resolv.conf)" == "nameserver 203.0.113.9" ]] || fail "bind-mounted file changed"

    echo "PASS: fix_dns_start refuses to claim a failed resolv.conf swap"
    ;;

fix-dns-stop)
    isolate_etc

    # No state files: nothing to restore, resolv.conf untouched.
    rm -rf "$STATE_DIR"
    write_resolv "nameserver 127.0.0.53"
    out=$(fix_dns_stop 2>&1) || fail "fix_dns_stop failed on a clean host"
    grep -q 'DNS was not modified' <<<"$out" || fail "no no-op message"
    [[ "$(cat /etc/resolv.conf)" == "nameserver 127.0.0.53" ]] || fail "clean resolv.conf was modified"

    # Resolver was not running before: restore the static backup, stay stopped.
    mkdir -p "$STATE_DIR"
    printf 'no\n' > "$RESOLVED_STATE_FILE"
    printf 'nameserver 198.51.100.53\n' > "$RESOLV_BACKUP"
    chmod 600 "$RESOLV_BACKUP"
    write_resolv "nameserver 127.0.0.1"
    out=$(fix_dns_stop 2>&1) || fail "fix_dns_stop failed to restore the backup: $out"
    [[ "$(cat /etc/resolv.conf)" == "nameserver 198.51.100.53" ]] || fail "backup not restored"
    [[ ! -f "$RESOLV_BACKUP" && ! -f "$RESOLVED_STATE_FILE" ]] || fail "DNS state files not consumed"
    grep -q 'resolv.conf restored from backup' <<<"$out" || fail "restore message missing"

    # No backup and no symlink preference: generic fallback.
    mkdir -p "$STATE_DIR"
    printf 'no\n' > "$RESOLVED_STATE_FILE"
    rm -f "$RESOLV_BACKUP"
    write_resolv "nameserver 127.0.0.1"
    out=$(fix_dns_stop 2>&1) || fail "fix_dns_stop failed to write the fallback: $out"
    [[ "$(cat /etc/resolv.conf)" == "nameserver 1.1.1.1" ]] || fail "generic fallback not written"
    grep -q 'generic resolv.conf fallback' <<<"$out" || fail "fallback message missing"

    # Masked units: only the recorded ones are unmasked, resolver restarted
    # only because it was running before.
    rm -rf "$STATE_DIR"
    mkdir -p "$STATE_DIR"
    printf 'yes\n' > "$RESOLVED_STATE_FILE"
    printf 'unit-a.service\n' > "$RESOLVED_MASK_STATE_FILE"
    INIT=systemd
    make_systemd_stubs
    : > "$STUB_LOG"
    out=$(fix_dns_stop 2>&1) || fail "fix_dns_stop failed to unmask: $out"
    grep -q '^systemctl unmask unit-a.service$' "$STUB_LOG" || fail "recorded unit was not unmasked"
    grep -q '^systemctl start systemd-resolved.service$' "$STUB_LOG" || fail "resolver was not restarted"
    [[ ! -f "$RESOLVED_MASK_STATE_FILE" ]] || fail "mask state file not consumed"
    grep -q 'DNS resolver restored' <<<"$out" || fail "resolver restore message missing"

    echo "PASS: fix_dns_stop guards, restores and unmasks"
    ;;

status-resolv)
    # `status` on a non-systemd init must judge /etc/resolv.conf against Tor.
    isolate_etc
    INIT=openrc
    make_firewall_stubs
    make_curl_stub
    export CT_TEST_ROUTING=1 CT_TEST_IPV4=203.0.113.7

    require_root() { :; }
    require_init() { :; }
    check_net_tools() { :; }
    service_tor_running() { return 1; }

    write_resolv "nameserver 127.0.0.1"
    out=$(cmd_status status 2>&1) || fail "status failed with a Tor-pointing resolv.conf: $out"
    grep -q '/etc/resolv.conf → Tor' <<<"$out" || fail "Tor-pointing resolv.conf not recognised"

    write_resolv "nameserver 1.1.1.1"
    out=$(cmd_status status 2>&1) || fail "status failed with a direct resolv.conf: $out"
    grep -q 'resolv.conf NOT pointing at Tor' <<<"$out" || fail "non-Tor resolv.conf not flagged"

    echo "PASS: status judges resolv.conf on non-systemd inits"
    ;;

*)
    fail "unknown mode: $MODE"
    ;;
esac

exit 0
