# shellcheck shell=bash
# Shared helpers for the BATS regression suite in tests/.
#
# Usage in a test file:
#     load 'helpers/setup'
#     setup() { setup_test; }
#
# setup_test() sources tor-route.sh's functions WITHOUT executing the command
# dispatcher at the bottom of the script, then points every path the script
# can write (TORRC, STATE_DIR and all derived state files) at the test's
# private BATS temp directory. External commands are stubbed through a
# per-test STUB_DIR prepended to PATH, so the suite never touches the host's
# firewall, /etc/resolv.conf, /etc/tor/torrc, /run, or any real service.
#
# Namespace helpers (tests/helpers/*-netns.sh) run outside BATS; they set
# TEST_TMP themselves and call init_test_env(). Keep every function below
# free of BATS-only commands (skip, run, assert_*) unless it is only called
# from a *.bats file.

HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$HELPERS_DIR/../.." && pwd)"
TOR_ROUTE_UNDER_TEST="${TOR_ROUTE_UNDER_TEST:-$REPO_ROOT/tor-route.sh}"
export TOR_ROUTE_UNDER_TEST

# Source all functions and globals from the script under test, stopping
# before the `case "$1" in` dispatcher. Fails loudly when the script's shape
# changed so a moved dispatcher cannot silently make tests meaningless.
load_script() {
    [[ -f "$TOR_ROUTE_UNDER_TEST" ]] || {
        echo "tor-route.sh not found at $TOR_ROUTE_UNDER_TEST" >&2
        return 1
    }
    grep -q '^case "\$1" in' "$TOR_ROUTE_UNDER_TEST" || {
        echo "command dispatcher not found in $TOR_ROUTE_UNDER_TEST" >&2
        return 1
    }
    # shellcheck disable=SC1090
    source <(sed '/^case "\$1" in/,$d' "$TOR_ROUTE_UNDER_TEST")
}

# Redirect every script-written path below the test's temp directory.
apply_test_paths() {
    TORRC="$TEST_TMP/torrc"
    STATE_DIR="$TEST_TMP/state"
    IPTABLES_BACKUP="$STATE_DIR/iptables-pre-tor.rules"
    IP6TABLES_BACKUP="$STATE_DIR/ip6tables-pre-tor.rules"
    RESOLV_BACKUP="$STATE_DIR/resolv.conf.pre-tor"
    RESOLVED_STATE_FILE="$STATE_DIR/resolved-state"
    COUNTRY_FILE="$STATE_DIR/country"
    TOR_STATE_FILE="$STATE_DIR/tor-state"
    RESOLVED_MASK_STATE_FILE="$STATE_DIR/resolved-mask"
    COMMAND_LOCK_FILE="$STATE_DIR/lock"
}

# Deterministic sandbox for one test (BATS and namespace helpers alike).
init_test_env() {
    TEST_TMP="${TEST_TMP:-$(mktemp -d)}"
    STUB_DIR="$TEST_TMP/stubs"
    mkdir -p "$STUB_DIR"
    STUB_LOG="$TEST_TMP/stub.log"
    : > "$STUB_LOG"
    load_script
    apply_test_paths
    # Colour-free output keeps assertions readable; messages still render.
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
    INIT="${TEST_INIT:-systemd}"
    TOR_UID="${TEST_TOR_UID:-4242}"
    TOR_USER="${TEST_TOR_USER:-tor}"
    RESOLVED_UNITS=()
    PATH="$STUB_DIR:$PATH"
    export PATH TOR_ROUTE_UNDER_TEST TEST_TMP STUB_DIR STUB_LOG
}

# BATS entry point; every *.bats file's setup() calls this.
setup_test() {
    TEST_TMP="$BATS_TEST_TMPDIR"
    init_test_env
    export BATS_LIB_PATH="${BATS_LIB_PATH:-/usr/lib/bats}"
    bats_load_library bats-support
    bats_load_library bats-assert
    bats_load_library bats-file
}

fail() { echo "FAIL: $*" >&2; return 1; }

# Make `command -v` report the named commands as missing without touching
# PATH: BATS's own tooling (and the shell) needs the real PATH, and direct
# invocations must keep resolving. This mirrors how the script probes
# dependencies with `command -v`.
hide_commands() {
    local names=" $* "
    eval "command() {
        if [[ \"\${1:-}\" == \"-v\" && \"$names\" == *\" \${2:-} \"* ]]; then
            return 1
        fi
        builtin command \"\$@\"
    }"
}

# make_stub <name> <<'EOF' ... EOF
make_stub() {
    local name="$1"
    mkdir -p "$STUB_DIR"
    cat > "$STUB_DIR/$name"
    chmod +x "$STUB_DIR/$name"
}

# ── Skip helpers (BATS-only) ──────────────────────────────────────────────────
skip_if_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] && skip "must run unprivileged (root would mutate the host)"
    return 0
}

needs_commands() {
    local c
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || skip "$c not available"
    done
}

needs_netns() {
    command -v unshare >/dev/null 2>&1 || skip "unshare not available"
    unshare -rn true 2>/dev/null || skip "unprivileged user/network namespaces unavailable"
}

needs_mountns() {
    command -v unshare >/dev/null 2>&1 || skip "unshare not available"
    unshare -rm true 2>/dev/null || skip "unprivileged user/mount namespaces unavailable"
}

# ── Stub factories ────────────────────────────────────────────────────────────
# Every stub appends its arguments to $STUB_LOG and honours CT_TEST_* flags
# exported by the test, so tests can assert both the command sequence and the
# decision the script derived from the simulated world.

# iptables/ip6tables busybox-style stubs.
#   CT_TEST_ROUTING=1         -> -S/-L OUTPUT show the Tor REDIRECT rule
#   CT_TEST_ROUTING_LEGACY=1  -> only -L OUTPUT shows it (-S empty)
#   CT_TEST_UDP_BLOCKED=0     -> filter -S OUTPUT omits the UDP DROP rule
#   CT_TEST_IPV6=unavailable  -> ip6tables -L -n fails (no IPv6 stack)
#   CT_TEST_IPV6_VERIFY=fail  -> -L OUTPUT reports policy ACCEPT after -P DROP
#   CT_TEST_FAIL_IPTABLES_ON=<fragment>, CT_TEST_FAIL_IP6TABLES_ON=<fragment>
make_firewall_stubs() {
    make_stub iptables <<'STUB'
#!/usr/bin/env bash
printf 'iptables %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
if [[ -n "${CT_TEST_FAIL_IPTABLES_ON:-}" && "$*" == *"${CT_TEST_FAIL_IPTABLES_ON}"* ]]; then
    exit 1
fi
case "$*" in
    "-t nat -S OUTPUT")
        [[ "${CT_TEST_ROUTING:-0}" == "1" || "${CT_TEST_ROUTING_LEGACY:-0}" == "1" ]] && \
            echo "-A OUTPUT -p tcp -m state --state NEW -j REDIRECT --to-ports ${TOR_TRANS_PORT:-9040}"
        exit 0 ;;
    "-t nat -L OUTPUT -n")
        [[ "${CT_TEST_ROUTING:-0}" == "1" || "${CT_TEST_ROUTING_LEGACY:-0}" == "1" ]] && \
            echo "REDIRECT  tcp  --  0.0.0.0/0  0.0.0.0/0  tcp dpt:443 redir ports ${TOR_TRANS_PORT:-9040}"
        exit 0 ;;
    "-S OUTPUT")
        [[ "${CT_TEST_UDP_BLOCKED:-1}" == "1" ]] && echo "-A OUTPUT -p udp -j DROP"
        exit 0 ;;
esac
exit 0
STUB
    make_stub ip6tables <<'STUB'
#!/usr/bin/env bash
printf 'ip6tables %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
if [[ -n "${CT_TEST_FAIL_IP6TABLES_ON:-}" && "$*" == *"${CT_TEST_FAIL_IP6TABLES_ON}"* ]]; then
    exit 1
fi
case "$*" in
    "-L -n")
        [[ "${CT_TEST_IPV6:-available}" == "available" ]] && exit 0 || exit 1 ;;
    "-L OUTPUT -n")
        if [[ "${CT_TEST_IPV6_VERIFY:-ok}" == "fail" ]]; then
            echo "Chain OUTPUT (policy ACCEPT)"
        else
            echo "Chain OUTPUT (policy DROP)"
        fi
        exit 0 ;;
esac
exit 0
STUB
}

# iptables-save / iptables-restore stubs. Save writes a recognizable body;
# restore drains stdin and logs. Failures are steerable per family:
#   CT_TEST_SAVE_FAIL=v4|v6|both, CT_TEST_RESTORE_FAIL=v4|v6|both
make_save_restore_stubs() {
    make_stub iptables-save <<'STUB'
#!/usr/bin/env bash
printf 'iptables-save\n' >> "${STUB_LOG:-/dev/null}"
[[ "${CT_TEST_SAVE_FAIL:-}" == "v4" || "${CT_TEST_SAVE_FAIL:-}" == "both" ]] && exit 1
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' 'COMMIT' 'PRE-TOR-V4-RULES'
STUB
    make_stub ip6tables-save <<'STUB'
#!/usr/bin/env bash
printf 'ip6tables-save\n' >> "${STUB_LOG:-/dev/null}"
[[ "${CT_TEST_SAVE_FAIL:-}" == "v6" || "${CT_TEST_SAVE_FAIL:-}" == "both" ]] && exit 1
printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' 'COMMIT' 'PRE-TOR-V6-RULES'
STUB
    make_stub iptables-restore <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
printf 'iptables-restore\n' >> "${STUB_LOG:-/dev/null}"
[[ "${CT_TEST_RESTORE_FAIL:-}" == "v4" || "${CT_TEST_RESTORE_FAIL:-}" == "both" ]] && exit 1
exit 0
STUB
    make_stub ip6tables-restore <<'STUB'
#!/usr/bin/env bash
cat >/dev/null
printf 'ip6tables-restore\n' >> "${STUB_LOG:-/dev/null}"
[[ "${CT_TEST_RESTORE_FAIL:-}" == "v6" || "${CT_TEST_RESTORE_FAIL:-}" == "both" ]] && exit 1
exit 0
STUB
}

# systemctl stub (the suite defaults INIT=systemd).
#   CT_TEST_TOR_RUNNING=1, CT_TEST_RESOLVED_RUNNING=1
#   CT_TEST_MASKED_UNITS="unitA unitB" -> those is-enabled print "masked"
#   CT_TEST_RELOAD_FAIL=1 -> kill --signal=SIGHUP fails
make_systemd_stubs() {
    make_stub systemctl <<'STUB'
#!/usr/bin/env bash
printf 'systemctl %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
case "$*" in
    "is-active --quiet tor")
        [[ "${CT_TEST_TOR_RUNNING:-0}" == "1" ]] && exit 0 || exit 3 ;;
    "is-active --quiet systemd-resolved.service")
        [[ "${CT_TEST_RESOLVED_RUNNING:-0}" == "1" ]] && exit 0 || exit 3 ;;
    "is-enabled "*)
        unit="$2"
        case " ${CT_TEST_MASKED_UNITS:-} " in
            *" $unit "*) echo "masked" ;;
            *)           echo "enabled" ;;
        esac
        exit 0 ;;
    "kill --signal=SIGHUP tor")
        [[ "${CT_TEST_RELOAD_FAIL:-0}" == "1" ]] && exit 1 || exit 0 ;;
esac
exit 0
STUB
}

# ss stub: CT_TEST_PORTS=1 makes both Tor ports appear listening.
make_ss_stub() {
    make_stub ss <<'STUB'
#!/usr/bin/env bash
printf 'ss %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
[[ "${CT_TEST_PORTS:-0}" == "1" ]] || exit 0
case "$*" in
    *-tlnp*) echo "LISTEN 0 128 127.0.0.1:${TOR_TRANS_PORT:-9040} 0.0.0.0:*" ;;
    *-ulnp*) echo "UNCONN 0 0 127.0.0.1:${TOR_DNS_PORT:-9053} 0.0.0.0:*" ;;
esac
exit 0
STUB
}

# journalctl stub used by service_tor_log on systemd.
make_journalctl_stub() {
    make_stub journalctl <<'STUB'
#!/usr/bin/env bash
printf 'journalctl %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
[[ "${CT_TEST_BOOTSTRAPPED:-0}" == "1" ]] && echo "Bootstrapped 100% (done)"
exit 0
STUB
}

# curl stub with per-URL behaviour:
#   CT_TEST_IPV4=<addr>        -> api.ipify.org body (empty => exit 22)
#   CT_TEST_IPV4_FILE=<file>   -> api.ipify.org walks the file line by line
#   CT_TEST_CURL_OK=1          -> any ipify/check.torproject request succeeds
#   CT_TEST_IPV6_ADDR=<addr>   -> api6.ipify.org body (empty => exit 22)
#   CT_TEST_GEO_PRIMARY=ok|ratelimited|empty
#   CT_TEST_GEO_FALLBACK=ok|fail
make_curl_stub() {
    make_stub curl <<'STUB'
#!/usr/bin/env bash
printf 'curl %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
url=""
for a in "$@"; do
    case "$a" in http*) url="$a" ;; esac
done
case "$url" in
    *api6.ipify.org*)
        if [[ -n "${CT_TEST_IPV6_ADDR:-}" ]]; then echo "$CT_TEST_IPV6_ADDR"; exit 0; fi
        exit 22 ;;
    *api.ipify.org*)
        if [[ -n "${CT_TEST_IPV4_FILE:-}" ]]; then
            n=$(cat "${CT_TEST_IPV4_FILE}.n" 2>/dev/null || echo 0)
            n=$((n + 1))
            echo "$n" > "${CT_TEST_IPV4_FILE}.n"
            sed -n "${n}p" "$CT_TEST_IPV4_FILE"
            exit 0
        fi
        if [[ -n "${CT_TEST_IPV4:-}" ]]; then echo "$CT_TEST_IPV4"; exit 0; fi
        [[ "${CT_TEST_CURL_OK:-0}" == "1" ]] && { echo "203.0.113.7"; exit 0; }
        exit 22 ;;
    *check.torproject.org*)
        [[ "${CT_TEST_CURL_OK:-0}" == "1" ]] && exit 0 || exit 22 ;;
    *ipwho.is*)
        case "${CT_TEST_GEO_PRIMARY:-empty}" in
            ok)          echo '{"country":"Germany","country_code":"DE","isp":"Primary ISP"}' ;;
            ratelimited) echo '{"success":false,"message":"Rate limit exceeded"}' ;;
        esac
        exit 0 ;;
    *ipwhois.app*)
        case "${CT_TEST_GEO_FALLBACK:-fail}" in
            ok) echo '{"country":"France","country_code":"FR","isp":"Fallback ISP"}' ;;
        esac
        exit 0 ;;
esac
exit 0
STUB
}

# conntrack stub: CT_TEST_CONNTRACK_FOUND=1 makes -D report a deletion;
# CT_TEST_CONNTRACK_ENTRIES=1 makes -L print a fake entry.
make_conntrack_stub() {
    make_stub conntrack <<'STUB'
#!/usr/bin/env bash
printf 'conntrack %s\n' "$*" >> "${STUB_LOG:-/dev/null}"
case "$*" in
    -D*)
        [[ "${CT_TEST_CONNTRACK_FOUND:-0}" == "1" ]] && exit 0 || exit 1 ;;
    -L*)
        [[ "${CT_TEST_CONNTRACK_ENTRIES:-0}" == "1" ]] && \
            echo "tcp 6 431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.2 sport=1234 dport=443 src=127.0.0.1 dst=10.0.0.2 sport=9040 dport=1234"
        exit 0 ;;
esac
exit 0
STUB
}

# id stub: makes `id -u tor` succeed so TOR_UID detection can be exercised.
make_id_stub() {
    make_stub id <<'STUB'
#!/usr/bin/env bash
if [[ "$*" == "-u tor" ]]; then echo "4242"; exit 0; fi
if [[ "$*" == "-u 4242" ]]; then echo "4242"; exit 0; fi
exec /usr/bin/id "$@"
STUB
}

# sleep stub: probe loops run 30-45 iterations; make them instantaneous.
make_sleep_stub() {
    make_stub sleep <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
}
