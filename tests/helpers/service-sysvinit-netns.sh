#!/usr/bin/env bash
# SysVinit service dispatch (/etc/init.d/tor) exercised inside a throwaway
# mount namespace: /etc is replaced by a private tmpfs so a fake init script
# can be installed without touching the host. Invoked by service.bats.

set -u

HELPERS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HELPERS_DIR/setup.bash"

fail() { echo "FAIL: $*" >&2; exit 1; }

TEST_TMP="${TEST_TMP:-$(mktemp -d)}"
export TEST_TMP
init_test_env

mount -t tmpfs tmpfs /etc || fail "could not isolate /etc with a tmpfs"
mkdir -p /etc/init.d
cat > /etc/init.d/tor <<'STUB'
#!/usr/bin/env bash
printf 'init.d/tor %s\n' "$*" >> "$STUB_LOG"
case "$*" in
    status) exit "${CT_TEST_SYSV_STATUS:-0}" ;;
esac
exit 0
STUB
chmod +x /etc/init.d/tor

INIT=sysvinit

service_tor_start   || fail "service_tor_start failed"
service_tor_stop    || fail "service_tor_stop failed"
service_tor_restart || fail "service_tor_restart failed"
service_tor_reload  || fail "service_tor_reload failed"
service_tor_running || fail "service_tor_running should succeed with status 0"

CT_TEST_SYSV_STATUS=3
export CT_TEST_SYSV_STATUS
if service_tor_running; then
    fail "service_tor_running should fail when status is non-zero"
fi

grep -q '^init.d/tor start$'   "$STUB_LOG" || fail "start not dispatched to /etc/init.d/tor"
grep -q '^init.d/tor stop$'    "$STUB_LOG" || fail "stop not dispatched to /etc/init.d/tor"
grep -q '^init.d/tor restart$' "$STUB_LOG" || fail "restart not dispatched to /etc/init.d/tor"
grep -q '^init.d/tor reload$'  "$STUB_LOG" || fail "reload not dispatched to /etc/init.d/tor"
grep -q '^init.d/tor status$'  "$STUB_LOG" || fail "running check not dispatched to /etc/init.d/tor"

echo "PASS: SysVinit service commands go through /etc/init.d/tor"
exit 0
