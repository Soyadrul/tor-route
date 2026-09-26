# tor-route tests

BATS regression suite for [`../tor-route.sh`](../tor-route.sh). It is the safety
net for changes to the script: if a refactor makes `start` skip a firewall
rule, `stop` lose a backup, or a partial ruleset pass as success, one of these
tests is expected to fail.

The suite is **safe to run on a development machine**: tests run unprivileged
and never touch the real firewall, `/etc/resolv.conf`, `/etc/tor/torrc`,
`/run` or any service. `helpers/setup.bash` sources the script *above* its
dispatcher, redirects every path the script writes to a per-test temporary
directory, and stubs external commands on `PATH`. The few tests that need to
exercise namespace-related behavior run a throwaway body under `unshare` and
`skip` themselves when user/network/mount namespaces (or their dependencies)
are unavailable — they never fall back to touching the host.

Real `start`/`stop`/`newnode` runs on a live system are intentionally **not**
part of this suite; test those on a disposable VM.

## Requirements (Arch Linux)

BATS itself and its assertion/helper libraries:

```bash
sudo pacman -S bats bats-support bats-assert bats-file
```

Arch's `bats` package points `BATS_LIB_PATH` at `/usr/lib/bats`, where the
distro installs the libraries, so no environment setup is needed there. On
other distros install `bats-core` plus the `bats-support`, `bats-assert` and
`bats-file` libraries and, if needed, export:

```bash
export BATS_LIB_PATH=/usr/lib/bats   # adjust to where the libraries live
```

The namespace-based tests use additional tools. If any are missing, or if
`unshare` cannot create the required namespaces, those specific tests `skip`
instead of failing:

```bash
sudo pacman -S util-linux iproute2 iptables conntrack-tools python3
```

| Package | Provides | Used by |
|---|---|---|
| `bats` | test runner | everything |
| `bats-support`, `bats-assert`, `bats-file` | assertion libraries | everything |
| `util-linux` | `unshare`, `setsid`, `mount` | namespace tests, `prompt_country_fallback` |
| `iproute2` | `ip`, `ss` | conntrack test |
| `iptables` | `iptables`/`ip6tables` | conntrack test |
| `conntrack-tools` | `conntrack` | conntrack test |
| `python3` | test listeners | conntrack test |

## Running the tests

Run everything as your normal user (not root):

```bash
bats tests/                      # full suite (108 tests at the time of writing)
bats tests/iptables.bats         # a single file
bats -f 'apply_iptables' tests/  # tests whose name matches a regex
bats --count tests/              # only print how many tests would run
bash -n tor-route.sh             # minimum syntax check of the script
```

Additional options:

- `TOR_ROUTE_UNDER_TEST=<path>` runs the suite against a copy of the script
  instead of the repository one. This is how mutation checks are done
  (deliberately break the copy, confirm the matching test goes red). Never
  point it at an installed script with a live Tor session.
- `BATS_LIB_PATH=/path/to/libs` overrides where `bats_load_library` finds
  `bats-support`/`bats-assert`/`bats-file`.

## What each test file covers

| Test file | Tests | Focus |
|---|---:|---|
| [`conntrack-cleanup.bats`](#conntrack-cleanupbats) | 1 | conntrack cleanup scoping in a real throwaway netns |
| [`country.bats`](#countrybats) | 4 | ISO country list and `validate_country`/`countries` |
| [`dispatch.bats`](#dispatchbats) | 8 | command dispatcher, root gate, usage, argument validation |
| [`dns.bats`](#dnsbats) | 11 | `resolv.conf` helpers, `fix_dns_start`/`fix_dns_stop`, DNSPort |
| [`flows.bats`](#flowsbats) | 12 | `start`/`stop`/`newnode` guard and unwind control flow |
| [`iptables.bats`](#iptablesbats) | 14 | firewall ruleset, save/restore guards, routing detection |
| [`probes.bats`](#probesbats) | 13 | `show_ip`, traffic probes, country-pin fallback |
| [`resolv-conf-replace.bats`](#resolv-conf-replacebats) | 1 | replacement helpers against bind mounts (mount ns) |
| [`service.bats`](#servicebats) | 13 | init-system service dispatch and `restore_tor_service` |
| [`state-and-lock.bats`](#state-and-lockbats) | 7 | state directory permissions/symlink guards and advisory lock |
| [`status-check.bats`](#status-checkbats) | 9 | `status`/`check` output and dependency gates |
| [`torrc.bats`](#torrcbats) | 15 | torrc marker handling, `configure_torrc`, cleanup/revert |

Counts are a snapshot — `bats --count tests/` prints the current numbers.

### `conntrack-cleanup.bats`

Runs against the real kernel inside `unshare -rn`. Builds a NAT setup with the
script's own REDIRECT rules, a fake Tor listener and an unrelated listener,
then runs `cleanup_conntrack_tor_ports` and checks that:

- entries whose **reply source port** is Tor's `TransPort`/`DNSPort` are deleted;
- an unrelated established flow survives (cleanup is not `conntrack -F`);
- the function prints only its one-line summary — conntrack's raw per-entry
  `src=`/`dst=` dump must not leak to the user.

Guards the withdrawn BUGS.md #1: keep the native `--reply-port-src` filter, do
not replace it with text parsing.

### `country.bats`

- `VALID_COUNTRIES` holds exactly the 249 ISO 3166-1 alpha-2 codes, all
  lowercase and unique.
- `validate_country` normalizes case (`US` → `us`) and rejects unknown,
  over-length, under-length, numeric and empty input.
- The `countries` command lists all 249 codes and works with an empty `PATH`
  (no root, no dependencies).

### `dispatch.bats`

- No arguments or an unknown command prints the usage block and exits 1.
- `start`, `stop`, `status`, `newnode` and `check` refuse to run as a normal
  user (`countries` is the only non-root command).
- `start --help` / `newnode -h` print usage and exit 0.
- `start`/`newnode` reject extra arguments before touching anything.
- `start` rejects an unknown country code with the uppercased code in the
  message.

### `dns.bats`

- `TOR_DNS_PORT` is off the mDNS/Avahi port 5353, above 1023, and is the port
  documented in the README (ported `dns-port-test.sh`, BUGS.md #5).
- `replace_file_verified` and `link_file_verified` succeed, fail when the
  target cannot be written/linked, and — importantly — detect the case where
  the underlying `mv`/`ln` silently did nothing instead of trusting them
  (BUGS.md #7).
- Mount namespace: `fix_dns_start` backs up `/etc/resolv.conf` (`0600`),
  records whether a resolver was running and which units it newly masked,
  verifies the swap to `127.0.0.1`, and refuses to claim success when the swap
  cannot happen (e.g. a bind-mounted `resolv.conf`).
- Mount namespace: `fix_dns_stop` no-ops with no state files, restores the
  static backup, writes the generic `1.1.1.1` fallback, unmasks only the units
  it recorded itself, and restarts the resolver only if it was running before
  `start`.
- Mount namespace: `status` on a non-systemd init reports whether
  `/etc/resolv.conf` points at Tor.

### `flows.bats`

Command-level behavior of `cmd_start`, `cmd_stop`, `cmd_newnode` and
`interrupt_unwind`, with the entry guards overridden and every external
command stubbed:

- `start` refuses to re-apply while routing is already active and touches
  neither torrc nor the firewall.
- `start` claims success only after the traffic probe passes; without a pin it
  warns instead, and with an unusable pin it asks and then either falls back
  to a random exit or performs a full abort unwind.
- The abort unwind removes the torrc block, the country/service state files
  and the firewall backups, and restores the firewall.
- `newnode` refuses when Tor is not running or routing is not active, and
  reverts torrc + country state when the reload fails.
- `stop` with no prior session leaves firewall and DNS untouched; `stop`
  aborts with manual recovery instructions when the rules survive the restore.
- `interrupt_unwind` is safe before anything was saved (guard-no-op restores).

### `iptables.bats`

- `apply_iptables` installs the documented NAT and filter ruleset rule by rule
  (DNS redirects with the Tor-owner exclusion, Tor-owner `RETURN`/`ACCEPT`,
  the four `NON_TOR` bypasses, the new-TCP redirect, the final UDP `DROP`, the
  IPv6 DROP policies).
- `apply_iptables` refuses to run without a Tor user; aborts on the first
  failing rule (regression test for the `set -e`-inside-`if ! ( ... )` bug
  — every rule must keep its `|| exit 1`); aborts when the IPv6 DROP policies
  do not verify; skips IPv6 entirely when the kernel has no IPv6 stack.
- `save_iptables` writes both backups atomically (`.tmp` + `mv`), `0600`, with
  no leftovers; leaves no partial backup when either family's save fails;
  skips the IPv6 backup when there is no IPv6 stack.
- `restore_iptables` never touches the firewall when no backup exists;
  otherwise flushes, resets IPv6 policies to ACCEPT, restores both families,
  removes the backups and cleans conntrack; a failing family keeps its backup
  and reports failure.
- `is_routing_active` works from `-S` output and from the `-L` fallback, and
  `ipv6_policy_state` classifies `unavailable`/`blocked`/`allowed`.

### `probes.bats`

- `show_ip` flags an IPv6 address as `LEAK!` only while routing is active,
  prints the host's own address without an alarm when routing is off, reports
  `Blocked` when an active route has no reachable IPv6, and warns when the
  IPv4 address cannot be fetched.
- Geo enrichment uses `ipwho.is` when it answers, falls back to
  `ipwhois.app` when the primary is rate-limited, and prints
  `Country/ISP: lookup unavailable.` when every provider fails.
- `probe_traffic` succeeds at the first successful request and gives up after
  its bounded retries (`sleep` stubbed out for speed).
- `wait_for_new_ip` succeeds when the exit IP changes and fails when it does
  not.
- `prompt_country_fallback` defaults to **abort** with no usable terminal
  (`setsid`, no controlling tty). The interactive choice path needs a real
  pty and is not covered.

### `resolv-conf-replace.bats`

Mount namespace port of `resolv-conf-replace-test.sh` (BUGS.md #7):
replacing or symlinking over a bind-mounted file must fail (EBUSY) and leave
no `.tmp` file behind.

### `service.bats`

- `service_tor_start/stop/restart/reload/running` dispatch correctly for
  systemd (`systemctl`), OpenRC (`rc-service`), Runit (`sv`) and SysVinit
  (`/etc/init.d/tor`, in a mount namespace); an unknown init system fails
  loudly instead of guessing.
- The log path follows the init system (OpenRC tails `TOR_LOG_FILE`, systemd
  uses `journalctl`).
- `resolver_running` is systemd-only.
- `restore_tor_service`: stops Tor when it was not running before, removes the
  torrc block and restarts Tor when it was, keeps `TOR_STATE_FILE` when the
  torrc cleanup aborts so a retry stays correct (follow-up hardening), and
  defaults to stopping when no state file exists.
- `detect_tor_user` picks the first existing account from `TOR_USERS`;
  `_banner_commit` prints `(STABLE)` or the short hash.

### `state-and-lock.bats`

- `ensure_state_dir` creates a `0700` directory, refuses a symlinked state
  directory, and refuses a state path that is not a directory.
- `acquire_command_lock` creates a `0600` lock file, refuses a symlinked lock
  file, fails fast while another process holds the lock, and read-only
  commands ignore a held lock.

### `status-check.bats`

- `status` reports service/routing/UDP/IPv6/masking/country/port lines while
  active; flags a missing UDP DROP rule and an allowed IPv6 policy as leaks;
  distinguishes `Not available` from `Blocked` for IPv6; and reports direct
  routing plus the random/unknown country sentinel when routing is off.
- `check` ends with `All checks passed` when every dependency exists and
  `Some checks failed` when one is missing.
- `check_dependencies` names the missing tools; `check_net_tools` only
  requires the tools it is asked for, so `stop` keeps working after Tor was
  uninstalled since `start`.

### `torrc.bats`

- `strip_torrc_block` removes only the marked block, is a no-op with no
  markers or no file, aborts with a backup for missing/reversed/nested marker
  structures, reports a failed backup without claiming success, and ignores
  `tor-routeXsh` lookalike markers.
- `configure_torrc` writes the marked block (ports, pin, `StrictNodes 1`),
  records the country or `random` in a `0600` state file, is idempotent, and
  refuses to write through a symlinked country file.
- `cleanup_torrc` removes the block and the country file while keeping user
  lines; `revert_torrc_to_previous` restores a previous pin or maps `random`
  back to no pin, without duplicating the block.

## `tests/helpers/`

### `setup.bash`

The shared harness. Every test file starts with `load 'helpers/setup'` and
calls `setup_test` from its own `setup()`. It:

- sources `tor-route.sh` above the `case "$1" in` dispatcher (failing loudly
  if the dispatcher moved), so tests call the real functions directly;
- redirects `TORRC`, `STATE_DIR` and all eight state-file paths into the
  per-test `$BATS_TEST_TMPDIR`, clears the colour codes, and presets
  `TOR_UID`/`INIT` so no real user or init system is queried;
- loads `bats-support`, `bats-assert` and `bats-file` (defaulting
  `BATS_LIB_PATH` to `/usr/lib/bats`);
- provides stub factories — `make_firewall_stubs`, `make_save_restore_stubs`,
  `make_systemd_stubs`, `make_ss_stub`, `make_journalctl_stub`,
  `make_curl_stub`, `make_conntrack_stub`, `make_id_stub`,
  `make_sleep_stub`, plus `make_stub` for one-off scripts. Every stub logs its
  arguments to `$STUB_LOG` and honours `CT_TEST_*` variables the test exports
  to steer its behavior;
- provides `hide_commands`, which makes `command -v` report chosen tools as
  missing without touching `PATH` (BATS itself needs the real `PATH`);
- provides skip helpers — `skip_if_root`, `needs_commands`, `needs_netns`,
  `needs_mountns` — used by tests whose prerequisites may be absent.

### `conntrack-netns.sh`

The body of `conntrack-cleanup.bats`, executed by the test under
`unshare -rn`. Uses the real `ip`, `iptables`, `conntrack` and a `python3`
listener; performs all its assertions inside the namespace and prints a
`PASS:` line on success.

### `resolv-netns.sh`

Executed under `unshare -rm`; replaces `/etc` with a private `tmpfs` (or
bind-mounts a file over `/etc/resolv.conf`) so the real file is never
modified. Selected by a mode argument:

| Mode | Checks |
|---|---|
| `replace-bind` | `replace_file_verified`/`link_file_verified` against bind mounts (BUGS.md #7) |
| `fix-dns-start` | backup, masking record, verified swap; resolver running and stopped |
| `fix-dns-start-bind-fail` | `fix_dns_start` fails and does not claim a failed swap |
| `fix-dns-stop` | no-op guard, backup restore, generic fallback, unmask + restart |
| `status-resolv` | `status` judges `resolv.conf` against Tor on non-systemd inits |

### `service-sysvinit-netns.sh`

Executed under `unshare -rm`; isolates `/etc` with a `tmpfs`, installs a fake
`/etc/init.d/tor` and verifies the SysVinit dispatch of
start/stop/restart/reload/running.

## Adding a test

Follow the existing pattern: `load 'helpers/setup'`, call `setup_test` in
`setup()`, stub every external command the code path can reach, and prefer
bats-assert/bats-file assertions (`assert_output --partial`,
`assert_file_contains`, `assert_file_permission`) over ad-hoc string matching.
When adding a new test file, add it to the table above.
