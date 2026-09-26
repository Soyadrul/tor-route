# tor-route tests

BATS regression suite for [`../tor-route.sh`](../tor-route.sh). It is the safety
net for changes to the script: if a refactor makes `start` skip a firewall
rule, `stop` lose a backup, or a partial ruleset pass as success, one of these
tests is expected to fail.

The suite is **safe to run on a development machine**: tests run unprivileged
and never touch the real firewall, `/etc/resolv.conf`, `/etc/tor/torrc`,
`/run` or any service. `helpers/setup.bash` sources the script *above* its
dispatcher, redirects the script's config and state paths to a per-test
temporary directory, and stubs external commands on `PATH`. The few tests
that need to
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

The namespace-based and terminal-based tests use additional tools. If any are
missing, or if `unshare` cannot create the required namespaces, those specific
tests `skip` instead of failing:

```bash
sudo pacman -S util-linux iproute2 iptables conntrack-tools python3
```

| Package | Provides | Used by |
|---|---|---|
| `bats` | test runner | everything |
| `bats-support`, `bats-assert`, `bats-file` | assertion libraries | everything |
| `util-linux` | `unshare`, `setsid`, `script`, `mount`, `flock` | namespace tests, interactive-prompt tests, advisory-lock tests |
| `coreutils` | `timeout` | interactive-prompt test (pty guard) |
| `iproute2` | `ip` | conntrack test |
| `iptables` | `iptables`/`ip6tables` | conntrack test |
| `conntrack-tools` | `conntrack` | conntrack test |
| `python3` | test listeners | conntrack test |

## Running the tests

Run everything as your normal user (not root):

```bash
bats tests/                      # full suite (165 tests at the time of writing)
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
| [`dns.bats`](#dnsbats) | 12 | `resolv.conf` helpers and `fix_dns_start`/`fix_dns_stop` |
| [`flows.bats`](#flowsbats) | 33 | `start`/`stop`/`newnode` control flow and every unwind stage |
| [`init.bats`](#initbats) | 11 | init-system detection and configuration (systemd, OpenRC, Runit, SysVinit) |
| [`iptables.bats`](#iptablesbats) | 20 | firewall ruleset, save/restore guards, routing/port checks |
| [`probes.bats`](#probesbats) | 17 | `show_ip`, traffic probes, country-pin fallback |
| [`resolv-conf-replace.bats`](#resolv-conf-replacebats) | 1 | replacement helpers against bind mounts (mount ns) |
| [`service.bats`](#servicebats) | 15 | init-system service dispatch and `restore_tor_service` |
| [`state-and-lock.bats`](#state-and-lockbats) | 9 | state directory permissions/symlink guards and advisory lock |
| [`status-check.bats`](#status-checkbats) | 18 | `status`/`check` output and dependency gates |
| [`torrc.bats`](#torrcbats) | 16 | torrc marker handling, `configure_torrc`, cleanup/revert |

Counts are a snapshot — `bats --count tests/` prints the current numbers.

### `conntrack-cleanup.bats`

Runs against the real kernel inside `unshare -rn`. Builds a NAT setup with the
script's own REDIRECT rules, a fake Tor listener and an unrelated listener,
then runs `cleanup_conntrack_tor_ports` and checks that:

- entries whose **reply source port** is Tor's `TransPort`/`DNSPort` are deleted;
- an unrelated established flow survives (cleanup is not `conntrack -F`);
- the function prints only its one-line summary — conntrack's raw per-entry
  `src=`/`dst=` dump must not leak to the user.

Guards the cleanup scoping: keep the native `--reply-port-src` filter, do not
replace it with text parsing.

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
  documented in the README.
- `replace_file_verified` and `link_file_verified` succeed, fail when the
  target cannot be written/linked, and — importantly — detect the case where
  the underlying `mv`/`ln` silently did nothing instead of trusting them.
- `fix_dns_start` refuses symlinked state files before touching anything
  (non-namespace), and in a mount namespace: backs up `/etc/resolv.conf`
  (`0600`), records whether a resolver was running and which units it newly
  masked, verifies the swap to `127.0.0.1`, skips masking entirely on
  non-systemd inits, and refuses to claim success when the swap cannot happen
  (e.g. a bind-mounted `resolv.conf`).
- Mount namespace: `fix_dns_stop` no-ops with no state files, restores the
  static backup, writes the generic `1.1.1.1` fallback, unmasks only the units
  it recorded itself (falling back to unmasking every unit for older sessions
  and reporting units that fail), restarts the resolver only if it was running
  before `start`, and reports — instead of hiding — failed symlink, backup and
  fallback writes.
- Mount namespace: `status` on a non-systemd init reports whether
  `/etc/resolv.conf` points at Tor.

### `flows.bats`

Command-level behavior of `cmd_start`, `cmd_stop`, `cmd_newnode` and
`interrupt_unwind`, with the entry guards overridden and every external
command stubbed:

- `start` refuses to re-apply while routing is already active and touches
  neither torrc nor the firewall.
- `start` claims success only after the traffic probe passes; it can also
  become ready through the listening port when no "Bootstrapped 100%" line
  appears. Without a pin it warns instead of claiming success, and with an
  unusable pin it asks and then either falls back to a random exit or performs
  a full abort unwind.
- `start` records whether Tor was running before, and every failure stage
  unwinds: Tor fails to start, ports never listen, firewall save fails,
  `apply_iptables` fails, DNS setup fails. The unwinds that would black-hole
  traffic (rules alive but backups gone) stop at the manual-recovery message
  instead of tearing Tor down.
- `newnode` refuses when Tor is not running or routing is not active, rejects
  unknown country codes, and reverts torrc + country state when the reload
  fails.
- `newnode`'s verification tail is fully covered: clearing a previous pin vs
  requesting a fresh random circuit, an unreadable old IP (fixed wait, warning
  instead of a success claim), an unchanged IP, user-accepted random fallback
  and user-aborted revert, plus warnings when either fallback reload fails.
- `stop` with no prior session leaves firewall and DNS untouched; it can
  demand `iptables-restore` only when a backup exists, aborts with manual
  recovery instructions when the rules survive the restore, reports a failed
  firewall restore and exits 1, and warns when direct connectivity cannot be
  verified.
- `interrupt_unwind` is safe before anything was saved (guard-no-op restores)
  and stops at manual recovery when the rules survive.

### `init.bats`

`detect_init` and `require_init` are otherwise shadowed by every other test
file, so this is the only place the real detection runs. All four supported
init systems — systemd, OpenRC, Runit and SysVinit — are covered:

- `detect_init` maps pid1 names (`systemd`, `openrc-init`/`openrc`, `runit`),
  distinguishes SysVinit from OpenRC for pid1 `init`, and falls back to
  `systemctl`/`rc-service`/`runsvdir` for unknown pid1 values — failing when
  none is available.
- `require_init` populates the three systemd-resolved units and an empty log
  source on systemd, and the per-init log paths otherwise: `/var/log/tor/log`
  for OpenRC and SysVinit, `/var/log/tor/current` for Runit. It rejects
  unsupported init values and aborts when detection fails.

### `iptables.bats`

- `apply_iptables` installs the documented NAT and filter ruleset rule by rule
  (DNS redirects with the Tor-owner exclusion, Tor-owner `RETURN`/`ACCEPT`,
  the four `NON_TOR` bypasses, the new-TCP redirect, the final UDP `DROP`, the
  IPv6 DROP policies).
- `apply_iptables` refuses to run without a Tor user; re-detects one when it
  was unknown at load time; aborts on the first failing rule (regression test
  for the `set -e`-inside-`if ! ( ... )` bug — every rule must keep its
  `|| exit 1`); aborts when the IPv6 DROP policies do not verify; skips IPv6
  entirely when the kernel has no IPv6 stack.
- `save_iptables` writes both backups atomically (`.tmp` + `mv`), `0600`, with
  no leftovers; leaves no partial backup when either family's save fails;
  skips the IPv6 backup when there is no IPv6 stack.
- `restore_iptables` never touches the firewall when no backup exists;
  otherwise flushes, resets IPv6 policies to ACCEPT, restores both families,
  removes the backups and cleans conntrack; keeps a failing family's backup
  and reports failure for IPv4 or IPv6; handles a session with only one
  family's backup; and skips IPv6 policy resets with no IPv6 stack.
- `is_routing_active` works from `-S` output and from the `-L` fallback;
  `ipv6_policy_state` classifies `unavailable`/`blocked`/`allowed`;
  `verify_tor_ports` reports each missing listener and succeeds once both
  ports listen; `cleanup_conntrack_tor_ports` skips cleanly when `conntrack`
  is not installed.

### `probes.bats`

- `show_ip` flags an IPv6 address as `LEAK!` only while routing is active,
  prints the host's own address without an alarm when routing is off, reports
  `Blocked` when an active route has no reachable IPv6 (`not configured /
  unreachable` while routing is off), and warns when the IPv4 address cannot
  be fetched.
- Geo enrichment uses `ipwho.is` when it answers, falls back to `ipwhois.app`
  when the primary is rate-limited or returns an empty body, prints partial
  fields when only the ISP is known, and prints
  `Country/ISP: lookup unavailable.` when every provider fails.
- `probe_traffic` succeeds at the first successful request, falls back to
  `check.torproject.org` when `api.ipify.org` is unreachable, and gives up
  after its bounded retries (`sleep` stubbed out for speed).
- `wait_for_new_ip` succeeds when the exit IP changes and fails when it does
  not.
- `prompt_country_fallback` defaults to **abort** with no usable terminal
  (`setsid`), and on a real pty (`script`) accepts `r` and defaults to abort
  for anything else.

### `resolv-conf-replace.bats`

Mount namespace coverage for the replacement helpers: replacing or symlinking
over a bind-mounted file must fail (EBUSY) and leave no `.tmp` file behind.

### `service.bats`

- `service_tor_start/stop/restart/reload/running` dispatch correctly for
  systemd (`systemctl`), OpenRC (`rc-service`), Runit (`sv`) and SysVinit
  (`/etc/init.d/tor`, in a mount namespace); every wrapper rejects an unknown
  init system instead of guessing.
- The log path follows the init system (OpenRC/Runit/SysVinit tail
  `TOR_LOG_FILE`, systemd uses `journalctl`).
- `resolver_*` helpers are no-ops on non-systemd inits; `resolver_running` is
  systemd-only.
- `restore_tor_service`: stops Tor when it was not running before, removes the
  torrc block and restarts Tor when it was, keeps `TOR_STATE_FILE` when the
  torrc cleanup aborts so a retry stays correct (follow-up hardening), and
  defaults to stopping when no state file exists.
- `detect_tor_user` picks the first existing account from `TOR_USERS` and
  leaves no user when none match; `_banner_commit` prints `(STABLE)` or the
  short hash.

### `state-and-lock.bats`

- `ensure_state_dir` creates a `0700` directory, refuses a symlinked state
  directory, refuses a state path that is not a directory, and reports a state
  directory that cannot be created.
- `acquire_command_lock` creates a `0600` lock file, refuses a symlinked lock
  file, fails fast while another process holds the lock, warns but continues
  when `flock` is unavailable, and read-only commands ignore a held lock.

### `status-check.bats`

- `status` reports service/routing/UDP/IPv6/masking/country/port lines while
  active; flags a missing UDP DROP rule, a resolver unit that is not masked,
  and an allowed IPv6 policy as leaks; distinguishes `Not available` from
  `Blocked` for IPv6; and reports direct routing, the
  `systemd-resolved active (normal)` case, and the random/unknown country
  sentinel when routing is off.
- `check` ends with `All checks passed` when every dependency exists and
  `Some checks failed` when one is missing.
- `check` display branches: a running Tor service, our torrc block present,
  torrc and/or Tor user missing, a state file showing `(exists)`, the
  routing-active NAT/filter dump, the three IPv6 policy outcomes, and
  `TOR_LOG_FILE` tailing on non-systemd inits (non-empty, empty, missing).
- Mount namespace: `check` reports `resolv.conf` as regular file (with its
  nameserver count), missing or symlink, plus the recorded pre-start resolver
  state.
- `check_dependencies` names the missing tools and refuses to run without a
  Tor user; `check_net_tools` only requires the tools it is asked for, so
  `stop` keeps working after Tor was uninstalled since `start`.

### `torrc.bats`

- `strip_torrc_block` removes only the marked block, is a no-op with no
  markers or no file, aborts with a backup for missing/reversed/nested marker
  structures, reports a failed backup without claiming success, ignores
  `tor-routeXsh` lookalike markers, and handles a file whose last line has no
  trailing newline.
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
  `make_sleep_stub`, plus `make_stub` for one-off scripts. The factories
  honour `CT_TEST_*` variables the test exports to steer their behavior (e.g.
  `CT_TEST_IPIFY_FAIL`, `CT_TEST_GEO_PRIMARY=isp`, `CT_TEST_UNMASK_FAIL`) and
  log their invocations to `$STUB_LOG` for exact-command assertions, except
  the silent `make_id_stub`/`make_sleep_stub`;
- provides `hide_commands`, which makes `command -v` report chosen tools as
  missing without touching `PATH` (BATS itself needs the real `PATH`). Each
  call replaces the previous hidden list, so pass every name in one call;
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
| `replace-bind` | `replace_file_verified`/`link_file_verified` against bind mounts |
| `fix-dns-start` | backup, masking record, verified swap; resolver running, stopped and non-systemd |
| `fix-dns-start-bind-fail` | `fix_dns_start` fails and does not claim a failed swap |
| `fix-dns-stop` | no-op guard, backup restore, generic fallback, unmask record and fallback list (incl. failures), failed symlink/backup/fallback writes, non-systemd |
| `check-resolv` | `check` reports regular/missing/symlink `resolv.conf`, nameserver count and pre-start resolver state |
| `status-resolv` | `status` judges `resolv.conf` against Tor on non-systemd inits |

### `service-sysvinit-netns.sh`

Executed under `unshare -rm`; isolates `/etc` with a `tmpfs`, installs a fake
`/etc/init.d/tor` and verifies the SysVinit dispatch of
start/stop/restart/reload/running.

## Coverage limits

An xtrace tracer on a full run reaches ~97% of executable statement lines.
Everything not covered is deliberate; do not add flaky tests for it:

- **Trace blind spots** the tracer cannot mark (`done < file`, `if ! (`,
  case-closing `} ;;`, multi-line `RESOLVED_UNITS=( ... )` data) — these *are*
  executed and asserted.
- **TOCTOU re-checks** that only fire if the filesystem changes between two
  adjacent checks: `ensure_state_dir`'s post-`mkdir`/post-`chmod` symlink and
  type re-checks, and `fix_dns_start`'s redundant `RESOLV_BACKUP` symlink
  check after the loop that already covers it.
- **Unreachable guards**: `prompt_country_fallback`'s
  `[[ ! -r /dev/tty ]]` early return and its stdin-fallback `read` — `/dev/tty`
  is mode 0666, so the readable branch always wins.
- **Root-only paths** (`require_root` success) and the intentional exclusion
  of live-system `start`/`stop`/`newnode` mutation.

## Adding a test

Follow the existing pattern: `load 'helpers/setup'`, call `setup_test` in
`setup()`, stub every external command the code path can reach, and prefer
bats-assert/bats-file assertions (`assert_output --partial`,
`assert_file_contains`, `assert_file_permission`) over ad-hoc string matching.
When adding or changing tests, keep the overview table and the matching
per-file section in sync (`bats --count tests/` prints the current counts).
