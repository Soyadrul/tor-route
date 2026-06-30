# tor-route

A Bash script that transparently routes all system TCP traffic through the [Tor](https://www.torproject.org/) anonymity network, blocks DNS and WebRTC leaks, and provides a one-command way to switch your Tor exit node. Supports Systemd, OpenRC, Runit, and SysVinit init systems.

> [!WARNING]
> Tested only on [Arch Linux](https://archlinux.org/) but SHOULD work on any other distro that has one of the following init systems: Systemd, OpenRC, Runit or SysVinit.

## Table of Contents:
1.  [How it works](#how-it-works)
    1.  [What gets protected](#what-gets-protected)
2.  [Requirements](#requirements)
3.  [Installation](#installation)
4.  [Usage](#usage)
    1.  [Examples](#examples)
5.  [What each command does internally](#what-each-command-does-internally)
    1.  [`start [CC]`](#start-cc)
    2.  [`countries`](#countries)
    3.  [`stop`](#stop)
    4.  [`status`](#status)
    5.  [`newnode [CC]`](#newnode-cc)
    6.  [`check`](#check)
6.  [Known limitations](#known-limitations)
     1.  [Browser WebRTC](#browser-webrtc)
     2.  [UDP applications](#udp-applications)
     3.  [Tor is not a VPN](#tor-is-not-a-vpn)
     4.  [Exit node country pinning](#exit-node-country-pinning)
     5.  [Exit node blocking](#exit-node-blocking)
7.  [Verifying you are connected through Tor](#verifying-you-are-connected-through-tor)
8.  [Troubleshooting](#troubleshooting)
9.  [File locations](#file-locations)
10.  [Security notes](#security-notes)
11.  [License](#license)

---

## How it works

When you connect to a website normally, your traffic travels directly from your machine to the destination server — your ISP can see every request, and every website sees your real public IP address.

This script intercepts all outgoing traffic at the operating system level using **iptables** (Linux's built-in firewall) and redirects it into a local Tor process running in *transparent proxy* mode. Tor then bounces your traffic through a chain of three volunteer-operated servers around the world before it reaches the destination. The website only ever sees the IP address of the final server in that chain (the *exit node*), not yours.

```
Without tor-route:
  Your machine ────────────────────────────────► Website
                     (ISP sees everything)

With tor-route:
  Your machine ──► Guard ──► Middle ──► Exit ──► Website
                  (your real IP is never seen by the website)
```

### What gets protected

| Traffic type | Treatment |
|---|---|
| TCP (HTTP, HTTPS, SSH, …) | Redirected through Tor |
| DNS queries | Redirected to Tor's internal DNS resolver |
| UDP (WebRTC, QUIC, STUN) | Blocked entirely (cannot be anonymised by Tor) |
| IPv6 | Blocked entirely (Tor does not support IPv6 transparent proxying) |
| LAN / private ranges | Passed through directly (local network still works) |

---

## Requirements

- **Root / sudo access**
- `tor`, `iptables`, `curl`, `ss` (from `iproute2` / `iproute`)
- `conntrack-tools` — optional, provides `conntrack` used to flush stale NAT entries on stop
- A supported init system: systemd, OpenRC, Runit, or SysVinit

> Install the packages with your distro's package manager (e.g. `sudo pacman -S tor iptables curl iproute2 conntrack-tools` on Arch).  `conntrack-tools` is optional; the script works without it.

---

## Installation

> [!IMPORTANT]
> The command below installs the **latest commit** from the `main` branch (bleeding edge).
> For a stable release, use the [latest release](https://github.com/Soyadrul/tor-route/releases/latest) instead.

Run the following command to download and install the latest **bleeding-edge** version of `tor-route` on any Linux distribution:

```bash
sudo curl -fsSL https://raw.githubusercontent.com/Soyadrul/tor-route/main/tor-route.sh -o /usr/local/bin/tor-route \
  && sudo chmod +x /usr/local/bin/tor-route
```

No other configuration is required before first use.

---

## Usage

All commands must be run as root.

```bash
sudo tor-route <command>
```

| Command | Description |
|---|---|
| `start [CC]` | Enable Tor routing. `CC` is an optional 2-letter country code to pin the exit node |
| `stop` | Disable Tor routing — restore normal internet |
| `status` | Show current routing state, exit node country, and public IP |
| `newnode [CC]` | Request a new Tor exit node. Optionally switch or clear the country pin |
| `countries` | Print a full list of all supported country codes |
| `check` | Run a thorough dry-run system check (safe to paste in GitHub issues) |

### Examples

```bash
# Start routing through Tor with a random exit node
sudo tor-route start

# Start routing through Tor with a US exit node
sudo tor-route start us

# Start routing through Tor with a German exit node
sudo tor-route start de

# Check what IP and country the outside world sees
sudo tor-route status

# Get a fresh random IP (clears any country pin)
sudo tor-route newnode

# Switch to a new Japanese exit node
sudo tor-route newnode jp

# List all supported country codes
sudo tor-route countries

# Run a system health check (safe to paste in bug reports)
sudo tor-route check

# Restore your normal internet connection
sudo tor-route stop
```

---

## What each command does internally

### `start [CC]`

1. Validates the optional country code `CC` against the full ISO 3166-1 alpha-2 list.
2. Appends transparent proxy settings to `/etc/tor/torrc`. If a country code was given, also adds `ExitNodes {cc}` and `StrictNodes 1` to pin exit nodes to that country.
3. Saves the active country (or `"random"`) to a state file so `status` and `newnode` can read it back.
4. Detects and displays the init system, then records whether a DNS resolver was running beforehand. On **systemd**, this masks `systemd-resolved` and its socket units to prevent socket activation from reviving it. On other inits, no masking is needed.
5. Replaces `/etc/resolv.conf` with a file pointing to `127.0.0.1`, so all DNS queries go to Tor's local DNS listener.
6. Starts the Tor service (via `systemctl`, `rc-service`, `sv`, or `/etc/init.d/tor` depending on the init system) and waits for it to bootstrap to 100%.
7. Verifies that Tor is actually listening on both expected ports before touching the firewall.
8. Backs up existing `iptables` and `ip6tables` rules, then applies the Tor redirect rules.

### `countries`

Prints a formatted table of all supported ISO 3166-1 alpha-2 country codes alongside usage examples. Useful to look up the code for a specific country before running `start` or `newnode`.

### `stop`

1. Detects and displays the init system.
2. Flushes all iptables/ip6tables rules and resets ip6tables default policies to ACCEPT. Then tries to restore any custom pre-Tor rules from backup. This guarantees a working baseline regardless of backup integrity — the clean flush runs first, and the backup restore is a best-effort overlay.
3. Flushes stale conntrack entries (if `conntrack` is available) that could otherwise redirect new connections to Tor's now-closed ports.
4. Unmasks DNS resolver units (systemd only; other inits skip this). Restores `/etc/resolv.conf` — prefers a symlink to systemd-resolved's live stub-resolv.conf when available (dynamic, stays in sync with network changes), then falls back to a static backup copy, then to a generic fallback (`nameserver 1.1.1.1`).
5. Only restarts the DNS resolver if it was running before `start` was called — the system is left exactly as it was found.
6. Stops the Tor service.
7. Removes the settings added to `/etc/tor/torrc`.

### `status`

Displays a live summary:
- The **detected init system** (systemd, openrc, runit, or sysvinit)
- Whether the Tor service is running
- Whether TCP traffic is being routed through Tor
- Whether UDP / WebRTC is blocked
- Whether IPv6 is blocked
- Whether the DNS resolver is masked (systemd) or redirected via `/etc/resolv.conf` (other inits)
- The **configured exit node country** (pinned code or `Random`)
- Whether Tor is listening on the correct ports
- Your current public IPv4, country, ISP, and IPv6 leak status

### `newnode [CC]`

Detects and displays the init system. Updates torrc with the new country preference (or clears the pin if no code is given), then sends a `SIGHUP` signal to the Tor process. This tells Tor to reload its configuration and rebuild all of its **circuits**. A circuit is the three-hop path your traffic takes through the Tor network:

```
Your machine ──► Guard node ──► Middle node ──► Exit node ──► Internet
```

The *exit node* is the server websites see as your IP. A new circuit means a new exit node and therefore a new public IP address and country. The current IP and country are shown before and after so you can confirm the change.

### `check`

Runs a comprehensive, read-only system diagnostic without modifying anything. The output is designed to be safe for pasting directly into GitHub issues — it reveals no public IPs, nameserver addresses, hostnames or search domains:

- **System** — script version, OS release, kernel, detected init system
- **Dependencies** — each binary found with its version string
- **Tor user** — which system usernames were tried, which one matched
- **Tor service** — running/stopped, listening TCP and DNS ports
- **torrc** — path, permissions, and whether the script's config block is present
- **State files** — which of the 5 backup/state files exist
- **Firewall** — iptables/ip6tables version, NAT rules if Tor routing is active, IPv6 policy
- **DNS** — resolv.conf type (symlink/regular file), line count, nameserver count (no actual addresses)
- **Tor log** — last 5 lines of journal/log output
- **Verdict** — pass/fail summary with an invitation to paste the full output in an issue

---

## Known limitations

### Browser WebRTC

The script blocks WebRTC UDP at the OS level, but some browsers can still expose your real IP through WebRTC's JavaScript API before the packet is ever sent. **You should also disable WebRTC inside your browser:**

- **Firefox:** go to `about:config`, search for `media.peerconnection.enabled`, and set it to `false`.
- **Chromium / Chrome:** install the [WebRTC Leak Shield](https://chrome.google.com/webstore/detail/webrtc-leak-shield/) extension.

### UDP applications

Because Tor cannot carry UDP traffic (other than its own internal DNS), all non-DNS UDP is dropped while Tor routing is active. Applications that rely on UDP — such as VoIP clients, some games, or QUIC-based services — will not work until you run `stop`.

### Tor is not a VPN

Tor provides anonymity through routing, not encryption of the final hop. Traffic between the exit node and the destination website is **not encrypted by Tor** unless the site uses HTTPS. Always ensure you are visiting HTTPS sites for end-to-end encryption.

### Exit node country pinning

When a country code is specified, Tor uses `StrictNodes 1`, which means it will **only** use exits in that country and will not fall back to others if none are available. If Tor appears to stall at bootstrapping or stops routing traffic, the chosen country may have no available exit nodes at that moment — run `newnode` without a country code to switch back to random, or try a different country.

### Exit node blocking

Many websites and services (Cloudflare, Google, etc.) detect and rate-limit or block known Tor exit nodes. This is expected behaviour — use `newnode` to try a different exit node, or use [Tor bridges](https://bridges.torproject.org/) for more persistent access.

---

## Verifying you are connected through Tor

After running `sudo tor-route start`, you can confirm that your traffic is actually going through the Tor network by visiting either of these sites in your browser:

- **https://check.torproject.org/** — the official Tor Project checker. It will display a green message confirming you are using Tor, or a warning if you are not.
- **https://www.whatismybrowser.com/detect/am-i-using-tor/** — an independent checker that detects Tor exit nodes and shows additional details about your browser's apparent identity.

If either site reports that you are **not** using Tor after running `start`, run `sudo tor-route status` and check that every line shows ✓ before investigating further.

---

## Troubleshooting

**Tor fails to start**
```bash
# Quick diagnostics (safe to paste in bug reports)
sudo tor-route check

# Detailed logs:
# systemd
journalctl -u tor -n 50

# OpenRC / SysVinit
tail -n 50 /var/log/tor/log

# Runit
tail -n 50 /var/log/tor/current
```
Look for permission errors or port conflicts.

**IP still shows as my real address after `start`**

Run `status` and check every line:
- `TCP routing: Through Tor ✓` — iptables rules are applied
- `UDP / WebRTC: Blocked ✓` — non-DNS UDP is dropped
- `IPv6: Blocked ✓` — no IPv6 leak
- `DNS (resolved): All units masked ✓` (systemd) or `DNS: /etc/resolv.conf → Tor ✓` (other inits) — resolver cannot bypass Tor
- `DNSPort 5353: Listening ✓` — Tor's DNS is actually running

If all lines show ✓ but the IP check website still shows your real IP, the website itself may be using WebRTC JavaScript — disable WebRTC in your browser as described above.

**DNS not resolving after `stop`**

The script now prefers a symlink to systemd-resolved's live stub-resolv.conf over a static backup. The DNS resolver may need a moment to fully start. Wait a few seconds, or run:
```bash
sudo tor-route stop
```
Run `stop` a second time — it will flush rules and reset policies, which reliably restores connectivity if the first run left something stale.

**`newnode` does not change the IP**

Tor may reuse the same exit node for a short period. Wait 15 seconds and try again. The Tor network does not guarantee a different country or IP on every circuit rebuild.

---

## File locations

| Path | Purpose |
|---|---|
| `/etc/tor/torrc` | Tor configuration — the script appends and removes its own block |
| `/etc/resolv.conf` | DNS resolver config — replaced during `start`, restored on `stop` |
| `/tmp/iptables-pre-tor.rules` | IPv4 firewall backup (exists only while Tor routing is active) |
| `/tmp/ip6tables-pre-tor.rules` | IPv6 firewall backup (exists only while Tor routing is active) |
| `/tmp/resolv.conf.pre-tor` | resolv.conf backup (exists only while Tor routing is active) |
| `/tmp/tor-route-country` | Records the active exit node country (or `random`) while Tor routing is active |
| `/tmp/tor-route-resolved-state` | Records whether a DNS resolver was running before `start` |

---

## Security notes

- This script is intended for **personal privacy use** on your own machine.
- It does not protect traffic from other devices on your network.
- Using Tor may be restricted or illegal in some countries — check your local laws.
- For maximum anonymity, use the [Tor Browser](https://www.torproject.org/download/) which includes additional fingerprinting protections that this script cannot provide.

---

## TO-DO

- [x] Support init systems other than Systemd:
  - [x] OpenRC
  - [x] Runit
  - [x] SysVinit
- [ ] Config file — move hardcoded vars (ports, state paths) to `/etc/tor-route.conf`
- [ ] `nftables` backend — support the modern `iptables` replacement
- [ ] Tor bridges support — bypass censorship in restrictive networks
- [ ] Split-tunneling — exclude specific users or processes from Tor routing
- [ ] Kill switch — block all traffic if Tor drops unexpectedly
- [ ] Auto-start service — command flag to enable Tor routing at boot
- [ ] `--dry-run` — preview what `start`/`stop` would do without applying
- [ ] Multi-distro installer — detect distro and install dependencies automatically
- [ ] BATS tests — basic shell-level regression tests
- [ ] Desktop notifications — alert on IP/country change via `newnode`

---

## License

This project is open source and avilable under the [GPL-3.0 License](LICENSE).
