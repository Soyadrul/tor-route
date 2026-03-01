# tor-route.sh

A Bash script for Arch Linux that transparently routes all system TCP traffic through the [Tor](https://www.torproject.org/) anonymity network, blocks DNS and WebRTC leaks, and provides a one-command way to switch your Tor exit node. **Now with optional exit node country selection.**

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

- **Arch Linux** (or an Arch-based distro such as Manjaro, EndeavourOS)
- **Root / sudo access**
- The following packages:

```bash
sudo pacman -S tor iptables curl iproute2
```

> `iproute2` provides the `ss` command used for port verification.  
> `curl` is used to display your public IP before and after switching.

---

## Installation

1. Download the script (or copy it manually)
```bash
curl -O https://raw.githubusercontent.com/Soyadrul/tor-route/refs/heads/main/tor-route.sh
```
2. Make it executable
```bash
chmod +x tor-route.sh
```

No other configuration is required before first use.

---

## Usage

All commands must be run as root.

```bash
sudo bash tor-route.sh <command> [country_code]
```

| Command | Description |
|---|---|
| `start [CC]` | Enable Tor routing — all traffic goes through Tor (optional country code) |
| `stop` | Disable Tor routing — restore normal internet |
| `status` | Show current routing state, public IP, and exit node country |
| `newnode [CC]` | Request a new Tor exit node (gives you a new IP address, optional country) |

### Examples

```bash
# Start routing through Tor with random exit node
sudo bash tor-route.sh start

# Start routing with a specific exit node country (Germany)
sudo bash tor-route.sh start DE

# Start routing with US exit node
sudo bash tor-route.sh start US

# Check what IP the outside world sees (shows country)
sudo bash tor-route.sh status

# Get a fresh IP address without stopping Tor
sudo bash tor-route.sh newnode

# Switch to a specific country (e.g., Netherlands)
sudo bash tor-route.sh newnode NL

# Restore your normal internet connection
sudo bash tor-route.sh stop
```

### Country Codes

Use ISO 3166-1 alpha-2 country codes (case-insensitive). Common examples:

| Code | Country | Code | Country |
|---|---|---|---|
| `US` | United States | `DE` | Germany |
| `GB` | United Kingdom | `FR` | France |
| `NL` | Netherlands | `CA` | Canada |
| `AU` | Australia | `JP` | Japan |
| `SG` | Singapore | `CH` | Switzerland |
| `SE` | Sweden | `NO` | Norway |

> **Note:** Country selection uses Tor's `ExitNodes` directive with `StrictNodes 1`. If the selected country has few or no available exit nodes, Tor may fail to build circuits. Countries with many exit nodes (US, DE, NL) work more reliably than smaller countries. Use `newnode` to try different exit nodes within the selected country.

---

## What each command does internally

### `start`

1. Appends transparent proxy settings to `/etc/tor/torrc` (`TransPort`, `DNSPort`, `AutomapHostsOnResolve`).
2. Detects and records whether `systemd-resolved` was active, then **masks** the service and its socket units (`systemd-resolved.service`, `systemd-resolved-varlink.socket`, `systemd-resolved-monitor.socket`) to prevent them from restarting automatically via socket activation.
3. Replaces `/etc/resolv.conf` with a file pointing to `127.0.0.1`, so all DNS queries go to Tor's local DNS listener.
4. Starts the Tor service and waits for it to bootstrap to 100%.
5. Verifies that Tor is actually listening on both expected ports before touching the firewall.
6. Backs up existing `iptables` and `ip6tables` rules, then applies the Tor redirect rules.

### `stop`

1. Restores the original `iptables` and `ip6tables` rules from backup.
2. Unmasks all `systemd-resolved` units and restores `/etc/resolv.conf`.
3. Only restarts `systemd-resolved` if it was running before `start` was called — the system is left exactly as it was found.
4. Stops the Tor service.
5. Removes the settings added to `/etc/tor/torrc`.

### `status`

Displays a live summary:
- Whether the Tor service is running
- Whether TCP traffic is being routed through Tor
- Whether UDP / WebRTC is blocked
- Whether IPv6 is blocked
- Whether `systemd-resolved` and its socket units are masked
- Whether Tor is listening on the correct ports
- Your current public IPv4 and IPv6 addresses

### `newnode`

Sends a `SIGHUP` signal to the Tor process. This tells Tor to reload its configuration and rebuild all of its **circuits**. A circuit is the three-hop path your traffic takes through the Tor network:

```
Your machine ──► Guard node ──► Middle node ──► Exit node ──► Internet
```

The *exit node* is the server websites see as your IP. A new circuit means a new exit node and therefore a new public IP address. Your current IP is shown before and after so you can confirm the change.

**With country selection:** If you provide a country code (e.g., `sudo bash tor-route.sh newnode DE`), the script will reconfigure Tor to prefer exit nodes in that country before requesting a new circuit. If no country code is provided, it uses the country set during `start` (if any) or random selection.

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

### Exit node blocking

Many websites and services (Cloudflare, Google, etc.) detect and rate-limit or block known Tor exit nodes. This is expected behaviour — use `newnode` to try a different exit node, or use [Tor bridges](https://bridges.torproject.org/) for more persistent access.

---

## Verifying you are connected through Tor

After running `sudo bash tor-route.sh start`, you can confirm that your traffic is actually going through the Tor network by visiting either of these sites in your browser:

- **https://check.torproject.org/** — the official Tor Project checker. It will display a green message confirming you are using Tor, or a warning if you are not.
- **https://www.whatismybrowser.com/detect/am-i-using-tor/** — an independent checker that detects Tor exit nodes and shows additional details about your browser's apparent identity.

If either site reports that you are **not** using Tor after running `start`, run `sudo bash tor-route.sh status` and check that every line shows ✓ before investigating further.

---

## Troubleshooting

**Tor fails to start**
```bash
journalctl -u tor -n 50
```
Look for permission errors or port conflicts.

**IP still shows as my real address after `start`**

Run `status` and check every line:
- `TCP routing: Through Tor ✓` — iptables rules are applied
- `UDP / WebRTC: Blocked ✓` — non-DNS UDP is dropped
- `IPv6: Blocked ✓` — no IPv6 leak
- `DNS (resolved): All units masked ✓` — resolver cannot bypass Tor
- `DNSPort 5353: Listening ✓` — Tor's DNS is actually running

If all lines show ✓ but the IP check website still shows your real IP, the website itself may be using WebRTC JavaScript — disable WebRTC in your browser as described above.

**DNS not resolving after `stop`**

`systemd-resolved` may need a moment to fully start. Wait a few seconds, or run:
```bash
sudo systemctl restart systemd-resolved
```

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
| `/tmp/tor-route-resolved-state` | Records whether `systemd-resolved` was running before `start` |

---

## Security notes

- This script is intended for **personal privacy use** on your own machine.
- It does not protect traffic from other devices on your network.
- Using Tor may be restricted or illegal in some countries — check your local laws.
- For maximum anonymity, use the [Tor Browser](https://www.torproject.org/download/) which includes additional fingerprinting protections that this script cannot provide.

---

## License

Do whatever you want with it, but don't hold the author liable.
