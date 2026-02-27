#!/usr/bin/env bash
# =============================================================================
#  tor-route.sh — Route all system traffic through Tor on Arch Linux
#  v4 — fixes: WebRTC/UDP leak, systemd-resolved auto-restart
#
#  Usage (must be run as root):
#    sudo bash tor-route.sh start    → Enable Tor routing
#    sudo bash tor-route.sh stop     → Disable Tor routing (back to normal)
#    sudo bash tor-route.sh status   → Show whether Tor routing is active
#    sudo bash tor-route.sh newnode  → Switch to a new Tor exit node (new IP)
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Configuration ─────────────────────────────────────────────────────────────
TOR_TRANS_PORT=9040   # Tor transparent TCP proxy port
TOR_DNS_PORT=5353     # Tor DNS port (unprivileged — Tor's user can bind to it)
TOR_UID=$(id -u tor 2>/dev/null)

# These address ranges stay on the local network and never go through Tor
NON_TOR="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

TORRC="/etc/tor/torrc"
IPTABLES_BACKUP="/tmp/iptables-pre-tor.rules"
IP6TABLES_BACKUP="/tmp/ip6tables-pre-tor.rules"
RESOLV_BACKUP="/tmp/resolv.conf.pre-tor"

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════╗"
    echo -e "║        Tor Traffic Router  v4        ║"
    echo -e "╚══════════════════════════════════════╝${RESET}\n"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✗] Must be run as root.  Try: ${BOLD}sudo bash $0 $1${RESET}"; exit 1
    fi
}

check_dependencies() {
    local missing=()
    for cmd in tor iptables ip6tables curl ss; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[✗] Missing: ${missing[*]}${RESET}"
        echo -e "    Install: ${BOLD}sudo pacman -S tor iptables curl iproute2${RESET}"; exit 1
    fi
    if [[ -z "$TOR_UID" ]]; then
        echo -e "${RED}[✗] 'tor' system user not found. Is tor installed?${RESET}"; exit 1
    fi
}

# ── torrc ─────────────────────────────────────────────────────────────────────
configure_torrc() {
    sed -i '/^# --- tor-route.sh/d
            /^VirtualAddrNetworkIPv4/d
            /^AutomapHostsOnResolve/d
            /^TransPort /d
            /^DNSPort /d' "$TORRC"
    cat >> "$TORRC" <<EOF

# --- tor-route.sh start ---
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:${TOR_TRANS_PORT}
DNSPort 127.0.0.1:${TOR_DNS_PORT}
# --- tor-route.sh end ---
EOF
    echo -e "${YELLOW}[i] torrc: TransPort=${TOR_TRANS_PORT}, DNSPort=${TOR_DNS_PORT}${RESET}"
}

cleanup_torrc() {
    sed -i '/^# --- tor-route.sh/d
            /^VirtualAddrNetworkIPv4/d
            /^AutomapHostsOnResolve/d
            /^TransPort /d
            /^DNSPort /d' "$TORRC"
    echo -e "${YELLOW}[i] torrc restored.${RESET}"
}

# ── DNS: mask systemd-resolved so it cannot restart itself ───────────────────
#
# v3 used `systemctl stop systemd-resolved`, but systemd-resolved has a
# Restart= directive in its unit file — it restores itself automatically
# within seconds. `systemctl mask` creates a symlink to /dev/null that
# makes systemd pretend the service doesn't exist, preventing any restart
# until we explicitly unmask it.
fix_dns_start() {
    echo -e "${YELLOW}[i] Masking and stopping systemd-resolved (prevents auto-restart)...${RESET}"
    cp --dereference /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null
    systemctl mask systemd-resolved   # blocks auto-restart
    systemctl stop systemd-resolved
    rm -f /etc/resolv.conf
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo -e "${GREEN}[✓] /etc/resolv.conf → 127.0.0.1 → iptables will forward to Tor:${TOR_DNS_PORT}${RESET}"
}

fix_dns_stop() {
    echo -e "${YELLOW}[i] Unmasking and restoring systemd-resolved...${RESET}"
    systemctl unmask systemd-resolved
    [[ -f "$RESOLV_BACKUP" ]] && cp "$RESOLV_BACKUP" /etc/resolv.conf && rm -f "$RESOLV_BACKUP"
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
    systemctl start systemd-resolved
    echo -e "${GREEN}[✓] systemd-resolved restored.${RESET}"
}

# ── Verify Tor is listening on expected ports ─────────────────────────────────
verify_tor_ports() {
    echo -e "${CYAN}[i] Verifying Tor port bindings...${RESET}"
    local ok=1
    ss -tlnp 2>/dev/null | grep -q ":${TOR_TRANS_PORT}" \
        && echo -e "    TransPort ${TOR_TRANS_PORT}: ${GREEN}Listening ✓${RESET}" \
        || { echo -e "    TransPort ${TOR_TRANS_PORT}: ${RED}NOT listening ✗${RESET}"; ok=0; }
    ss -ulnp 2>/dev/null | grep -q ":${TOR_DNS_PORT}" \
        && echo -e "    DNSPort   ${TOR_DNS_PORT}:  ${GREEN}Listening ✓${RESET}" \
        || { echo -e "    DNSPort   ${TOR_DNS_PORT}:  ${RED}NOT listening ✗${RESET}"; ok=0; }
    [[ $ok -eq 0 ]] && { echo -e "\n${RED}[✗] Tor is not listening on required ports.${RESET}"
                          echo -e "    Check: ${BOLD}journalctl -u tor -n 50${RESET}"; return 1; }
    return 0
}

# ── iptables ──────────────────────────────────────────────────────────────────
save_iptables() {
    iptables-save  > "$IPTABLES_BACKUP"
    ip6tables-save > "$IP6TABLES_BACKUP"
    echo -e "${YELLOW}[i] Firewall rules backed up.${RESET}"
}

restore_iptables() {
    if [[ -f "$IPTABLES_BACKUP" ]]; then
        iptables-restore  < "$IPTABLES_BACKUP"  && rm -f "$IPTABLES_BACKUP"
        ip6tables-restore < "$IP6TABLES_BACKUP" && rm -f "$IP6TABLES_BACKUP"
        echo -e "${GREEN}[✓] Firewall rules restored.${RESET}"
    else
        iptables  -F; iptables  -t nat -F
        ip6tables -F; ip6tables -t nat -F
        echo -e "${YELLOW}[i] No backup found — rules flushed.${RESET}"
    fi
}

apply_iptables() {
    # Start with a clean slate in the chains we'll modify
    iptables -t nat -F OUTPUT
    iptables -F OUTPUT

    # ── NAT table (OUTPUT chain): redirect traffic into Tor ──────────────────

    # DNS/UDP (port 53) → Tor's DNS port, excluding Tor's own traffic
    iptables -t nat -A OUTPUT \
        -m owner ! --uid-owner "$TOR_UID" \
        -p udp --dport 53 \
        -j REDIRECT --to-ports "$TOR_DNS_PORT"

    # DNS/TCP (port 53) → same (large DNS responses fall back to TCP)
    iptables -t nat -A OUTPUT \
        -m owner ! --uid-owner "$TOR_UID" \
        -p tcp --dport 53 \
        -j REDIRECT --to-ports "$TOR_DNS_PORT"

    # Tor's own traffic: let it out untouched (prevents routing loop)
    iptables -t nat -A OUTPUT \
        -m owner --uid-owner "$TOR_UID" \
        -j RETURN

    # LAN / loopback addresses: pass through directly
    for addr in $NON_TOR; do
        iptables -t nat -A OUTPUT -d "$addr" -j RETURN
    done

    # All new TCP connections → Tor's transparent proxy
    iptables -t nat -A OUTPUT \
        -p tcp \
        -m state --state NEW \
        -j REDIRECT --to-ports "$TOR_TRANS_PORT"

    # ── FILTER table (OUTPUT chain): block UDP leaks ──────────────────────────
    #
    # *** FIX v4: Block all non-DNS UDP — this kills WebRTC leaks.
    #
    # WebRTC is a browser feature (used for video calls) that sends UDP packets
    # to STUN servers. These servers reply with your true public IP address.
    # NordVPN's website (and similar IP-check tools) use WebRTC specifically
    # because it bypasses proxies and iptables NAT rules that only affect TCP.
    #
    # Tor cannot carry UDP traffic (except DNS which we handle separately),
    # so the only safe thing to do with non-DNS UDP is to DROP it entirely.
    # This prevents WebRTC, QUIC (HTTP/3), and any other UDP protocol from
    # leaking your real IP while Tor is active.
    #
    # Rule order:
    #   1. Allow Tor's own UDP (it needs to talk to the Tor network)
    #   2. Allow DNS/UDP to localhost (our iptables NAT rule above will
    #      redirect it to Tor's DNS port — so it's safe)
    #   3. Allow UDP to local/private IPs (LAN traffic must still work)
    #   4. DROP everything else (WebRTC, QUIC, STUN, etc.)

    # Allow Tor's own UDP outbound
    iptables -A OUTPUT \
        -m owner --uid-owner "$TOR_UID" \
        -p udp \
        -j ACCEPT

    # Allow DNS queries to localhost (they get redirected to Tor by NAT above)
    iptables -A OUTPUT \
        -p udp --dport 53 \
        -d 127.0.0.1 \
        -j ACCEPT

    # Allow UDP to LAN/private ranges (printers, mDNS, local services)
    for addr in $NON_TOR; do
        iptables -A OUTPUT -p udp -d "$addr" -j ACCEPT
    done

    # DROP all other UDP — this is what stops WebRTC and other UDP leaks
    iptables -A OUTPUT -p udp -j DROP

    # ── IPv6: block entirely ──────────────────────────────────────────────────
    # Tor does not support IPv6 transparent proxying. Without this, browsers
    # connect to dual-stack sites over IPv6 and bypass Tor completely.
    ip6tables -P INPUT   DROP
    ip6tables -P OUTPUT  DROP
    ip6tables -P FORWARD DROP

    echo -e "${YELLOW}[i] IPv6 fully blocked.${RESET}"
    echo -e "${YELLOW}[i] Non-DNS UDP blocked (WebRTC/QUIC/STUN leaks prevented).${RESET}"
}

# ── Public IP check ───────────────────────────────────────────────────────────
show_ip() {
    echo -e "${CYAN}[i] Fetching public IP...${RESET}"
    local ip
    ip=$(curl -s --max-time 12 -4 https://api.ipify.org 2>/dev/null)
    [[ -n "$ip" ]] \
        && echo -e "    IPv4: ${BOLD}${ip}${RESET}" \
        || echo -e "    ${YELLOW}IPv4: could not fetch (Tor may still be starting).${RESET}"

    local ip6
    ip6=$(curl -s --max-time 5 -6 https://api6.ipify.org 2>/dev/null)
    [[ -n "$ip6" ]] \
        && echo -e "    IPv6: ${RED}${BOLD}${ip6}  ← LEAK!${RESET}" \
        || echo -e "    IPv6: ${GREEN}Blocked ✓${RESET}"
}

# =============================================================================
#  COMMANDS
# =============================================================================

cmd_start() {
    banner
    require_root start
    check_dependencies

    echo -e "${CYAN}[→] Starting Tor routing...${RESET}\n"

    configure_torrc
    fix_dns_start

    echo -e "${YELLOW}[i] Starting Tor...${RESET}"
    systemctl restart tor
    echo -n "    Bootstrapping"
    for i in {1..25}; do
        sleep 1; echo -n "."
        journalctl -u tor -n 30 --no-pager 2>/dev/null | grep -q "Bootstrapped 100%" && break
    done
    echo ""

    if ! systemctl is-active --quiet tor; then
        echo -e "${RED}[✗] Tor failed to start.${RESET}"
        echo -e "    Run: ${BOLD}journalctl -u tor -n 50${RESET}"
        fix_dns_stop; cleanup_torrc; exit 1
    fi
    echo -e "${GREEN}[✓] Tor is running.${RESET}\n"

    if ! verify_tor_ports; then
        fix_dns_stop; cleanup_torrc; systemctl stop tor; exit 1
    fi

    save_iptables
    apply_iptables

    echo -e "\n${GREEN}${BOLD}[✓] All traffic is now routed through Tor!${RESET}"
    echo -e "    ${YELLOW}Important:${RESET} To fully prevent WebRTC leaks in your browser,"
    echo -e "    also disable WebRTC or install the 'WebRTC Leak Shield' extension.\n"
    show_ip
    echo -e "\n    ${BOLD}sudo bash $0 newnode${RESET}  — new exit node / new IP"
    echo -e "    ${BOLD}sudo bash $0 stop${RESET}     — restore normal internet\n"
}

cmd_stop() {
    banner
    require_root stop
    echo -e "${CYAN}[→] Restoring normal internet...${RESET}\n"

    restore_iptables
    fix_dns_stop
    systemctl stop tor
    echo -e "${GREEN}[✓] Tor stopped.${RESET}"
    cleanup_torrc

    echo -e "\n${GREEN}${BOLD}[✓] Normal internet restored.${RESET}\n"
    sleep 2
    show_ip
    echo ""
}

cmd_status() {
    banner
    echo -e "${CYAN}[→] Status:${RESET}\n"

    systemctl is-active --quiet tor \
        && echo -e "  Tor service:       ${GREEN}${BOLD}Running${RESET}" \
        || echo -e "  Tor service:       ${RED}${BOLD}Stopped${RESET}"

    iptables -t nat -L OUTPUT 2>/dev/null | grep -q "REDIRECT.*${TOR_TRANS_PORT}" \
        && echo -e "  TCP routing:       ${GREEN}${BOLD}Through Tor ✓${RESET}" \
        || echo -e "  TCP routing:       ${YELLOW}Direct (not through Tor)${RESET}"

    iptables -L OUTPUT 2>/dev/null | grep -q "udp.*DROP\|DROP.*udp" \
        && echo -e "  UDP / WebRTC:      ${GREEN}${BOLD}Blocked ✓${RESET}" \
        || echo -e "  UDP / WebRTC:      ${RED}${BOLD}NOT blocked — WebRTC leak possible!${RESET}"

    ip6tables -L OUTPUT 2>/dev/null | grep -q "DROP\|policy DROP" \
        && echo -e "  IPv6:              ${GREEN}${BOLD}Blocked ✓${RESET}" \
        || echo -e "  IPv6:              ${YELLOW}Not blocked${RESET}"

    systemctl is-active --quiet systemd-resolved \
        && echo -e "  DNS:               ${RED}${BOLD}systemd-resolved running — DNS may leak!${RESET}" \
        || echo -e "  DNS:               ${GREEN}${BOLD}Masked → routed through Tor ✓${RESET}"

    if systemctl is-active --quiet tor; then
        echo ""
        verify_tor_ports
    fi

    echo ""
    show_ip
    echo ""
}

cmd_newnode() {
    banner
    require_root newnode

    if ! systemctl is-active --quiet tor; then
        echo -e "${RED}[✗] Tor is not running. Run: sudo bash $0 start${RESET}"; exit 1
    fi

    echo -e "${CYAN}[→] Requesting a new Tor circuit (new exit node = new IP)...${RESET}\n"
    echo -e "  ${YELLOW}Current IP:${RESET}"; show_ip

    # SIGHUP makes Tor reload its config and rebuild all circuits.
    # Circuit = 3-hop path: Guard → Middle → Exit node.
    # The Exit is what websites see as your IP. New circuit = new Exit = new IP.
    systemctl kill --signal=SIGHUP tor
    echo -e "\n  Waiting for new circuit..."; sleep 7

    echo -e "\n  ${YELLOW}New IP:${RESET}"; show_ip
    echo -e "\n${GREEN}[✓] New circuit requested.${RESET}"
    echo -e "    ${YELLOW}Tip:${RESET} If the IP is unchanged, wait ~15 s and try again.\n"
}

# =============================================================================
#  ENTRY POINT
# =============================================================================
case "$1" in
    start)   cmd_start   ;;
    stop)    cmd_stop    ;;
    status)  cmd_status  ;;
    newnode) cmd_newnode ;;
    *)
        banner
        echo -e "  ${BOLD}Usage:${RESET}  sudo bash $0 {start|stop|status|newnode}\n"
        echo -e "  ${GREEN}start${RESET}    Route all traffic through Tor"
        echo -e "  ${RED}stop${RESET}     Restore normal internet routing"
        echo -e "  ${CYAN}status${RESET}   Show routing status and public IP"
        echo -e "  ${YELLOW}newnode${RESET}  Switch to a new Tor exit node (new IP)\n"
        exit 1 ;;
esac
