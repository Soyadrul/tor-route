#!/usr/bin/env bash
# =============================================================================
#  tor-route.sh — Route all system traffic through Tor on Arch Linux
#  v6 — adds: exit node country selection (start/newnode CC),
#              country display in status
#
#  Usage (must be run as root):
#    sudo bash tor-route.sh start [CC]   → Enable Tor routing (optional country code)
#    sudo bash tor-route.sh stop         → Disable Tor routing (back to normal)
#    sudo bash tor-route.sh status       → Show whether Tor routing is active
#    sudo bash tor-route.sh newnode [CC] → Switch to a new Tor exit node (optional country)
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Configuration ─────────────────────────────────────────────────────────────
TOR_TRANS_PORT=9040
TOR_DNS_PORT=5353
TOR_UID=$(id -u tor 2>/dev/null)
NON_TOR="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
TORRC="/etc/tor/torrc"

# Backup / state files written during `start`, read back during `stop`
IPTABLES_BACKUP="/tmp/iptables-pre-tor.rules"
IP6TABLES_BACKUP="/tmp/ip6tables-pre-tor.rules"
RESOLV_BACKUP="/tmp/resolv.conf.pre-tor"

# This file records whether systemd-resolved was active BEFORE we touched it.
# `stop` reads it so it only restores the service if it was running originally.
RESOLVED_STATE_FILE="/tmp/tor-route-resolved-state"

# This file stores the selected exit node country code (if any).
# Used by newnode to re-apply the same country constraint.
EXIT_NODE_COUNTRY_FILE="/tmp/tor-route-exit-country"

# All systemd units that together make up systemd-resolved.
# We must mask ALL of them — masking only the service leaves the socket units
# alive, and socket activation will silently revive the service the moment
# any DNS traffic appears (which is what caused the v4 leak).
RESOLVED_UNITS=(
    systemd-resolved.service
    systemd-resolved-varlink.socket
    systemd-resolved-monitor.socket
)

# ── Country Codes ─────────────────────────────────────────────────────────────
# List of valid ISO 3166-1 alpha-2 country codes for Tor exit node selection
VALID_COUNTRY_CODES=(
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
)

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════╗"
    echo -e "║        Tor Traffic Router  v6        ║"
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

# ── Country Code Validation ───────────────────────────────────────────────────
# Validates if the provided country code is valid (ISO 3166-1 alpha-2)
validate_country_code() {
    local code="$1"
    code=$(echo "$code" | tr '[:lower:]' '[:upper:]')
    for valid in "${VALID_COUNTRY_CODES[@]}"; do
        [[ "$code" == "$valid" ]] && echo "$code" && return 0
    done
    return 1
}

# Get country name from code (simplified list of common countries)
get_country_name() {
    local code="$1"
    case "$code" in
        US) echo "United States" ;;
        GB) echo "United Kingdom" ;;
        DE) echo "Germany" ;;
        FR) echo "France" ;;
        NL) echo "Netherlands" ;;
        CA) echo "Canada" ;;
        AU) echo "Australia" ;;
        JP) echo "Japan" ;;
        SG) echo "Singapore" ;;
        CH) echo "Switzerland" ;;
        SE) echo "Sweden" ;;
        NO) echo "Norway" ;;
        FI) echo "Finland" ;;
        DK) echo "Denmark" ;;
        AT) echo "Austria" ;;
        BE) echo "Belgium" ;;
        ES) echo "Spain" ;;
        IT) echo "Italy" ;;
        PL) echo "Poland" ;;
        CZ) echo "Czech Republic" ;;
        RO) echo "Romania" ;;
        UA) echo "Ukraine" ;;
        RU) echo "Russia" ;;
        BR) echo "Brazil" ;;
        AR) echo "Argentina" ;;
        MX) echo "Mexico" ;;
        IN) echo "India" ;;
        CN) echo "China" ;;
        KR) echo "South Korea" ;;
        HK) echo "Hong Kong" ;;
        TW) echo "Taiwan" ;;
        TH) echo "Thailand" ;;
        MY) echo "Malaysia" ;;
        ID) echo "Indonesia" ;;
        PH) echo "Philippines" ;;
        VN) echo "Vietnam" ;;
        ZA) echo "South Africa" ;;
        IL) echo "Israel" ;;
        TR) echo "Turkey" ;;
        AE) echo "United Arab Emirates" ;;
        *) echo "Unknown" ;;
    esac
}

# Fetch country code from IP address using ipapi.co API
get_country_from_ip() {
    local ip="$1"
    local country_code
    country_code=$(curl -s --max-time 10 "https://ipapi.co/${ip}/country/" 2>/dev/null | tr -d '[:space:]')
    if [[ ${#country_code} -eq 2 ]]; then
        echo "$country_code"
        return 0
    fi
    return 1
}

# Save the selected country code to file
save_country_selection() {
    local code="$1"
    if [[ -z "$code" ]]; then
        rm -f "$EXIT_NODE_COUNTRY_FILE"
    else
        echo "$code" > "$EXIT_NODE_COUNTRY_FILE"
    fi
}

# Load the previously selected country code from file
load_country_selection() {
    if [[ -f "$EXIT_NODE_COUNTRY_FILE" ]]; then
        cat "$EXIT_NODE_COUNTRY_FILE"
    fi
}

# ── torrc ─────────────────────────────────────────────────────────────────────
# Configure torrc with optional exit node country constraint
# Args: $1 = country code (optional, empty for random)
configure_torrc() {
    local country_code="$1"
    sed -i '/^# --- tor-route.sh/d
            /^VirtualAddrNetworkIPv4/d
            /^AutomapHostsOnResolve/d
            /^TransPort /d
            /^DNSPort /d
            /^ExitNodes /d
            /^StrictNodes /d' "$TORRC"
    
    cat >> "$TORRC" <<EOF

# --- tor-route.sh start ---
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:${TOR_TRANS_PORT}
DNSPort 127.0.0.1:${TOR_DNS_PORT}
EOF

    if [[ -n "$country_code" ]]; then
        echo "ExitNodes {$country_code}" >> "$TORRC"
        echo "StrictNodes 1" >> "$TORRC"
        echo "# --- tor-route.sh end ---" >> "$TORRC"
        echo -e "${YELLOW}[i] torrc: TransPort=${TOR_TRANS_PORT}, DNSPort=${TOR_DNS_PORT}, ExitNodes=${country_code}${RESET}"
    else
        echo "# --- tor-route.sh end ---" >> "$TORRC"
        echo -e "${YELLOW}[i] torrc: TransPort=${TOR_TRANS_PORT}, DNSPort=${TOR_DNS_PORT} (random exit)${RESET}"
    fi
}

cleanup_torrc() {
    sed -i '/^# --- tor-route.sh/d
            /^VirtualAddrNetworkIPv4/d
            /^AutomapHostsOnResolve/d
            /^TransPort /d
            /^DNSPort /d
            /^ExitNodes /d
            /^StrictNodes /d' "$TORRC"
    echo -e "${YELLOW}[i] torrc restored.${RESET}"
}

# ── DNS: stop and mask systemd-resolved AND its socket units ─────────────────
fix_dns_start() {
    # --- Record original state BEFORE we touch anything ---
    #
    # We check whether systemd-resolved.service is currently active and save
    # "yes" or "no" to a temp file. `stop` will read this file and only
    # restore the service if it was running before we started.
    if systemctl is-active --quiet systemd-resolved.service; then
        echo "yes" > "$RESOLVED_STATE_FILE"
        echo -e "${YELLOW}[i] systemd-resolved was running — will restore it on stop.${RESET}"
    else
        echo "no" > "$RESOLVED_STATE_FILE"
        echo -e "${YELLOW}[i] systemd-resolved was NOT running — will leave it stopped on stop.${RESET}"
    fi

    # Back up resolv.conf before touching it
    cp --dereference /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null

    # Mask and stop ALL related units.
    #
    # Why mask the socket units too?
    # systemd uses "socket activation": instead of keeping a service running
    # all the time, it keeps a lightweight socket open. The moment any process
    # sends traffic to that socket, systemd automatically starts the full
    # service. If we only mask systemd-resolved.service but leave the sockets
    # alive, any DNS query will silently bring systemd-resolved back to life —
    # which is exactly what was happening in v4.
    echo -e "${YELLOW}[i] Masking all systemd-resolved units (service + sockets)...${RESET}"
    for unit in "${RESOLVED_UNITS[@]}"; do
        systemctl mask --now "$unit" 2>/dev/null && \
            echo -e "    Masked: ${unit}" || \
            echo -e "    ${YELLOW}(skipped — not found: ${unit})${RESET}"
    done

    # Write a plain resolv.conf pointing to 127.0.0.1.
    # iptables will intercept port-53 queries there and forward them to
    # Tor's DNS listener on port 5353.
    rm -f /etc/resolv.conf
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo -e "${GREEN}[✓] /etc/resolv.conf → 127.0.0.1 (iptables will forward to Tor:${TOR_DNS_PORT}).${RESET}"
}

fix_dns_stop() {
    # Unmask and re-enable all units we masked
    echo -e "${YELLOW}[i] Unmasking systemd-resolved units...${RESET}"
    for unit in "${RESOLVED_UNITS[@]}"; do
        systemctl unmask "$unit" 2>/dev/null && \
            echo -e "    Unmasked: ${unit}" || \
            echo -e "    ${YELLOW}(skipped: ${unit})${RESET}"
    done

    # Restore resolv.conf
    if [[ -f "$RESOLV_BACKUP" ]]; then
        cp "$RESOLV_BACKUP" /etc/resolv.conf
        rm -f "$RESOLV_BACKUP"
        echo -e "${YELLOW}[i] resolv.conf restored from backup.${RESET}"
    else
        # No backup — recreate the standard symlink used by Arch + systemd
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
        echo -e "${YELLOW}[i] No resolv.conf backup found — recreated default symlink.${RESET}"
    fi

    # Only start systemd-resolved if it was active before we ran `start`.
    # This avoids leaving the user's system in a different state than it was.
    local was_running
    was_running=$(cat "$RESOLVED_STATE_FILE" 2>/dev/null || echo "yes")
    rm -f "$RESOLVED_STATE_FILE"

    if [[ "$was_running" == "yes" ]]; then
        systemctl start systemd-resolved.service
        echo -e "${GREEN}[✓] systemd-resolved restored (it was running before).${RESET}"
    else
        echo -e "${YELLOW}[i] systemd-resolved was not running before — leaving it stopped.${RESET}"
    fi
}

# ── Verify Tor port bindings ──────────────────────────────────────────────────
verify_tor_ports() {
    echo -e "${CYAN}[i] Verifying Tor port bindings...${RESET}"
    local ok=1
    ss -tlnp 2>/dev/null | grep -q ":${TOR_TRANS_PORT}" \
        && echo -e "    TransPort ${TOR_TRANS_PORT}: ${GREEN}Listening ✓${RESET}" \
        || { echo -e "    TransPort ${TOR_TRANS_PORT}: ${RED}NOT listening ✗${RESET}"; ok=0; }
    ss -ulnp 2>/dev/null | grep -q ":${TOR_DNS_PORT}" \
        && echo -e "    DNSPort   ${TOR_DNS_PORT}:  ${GREEN}Listening ✓${RESET}" \
        || { echo -e "    DNSPort   ${TOR_DNS_PORT}:  ${RED}NOT listening ✗${RESET}"; ok=0; }
    [[ $ok -eq 0 ]] && {
        echo -e "\n${RED}[✗] Tor is not listening on required ports.${RESET}"
        echo -e "    Check: ${BOLD}journalctl -u tor -n 50${RESET}"
        return 1
    }
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
    iptables -t nat -F OUTPUT
    iptables -F OUTPUT

    # DNS/UDP port 53 → Tor DNS (excludes Tor's own traffic)
    iptables -t nat -A OUTPUT \
        -m owner ! --uid-owner "$TOR_UID" \
        -p udp --dport 53 \
        -j REDIRECT --to-ports "$TOR_DNS_PORT"

    # DNS/TCP port 53 → Tor DNS (large responses fall back to TCP)
    iptables -t nat -A OUTPUT \
        -m owner ! --uid-owner "$TOR_UID" \
        -p tcp --dport 53 \
        -j REDIRECT --to-ports "$TOR_DNS_PORT"

    # Tor's own traffic passes untouched (prevents redirect loop)
    iptables -t nat -A OUTPUT \
        -m owner --uid-owner "$TOR_UID" \
        -j RETURN

    # LAN/loopback ranges bypass Tor
    for addr in $NON_TOR; do
        iptables -t nat -A OUTPUT -d "$addr" -j RETURN
    done

    # All new TCP connections → Tor transparent proxy
    iptables -t nat -A OUTPUT \
        -p tcp \
        -m state --state NEW \
        -j REDIRECT --to-ports "$TOR_TRANS_PORT"

    # Block all non-DNS UDP (kills WebRTC/QUIC/STUN leaks)
    iptables -A OUTPUT -m owner --uid-owner "$TOR_UID" -p udp -j ACCEPT
    iptables -A OUTPUT -p udp --dport 53 -d 127.0.0.1 -j ACCEPT
    for addr in $NON_TOR; do
        iptables -A OUTPUT -p udp -d "$addr" -j ACCEPT
    done
    iptables -A OUTPUT -p udp -j DROP

    # Block all IPv6 (Tor can't proxy it; would leak real IP on dual-stack sites)
    ip6tables -P INPUT   DROP
    ip6tables -P OUTPUT  DROP
    ip6tables -P FORWARD DROP

    echo -e "${YELLOW}[i] IPv6 blocked. Non-DNS UDP blocked (WebRTC/STUN/QUIC prevented).${RESET}"
}

# ── Public IP display ─────────────────────────────────────────────────────────
# Fetch and display public IP with country information
# Args: $1 = "quiet" to suppress output (returns IP via echo)
show_ip() {
    local quiet="${1:-}"
    local ip country_code country_name
    
    [[ "$quiet" != "quiet" ]] && echo -e "${CYAN}[i] Fetching public IP...${RESET}"
    
    ip=$(curl -s --max-time 12 -4 https://api.ipify.org 2>/dev/null)
    
    if [[ -n "$ip" ]]; then
        # Try to get country from IP
        country_code=$(get_country_from_ip "$ip")
        if [[ -n "$country_code" ]]; then
            country_name=$(get_country_name "$country_code")
            if [[ "$quiet" != "quiet" ]]; then
                echo -e "    IPv4: ${BOLD}${ip}${RESET} (${country_code} — ${country_name})"
            else
                echo "$ip"
            fi
        else
            if [[ "$quiet" != "quiet" ]]; then
                echo -e "    IPv4: ${BOLD}${ip}${RESET}"
            else
                echo "$ip"
            fi
        fi
    else
        [[ "$quiet" != "quiet" ]] && echo -e "    ${YELLOW}IPv4: could not fetch (Tor may still be starting).${RESET}"
        [[ "$quiet" == "quiet" ]] && echo ""
    fi
    
    local ip6
    ip6=$(curl -s --max-time 5 -6 https://api6.ipify.org 2>/dev/null)
    if [[ -n "$ip6" ]]; then
        [[ "$quiet" != "quiet" ]] && echo -e "    IPv6: ${RED}${BOLD}${ip6}  ← LEAK!${RESET}"
    else
        [[ "$quiet" != "quiet" ]] && echo -e "    IPv6: ${GREEN}Blocked ✓${RESET}"
    fi
}

# =============================================================================
#  COMMANDS
# =============================================================================

cmd_start() {
    banner
    require_root start
    check_dependencies

    local country_code=""
    if [[ -n "$1" ]]; then
        country_code=$(validate_country_code "$1")
        if [[ -z "$country_code" ]]; then
            echo -e "${RED}[✗] Invalid country code: $1${RESET}"
            echo -e "    Use a valid ISO 3166-1 alpha-2 code (e.g., US, DE, GB, FR)"
            echo -e "    Omit the argument for random exit node selection."
            exit 1
        fi
    fi

    echo -e "${CYAN}[→] Starting Tor routing...${RESET}\n"
    configure_torrc "$country_code"
    fix_dns_start

    # Save country selection for future newnode calls
    save_country_selection "$country_code"

    echo -e "${YELLOW}[i] Starting Tor...${RESET}"
    systemctl restart tor
    echo -n "    Bootstrapping"
    for i in {1..25}; do
        sleep 1; echo -n "."
        journalctl -u tor -n 30 --no-pager 2>/dev/null | grep -q "Bootstrapped 100%" && break
    done
    echo ""

    if ! systemctl is-active --quiet tor; then
        echo -e "${RED}[✗] Tor failed to start. Run: journalctl -u tor -n 50${RESET}"
        fix_dns_stop; cleanup_torrc; exit 1
    fi
    echo -e "${GREEN}[✓] Tor is running.${RESET}\n"

    if ! verify_tor_ports; then
        fix_dns_stop; cleanup_torrc; systemctl stop tor; exit 1
    fi

    save_iptables
    apply_iptables

    echo -e "\n${GREEN}${BOLD}[✓] All traffic is now routed through Tor!${RESET}"
    if [[ -n "$country_code" ]]; then
        local country_name
        country_name=$(get_country_name "$country_code")
        echo -e "    ${YELLOW}Exit node country:${RESET} ${country_code} — ${country_name}"
    else
        echo -e "    ${YELLOW}Exit node country:${RESET} Random (any country)"
    fi
    echo -e "    ${YELLOW}Tip:${RESET} Also disable WebRTC inside your browser for full protection."
    echo -e "    Firefox: about:config → media.peerconnection.enabled → false\n"
    show_ip
    echo -e "\n    ${BOLD}sudo bash $0 newnode [CC]${RESET}  — new exit node (optional country)"
    echo -e "    ${BOLD}sudo bash $0 stop${RESET}           — restore normal internet\n"
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
        && echo -e "  Tor service:       ${GREEN}${BOLD}Running ✓${RESET}" \
        || echo -e "  Tor service:       ${RED}${BOLD}Stopped${RESET}"

    iptables -t nat -L OUTPUT 2>/dev/null | grep -q "REDIRECT.*${TOR_TRANS_PORT}" \
        && echo -e "  TCP routing:       ${GREEN}${BOLD}Through Tor ✓${RESET}" \
        || echo -e "  TCP routing:       ${YELLOW}Direct (not through Tor)${RESET}"

    iptables -L OUTPUT 2>/dev/null | grep -q "udp.*DROP\|DROP.*udp" \
        && echo -e "  UDP / WebRTC:      ${GREEN}${BOLD}Blocked ✓${RESET}" \
        || echo -e "  UDP / WebRTC:      ${RED}${BOLD}NOT blocked — leak possible!${RESET}"

    ip6tables -L OUTPUT 2>/dev/null | grep -q "DROP\|policy DROP" \
        && echo -e "  IPv6:              ${GREEN}${BOLD}Blocked ✓${RESET}" \
        || echo -e "  IPv6:              ${YELLOW}Not blocked${RESET}"

    # Check the service AND its socket units
    local resolved_ok=true
    for unit in "${RESOLVED_UNITS[@]}"; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            resolved_ok=false
            echo -e "  DNS ($unit): ${RED}${BOLD}ACTIVE — may leak!${RESET}"
        fi
    done
    $resolved_ok && echo -e "  DNS (resolved):    ${GREEN}${BOLD}All units masked ✓${RESET}"

    # Show exit node country configuration
    local saved_country
    saved_country=$(load_country_selection)
    if [[ -n "$saved_country" ]]; then
        local country_name
        country_name=$(get_country_name "$saved_country")
        echo -e "  Exit node country: ${GREEN}${BOLD}${saved_country} — ${country_name} ✓${RESET}"
    else
        echo -e "  Exit node country: ${YELLOW}Random (any country)${RESET}"
    fi

    if systemctl is-active --quiet tor; then
        echo ""; verify_tor_ports
    fi

    echo ""; show_ip; echo ""
}

cmd_newnode() {
    banner
    require_root newnode

    if ! systemctl is-active --quiet tor; then
        echo -e "${RED}[✗] Tor is not running. Run: sudo bash $0 start${RESET}"; exit 1
    fi

    local country_code=""
    local country_name=""

    # Check if user provided a country code
    if [[ -n "$1" ]]; then
        country_code=$(validate_country_code "$1")
        if [[ -z "$country_code" ]]; then
            echo -e "${RED}[✗] Invalid country code: $1${RESET}"
            echo -e "    Use a valid ISO 3166-1 alpha-2 code (e.g., US, DE, GB, FR)"
            echo -e "    Omit the argument to use the current setting."
            exit 1
        fi
        save_country_selection "$country_code"
        country_name=$(get_country_name "$country_code")

        # Reconfigure Tor with new country constraint
        configure_torrc "$country_code"
        country_changed=true
        echo -e "${YELLOW}[i] Exit node country changed to: ${country_code} — ${country_name}${RESET}"
        echo -e "${YELLOW}[i] Restarting Tor to apply new exit node configuration...${RESET}\n"
        
        # Restart Tor to apply the new ExitNodes setting (reload is not sufficient)
        systemctl restart tor
        echo -n "    Bootstrapping"
        for i in {1..25}; do
            sleep 1; echo -n "."
            journalctl -u tor -n 30 --no-pager 2>/dev/null | grep -q "Bootstrapped 100%" && break
        done
        echo ""
        
        if ! systemctl is-active --quiet tor; then
            echo -e "\n${RED}[✗] Tor failed to restart. Run: journalctl -u tor -n 50${RESET}"
            exit 1
        fi
        echo -e "${GREEN}[✓] Tor is running with new configuration.${RESET}\n"
    else
        # Check for previously saved country preference
        country_code=$(load_country_selection)
        if [[ -n "$country_code" ]]; then
            country_name=$(get_country_name "$country_code")
            echo -e "${YELLOW}[i] Using saved country preference: ${country_code} — ${country_name}${RESET}"
            # Ensure torrc has the correct ExitNodes setting
            configure_torrc "$country_code"
            echo -e "${YELLOW}[i] Restarting Tor to apply exit node configuration...${RESET}\n"
            systemctl restart tor
            echo -n "    Bootstrapping"
            for i in {1..25}; do
                sleep 1; echo -n "."
                journalctl -u tor -n 30 --no-pager 2>/dev/null | grep -q "Bootstrapped 100%" && break
            done
            echo ""
            if ! systemctl is-active --quiet tor; then
                echo -e "\n${RED}[✗] Tor failed to restart. Run: journalctl -u tor -n 50${RESET}"
                exit 1
            fi
            echo -e "${GREEN}[✓] Tor is running with saved country configuration.${RESET}\n"
        else
            echo ""
        fi
    fi

    echo -e "${CYAN}[→] Requesting a new Tor circuit (new exit node = new IP)...${RESET}\n"
    echo -e "  ${YELLOW}Current:${RESET}"; show_ip

    # Signal Tor to build a new circuit
    systemctl kill --signal=SIGHUP tor
    echo -e "\n  Waiting for new circuit..."; sleep 7

    echo -e "\n  ${YELLOW}New:${RESET}"; show_ip
    echo -e "\n${GREEN}[✓] New circuit requested.${RESET}"
    echo -e "    ${YELLOW}Tip:${RESET} If the IP is unchanged, wait ~15 s and try again.\n"
}

# =============================================================================
#  ENTRY POINT
# =============================================================================
case "$1" in
    start)   cmd_start   "$2" ;;
    stop)    cmd_stop    ;;
    status)  cmd_status  ;;
    newnode) cmd_newnode "$2" ;;
    *)
        banner
        echo -e "  ${BOLD}Usage:${RESET}  sudo bash $0 {start|stop|status|newnode} [country_code]\n"
        echo -e "  ${GREEN}start${RESET}    Route all traffic through Tor"
        echo -e "             Optional: country code (e.g., US, DE, GB, FR, NL)"
        echo -e "  ${RED}stop${RESET}     Restore normal internet routing"
        echo -e "  ${CYAN}status${RESET}   Show routing status and public IP with country"
        echo -e "  ${YELLOW}newnode${RESET}  Switch to a new Tor exit node (new IP)"
        echo -e "             Optional: country code to change exit node country\n"
        echo -e "  ${BOLD}Examples:${RESET}"
        echo -e "    sudo bash $0 start          # Random exit node"
        echo -e "    sudo bash $0 start DE       # Germany exit node"
        echo -e "    sudo bash $0 newnode US     # Switch to US exit node"
        echo -e "    sudo bash $0 status         # Show current configuration\n"
        exit 1 ;;
esac
