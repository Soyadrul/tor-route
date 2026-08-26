#!/usr/bin/env bash
# =============================================================================
#  tor-route.sh - Route all system traffic through Tor
#  Init system abstraction with systemd, openrc, runit, sysvinit
#
#  Usage (must be run as root):
#    sudo tor-route start [CC]    → Enable Tor routing
#                                            CC = optional 2-letter country code
#                                            e.g. start us  / start de  / start jp
#    sudo tor-route stop          → Disable Tor routing (back to normal)
#    sudo tor-route status        → Show routing state and exit node info
#    sudo tor-route newnode [CC]  → Switch exit node, optionally pin country
#    sudo tor-route countries     → List all supported country codes
#    sudo tor-route check         → Thorough dry-run system check (safe to paste in GitHub issues)
# =============================================================================

VERSION="1.3.2"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# ── Configuration ─────────────────────────────────────────────────────────────
TOR_TRANS_PORT=9040
TOR_DNS_PORT=5353
TOR_USERS=(tor debian-tor toranon _tor)
TOR_USER=""
for _tu in "${TOR_USERS[@]}"; do
    TOR_UID=$(id -u "$_tu" 2>/dev/null)
    if [[ -n "$TOR_UID" ]]; then
        TOR_USER="$_tu"
        break
    fi
done
NON_TOR="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
TORRC="/etc/tor/torrc"

# Backup / state files written during `start`, read back during `stop`
IPTABLES_BACKUP="/tmp/iptables-pre-tor.rules"
IP6TABLES_BACKUP="/tmp/ip6tables-pre-tor.rules"
RESOLV_BACKUP="/tmp/resolv.conf.pre-tor"

# Records whether a DNS resolver was active before `start` touched it.
# `stop` reads this so it only restores the resolver if it was running originally.
# On systemd this tracks systemd-resolved; on other inits it always records "no".
RESOLVED_STATE_FILE="/tmp/tor-route-resolved-state"

# Persists the active country code (or "random") so `status` and `newnode`
# can read it back without re-parsing torrc.
COUNTRY_FILE="/tmp/tor-route-country"

# Records whether the Tor service itself was running before `start` took it
# over, so `stop`/unwind can put it back the way it was found (mirrors
# RESOLVED_STATE_FILE for the DNS resolver).
TOR_STATE_FILE="/tmp/tor-route-tor-state"

# Lists the systemd-resolved units that were NOT already masked before
# `start`, so `stop` only unmasks those; units the user had deliberately
# masked themselves stay masked after the session.
RESOLVED_MASK_STATE_FILE="/tmp/tor-route-resolved-mask"

# Advisory lock held by mutating commands (start/stop/newnode) so two
# overlapping invocations cannot corrupt each other's backups or state.
COMMAND_LOCK_FILE="/tmp/tor-route.lock"

# Populated by require_init() based on the detected init system.
# For systemd: socket units must be masked alongside the service to prevent
# socket activation from silently reviving systemd-resolved.
RESOLVED_UNITS=()

# Path to Tor's log file for non-systemd inits (systemd uses journalctl instead).
TOR_LOG_FILE=""

# ── Init system abstraction ───────────────────────────────────────────────────
# Thin wrappers around init-system-specific commands.
# Each function dispatches on $INIT so adding a new init system means
# adding a case branch here and in RESOLVED_UNITS population below.

INIT=""
SUPPORTED_INITS=(systemd openrc runit sysvinit)

service_tor_start() {
    case "$INIT" in
        systemd)  systemctl start tor ;;
        openrc)   rc-service tor start ;;
        runit)    sv start tor ;;
        sysvinit) /etc/init.d/tor start ;;
        *)        die_unsupported ;;
    esac
}
service_tor_stop() {
    case "$INIT" in
        systemd)  systemctl stop tor ;;
        openrc)   rc-service tor stop ;;
        runit)    sv stop tor ;;
        sysvinit) /etc/init.d/tor stop ;;
        *)        die_unsupported ;;
    esac
}
service_tor_restart() {
    case "$INIT" in
        systemd)  systemctl restart tor ;;
        openrc)   rc-service tor restart ;;
        runit)    sv restart tor ;;
        sysvinit) /etc/init.d/tor restart ;;
        *)        die_unsupported ;;
    esac
}
service_tor_running() {
    case "$INIT" in
        systemd)  systemctl is-active --quiet tor ;;
        openrc)   rc-service tor status &>/dev/null ;;
        runit)    sv status tor &>/dev/null ;;
        sysvinit) /etc/init.d/tor status &>/dev/null ;;
        *)        die_unsupported ;;
    esac
}
service_tor_reload() {
    case "$INIT" in
        systemd)  systemctl kill --signal=SIGHUP tor ;;
        openrc)   rc-service tor reload ;;
        runit)    sv reload tor ;;
        sysvinit) /etc/init.d/tor reload ;;
        *)        die_unsupported ;;
    esac
}
service_tor_log() {
    case "$INIT" in
        systemd)  journalctl -u tor -n 30 --no-pager "$@" ;;
        openrc|sysvinit) tail -n 30 "$TOR_LOG_FILE" 2>/dev/null ;;
        runit)    tail -n 30 "$TOR_LOG_FILE" 2>/dev/null ;;
        *)        die_unsupported ;;
    esac
}

resolver_running() {
    case "$INIT" in
        systemd)  systemctl is-active --quiet systemd-resolved.service ;;
        *)        return 1 ;;
    esac
}
resolver_start() {
    case "$INIT" in
        systemd)  systemctl start systemd-resolved.service ;;
        *)        return 0 ;;
    esac
}
resolver_mask_now() {
    case "$INIT" in
        systemd)  systemctl mask --now "$1" ;;
        *)        return 0 ;;
    esac
}
resolver_unmask() {
    case "$INIT" in
        systemd)  systemctl unmask "$1" ;;
        *)        return 0 ;;
    esac
}
resolver_is_active() {
    case "$INIT" in
        systemd)  systemctl is-active --quiet "$1" 2>/dev/null ;;
        *)        return 1 ;;
    esac
}

die_unsupported() {
    echo -e "${RED}[✗] Init system '${INIT}' is not supported for this operation.${RESET}"; exit 1
}

detect_init() {
    local pid1
    pid1=$(cat /proc/1/comm 2>/dev/null)

    case "$pid1" in
        systemd)                echo "systemd"  ;;
        openrc-init|openrc)     echo "openrc"   ;;
        runit)                  echo "runit"    ;;
        init)
            if command -v openrc &>/dev/null; then
                echo "openrc"
            else
                echo "sysvinit"
            fi
            ;;
        *)
            if   command -v systemctl  &>/dev/null; then echo "systemd"
            elif command -v rc-service &>/dev/null; then echo "openrc"
            elif command -v runsvdir   &>/dev/null; then echo "runit"
            else return 1
            fi ;;
    esac
}

require_init() {
    INIT=$(detect_init) || {
        echo -e "${RED}[✗] Could not detect init system.${RESET}"; exit 1
    }

    # Populate RESOLVED_UNITS for the current init system.
    case "$INIT" in
        systemd)
            RESOLVED_UNITS=(
                systemd-resolved-varlink.socket
                systemd-resolved-monitor.socket
                systemd-resolved.service
            )
            TOR_LOG_FILE="" ;;
        openrc)
            RESOLVED_UNITS=()
            TOR_LOG_FILE="/var/log/tor/log" ;;
        runit)
            RESOLVED_UNITS=()
            TOR_LOG_FILE="/var/log/tor/current" ;;
        sysvinit)
            RESOLVED_UNITS=()
            TOR_LOG_FILE="/var/log/tor/log" ;;
        *)
            echo -e "  Init system:      ${RED}${BOLD}${INIT}${RESET}"
            echo -e "  ${RED}${BOLD}→${RESET} ${RED}Not supported. Supported: ${SUPPORTED_INITS[*]}${RESET}"
            exit 1 ;;
    esac
    echo -e "  Init system:      ${CYAN}${BOLD}${INIT}${RESET}\n"
}

# ── Helpers ───────────────────────────────────────────────────────────────────
banner() {
    echo -e "\n${CYAN}${BOLD}╔══════════════════════════════════════════╗"
    echo -e "║        Tor Traffic Router  v${VERSION}        ║"
    echo -e "╚══════════════════════════════════════════╝${RESET}\n"
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✗] Must be run as root.  Try: ${BOLD}sudo ${0##*/} $1${RESET}"; exit 1
    fi
}

check_dependencies() {
    local missing=()
    for cmd in tor iptables ip6tables iptables-save ip6tables-save curl ss; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[✗] Missing: ${missing[*]}${RESET}"
        echo -e "    Install the missing packages using your distro's package manager.${RESET}"; exit 1
    fi
    if [[ -z "$TOR_UID" ]]; then
        echo -e "${RED}[✗] Tor system user not found (looked for: ${TOR_USERS[*]}). Is tor installed?${RESET}"; exit 1
    fi
}

# Lighter check for commands that every network-facing command uses.
# Unlike check_dependencies it does NOT require the tor binary or Tor user,
# so `stop` keeps working even if Tor was uninstalled since `start`; it only
# guarantees the tools needed to restore or inspect the firewall are present.
# Optional args restrict the requirement set (e.g. stop only needs
# iptables/ip6tables - curl is only used for the post-restore probe).
check_net_tools() {
    local missing=() cmd tools=("$@")
    [[ ${#tools[@]} -eq 0 ]] && tools=(iptables ip6tables curl ss)
    for cmd in "${tools[@]}"; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}[✗] Missing: ${missing[*]}${RESET}"
        echo -e "    Install the missing packages using your distro's package manager."
        exit 1
    fi
}

# Serialise mutating commands (start/stop/newnode). They all rewrite the same
# state - firewall, resolv.conf, torrc, services - and `start`'s "already
# active?" gate runs long before the rules appear, so two overlapping runs
# could both pass it and one would back up the other's Tor-state rules for a
# later stop to restore as if they were pre-Tor state. flock releases the
# lock automatically when the process dies, so stale locks cannot happen.
# Read-only commands (status/check/countries) are deliberately not locked.
acquire_command_lock() {
    exec 9>>"$COMMAND_LOCK_FILE"
    if command -v flock &>/dev/null; then
        if ! flock -n 9; then
            echo -e "${RED}[✗] Another tor-route command is already running.${RESET}"
            echo -e "    ${YELLOW}Wait for it to finish, then try again.${RESET}"
            exit 1
        fi
    else
        echo -e "${YELLOW}[!] flock not found - running WITHOUT protection against concurrent runs.${RESET}"
    fi
}

# ── Country code validation ───────────────────────────────────────────────────
# Full list of ISO 3166-1 alpha-2 codes that Tor supports as exit node filters.
# Tor uses the two-letter code wrapped in braces, e.g. {us}, {de}, {jp}.
VALID_COUNTRIES=(
    ad ae af ag ai al am ao aq ar as at au aw ax az
    ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz
    ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz
    de dj dk dm do dz
    ec ee eg eh er es et
    fi fj fk fm fo fr
    ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy
    hk hm hn hr ht hu
    id ie il im in io iq ir is it
    je jm jo jp
    ke kg kh ki km kn kp kr kw ky kz
    la lb lc li lk lr ls lt lu lv ly
    ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz
    na nc ne nf ng ni nl no np nr nu nz
    om
    pa pe pf pg ph pk pl pm pn pr ps pt pw py
    qa
    re ro rs ru rw
    sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz
    tc td tf tg th tj tk tl tm tn to tr tt tv tw tz
    ua ug um us uy uz
    va vc ve vg vi vn vu
    wf ws
    ye yt
    za zm zw
)

validate_country() {
    # Takes a country code string, lowercases it, checks it against the list.
    # Prints the normalised code and returns 0 on success, 1 on failure.
    local input="${1,,}"   # ,, = lowercase in bash
    for cc in "${VALID_COUNTRIES[@]}"; do
        if [[ "$cc" == "$input" ]]; then
            echo "$cc"
            return 0
        fi
    done
    return 1
}

cmd_check() {
    banner
    require_root check
    require_init

    local all_ok=0

    # ── System ──────────────────────────────────────────────────────────────
    echo -e "  ${BOLD}── System ──────────────────────────────${RESET}"
    echo -e "  Script:    tor-route.sh v${VERSION}"
    if [[ -f /etc/os-release ]]; then
        echo -e "  OS:        $(grep -oP '(?<=^PRETTY_NAME=").*(?=")' /etc/os-release 2>/dev/null || grep -oP '(?<=^PRETTY_NAME=).*' /etc/os-release 2>/dev/null | tr -d '"')"
    fi
    echo -e "  Kernel:    $(uname -rs 2>/dev/null)"

    # ── Dependencies ────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── Dependencies ────────────────────────${RESET}"
    local v
    for cmd in tor iptables ip6tables iptables-save ip6tables-save curl ss; do
        if command -v "$cmd" &>/dev/null; then
            v=$("$cmd" --version 2>/dev/null | head -1)
            echo -e "    ${GREEN}✓${RESET} ${cmd}  ${YELLOW}(${v:-version unknown})${RESET}"
        else
            echo -e "    ${RED}✗${RESET} ${cmd}  ${YELLOW}(missing)${RESET}"
            all_ok=1
        fi
    done

    # ── Tor user ────────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── Tor user ────────────────────────────${RESET}"
    echo -e "  Lookup:    ${TOR_USERS[*]}"
    if [[ -n "$TOR_UID" ]]; then
        echo -e "  Found:     ${TOR_USER} (UID ${TOR_UID})"
    else
        echo -e "  Found:     ${RED}none${RESET}"
        all_ok=1
    fi

    # ── Tor service ────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── Tor service ─────────────────────────${RESET}"
    if service_tor_running; then
        echo -e "  Status:    ${GREEN}Running${RESET}"
    else
        echo -e "  Status:    ${YELLOW}Not running${RESET}"
    fi
    echo -e "  Ports:     $(ss -tlnp 2>/dev/null | grep tor | awk '{print $4}' | tr '\n' ' ' || echo '(none)')"
    echo -e "  DNS port:  $(ss -ulnp 2>/dev/null | grep tor | awk '{print $4}' | tr '\n' ' ' || echo '(none)')"

    # ── Torrc ───────────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── torrc ───────────────────────────────${RESET}"
    if [[ -f "$TORRC" ]]; then
        echo -e "  Path:      ${TORRC}"
        echo -e "  Readable:  $([[ -r "$TORRC" ]] && echo "${GREEN}yes${RESET}" || echo "${RED}no${RESET}")"
        echo -e "  Writable:  $([[ -w "$TORRC" ]] && echo "${GREEN}yes${RESET}" || echo "${RED}no${RESET}")"
        if grep -q "^# --- tor-route.sh start" "$TORRC"; then
            echo -e "  Our block: ${YELLOW}present${RESET}"
            sed -n '/^# --- tor-route.sh start ---$/,/^# --- tor-route.sh end ---$/p' "$TORRC" | sed 's/^/    /'
        else
            echo -e "  Our block: not present"
        fi
    else
        echo -e "  Path:      ${TORRC}"
        echo -e "  Exists:    ${RED}no${RESET}"
        all_ok=1
    fi

    # ── State files ─────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── State files ─────────────────────────${RESET}"
    for f in IPTABLES_BACKUP IP6TABLES_BACKUP RESOLV_BACKUP RESOLVED_STATE_FILE COUNTRY_FILE TOR_STATE_FILE RESOLVED_MASK_STATE_FILE; do
        local path="${!f}"
        if [[ -f "$path" ]]; then
            echo -e "  ${f}:  ${path}  ${GREEN}(exists)${RESET}"
        else
            echo -e "  ${f}:  ${path}  (not present)"
        fi
    done

    # ── Firewall ────────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── Firewall ────────────────────────────${RESET}"
    echo -e "  iptables:  $(iptables --version 2>/dev/null || echo 'not found')"
    if is_routing_active; then
        echo -e "  NAT OUTPUT:"
        iptables -t nat -L OUTPUT -n 2>/dev/null | sed 's/^/    /'
        echo -e "  Filter OUTPUT:"
        iptables -L OUTPUT -n -v 2>/dev/null | sed 's/^/    /'
    else
        echo -e "  NAT OUTPUT:  ${GREEN}(no Tor redirect — normal routing)${RESET}"
    fi
    if command -v ip6tables &>/dev/null; then
        echo -e "  ip6tables: $(ip6tables --version 2>/dev/null || echo 'found')"
        # Report the actual chain POLICY, not the presence of any DROP rule:
        # a user's own firewall can contain DROP rules while everything
        # still passes by default policy.
        local v6pol
        v6pol=$(ip6tables -L OUTPUT -n 2>/dev/null | head -n1)
        if [[ "$v6pol" == *"policy DROP"* ]]; then
            echo -e "  IPv6 policy:  ${GREEN}Blocked${RESET}"
        elif [[ "$v6pol" =~ \((policy\ [A-Z]+)\) ]]; then
            echo -e "  IPv6 policy:  ${YELLOW}Not blocked (${BASH_REMATCH[1]})${RESET}"
        else
            echo -e "  IPv6 policy:  ${YELLOW}Not blocked (no stack or unreadable)${RESET}"
        fi
    else
        echo -e "  ip6tables: ${YELLOW}not available${RESET}"
    fi

    # ── DNS ──────────────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── DNS ─────────────────────────────────${RESET}"
    if [[ -L /etc/resolv.conf ]]; then
        echo -e "  resolv.conf:  symlink → $(readlink /etc/resolv.conf)"
    elif [[ -f /etc/resolv.conf ]]; then
        echo -e "  resolv.conf:  regular file (${GREEN}$(wc -l < /etc/resolv.conf) lines${RESET})"
    else
        echo -e "  resolv.conf:  ${RED}missing${RESET}"
    fi
    # grep -c always prints a count (0 included); only an unreadable file
    # yields empty output, so no "|| echo 0" here - that would double the
    # zero into "0\n0".
    local ns_count
    ns_count=$(grep -c '^nameserver' /etc/resolv.conf 2>/dev/null)
    echo -e "  Nameservers:  ${ns_count:-0} entries"
    echo -e "  Backup:       $( [[ -f "$RESOLV_BACKUP" ]] && echo "${GREEN}exists${RESET}" || echo 'not present' )"
    if [[ "$INIT" == "systemd" ]] && [[ -f "$RESOLVED_STATE_FILE" ]]; then
        echo -e "  Resolved:     was $(cat "$RESOLVED_STATE_FILE")"
    fi

    # ── Tor log ─────────────────────────────────────────────────────────────
    echo -e "\n  ${BOLD}── Tor log ─────────────────────────────${RESET}"
    local loglines
    if [[ "$INIT" == "systemd" ]]; then
        echo -e "  Source:    journalctl -u tor (last 5 lines)"
        loglines=$(journalctl -u tor -n 5 --no-pager 2>/dev/null)
        if [[ -n "$loglines" ]]; then
            echo "$loglines" | sed 's/^/  /'
        else
            echo -e "  ${YELLOW}(no entries yet)${RESET}"
        fi
    elif [[ -f "$TOR_LOG_FILE" ]]; then
        echo -e "  Source:    ${TOR_LOG_FILE} (tail, last 5 lines)"
        loglines=$(tail -n 5 "$TOR_LOG_FILE" 2>/dev/null)
        if [[ -n "$loglines" ]]; then
            echo "$loglines" | sed 's/^/  /'
        else
            echo -e "  ${YELLOW}(empty)${RESET}"
        fi
    else
        echo -e "  Source:    ${TOR_LOG_FILE} (tail)"
        echo -e "  ${YELLOW}(not found - not required; readiness is checked via ports and traffic probe)${RESET}"
    fi

    # ── Verdict ─────────────────────────────────────────────────────────────
    if [[ $all_ok -eq 0 ]]; then
        echo -e "\n${GREEN}${BOLD}[✓] All checks passed.${RESET}"
    else
        echo -e "\n${YELLOW}${BOLD}[!] Some checks failed — review the items above.${RESET}"
    fi
    echo -e "\n${BOLD}Paste the full output above when opening a GitHub issue.${RESET}"
    echo ""
}

cmd_countries() {
    banner
    echo -e "${CYAN}Supported country codes (ISO 3166-1 alpha-2):${RESET}\n"
    # Print in tidy columns of 12
    local i=0
    for cc in "${VALID_COUNTRIES[@]}"; do
        printf "  ${BOLD}%s${RESET}" "${cc^^}"
        (( i++ ))
        (( i % 12 == 0 )) && echo ""
    done
    echo -e "\n\n  ${YELLOW}Usage examples:${RESET}"
    echo -e "    sudo ${0##*/} start us      → pin exit to United States"
    echo -e "    sudo ${0##*/} start de      → pin exit to Germany"
    echo -e "    sudo ${0##*/} newnode jp    → switch to a Japanese exit node"
    echo -e "    sudo ${0##*/} start         → random exit (no country filter)\n"
}


# Remove only the tor-route-managed block from torrc (the marked section
# appended by configure_torrc). Any TransPort/DNSPort/ExitNodes lines that
# existed BEFORE tor-route (outside the markers) are left untouched.
strip_torrc_block() {
    sed -i '/^# --- tor-route.sh start ---$/,/^# --- tor-route.sh end ---$/d' "$TORRC" 2>/dev/null
}

configure_torrc() {
    # Optional first argument: a validated 2-letter country code, or empty for random.
    local country="${1:-}"

    strip_torrc_block

    if [[ -n "$country" ]]; then
        # ExitNodes {cc} tells Tor to only use exit nodes in that country.
        # StrictNodes 1 makes the restriction hard - Tor will not fall back
        # to other countries if no exit is available (it will wait instead).
        cat >> "$TORRC" <<EOF

# --- tor-route.sh start ---
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:${TOR_TRANS_PORT}
DNSPort 127.0.0.1:${TOR_DNS_PORT}
ExitNodes {${country}}
StrictNodes 1
# --- tor-route.sh end ---
EOF
        echo -e "${YELLOW}[i] torrc: TransPort=${TOR_TRANS_PORT}, DNSPort=${TOR_DNS_PORT}, ExitNodes={${country^^}}${RESET}"
        echo "${country}" > "$COUNTRY_FILE"
    else
        cat >> "$TORRC" <<EOF

# --- tor-route.sh start ---
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 127.0.0.1:${TOR_TRANS_PORT}
DNSPort 127.0.0.1:${TOR_DNS_PORT}
# --- tor-route.sh end ---
EOF
        echo -e "${YELLOW}[i] torrc: TransPort=${TOR_TRANS_PORT}, DNSPort=${TOR_DNS_PORT}, ExitNodes=random${RESET}"
        echo "random" > "$COUNTRY_FILE"
    fi
}

cleanup_torrc() {
    # NOT removing bare TransPort/DNSPort/ExitNodes lines here: they may be
    # the user's own pre-existing config. Only our marked block goes away.
    strip_torrc_block
    rm -f "$COUNTRY_FILE"
    echo -e "${YELLOW}[i] torrc restored.${RESET}"
}

# Put the Tor service back the way `start` found it. If Tor was already
# running before (recorded in TOR_STATE_FILE), clean torrc first and restart
# the service so it comes back on the user's own configuration; if it was
# not running, just stop it. Consumes the state file either way; a missing
# file defaults to "not running", i.e. the old stop-always behaviour.
restore_tor_service() {
    local was_running
    was_running=$(cat "$TOR_STATE_FILE" 2>/dev/null)
    rm -f "$TOR_STATE_FILE"
    if [[ "$was_running" == "yes" ]]; then
        echo -e "${YELLOW}[i] Tor was running before - restoring it with the original config...${RESET}"
        cleanup_torrc
        service_tor_restart
        echo -e "${GREEN}[✓] Tor service restored.${RESET}"
    else
        service_tor_stop
        cleanup_torrc
        echo -e "${GREEN}${BOLD}[✓] Tor stopped.${RESET}"
    fi
}

# Fired when the Tor redirect rules are still live but the firewall backups
# are gone (deleted externally mid-session): restore_iptables no-ops through
# its guard, so stopping Tor here would leave all traffic pointed at a dead
# transparent proxy. Print exact manual recovery steps instead of mutating
# anything further or claiming success.
print_manual_rule_recovery() {
    echo -e "\n${RED}${BOLD}[✗] Tor routing rules are still active but the firewall backups are missing.${RESET}"
    echo -e "    ${RED}Stopping Tor now would black-hole your traffic, so it was left running.${RESET}"
    echo -e "    ${YELLOW}Remove the leftover rules manually, then run ${BOLD}stop${RESET}${YELLOW} again:${RESET}"
    echo -e "      ${BOLD}iptables -t nat -F OUTPUT && iptables -F OUTPUT${RESET}"
    echo -e "      ${BOLD}ip6tables -P INPUT ACCEPT && ip6tables -P OUTPUT ACCEPT && ip6tables -P FORWARD ACCEPT${RESET}"
}

# Unwind hook for `start` when the user interrupts it at any point after the
# script starts mutating the system (torrc, Tor, firewall, DNS). Leaves the
# system exactly as it was: rules restored, DNS restored, Tor stopped, torrc
# cleaned. Safe to run at any time because restore_iptables/fix_dns_stop
# no-op through their guards when nothing was saved yet.
interrupt_unwind() {
    echo ""
    echo -e "${RED}[✗] Interrupted. Restoring normal internet...${RESET}"
    restore_iptables
    # If the rules survived the restore, the backups were deleted out from
    # under the session - tearing down Tor now would black-hole everything.
    if is_routing_active; then
        print_manual_rule_recovery
        exit 1
    fi
    fix_dns_stop
    restore_tor_service
    exit 1
}

# ── DNS resolver handling ─────────────────────────────────────────────────────
fix_dns_start() {
    # Record whether a DNS resolver was running before we touch anything.
    # On systemd this checks systemd-resolved; on other inits it's always "no".
    if resolver_running; then
        echo "yes" > "$RESOLVED_STATE_FILE"
        echo -e "${YELLOW}[i] DNS resolver was running - will restore it on stop.${RESET}"
    else
        echo "no" > "$RESOLVED_STATE_FILE"
        echo -e "${YELLOW}[i] DNS resolver was NOT running - will leave it stopped on stop.${RESET}"
    fi

    # Back up resolv.conf before touching it. Root-only mode: the dump can
    # reveal internal nameserver topology, and /tmp is world-readable by
    # default. (No global umask change - /etc/resolv.conf itself must stay
    # readable by every process.)
    cp --dereference /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null
    chmod 600 "$RESOLV_BACKUP" 2>/dev/null

    # Mask and stop all resolver units (systemd only; other inits skip this).
    #
    # Why mask the socket units too?
    # systemd uses "socket activation": instead of keeping a service running
    # all the time, it keeps a lightweight socket open. The moment any process
    # sends traffic to that socket, systemd automatically starts the full
    # service. If we only mask systemd-resolved.service but leave the sockets
    # alive, any DNS query will silently bring systemd-resolved back to life.
    if [[ "$INIT" == "systemd" ]]; then
        echo -e "${YELLOW}[i] Masking DNS resolver units...${RESET}"
        # Record which units were NOT masked beforehand so `stop` only
        # unmasks those - a unit the user deliberately masked themselves
        # must stay masked after the session.
        local prev
        : > "$RESOLVED_MASK_STATE_FILE"
        for unit in "${RESOLVED_UNITS[@]}"; do
            # `is-enabled` prints "masked" for masked units while exiting
            # non-zero - never append a fallback with || here, or a masked
            # unit would be captured as "masked"$'\n'"not-found".
            prev=$(systemctl is-enabled "$unit" 2>/dev/null)
            if [[ "$prev" != "masked" ]]; then
                echo "$unit" >> "$RESOLVED_MASK_STATE_FILE"
            fi
            resolver_mask_now "$unit" 2>/dev/null && \
                echo -e "    Masked: ${unit}" || \
                echo -e "    ${YELLOW}(skipped - not found: ${unit})${RESET}"
        done
    fi

    # Write a plain resolv.conf pointing to 127.0.0.1
    # iptables will intercept port 53 queries there and forward them to
    # Tor's DNS listener on port ${TOR_DNS_PORT}.
    rm -f /etc/resolv.conf
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    echo -e "${GREEN}[✓] /etc/resolv.conf → 127.0.0.1 (iptables will forward to Tor:${TOR_DNS_PORT}).${RESET}"
}

fix_dns_stop() {
    # If fix_dns_start never ran (e.g. `start` failed before touching DNS),
    # there is nothing to restore - the 1.1.1.1 fallback below would
    # otherwise clobber an untouched resolv.conf.
    if [[ ! -f "$RESOLVED_STATE_FILE" && ! -f "$RESOLV_BACKUP" ]]; then
        echo -e "${YELLOW}[i] DNS was not modified by this run - leaving it untouched.${RESET}"
        return 0
    fi

    # Unmask resolver units (systemd only; other inits have none). Only
    # units that were NOT already masked before `start` get unmasked - see
    # fix_dns_start. A missing record file means the session was started by
    # an older script version, so fall back to unmasking everything.
    if [[ "$INIT" == "systemd" ]]; then
        echo -e "${YELLOW}[i] Unmasking DNS resolver units...${RESET}"
        if [[ -f "$RESOLVED_MASK_STATE_FILE" ]]; then
            while IFS= read -r unit; do
                [[ -z "$unit" ]] && continue
                resolver_unmask "$unit" 2>/dev/null && \
                    echo -e "    Unmasked: ${unit}" || \
                    echo -e "    ${YELLOW}(skipped: ${unit})${RESET}"
            done < "$RESOLVED_MASK_STATE_FILE"
        else
            for unit in "${RESOLVED_UNITS[@]}"; do
                resolver_unmask "$unit" 2>/dev/null && \
                    echo -e "    Unmasked: ${unit}" || \
                    echo -e "    ${YELLOW}(skipped: ${unit})${RESET}"
            done
        fi
        rm -f "$RESOLVED_MASK_STATE_FILE"
    fi

    # Restore resolv.conf.
    # Prefer symlink to resolved's live stub (dynamic, updates with network changes)
    # over a static backup file.
    if [[ -f /run/systemd/resolve/stub-resolv.conf ]]; then
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
        echo -e "${YELLOW}[i] resolv.conf → symlink to stub-resolv.conf.${RESET}"
    elif [[ -f "$RESOLV_BACKUP" ]]; then
        cp "$RESOLV_BACKUP" /etc/resolv.conf
        echo -e "${YELLOW}[i] resolv.conf restored from backup.${RESET}"
    else
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        echo -e "${YELLOW}[i] No resolv.conf backup found - wrote generic fallback.${RESET}"
    fi
    rm -f "$RESOLV_BACKUP"

    # Restart the DNS resolver only if it was running before `start`.
    local was_running
    was_running=$(cat "$RESOLVED_STATE_FILE" 2>/dev/null || echo "yes")
    rm -f "$RESOLVED_STATE_FILE"

    if [[ "$was_running" == "yes" ]]; then
        resolver_start
        echo -e "${GREEN}[✓] DNS resolver restored (it was running before).${RESET}"
    else
        echo -e "${YELLOW}[i] DNS resolver was not running before - leaving it stopped.${RESET}"
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
        echo -e "    Check Tor logs for errors (${BOLD}sudo ${0##*/} status${RESET} to verify the service state)."
        return 1
    }
    return 0
}

# ── iptables ──────────────────────────────────────────────────────────────────
# True when the kernel actually exposes an IPv6 stack. With ipv6.disable=1
# (or the module blacklisted) ip6tables cannot even list rules: there is
# nothing to block and nothing that could leak, so every IPv6 step becomes a
# no-op instead of aborting `start`.
ipv6_available() {
    ip6tables -L -n &>/dev/null
}

save_iptables() {
    # A failed save aborts start. A partial backup must not survive: if only
    # one family was saved, restore_iptables would flush BOTH and restore
    # just the one - destroying the other family's rules. Delete both files
    # and abort before any rules are touched. Empty output with exit 0 is a
    # valid baseline (fresh system, no rules to back up).
    #
    # Each dump lands in a .tmp sibling first and is renamed into place:
    # rename(2) is atomic within /tmp, so an interrupt mid-save can never
    # leave a truncated file behind that restore_iptables would mistake for
    # a complete backup. Stray .tmp files are inert - restore only ever
    # reads the final names.
    rm -f "$IPTABLES_BACKUP.tmp" "$IP6TABLES_BACKUP.tmp"
    if ! iptables-save > "$IPTABLES_BACKUP.tmp"; then
        rm -f "$IPTABLES_BACKUP.tmp" "$IP6TABLES_BACKUP.tmp"
        echo -e "${RED}[✗] Firewall save failed. Aborting - your rules are untouched.${RESET}"
        return 1
    fi
    mv "$IPTABLES_BACKUP.tmp" "$IPTABLES_BACKUP"
    # An absent IPv6 stack has no rules to back up and cannot leak - skip the
    # v6 save instead of failing start over it.
    if ipv6_available; then
        if ! ip6tables-save > "$IP6TABLES_BACKUP.tmp"; then
            rm -f "$IPTABLES_BACKUP" "$IP6TABLES_BACKUP.tmp" "$IPTABLES_BACKUP.tmp"
            echo -e "${RED}[✗] Firewall save failed. Aborting - your rules are untouched.${RESET}"
            return 1
        fi
        mv "$IP6TABLES_BACKUP.tmp" "$IP6TABLES_BACKUP"
    else
        rm -f "$IP6TABLES_BACKUP"
        echo -e "${YELLOW}[i] IPv6 not available - skipping IPv6 backup (nothing to block or restore).${RESET}"
    fi
    # Root-only mode for the same reason as the resolv.conf backup above:
    # firewall dumps expose network topology into a world-readable /tmp.
    chmod 600 "$IPTABLES_BACKUP" "$IP6TABLES_BACKUP" 2>/dev/null
    echo -e "${YELLOW}[i] Firewall rules backed up.${RESET}"
}

restore_iptables() {
    # If `start` never saved a firewall (backups absent), there is nothing to
    # restore - flushing everything here would wipe the user's existing rules.
    if [[ ! -f "$IPTABLES_BACKUP" && ! -f "$IP6TABLES_BACKUP" ]]; then
        echo -e "${YELLOW}[i] Firewall was not modified by this run - leaving it untouched.${RESET}"
        return 0
    fi

    local restored=0

    # Stage 1: always flush and reset policies — guarantees a working baseline
    # regardless of backup state. Without this, ip6tables DROP policies set by
    # apply_iptables persist after ip6tables -F (which only flushes rules).
    iptables -F; iptables -t nat -F
    if ipv6_available; then
        ip6tables -F; ip6tables -t nat -F
        ip6tables -P INPUT ACCEPT
        ip6tables -P OUTPUT ACCEPT
        ip6tables -P FORWARD ACCEPT
    fi
    echo -e "${YELLOW}[i] Rules flushed, policies reset to ACCEPT.${RESET}"

    # Stage 2: try to restore any custom pre-Tor rules from backup. Each
    # family reports separately so a failure is not silently absorbed.
    if [[ -f "$IPTABLES_BACKUP" ]]; then
        if iptables-restore < "$IPTABLES_BACKUP" 2>/dev/null; then
            rm -f "$IPTABLES_BACKUP"
            echo -e "${YELLOW}[i] Custom iptables rules restored.${RESET}"
        else
            echo -e "${RED}[✗] FAILED to restore iptables rules from backup.${RESET}"
            echo -e "    ${RED}Backup kept at ${IPTABLES_BACKUP} for manual restore.${RESET}"
            restored=1
        fi
    else
        echo -e "${YELLOW}[i] No iptables backup to restore.${RESET}"
    fi
    if [[ -f "$IP6TABLES_BACKUP" ]]; then
        if ip6tables-restore < "$IP6TABLES_BACKUP" 2>/dev/null; then
            rm -f "$IP6TABLES_BACKUP"
            echo -e "${YELLOW}[i] Custom ip6tables rules restored.${RESET}"
        else
            echo -e "${RED}[✗] FAILED to restore ip6tables rules from backup.${RESET}"
            echo -e "    ${RED}Backup kept at ${IP6TABLES_BACKUP} for manual restore.${RESET}"
            restored=1
        fi
    else
        echo -e "${YELLOW}[i] No ip6tables backup to restore.${RESET}"
    fi

    # Delete conntrack entries that still point at Tor's ports (NAT state
    # carries the rewrite independently of the current ruleset). Match the
    # REPLY tuple: REDIRECT rewrites connections so Tor's local port becomes
    # the reply SOURCE port, while the original destination port stays
    # whatever the application dialed (443, 53, ...) - plain --dport would
    # therefore match almost nothing and stale entries would survive until
    # they expire. Still scoped to the TOR_* ports only: a broad
    # `conntrack -F` would also tear down every established connection that
    # was never routed through Tor (e.g. an SSH session calling `stop`
    # itself).
    echo -e "${YELLOW}[i] Removing conntrack entries for Tor ports...${RESET}"
    if command -v conntrack &>/dev/null; then
        conntrack -D -p tcp --reply-port-src "$TOR_TRANS_PORT" 2>/dev/null
        conntrack -D -p udp --reply-port-src "$TOR_DNS_PORT" 2>/dev/null
    else
        echo -e "    ${YELLOW}(conntrack not available, skipping)${RESET}"
    fi

    return $restored
}

apply_iptables() {
    # Every mutation runs under set -e inside a subshell: the FIRST failing
    # command aborts and surfaces as a failure here, instead of half a
    # ruleset silently passing the later checks. The caller unwinds via
    # restore_iptables on failure.
    if ! (
        set -e

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

        # Block all IPv6 (Tor can't proxy it; would leak real IP on dual-stack
        # sites). On kernels without an IPv6 stack there is nothing to leak -
        # skip instead of failing.
        if ipv6_available; then
            ip6tables -P INPUT   DROP
            ip6tables -P OUTPUT  DROP
            ip6tables -P FORWARD DROP

            # Verify the policies actually took effect. If ip6tables failed
            # silently here despite a working stack, IPv6 traffic would keep
            # flowing unproxied - a leak. Abort so `start` never claims success
            # over an enabled IPv6 stack.
            if ! ip6tables -L OUTPUT -n 2>/dev/null | grep -q "policy DROP"; then
                echo -e "${RED}[✗] Could not apply IPv6 DROP policies - IPv6 would stay enabled and leak. Check that the ipv6 kernel module is loaded.${RESET}" >&2
                exit 1
            fi
            echo -e "${YELLOW}[i] IPv6 blocked.${RESET}"
        else
            echo -e "${YELLOW}[i] IPv6 not available (disabled in kernel?) - skipping IPv6 blocking, nothing to leak.${RESET}"
        fi
    ); then
        echo -e "${RED}[✗] Failed to apply the firewall rules.${RESET}"
        return 1
    fi

    echo -e "${YELLOW}[i] Non-DNS UDP blocked (WebRTC/STUN/QUIC prevented).${RESET}"
    return 0
}

# 0 if the Tor transparent redirect is currently present in iptables,
# non-zero otherwise. Also used by `status`/`check`/`start` as the canonical
# "is Tor routing active?" test.
is_routing_active() {
    iptables -t nat -L OUTPUT 2>/dev/null | grep -q "REDIRECT.*${TOR_TRANS_PORT}"
}

# ── Public IP display ─────────────────────────────────────────────────────────
show_ip() {
    echo -e "${CYAN}[i] Fetching public IP...${RESET}"
    local ip
    ip=$(curl -s --max-time 12 -4 https://api.ipify.org 2>/dev/null)
    if [[ -n "$ip" ]]; then
        echo -e "    IPv4: ${BOLD}${ip}${RESET}"
        # Geo-IP lookup: ask which country/ISP the current (exit) IP belongs
        # to, over HTTPS - a plaintext query would let anyone on the path
        # (including the exit node itself) see or tamper with the answer.
        # ipwho.is serves the free JSON endpoint without an API key
        # (ip-api.com's free tier is HTTP-only).
        local geo
        geo=$(curl -s --max-time 8 "https://ipwho.is/${ip}" 2>/dev/null)
        if [[ -n "$geo" ]]; then
            local country_name country_code isp
            country_name=$(echo "$geo" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
            country_code=$(echo "$geo" | grep -o '"country_code":"[^"]*"' | cut -d'"' -f4)
            isp=$(echo "$geo" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
            [[ -n "$country_name" ]] && echo -e "    Country: ${BOLD}${country_name} (${country_code})${RESET}"
            [[ -n "$isp"          ]] && echo -e "    ISP/Org: ${BOLD}${isp}${RESET}"
        fi
    else
        echo -e "    ${YELLOW}IPv4: could not fetch (Tor may still be starting).${RESET}"
    fi
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
    acquire_command_lock
    if [[ $# -gt 2 ]]; then
        echo -e "${RED}[✗] Unexpected argument(s): ${*:3}${RESET}"
        echo -e "    Usage: sudo ${0##*/} start [CC]"
        exit 1
    fi
    require_init
    check_dependencies

    # Refuse to re-apply over an active session. Re-running `start` would
    # overwrite the firewall/resolv.conf backups with the *current* Tor state,
    # so a later `stop` would restore the wrong data.
    if is_routing_active; then
        echo -e "${YELLOW}[i] Tor routing is already active. Run ${BOLD}sudo ${0##*/} stop${RESET}${YELLOW} first to re-apply, or use ${BOLD}sudo ${0##*/} newnode${RESET}${YELLOW} to change the exit node.${RESET}"
        exit 0
    fi

    # Parse optional country code argument ($2 when called as `start CC`)
    local country=""
    if [[ -n "${2:-}" ]]; then
        case "${2,,}" in
            h|help|-h|--help)
                echo -e "Usage: sudo ${0##*/} start [CC]"
                echo -e "       CC = optional 2-letter country code to pin the exit node (list: sudo ${0##*/} countries)"
                exit 0 ;;
            *)
                country=$(validate_country "$2") || {
                    echo -e "${RED}[✗] Unknown country code: '${2^^}'.${RESET}"
                    echo -e "    Run  ${BOLD}sudo ${0##*/} countries${RESET}  to see all valid codes."
                    exit 1
                } ;;
        esac
        echo -e "${CYAN}[→] Starting Tor routing with exit node in: ${BOLD}${country^^}${RESET}\n"
    else
        echo -e "${CYAN}[→] Starting Tor routing with random exit node...${RESET}\n"
    fi

    # From here on the script mutates the system (torrc, Tor, firewall, DNS).
    # An interrupt must unwind all of it. The trap is safe to install early:
    # restore_iptables and fix_dns_stop no-op via their guards when nothing
    # was saved yet, so a Ctrl+C during bootstrap leaves everything untouched.
    trap interrupt_unwind INT TERM
    configure_torrc "$country"

    # Record whether the Tor service was running before we take it over, so
    # stop/unwind can put it back the way it was found (mirrors how the DNS
    # resolver state is tracked in RESOLVED_STATE_FILE).
    if service_tor_running; then
        echo "yes" > "$TOR_STATE_FILE"
        echo -e "${YELLOW}[i] Tor was already running - it will be restored on stop/unwind.${RESET}"
    else
        echo "no" > "$TOR_STATE_FILE"
    fi

    echo -e "${YELLOW}[i] Starting Tor...${RESET}"
    service_tor_restart
    echo -n "    Bootstrapping"
    for i in {1..25}; do
        sleep 1; echo -n "."
        service_tor_log 2>/dev/null | grep -q "Bootstrapped 100%" && break
        ss -tlnp 2>/dev/null | grep -q ":${TOR_TRANS_PORT}" && break
    done
    echo ""

    if ! service_tor_running; then
        echo -e "${RED}[✗] Tor failed to start. Check Tor logs for errors (${BOLD}sudo ${0##*/} status${RESET}).${RESET}"
        fix_dns_stop; restore_tor_service; exit 1
    fi
    echo -e "${GREEN}[✓] Tor is running.${RESET}\n"

    if ! verify_tor_ports; then
        fix_dns_stop; restore_tor_service; exit 1
    fi

    if ! save_iptables; then
        fix_dns_stop; restore_tor_service; exit 1
    fi
    if ! apply_iptables; then
        # Rules were partially applied - restore what we saved, then unwind.
        restore_iptables
        fix_dns_stop; restore_tor_service; exit 1
    fi

    # Swap resolv.conf only once the redirect rules exist, so the system's
    # DNS keeps working until then instead of pointing at a dead
    # 127.0.0.1:53 for the whole bootstrap.
    fix_dns_start

    # The probe below goes through the iptables redirect, so it only succeeds
    # once Tor has built a usable circuit. Announce success only then; if Tor
    # is still bootstrapping after the timeout, warn instead of claiming ✓.
    echo -n "    Waiting for traffic to route through Tor"
    local routed=0
    for i in {1..45}; do
        sleep 1; echo -n "."
        if curl -sf --max-time 2 -4 https://api.ipify.org >/dev/null 2>&1 ||
           curl -sf --max-time 2 -4 https://check.torproject.org >/dev/null 2>&1; then
            routed=1
            break
        fi
    done
    trap - INT TERM
    echo ""

    if [[ $routed -eq 1 ]]; then
        echo -e "\n${GREEN}${BOLD}[✓] All traffic is now routed through Tor!${RESET}"
    else
        echo -e "\n${YELLOW}${BOLD}[!] Tor routing rules are active, but traffic is not flowing yet.${RESET}"
        echo -e "    ${YELLOW}Tor may still be bootstrapping - traffic will route automatically once it is ready.${RESET}"
        echo -e "    Verify with: ${BOLD}sudo ${0##*/} status${RESET}"
    fi
    echo -e "    ${YELLOW}Tip:${RESET} Also disable WebRTC inside your browser for full protection."
    echo -e "    Firefox: about:config → media.peerconnection.enabled → false\n"
    show_ip
    echo -e "\n    ${BOLD}sudo ${0##*/} newnode [CC]${RESET}  - new exit node / new IP"
    echo -e "    ${BOLD}sudo ${0##*/} stop${RESET}          - restore normal internet\n"
}

cmd_stop() {
    banner
    require_root stop
    acquire_command_lock
    require_init
    # stop must always be able to run even if Tor was uninstalled; only the
    # restore tools are strictly required (curl is used by the verification
    # probe and show_ip below, but a missing curl must not block restoring).
    # iptables-restore/ip6tables-restore are demanded only when a matching
    # backup actually exists - catching the gap upfront instead of mid-
    # restore, while exotic systems with no backups at all can still stop.
    local need=(iptables ip6tables)
    [[ -f "$IPTABLES_BACKUP" ]] && need+=(iptables-restore)
    [[ -f "$IP6TABLES_BACKUP" ]] && need+=(ip6tables-restore)
    check_net_tools "${need[@]}"
    echo -e "${CYAN}[→] Restoring normal internet...${RESET}\n"

    # A Ctrl+C here must not leave the box half-restored (rules flushed but
    # backups removed, resolv.conf rewritten, Tor stopped). interrupt_unwind
    # is safe to trigger at any point: its restore steps no-op through their
    # guards once the backups/state files are gone, so an interrupt between
    # steps simply finishes the restoration.
    trap interrupt_unwind INT TERM

    # 0 = firewall fully restored, 1 = one or both rule restores failed.
    # A failed restore must not be announced as a success below.
    local fw_restored=0
    restore_iptables || fw_restored=1
    # Verify the rules actually went away before tearing down Tor. If they
    # survived (backups deleted externally mid-session), stopping Tor would
    # black-hole all traffic while the script claimed success.
    if is_routing_active; then
        trap - INT TERM
        print_manual_rule_recovery
        exit 1
    fi
    fix_dns_stop
    restore_tor_service
    trap - INT TERM

    if [[ $fw_restored -ne 0 ]]; then
        echo -e "\n${RED}${BOLD}[✗] Firewall rules could NOT be fully restored.${RESET}"
        echo -e "    ${RED}Your system may be missing its custom firewall rules.${RESET}"
        echo -e "    ${RED}Restore manually from the backups listed above (${IPTABLES_BACKUP} / ${IP6TABLES_BACKUP}).${RESET}"
        exit 1
    fi

    echo -e "\n${GREEN}${BOLD}[✓] Normal internet restored.${RESET}\n"
    # The restored DNS resolver (systemd-resolved in particular) can take a
    # few seconds to accept queries after start. Verify direct connectivity
    # with a bounded retry before showing the public IP.
    echo -n "    Verifying direct connectivity"
    local connected=0
    for i in {1..10}; do
        sleep 1; echo -n "."
        if curl -sf --max-time 2 -4 https://api.ipify.org >/dev/null 2>&1; then
            connected=1
            break
        fi
    done
    echo ""
    if [[ $connected -eq 1 ]]; then
        echo -e "${GREEN}[✓] Direct internet connectivity confirmed.${RESET}"
    else
        echo -e "${YELLOW}[!] Direct internet not verified yet - the resolver may still be starting.${RESET}"
        echo -e "    ${YELLOW}A second ${BOLD}stop${RESET}${YELLOW} won't change this (restore already ran); wait a moment and re-check with ${BOLD}sudo ${0##*/} status${RESET}.${RESET}"
    fi
    echo ""
    show_ip
    echo ""
}

cmd_status() {
    banner
    require_root status
    require_init
    check_net_tools
    echo -e "${CYAN}[→] Status:${RESET}\n"

    service_tor_running \
        && echo -e "  Tor service:       ${GREEN}${BOLD}Running ✓${RESET}" \
        || echo -e "  Tor service:       ${RED}${BOLD}Stopped${RESET}"

    if is_routing_active; then
        echo -e "  TCP routing:       ${GREEN}${BOLD}Through Tor ✓${RESET}"

        # Match our OWN rules, not just any DROP rule the user's firewall
        # may already contain: -S prints the exact rule syntax we applied,
        # and the v6 check looks at the chain POLICY line only.
        if iptables -S OUTPUT 2>/dev/null | grep -q -- "-p udp -j DROP"; then
            echo -e "  UDP / WebRTC:      ${GREEN}${BOLD}Blocked ✓${RESET}"
        else
            echo -e "  UDP / WebRTC:      ${RED}${BOLD}NOT blocked - leak possible!${RESET}"
        fi

        if ip6tables -L OUTPUT 2>/dev/null | head -n1 | grep -q "policy DROP"; then
            echo -e "  IPv6:              ${GREEN}${BOLD}Blocked ✓${RESET}"
        else
            echo -e "  IPv6:              ${RED}${BOLD}NOT blocked - leak possible!${RESET}"
        fi

        # The DNS masking state only means something while routing is
        # active: `start` masks the resolver (systemd) or repoints
        # resolv.conf. Checked inside the same branch as the rules above.
        if [[ "$INIT" == "systemd" ]]; then
            local resolved_ok=true
            for unit in "${RESOLVED_UNITS[@]}"; do
                # Mask state is only visible via `is-enabled` ("masked");
                # is-active reflects the runtime state, not whether the unit
                # could silently come back via socket activation.
                if [[ "$(systemctl is-enabled "$unit" 2>/dev/null)" != "masked" ]]; then
                    resolved_ok=false
                    echo -e "  DNS ($unit): ${RED}${BOLD}NOT masked - may leak!${RESET}"
                fi
            done
            $resolved_ok && echo -e "  DNS (resolved):    ${GREEN}${BOLD}All units masked ✓${RESET}"
        else
            if grep -q '^nameserver 127.0.0.1' /etc/resolv.conf 2>/dev/null; then
                echo -e "  DNS:               ${GREEN}${BOLD}/etc/resolv.conf → Tor ✓${RESET}"
            else
                echo -e "  DNS:               ${RED}${BOLD}resolv.conf NOT pointing at Tor - leak possible!${RESET}"
            fi
        fi
    else
        echo -e "  TCP routing:       ${YELLOW}Direct (not through Tor)${RESET}"
        echo -e "  UDP / WebRTC:      Not routed (no filtering)"
        echo -e "  IPv6:              Not blocked (routing is off)"
        if resolver_is_active systemd-resolved.service; then
            echo -e "  DNS:               ${YELLOW}systemd-resolved active (normal, not routed)${RESET}"
        else
            echo -e "  DNS:               ${YELLOW}normal (not routed through Tor)${RESET}"
        fi
    fi

    # Show configured exit node country from state file
    if [[ -f "$COUNTRY_FILE" ]]; then
        local saved_country
        saved_country=$(cat "$COUNTRY_FILE")
        if [[ "$saved_country" == "random" ]]; then
            echo -e "  Exit node country: ${CYAN}${BOLD}Random (no country filter)${RESET}"
        else
            echo -e "  Exit node country: ${CYAN}${BOLD}${saved_country^^} (pinned)${RESET}"
        fi
    else
        echo -e "  Exit node country: ${YELLOW}Unknown (Tor not started by this script)${RESET}"
    fi

    if service_tor_running; then
        echo ""; verify_tor_ports
    fi

    echo ""; show_ip; echo ""
}

cmd_newnode() {
    banner
    require_root newnode
    acquire_command_lock
    if [[ $# -gt 2 ]]; then
        echo -e "${RED}[✗] Unexpected argument(s): ${*:3}${RESET}"
        echo -e "    Usage: sudo ${0##*/} newnode [CC]"
        exit 1
    fi
    require_init
    check_net_tools

    if ! service_tor_running; then
        echo -e "${RED}[✗] Tor is not running. Run: sudo ${0##*/} start${RESET}"; exit 1
    fi

    # A reload only makes sense inside an active session: without the
    # redirect rules nothing is routed, the IP-change verification below
    # would compare your real address against itself, and writing the
    # country state file would leave stale state behind for status to
    # misreport afterwards.
    if ! is_routing_active; then
        echo -e "${RED}[✗] Tor routing is not active. Run: sudo ${0##*/} start${RESET}"; exit 1
    fi

    # Parse optional country code argument
    local country=""
    if [[ -n "${2:-}" ]]; then
        case "${2,,}" in
            h|help|-h|--help)
                echo -e "Usage: sudo ${0##*/} newnode [CC]"
                echo -e "       CC = optional 2-letter country code to pin the exit node (list: sudo ${0##*/} countries)"
                exit 0 ;;
            *)
                country=$(validate_country "$2") || {
                    echo -e "${RED}[✗] Unknown country code: '${2^^}'.${RESET}"
                    echo -e "    Run  ${BOLD}sudo ${0##*/} countries${RESET}  to see all valid codes."
                    exit 1
                } ;;
        esac
        echo -e "${CYAN}[→] Switching to a new exit node in: ${BOLD}${country^^}${RESET}\n"
    else
        # If no country given, check if one was previously pinned and clear it
        local prev
        prev=$(cat "$COUNTRY_FILE" 2>/dev/null || echo "random")
        if [[ "$prev" != "random" ]]; then
            echo -e "${CYAN}[→] Switching to a new random exit node (clearing previous pin: ${prev^^})...${RESET}\n"
        else
            echo -e "${CYAN}[→] Requesting a new random Tor circuit (new exit node = new IP)...${RESET}\n"
        fi
    fi

    # SIGHUP = reload config and rebuild all circuits.
    # New circuit = new Guard → Middle → Exit chain = new public IP.
    # Capture the current IP first (same endpoint show_ip uses) so a change
    # can be verified instead of assuming it after a fixed wait.
    local old_ip changed=0
    old_ip=$(curl -s --max-time 5 -4 https://api.ipify.org 2>/dev/null)

    echo -e "  ${YELLOW}Current:${RESET}"; show_ip

    # From the torrc write until the reload completes, an interrupt must
    # revert the edit (same contract as the reload-failure path below).
    # Before this point nothing has been modified yet, so no trap is needed.
    trap 'cleanup_torrc; echo ""; echo -e "${RED}[✗] Interrupted - torrc changes reverted, reload not sent.${RESET}"; exit 1' INT TERM
    configure_torrc "$country"

    if ! service_tor_reload; then
        cleanup_torrc
        echo -e "${RED}[✗] Tor reload failed - torrc changes reverted.${RESET}"
        exit 1
    fi

    # Reload done - there is nothing left to revert; from here an interrupt
    # merely abandons the wait for the new circuit.
    trap 'echo ""; echo -e "${RED}[✗] Interrupted - new circuit request aborted.${RESET}"; exit 1' INT TERM

    if [[ -n "$old_ip" ]]; then
        echo -e "\n  Waiting for a new circuit (new IP)..."
        for i in {1..30}; do
            sleep 1; echo -n "."
            local new_ip
            new_ip=$(curl -sf --max-time 2 -4 https://api.ipify.org 2>/dev/null)
            if [[ -n "$new_ip" && "$new_ip" != "$old_ip" ]]; then
                changed=1
                break
            fi
        done
        echo ""
    else
        # Could not read the IP before switching - cannot verify a change.
        echo -e "\n  Waiting for a new circuit..."; sleep 15
    fi
    trap - INT TERM

    echo -e "\n  ${YELLOW}New:${RESET}"; show_ip
    if [[ $changed -eq 1 ]]; then
        echo -e "\n${GREEN}[✓] New circuit requested - IP changed.${RESET}"
    else
        echo -e "\n${YELLOW}${BOLD}[!] New circuit requested, but the IP has not changed yet.${RESET}"
        if [[ -n "$old_ip" ]]; then
            echo -e "    ${YELLOW}Tor may have reused the same exit node - wait ~15 s and try again.${RESET}"
        else
            echo -e "    ${YELLOW}Could not read the IP before switching, so the change could not be verified.${RESET}"
        fi
    fi
    echo ""
}

# =============================================================================
#  ENTRY POINT
# =============================================================================
case "$1" in
    check)     cmd_check         ;;
    start)     cmd_start     "$@" ;;
    stop)      cmd_stop          ;;
    status)    cmd_status        ;;
    newnode)   cmd_newnode   "$@" ;;
    countries) cmd_countries     ;;
    *)
        banner
        echo -e "  ${BOLD}Usage:${RESET}  sudo ${0##*/} {start|stop|status|newnode|countries|check}\n"
        echo -e "  ${GREEN}start [CC]${RESET}    Route all traffic through Tor"
        echo -e "               CC = optional 2-letter country code for exit node"
        echo -e "               e.g.  start us  /  start de  /  start jp"
        echo -e "  ${RED}stop${RESET}          Restore normal internet routing"
        echo -e "  ${CYAN}status${RESET}        Show routing status, exit node country and public IP"
        echo -e "  ${YELLOW}newnode [CC]${RESET}  Switch to a new exit node (optionally pin a country)"
        echo -e "  ${CYAN}countries${RESET}     List all supported country codes"
        echo -e "  ${YELLOW}check${RESET}        Run a dry-run system check for potential issues\n"
        exit 1 ;;
esac
