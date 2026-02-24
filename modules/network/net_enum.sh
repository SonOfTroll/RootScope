#!/usr/bin/env bash
# ============================================================================
# RootScope — modules/network/net_enum.sh
# Network enumeration module.
# ============================================================================

MODULE_NAME="network"

run_network_enum() {
    print_section "Network Enumeration"
    log_info "${MODULE_NAME}" "Starting network enumeration"
    _enum_interfaces
    _enum_listening_ports
    _enum_connections
    _enum_routes
    _enum_firewall
    _enum_dns_config
    _enum_nfs_shares
    log_info "${MODULE_NAME}" "Network enumeration complete"
}

_enum_interfaces() {
    print_subsection "Network Interfaces"
    local ifaces
    if cmd_exists ip; then
        ifaces=$(ip -o addr show 2>/dev/null | awk '{print $2, $4}')
    elif cmd_exists ifconfig; then
        ifaces=$(ifconfig 2>/dev/null | grep 'inet ' | awk '{print $1, $2}')
    fi
    [[ -n "${ifaces}" ]] && emit_finding "INFO" "${MODULE_NAME}" "interfaces" \
        "Network interfaces: $(echo "${ifaces}" | tr '\n' ' | ')" ""

    local iface_count
    iface_count=$(ip -o link show 2>/dev/null | grep -c "state UP" || echo 0)
    (( iface_count > 1 )) && register_finding "LOW" "${MODULE_NAME}" "multi_interface" \
        "Multiple active interfaces (${iface_count}) — potential pivot" ""

    local promisc
    promisc=$(ip link show 2>/dev/null | grep -i "PROMISC")
    [[ -n "${promisc}" ]] && register_finding "MEDIUM" "${MODULE_NAME}" "promiscuous_mode" \
        "Interface in promiscuous mode" "Possible sniffing in progress"
}

_enum_listening_ports() {
    print_subsection "Listening Ports"
    local listeners=""
    if cmd_exists ss; then
        listeners=$(ss -tlnp 2>/dev/null)
    elif cmd_exists netstat; then
        listeners=$(netstat -tlnp 2>/dev/null)
    fi
    [[ -z "${listeners}" ]] && return

    if echo "${listeners}" | grep -qE '127\.0\.0\.1.*(3306|5432|6379|27017|9200)'; then
        register_finding "MEDIUM" "${MODULE_NAME}" "database_localhost" \
            "Database on localhost — check auth bypass" "Try default/empty credentials"
    fi
    local public_svcs
    public_svcs=$(echo "${listeners}" | grep '0.0.0.0' | awk '{print $4}' | tr '\n' ', ')
    [[ -n "${public_svcs}" ]] && emit_finding "INFO" "${MODULE_NAME}" "public_services" \
        "Services on all interfaces: ${public_svcs}" ""
}

_enum_connections() {
    print_subsection "Established Connections"
    local conns=""
    if cmd_exists ss; then
        conns=$(ss -tnp 2>/dev/null | grep "ESTAB" | head -20)
    elif cmd_exists netstat; then
        conns=$(netstat -tnp 2>/dev/null | grep "ESTABLISHED" | head -20)
    fi
    [[ -n "${conns}" ]] && emit_finding "INFO" "${MODULE_NAME}" "connections" \
        "Active connections: $(echo "${conns}" | wc -l)" ""
}

_enum_routes() {
    print_subsection "Routing Table"
    local routes=""
    cmd_exists ip && routes=$(ip route show 2>/dev/null)
    [[ -n "${routes}" ]] && emit_finding "INFO" "${MODULE_NAME}" "routes" \
        "Routes: $(echo "${routes}" | wc -l) entries" ""
}

_enum_firewall() {
    print_subsection "Firewall Rules"
    local rules
    rules=$(run_timeout 5 iptables -L -n 2>/dev/null)
    if [[ -n "${rules}" ]]; then
        local cnt
        cnt=$(echo "${rules}" | grep -cE '^(ACCEPT|DROP|REJECT)')
        (( cnt == 0 )) && register_finding "MEDIUM" "${MODULE_NAME}" "no_firewall" \
            "No active iptables rules — firewall may be disabled" ""
    fi
}

_enum_dns_config() {
    print_subsection "DNS Configuration"
    if [[ -f /etc/resolv.conf ]]; then
        local ns
        ns=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ', ')
        emit_finding "INFO" "${MODULE_NAME}" "dns_servers" "DNS: ${ns}" ""
    fi
}

_enum_nfs_shares() {
    print_subsection "NFS Shares"
    if [[ -f /etc/exports ]] && can_read /etc/exports; then
        local exports
        exports=$(safe_read /etc/exports)
        if echo "${exports}" | grep -q "no_root_squash"; then
            register_finding "CRITICAL" "${MODULE_NAME}" "nfs_no_root_squash" \
                "NFS with no_root_squash found" \
                "Mount remotely as root → create SUID binary → execute locally"
        fi
        [[ -n "${exports}" ]] && emit_finding "INFO" "${MODULE_NAME}" "nfs_exports" \
            "NFS exports: $(echo "${exports}" | grep -v '^#')" ""
    fi
}
