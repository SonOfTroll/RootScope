#!/usr/bin/env bash
# ============================================================================
# RootScope — modules/services/svc_enum.sh
# Service enumeration module.
# Enumerates: running services, systemd units, init.d scripts, xinetd,
#             service configurations with writable checks.
# ============================================================================

MODULE_NAME="services"

run_services_enum() {
    print_section "Service Enumeration"
    log_info "${MODULE_NAME}" "Starting service enumeration"

    _enum_running_services
    _enum_systemd_units
    _enum_initd_scripts
    _enum_xinetd
    _enum_service_configs

    log_info "${MODULE_NAME}" "Service enumeration complete"
}

# ---------------------------------------------------------------------------
# Running services and processes
# ---------------------------------------------------------------------------
_enum_running_services() {
    print_subsection "Running Services & Processes"

    # Processes running as root
    local root_procs
    root_procs=$(ps aux 2>/dev/null | awk '$1 == "root" {print $11}' | sort -u | head -30)

    if [[ -n "${root_procs}" ]]; then
        emit_finding "INFO" "${MODULE_NAME}" "root_processes" \
            "Processes running as root: $(echo "${root_procs}" | tr '\n' ', ')" ""
    fi

    # Look for services running as root that shouldn't
    local interesting_services=("mysql" "mysqld" "postgres" "apache2" "httpd" "nginx"
                                 "redis" "mongod" "elasticsearch" "tomcat" "jenkins"
                                 "docker" "containerd")

    for svc in "${interesting_services[@]}"; do
        local svc_procs
        svc_procs=$(ps aux 2>/dev/null | grep -i "[${svc:0:1}]${svc:1}" | awk '{print $1, $11}')
        if [[ -n "${svc_procs}" ]]; then
            local running_user
            running_user=$(echo "${svc_procs}" | head -1 | awk '{print $1}')
            if [[ "${running_user}" == "root" ]]; then
                register_finding "MEDIUM" "${MODULE_NAME}" "service_as_root" \
                    "${svc} running as root" \
                    "Service should run as dedicated low-privilege user"
            fi
            emit_finding "INFO" "${MODULE_NAME}" "service_running" \
                "${svc} is running (user: ${running_user})" ""
        fi
    done

    # Check for screen/tmux sessions owned by other users
    local screen_sessions
    screen_sessions=$(find /var/run/screen -type d -readable 2>/dev/null)
    if [[ -n "${screen_sessions}" ]]; then
        emit_finding "LOW" "${MODULE_NAME}" "screen_sessions" \
            "Screen session directories found" \
            "Check for accessible sessions that might give shell access"
    fi
}

# ---------------------------------------------------------------------------
# Systemd service units analysis
# ---------------------------------------------------------------------------
_enum_systemd_units() {
    print_subsection "Systemd Service Units"

    if ! cmd_exists systemctl; then
        emit_finding "INFO" "${MODULE_NAME}" "no_systemd" "systemctl not available" ""
        return
    fi

    # List enabled services
    local enabled_units
    enabled_units=$(systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | awk '{print $1}' | grep '\.service$')

    # Check for writable service unit files
    while IFS= read -r unit; do
        [[ -z "${unit}" ]] && continue
        local unit_path
        unit_path=$(systemctl show -p FragmentPath "${unit}" 2>/dev/null | cut -d= -f2)

        if [[ -f "${unit_path}" ]] && can_write "${unit_path}"; then
            register_finding "CRITICAL" "${MODULE_NAME}" "writable_systemd_unit" \
                "Writable systemd service: ${unit_path}" \
                "Modify ExecStart to execute escalation payload on restart"
        fi

        # Check ExecStart binary permissions
        if [[ -f "${unit_path}" ]]; then
            local exec_binary
            exec_binary=$(grep -oP 'ExecStart=\K[^ ]+' "${unit_path}" 2>/dev/null | head -1)
            if [[ -f "${exec_binary}" ]] && can_write "${exec_binary}"; then
                register_finding "CRITICAL" "${MODULE_NAME}" "writable_service_binary" \
                    "Writable service binary: ${exec_binary} (used by ${unit})" \
                    "Replace binary with escalation payload"
            fi
        fi
    done <<< "${enabled_units}"
}

# ---------------------------------------------------------------------------
# Init.d scripts
# ---------------------------------------------------------------------------
_enum_initd_scripts() {
    print_subsection "Init.d Scripts"

    if [[ ! -d /etc/init.d ]]; then
        return
    fi

    local writable_init
    writable_init=$(find /etc/init.d -writable -type f 2>/dev/null)

    if [[ -n "${writable_init}" ]]; then
        while IFS= read -r script; do
            [[ -z "${script}" ]] && continue
            register_finding "HIGH" "${MODULE_NAME}" "writable_initd" \
                "Writable init.d script: ${script}" \
                "Add malicious commands to execute on service start/restart"
        done <<< "${writable_init}"
    fi
}

# ---------------------------------------------------------------------------
# Xinetd enumeration
# ---------------------------------------------------------------------------
_enum_xinetd() {
    print_subsection "Xinetd Services"

    if [[ -d /etc/xinetd.d ]]; then
        local xinet_configs
        xinet_configs=$(ls /etc/xinetd.d/ 2>/dev/null)

        if [[ -n "${xinet_configs}" ]]; then
            emit_finding "INFO" "${MODULE_NAME}" "xinetd_found" \
                "Xinetd configs found: ${xinet_configs}" ""

            # Check for writable xinetd configs
            local writable_xinet
            writable_xinet=$(find /etc/xinetd.d -writable -type f 2>/dev/null)
            if [[ -n "${writable_xinet}" ]]; then
                register_finding "HIGH" "${MODULE_NAME}" "writable_xinetd" \
                    "Writable xinetd config: ${writable_xinet}" \
                    "Modify to redirect service execution"
            fi
        fi
    fi
}

# ---------------------------------------------------------------------------
# Service configuration files analysis
# ---------------------------------------------------------------------------
_enum_service_configs() {
    print_subsection "Service Configuration Files"

    local config_paths=(
        "/etc/apache2" "/etc/nginx" "/etc/mysql" "/etc/postgresql"
        "/etc/redis" "/etc/mongod.conf" "/etc/elasticsearch"
        "/etc/tomcat" "/etc/php"
    )

    for cfg in "${config_paths[@]}"; do
        if [[ -e "${cfg}" ]]; then
            emit_finding "INFO" "${MODULE_NAME}" "service_config" \
                "Service config found: ${cfg}" ""

            # Check for writable config files
            if [[ -d "${cfg}" ]]; then
                local writable
                writable=$(find "${cfg}" -writable -type f 2>/dev/null | head -5)
                if [[ -n "${writable}" ]]; then
                    register_finding "HIGH" "${MODULE_NAME}" "writable_service_config" \
                        "Writable service config in ${cfg}: $(echo "${writable}" | tr '\n' ', ')" \
                        "Modify config to enable RCE or change service behavior"
                fi
            elif [[ -f "${cfg}" ]] && can_write "${cfg}"; then
                register_finding "HIGH" "${MODULE_NAME}" "writable_service_config" \
                    "Writable service config: ${cfg}" \
                    "Modify config to enable RCE or change service behavior"
            fi
        fi
    done

    # Check for MySQL running with --skip-grant-tables or empty root password
    if cmd_exists mysql; then
        local mysql_no_auth
        mysql_no_auth=$(mysql -u root -e "SELECT 1" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            register_finding "HIGH" "${MODULE_NAME}" "mysql_no_auth" \
                "MySQL allows root login without password" \
                "Access MySQL as root — check for UDF exploitation or file read/write"
        fi
    fi
}
