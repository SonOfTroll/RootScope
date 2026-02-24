#!/usr/bin/env bash
# ============================================================================
# RootScope — modules/system/sys_info.sh
# System information enumeration module.
# Enumerates: OS, kernel, hostname, arch, uptime, users, sudo config,
#             environment variables, cron jobs, systemd timers, PATH analysis.
# ============================================================================

MODULE_NAME="system"

run_system_enum() {
    print_section "System Information Enumeration"
    log_info "${MODULE_NAME}" "Starting system enumeration"

    _enum_os_info
    _enum_kernel_info
    _enum_user_info
    _enum_sudo_config
    _enum_env_vars
    _enum_cron_jobs
    _enum_systemd_timers
    _enum_path_analysis

    log_info "${MODULE_NAME}" "System enumeration complete"
}

# ---------------------------------------------------------------------------
# OS & host information
# ---------------------------------------------------------------------------
_enum_os_info() {
    print_subsection "Operating System & Host"

    local hostname_val arch_val uptime_val os_family os_ver

    hostname_val=$(hostname 2>/dev/null || echo "unknown")
    arch_val=$(get_arch)
    uptime_val=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo "unknown")
    os_family=$(get_os_family)
    os_ver=$(get_os_version)

    emit_finding "INFO" "${MODULE_NAME}" "os_info" \
        "OS: ${os_family} ${os_ver} | Arch: ${arch_val} | Host: ${hostname_val}" ""

    emit_finding "INFO" "${MODULE_NAME}" "uptime" "Uptime: ${uptime_val}" ""

    # Check if /etc/os-release is world-readable (expected, but document it)
    if can_read /etc/machine-id; then
        local machine_id
        machine_id=$(safe_read /etc/machine-id)
        emit_finding "INFO" "${MODULE_NAME}" "machine_id" \
            "Machine ID: ${machine_id}" ""
    fi
}

# ---------------------------------------------------------------------------
# Kernel information + exploit check
# ---------------------------------------------------------------------------
_enum_kernel_info() {
    print_subsection "Kernel Information"

    local kernel_ver
    kernel_ver=$(get_kernel_version)

    emit_finding "INFO" "${MODULE_NAME}" "kernel_version" \
        "Kernel: ${kernel_ver}" ""

    # Cross-reference kernel version against exploit database
    _init_exploit_db_paths
    local exploits
    exploits=$(check_kernel_exploits "${kernel_ver}")

    if [[ -n "${exploits}" ]]; then
        while IFS='|' read -r prefix cve name desc sev range; do
            register_finding "${sev}" "${MODULE_NAME}" "kernel_exploit" \
                "${cve} (${name}): ${desc} [Affected: ${range}]" \
                "Research ${cve} for proof-of-concept exploits"
        done <<< "${exploits}"
    else
        emit_finding "INFO" "${MODULE_NAME}" "kernel_safe" \
            "No known kernel exploits matched for ${kernel_ver}" ""
    fi
}

# ---------------------------------------------------------------------------
# User & group enumeration
# ---------------------------------------------------------------------------
_enum_user_info() {
    print_subsection "Users & Groups"

    # Current user context
    local curr_user curr_uid curr_groups
    curr_user=$(whoami 2>/dev/null)
    curr_uid=$(id -u 2>/dev/null)
    curr_groups=$(id -Gn 2>/dev/null)

    emit_finding "INFO" "${MODULE_NAME}" "current_user" \
        "Running as: ${curr_user} (UID: ${curr_uid}) Groups: ${curr_groups}" ""

    # Users with UID 0 (root-equivalent)
    local root_users
    root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
    local root_count
    root_count=$(echo "${root_users}" | grep -c . 2>/dev/null || echo 0)

    if (( root_count > 1 )); then
        register_finding "HIGH" "${MODULE_NAME}" "multiple_root_users" \
            "Multiple UID 0 users: ${root_users//$'\n'/, }" \
            "Investigate non-root accounts with UID 0 — potential backdoor"
    fi

    # Users with login shells
    local login_users
    login_users=$(grep -vE '(nologin|false|sync|halt|shutdown)$' /etc/passwd 2>/dev/null | awk -F: '{print $1}')
    emit_finding "INFO" "${MODULE_NAME}" "login_users" \
        "Users with login shells: $(echo "${login_users}" | tr '\n' ', ')" ""

    # Users with empty passwords
    if can_read /etc/shadow; then
        local empty_pw
        empty_pw=$(awk -F: '($2 == "" || $2 == "!") && $1 != "*" {print $1}' /etc/shadow 2>/dev/null)
        if [[ -n "${empty_pw}" ]]; then
            register_finding "CRITICAL" "${MODULE_NAME}" "empty_password" \
                "Users with empty/no password: ${empty_pw//$'\n'/, }" \
                "su to these accounts without a password"
        fi
    fi

    # Check if current user is in interesting groups
    local interesting_groups=("docker" "lxd" "disk" "adm" "video" "shadow" "staff" "sudo" "wheel" "root")
    for grp in "${interesting_groups[@]}"; do
        if id -nG 2>/dev/null | grep -qw "${grp}"; then
            local sev="MEDIUM"
            [[ "${grp}" =~ ^(docker|lxd|disk|root)$ ]] && sev="HIGH"
            register_finding "${sev}" "${MODULE_NAME}" "interesting_group" \
                "Current user is member of '${grp}' group" \
                "Group '${grp}' may allow privilege escalation"
        fi
    done
}

# ---------------------------------------------------------------------------
# Sudo configuration analysis
# ---------------------------------------------------------------------------
_enum_sudo_config() {
    print_subsection "Sudo Configuration"

    # Check if sudo is available
    if ! cmd_exists sudo; then
        emit_finding "INFO" "${MODULE_NAME}" "no_sudo" "sudo not installed" ""
        return
    fi

    # Try sudo -l (non-interactive)
    local sudo_list
    sudo_list=$(sudo -n -l 2>/dev/null)
    local sudo_rc=$?

    if [[ ${sudo_rc} -eq 0 ]] && [[ -n "${sudo_list}" ]]; then
        # NOPASSWD entries
        local nopasswd
        nopasswd=$(echo "${sudo_list}" | grep -i "NOPASSWD")
        if [[ -n "${nopasswd}" ]]; then
            while IFS= read -r line; do
                local binary
                binary=$(echo "${line}" | awk '{print $NF}')
                local hint
                hint=$(generate_exploit_hint "sudo_rule" "${line}")
                register_finding "CRITICAL" "${MODULE_NAME}" "sudo_nopasswd" \
                    "NOPASSWD sudo: ${line}" "${hint}"
            done <<< "${nopasswd}"
        fi

        # Check for ALL patterns
        if echo "${sudo_list}" | grep -q "(ALL.*ALL)"; then
            register_finding "CRITICAL" "${MODULE_NAME}" "sudo_all" \
                "User can sudo ALL commands (may require password)" \
                "Use 'sudo su' or 'sudo bash' if password is known"
        fi

        # Check for wildcard entries
        if echo "${sudo_list}" | grep -qE '\*'; then
            register_finding "HIGH" "${MODULE_NAME}" "sudo_wildcard" \
                "Wildcard (*) found in sudo rules — potential bypass" \
                "Research wildcard abuse techniques for the specific binary"
        fi

        # Emit full sudo list as INFO
        emit_finding "INFO" "${MODULE_NAME}" "sudo_list" \
            "sudo -l output: $(echo "${sudo_list}" | head -20)" ""
    else
        emit_finding "INFO" "${MODULE_NAME}" "sudo_denied" \
            "Cannot list sudo privileges (password required or denied)" ""
    fi

    # Check sudoers file permissions
    if [[ -f /etc/sudoers ]]; then
        local sudoers_perms
        sudoers_perms=$(stat -c '%a %U:%G' /etc/sudoers 2>/dev/null)
        if [[ "${sudoers_perms}" != "440 root:root"* ]] && [[ "${sudoers_perms}" != "400 root:root"* ]]; then
            register_finding "HIGH" "${MODULE_NAME}" "sudoers_perms" \
                "/etc/sudoers has non-standard permissions: ${sudoers_perms}" \
                "Check if sudoers is writable by current user"
        fi
    fi

    # Check sudoers.d directory
    if [[ -d /etc/sudoers.d ]]; then
        local writable_sudoers
        writable_sudoers=$(find /etc/sudoers.d -writable -type f 2>/dev/null)
        if [[ -n "${writable_sudoers}" ]]; then
            register_finding "CRITICAL" "${MODULE_NAME}" "writable_sudoers_d" \
                "Writable files in /etc/sudoers.d: ${writable_sudoers}" \
                "Add NOPASSWD ALL rule for current user"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Environment variable analysis
# ---------------------------------------------------------------------------
_enum_env_vars() {
    print_subsection "Environment Variables"

    # LD_PRELOAD / LD_LIBRARY_PATH (hijack vectors)
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        register_finding "HIGH" "${MODULE_NAME}" "ld_preload" \
            "LD_PRELOAD is set: ${LD_PRELOAD}" \
            "Shared library preloading — potential hijack vector"
    fi

    if [[ -n "${LD_LIBRARY_PATH:-}" ]]; then
        register_finding "MEDIUM" "${MODULE_NAME}" "ld_library_path" \
            "LD_LIBRARY_PATH is set: ${LD_LIBRARY_PATH}" \
            "Library search path manipulation — check for writable directories"
    fi

    # Check env_keep in sudo
    local env_keep
    env_keep=$(sudo -n -l 2>/dev/null | grep "env_keep")
    if [[ -n "${env_keep}" ]]; then
        if echo "${env_keep}" | grep -qiE "LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB"; then
            register_finding "HIGH" "${MODULE_NAME}" "sudo_env_keep" \
                "Sudo preserves dangerous env vars: ${env_keep}" \
                "Library injection via preserved environment variable in sudo"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Cron job enumeration
# ---------------------------------------------------------------------------
_enum_cron_jobs() {
    print_subsection "Cron Jobs"

    local cron_files=(
        "/etc/crontab"
        "/etc/cron.d"
        "/var/spool/cron"
        "/var/spool/cron/crontabs"
    )

    for cf in "${cron_files[@]}"; do
        if [[ -f "${cf}" ]] && can_read "${cf}"; then
            # Check if writable
            if can_write "${cf}"; then
                register_finding "CRITICAL" "${MODULE_NAME}" "writable_cron" \
                    "Writable cron file: ${cf}" \
                    "Inject a reverse shell or SUID binary creation job"
            fi

            # Parse cron entries for scripts we can write to
            while IFS= read -r line; do
                [[ "${line}" =~ ^[[:space:]]*# ]] && continue
                [[ -z "${line}" ]] && continue

                # Extract command (last field after timing)
                local cmd_path
                cmd_path=$(echo "${line}" | awk '{for(i=6;i<=NF;i++) printf "%s ", $i; print ""}' | awk '{print $1}')

                if [[ -f "${cmd_path}" ]] && can_write "${cmd_path}"; then
                    register_finding "CRITICAL" "${MODULE_NAME}" "writable_cron_script" \
                        "Writable cron script: ${cmd_path} (from ${cf})" \
                        "Modify script to execute a privilege escalation payload"
                fi
            done < "${cf}" 2>/dev/null
        fi
    done

    # Check cron directories
    local cron_dirs=("/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly")
    for cd in "${cron_dirs[@]}"; do
        if [[ -d "${cd}" ]]; then
            local writable_scripts
            writable_scripts=$(find "${cd}" -writable -type f 2>/dev/null)
            if [[ -n "${writable_scripts}" ]]; then
                register_finding "HIGH" "${MODULE_NAME}" "writable_cron_dir_script" \
                    "Writable scripts in ${cd}: ${writable_scripts}" \
                    "Modify to execute escalation payload on next cron run"
            fi
        fi
    done

    # Current user's crontab
    local user_cron
    user_cron=$(crontab -l 2>/dev/null)
    if [[ -n "${user_cron}" ]]; then
        emit_finding "INFO" "${MODULE_NAME}" "user_crontab" \
            "Current user crontab entries found" ""
    fi
}

# ---------------------------------------------------------------------------
# Systemd timers enumeration
# ---------------------------------------------------------------------------
_enum_systemd_timers() {
    print_subsection "Systemd Timers"

    if ! cmd_exists systemctl; then
        emit_finding "INFO" "${MODULE_NAME}" "no_systemd" "systemd not available" ""
        return
    fi

    local timers
    timers=$(systemctl list-timers --all --no-pager 2>/dev/null)
    if [[ -n "${timers}" ]]; then
        emit_finding "INFO" "${MODULE_NAME}" "systemd_timers" \
            "Active systemd timers found (check for writable units)" ""

        # Check for writable timer/service units
        local unit_files
        unit_files=$(systemctl list-unit-files --type=timer --no-pager 2>/dev/null | awk '{print $1}' | grep '\.timer$')
        for unit in ${unit_files}; do
            local unit_path
            unit_path=$(systemctl show -p FragmentPath "${unit}" 2>/dev/null | cut -d= -f2)
            if [[ -f "${unit_path}" ]] && can_write "${unit_path}"; then
                register_finding "HIGH" "${MODULE_NAME}" "writable_timer" \
                    "Writable systemd timer: ${unit_path}" \
                    "Modify timer to execute escalation payload"
            fi
        done
    fi
}

# ---------------------------------------------------------------------------
# PATH analysis — check for writable directories in PATH
# ---------------------------------------------------------------------------
_enum_path_analysis() {
    print_subsection "PATH Analysis"

    IFS=':' read -ra path_dirs <<< "${PATH}"
    for dir in "${path_dirs[@]}"; do
        if [[ -d "${dir}" ]] && can_write "${dir}"; then
            register_finding "HIGH" "${MODULE_NAME}" "writable_path_dir" \
                "Writable PATH directory: ${dir}" \
                "Place a malicious binary here to hijack commands (PATH injection)"
        fi
    done

    # Check for relative paths in PATH
    for dir in "${path_dirs[@]}"; do
        if [[ "${dir}" != /* ]]; then
            register_finding "MEDIUM" "${MODULE_NAME}" "relative_path" \
                "Relative directory in PATH: '${dir}'" \
                "Relative PATH entries can be exploited via working directory manipulation"
        fi
    done
}
