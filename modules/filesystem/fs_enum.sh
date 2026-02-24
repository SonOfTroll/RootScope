#!/usr/bin/env bash
# ============================================================================
# RootScope — modules/filesystem/fs_enum.sh
# Filesystem enumeration module.
# Enumerates: SUID/SGID binaries, world-writable files/dirs, capabilities,
#             sensitive file permissions, unmounted drives, /tmp analysis.
# ============================================================================

MODULE_NAME="filesystem"

run_filesystem_enum() {
    print_section "Filesystem Enumeration"
    log_info "${MODULE_NAME}" "Starting filesystem enumeration"

    _init_exploit_db_paths

    _enum_suid_binaries
    _enum_sgid_binaries
    _enum_capabilities
    _enum_world_writable
    _enum_sensitive_files
    _enum_unmounted_drives
    _enum_tmp_analysis

    log_info "${MODULE_NAME}" "Filesystem enumeration complete"
}

# ---------------------------------------------------------------------------
# SUID binary enumeration with GTFOBins cross-reference
# ---------------------------------------------------------------------------
_enum_suid_binaries() {
    print_subsection "SUID Binaries"

    local suid_bins
    suid_bins=$(find / -perm -4000 -type f 2>/dev/null)

    if [[ -z "${suid_bins}" ]]; then
        emit_finding "INFO" "${MODULE_NAME}" "no_suid" "No SUID binaries found" ""
        return
    fi

    while IFS= read -r binary; do
        [[ -z "${binary}" ]] && continue

        # Check against whitelist
        if is_suid_whitelisted "${binary}"; then
            emit_finding "INFO" "${MODULE_NAME}" "suid_whitelisted" \
                "SUID (whitelisted): ${binary}" ""
            continue
        fi

        # Non-standard SUID — check GTFOBins
        local gtfo_matches
        gtfo_matches=$(check_gtfobins "${binary}" "suid")

        if [[ -n "${gtfo_matches}" ]]; then
            while IFS='|' read -r _ bin tech cmd sev; do
                register_finding "${sev}" "${MODULE_NAME}" "suid_gtfobins" \
                    "SUID binary with GTFOBins exploit: ${binary}" \
                    "Exploit: ${cmd}"
            done <<< "${gtfo_matches}"
        else
            # Non-standard SUID but no known exploit
            local owner perms
            owner=$(stat -c '%U:%G' "${binary}" 2>/dev/null)
            perms=$(stat -c '%a' "${binary}" 2>/dev/null)
            register_finding "MEDIUM" "${MODULE_NAME}" "suid_nonstandard" \
                "Non-standard SUID binary: ${binary} (${perms} ${owner})" \
                "Investigate for potential exploitation paths"
        fi
    done <<< "${suid_bins}"
}

# ---------------------------------------------------------------------------
# SGID binary enumeration
# ---------------------------------------------------------------------------
_enum_sgid_binaries() {
    print_subsection "SGID Binaries"

    local sgid_bins
    sgid_bins=$(find / -perm -2000 -type f 2>/dev/null | head -50)

    while IFS= read -r binary; do
        [[ -z "${binary}" ]] && continue

        # SGID items on sensitive groups
        local group_name
        group_name=$(stat -c '%G' "${binary}" 2>/dev/null)

        case "${group_name}" in
            shadow|root|disk|adm)
                register_finding "MEDIUM" "${MODULE_NAME}" "sgid_sensitive" \
                    "SGID binary with sensitive group '${group_name}': ${binary}" \
                    "SGID on '${group_name}' may allow reading sensitive files"
                ;;
            *)
                emit_finding "INFO" "${MODULE_NAME}" "sgid_binary" \
                    "SGID binary [${group_name}]: ${binary}" ""
                ;;
        esac
    done <<< "${sgid_bins}"
}

# ---------------------------------------------------------------------------
# Linux capabilities enumeration
# ---------------------------------------------------------------------------
_enum_capabilities() {
    print_subsection "Linux Capabilities"

    if ! cmd_exists getcap; then
        emit_finding "INFO" "${MODULE_NAME}" "no_getcap" "getcap not available" ""
        return
    fi

    local cap_bins
    cap_bins=$(getcap -r / 2>/dev/null)

    if [[ -z "${cap_bins}" ]]; then
        emit_finding "INFO" "${MODULE_NAME}" "no_caps" \
            "No binaries with special capabilities found" ""
        return
    fi

    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue

        local binary caps
        binary=$(echo "${line}" | awk '{print $1}')
        caps=$(echo "${line}" | awk '{for(i=2;i<=NF;i++) printf "%s ", $i}')

        # Check for dangerous capabilities
        local dangerous_caps=("cap_sys_admin" "cap_sys_ptrace" "cap_sys_module"
                              "cap_dac_override" "cap_dac_read_search" "cap_setuid"
                              "cap_setgid" "cap_fowner" "cap_sys_rawio" "cap_setfcap"
                              "cap_chown" "cap_net_admin")

        local is_dangerous=false
        local matched_cap=""

        for dcap in "${dangerous_caps[@]}"; do
            if echo "${caps}" | grep -qi "${dcap}"; then
                is_dangerous=true
                matched_cap="${dcap}"
                break
            fi
        done

        if [[ "${is_dangerous}" == "true" ]]; then
            local cap_exploits
            cap_exploits=$(check_capability_exploits "${matched_cap}")
            local hint=""
            if [[ -n "${cap_exploits}" ]]; then
                hint=$(echo "${cap_exploits}" | head -1 | cut -d'|' -f4)
            fi
            register_finding "HIGH" "${MODULE_NAME}" "dangerous_capability" \
                "Dangerous capability on ${binary}: ${caps}" "${hint}"
        else
            emit_finding "LOW" "${MODULE_NAME}" "capability" \
                "Capability: ${binary} → ${caps}" ""
        fi
    done <<< "${cap_bins}"
}

# ---------------------------------------------------------------------------
# World-writable files and directories
# ---------------------------------------------------------------------------
_enum_world_writable() {
    print_subsection "World-Writable Files & Directories"

    # World-writable directories (excluding /tmp, /var/tmp, /dev/shm)
    local ww_dirs
    ww_dirs=$(find / -writable -type d \
        ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/dev/shm/*" \
        ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" \
        2>/dev/null | head -30)

    while IFS= read -r dir; do
        [[ -z "${dir}" ]] && continue

        # Check if sticky bit is missing (more dangerous)
        if ! stat -c '%a' "${dir}" 2>/dev/null | grep -q '^1'; then
            register_finding "MEDIUM" "${MODULE_NAME}" "world_writable_dir_no_sticky" \
                "World-writable dir without sticky bit: ${dir}" \
                "Files in this directory can be modified/deleted by any user"
        else
            emit_finding "LOW" "${MODULE_NAME}" "world_writable_dir" \
                "World-writable dir (sticky bit set): ${dir}" ""
        fi
    done <<< "${ww_dirs}"

    # World-writable files in system directories
    local ww_files
    ww_files=$(find /etc /usr /opt -writable -type f 2>/dev/null | head -20)

    while IFS= read -r file; do
        [[ -z "${file}" ]] && continue
        register_finding "HIGH" "${MODULE_NAME}" "world_writable_file" \
            "World-writable system file: ${file}" \
            "Check if file is executed by root or a privileged process"
    done <<< "${ww_files}"
}

# ---------------------------------------------------------------------------
# Sensitive file permission checks
# ---------------------------------------------------------------------------
_enum_sensitive_files() {
    print_subsection "Sensitive File Permissions"

    local -A sensitive_files=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="640"
        ["/etc/sudoers"]="440"
        ["/etc/ssh/sshd_config"]="600"
        ["/root/.ssh/authorized_keys"]="600"
    )

    for file in "${!sensitive_files[@]}"; do
        if [[ -f "${file}" ]]; then
            local expected="${sensitive_files[$file]}"

            if can_write "${file}"; then
                local sev="CRITICAL"
                local hint=""
                case "${file}" in
                    */passwd)  hint="Add root-equivalent user entry" ;;
                    */shadow)  hint="Replace root password hash" ;;
                    */sudoers) hint="Add NOPASSWD ALL rule" ;;
                esac
                register_finding "${sev}" "${MODULE_NAME}" "writable_sensitive" \
                    "Writable sensitive file: ${file}" "${hint}"
            fi

            # Check for world-readable shadow
            if [[ "${file}" == "/etc/shadow" ]] && can_read "${file}"; then
                if ! is_root; then
                    register_finding "HIGH" "${MODULE_NAME}" "readable_shadow" \
                        "/etc/shadow is readable by unprivileged user" \
                        "Extract and crack password hashes"
                fi
            fi
        fi
    done
}

# ---------------------------------------------------------------------------
# Unmounted drives / partitions
# ---------------------------------------------------------------------------
_enum_unmounted_drives() {
    print_subsection "Unmounted Drives"

    if cmd_exists lsblk; then
        local unmounted
        unmounted=$(lsblk -o NAME,MOUNTPOINT,SIZE,TYPE -n 2>/dev/null | awk '$2 == "" && $4 == "part" {print $1, $3}')
        if [[ -n "${unmounted}" ]]; then
            emit_finding "LOW" "${MODULE_NAME}" "unmounted_partitions" \
                "Unmounted partitions found: ${unmounted}" \
                "May contain sensitive data — try mounting if accessible"
        fi
    fi
}

# ---------------------------------------------------------------------------
# /tmp directory analysis
# ---------------------------------------------------------------------------
_enum_tmp_analysis() {
    print_subsection "/tmp Analysis"

    # Check for interesting files in /tmp
    local tmp_interesting
    tmp_interesting=$(find /tmp /var/tmp /dev/shm -maxdepth 2 -type f \
        \( -name "*.sh" -o -name "*.py" -o -name "*.key" -o -name "*.pem" \
           -o -name "*.conf" -o -name "*.bak" -o -name "*.sql" \) \
        2>/dev/null)

    if [[ -n "${tmp_interesting}" ]]; then
        while IFS= read -r file; do
            [[ -z "${file}" ]] && continue
            register_finding "LOW" "${MODULE_NAME}" "tmp_interesting_file" \
                "Interesting file in tmp: ${file}" \
                "Review for credentials or exploitable scripts"
        done <<< "${tmp_interesting}"
    fi
}
