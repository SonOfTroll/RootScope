#!/usr/bin/env bash
# ============================================================================
# RootScope — modules/software/sw_enum.sh
# Software enumeration module.
# Enumerates: installed packages, compilers, interpreters, dev tools,
#             vulnerable version detection, package managers.
# ============================================================================

MODULE_NAME="software"

run_software_enum() {
    print_section "Software Enumeration"
    log_info "${MODULE_NAME}" "Starting software enumeration"
    _enum_package_managers
    _enum_compilers
    _enum_interpreters
    _enum_dev_tools
    _enum_vulnerable_software
    log_info "${MODULE_NAME}" "Software enumeration complete"
}

_enum_package_managers() {
    print_subsection "Package Managers"
    local -a pkg_mgrs=("apt" "dpkg" "yum" "dnf" "rpm" "pacman" "apk" "zypper" "snap" "flatpak" "pip" "pip3" "gem" "npm" "cargo")
    for pm in "${pkg_mgrs[@]}"; do
        if cmd_exists "${pm}"; then
            emit_finding "INFO" "${MODULE_NAME}" "pkg_manager" \
                "Package manager available: ${pm}" ""
        fi
    done
}

_enum_compilers() {
    print_subsection "Compilers & Build Tools"
    local -a compilers=("gcc" "g++" "cc" "make" "cmake" "as" "ld" "nasm")
    local found_compiler=false
    for comp in "${compilers[@]}"; do
        if cmd_exists "${comp}"; then
            local version
            version=$("${comp}" --version 2>/dev/null | head -1)
            emit_finding "INFO" "${MODULE_NAME}" "compiler" \
                "${comp}: ${version}" ""
            found_compiler=true
        fi
    done

    if [[ "${found_compiler}" == "true" ]]; then
        register_finding "LOW" "${MODULE_NAME}" "compiler_available" \
            "Compilers available — can compile kernel exploits on target" \
            "Use gcc to compile local privilege escalation exploits"
    fi
}

_enum_interpreters() {
    print_subsection "Script Interpreters"
    local -a interps=("python" "python3" "python2" "perl" "ruby" "php" "node" "lua" "wish" "expect" "tclsh")
    for interp in "${interps[@]}"; do
        if cmd_exists "$interp"; then
            if [[ "$interp" == "wish" ]]; then
                ver="wish present"
            else
                ver=$("${interp}" --version 2>&1 | head -1)
            fi

            emit_finding "INFO" "$MODULE_NAME" "interpreter" "$interp: $ver"
        fi
            # Check GTFOBins for interpreter exploitation
            _init_exploit_db_paths
            local gtfo
            gtfo=$(check_gtfobins "${interp}" "all")
            if [[ -n "${gtfo}" ]]; then
                emit_finding "LOW" "${MODULE_NAME}" "interpreter_gtfobins" \
                    "${interp} has GTFOBins entries (check if SUID/sudo)" ""
            fi
        fi
    done
}

_enum_dev_tools() {
    print_subsection "Development & Transfer Tools"
    local -a tools=("wget" "curl" "fetch" "nc" "ncat" "netcat" "socat"
                     "ssh" "scp" "rsync" "ftp" "tftp" "git" "svn"
                     "gdb" "strace" "ltrace" "tcpdump" "nmap" "dig")
    for tool in "${tools[@]}"; do
        if cmd_exists "${tool}"; then
            emit_finding "INFO" "${MODULE_NAME}" "tool_available" \
                "Tool available: ${tool}" ""
        fi
    done

    # wget/curl for file transfer
    if cmd_exists wget || cmd_exists curl; then
        emit_finding "LOW" "${MODULE_NAME}" "file_transfer" \
            "File transfer tools available (wget/curl)" \
            "Can download exploits and tools from attacker machine"
    fi
}

_enum_vulnerable_software() {
    print_subsection "Vulnerable Software Detection"

    # Sudo version check
    if cmd_exists sudo; then
        local sudo_ver
        sudo_ver=$(sudo -V 2>/dev/null | head -1 | grep -oP '[\d.]+')
        if [[ -n "${sudo_ver}" ]]; then
            emit_finding "INFO" "${MODULE_NAME}" "sudo_version" \
                "Sudo version: ${sudo_ver}" ""

            # CVE-2021-3156 (Baron Samedit) — sudo < 1.9.5p2
            if _version_in_range "${sudo_ver}" "1.8.0" "1.9.5"; then
                register_finding "CRITICAL" "${MODULE_NAME}" "sudo_cve_2021_3156" \
                    "Sudo ${sudo_ver} may be vulnerable to CVE-2021-3156 (Baron Samedit)" \
                    "Heap overflow in sudoedit — run: sudoedit -s '\\' 2>&1 | grep 'not a regular file'"
            fi

            # CVE-2019-14287 — sudo < 1.8.28
            if _version_in_range "${sudo_ver}" "1.7.0" "1.8.27"; then
                register_finding "HIGH" "${MODULE_NAME}" "sudo_cve_2019_14287" \
                    "Sudo ${sudo_ver} may be vulnerable to CVE-2019-14287" \
                    "Bypass runas restriction: sudo -u#-1 /bin/bash"
            fi
        fi
    fi

    # Polkit version check (CVE-2021-4034 PwnKit)
    if cmd_exists pkexec; then
        local pkexec_ver
        pkexec_ver=$(pkexec --version 2>/dev/null | grep -oP '[\d.]+')
        if [[ -n "${pkexec_ver}" ]]; then
            emit_finding "INFO" "${MODULE_NAME}" "pkexec_version" \
                "pkexec version: ${pkexec_ver}" ""
            # PwnKit affects pkexec < 0.120
            if _version_in_range "${pkexec_ver}" "0.100" "0.119"; then
                register_finding "CRITICAL" "${MODULE_NAME}" "pwnkit" \
                    "pkexec ${pkexec_ver} likely vulnerable to CVE-2021-4034 (PwnKit)" \
                    "Local privilege escalation — multiple PoCs available"
            fi
        fi
    fi

    # Screen version (CVE-2017-5618)
    if cmd_exists screen; then
        local screen_ver
        screen_ver=$(screen --version 2>/dev/null | grep -oP '[\d.]+')
        if [[ -n "${screen_ver}" ]] && [[ "${screen_ver}" == "4.5.0" ]]; then
            register_finding "HIGH" "${MODULE_NAME}" "screen_4_5_0" \
                "GNU Screen ${screen_ver} — CVE-2017-5618 (logfile overwrite)" \
                "Exploit via screen -D -m -L root root"
        fi
    fi
}
