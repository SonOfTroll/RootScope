#!/usr/bin/env bash
# ============================================================================
# RootScope — plugins/stealth_mode/stealth.sh
# Stealth mode plugin — minimizes forensic footprint.
# Overrides I/O to avoid disk writes, suppresses noisy commands,
# and uses /proc reads instead of standard tools.
# ============================================================================

PLUGIN_NAME="stealth_mode"
PLUGIN_DESCRIPTION="Stealth mode: minimize disk I/O and forensic artifacts"
PLUGIN_AUTHOR="RootScope"

run_plugin() {
    log_info "plugin:${PLUGIN_NAME}" "Activating stealth mode overrides"

    # Override output to prevent disk writes
    export ROOTSCOPE_STEALTH=1

    # Redirect log writes to /dev/null if stealth
    ROOTSCOPE_LOG_FILE="/dev/null"

    # Override find to use rate-limited, quieter scanning
    _stealth_find() {
        # Use ionice to reduce I/O priority
        if cmd_exists ionice; then
            ionice -c 3 find "$@" 2>/dev/null
        else
            find "$@" 2>/dev/null
        fi
    }

    # Override file reading to use /proc/self/fd trick
    _stealth_cat() {
        local file="$1"
        if [[ -r "${file}" ]]; then
            exec 3< "${file}"
            cat <&3
            exec 3<&-
        fi
    }

    # Disable commands that generate system logs
    _stealth_skip() {
        log_info "plugin:${PLUGIN_NAME}" "Skipped noisy command: $1"
        return 0
    }

    # Export stealth helpers for modules to use
    export -f _stealth_find _stealth_cat _stealth_skip 2>/dev/null

    # Suppress bash history for this session
    unset HISTFILE 2>/dev/null
    export HISTSIZE=0

    print_info "Stealth mode active — disk writes minimized"
    return 0
}
