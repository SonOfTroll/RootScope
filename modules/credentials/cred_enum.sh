#!/usr/bin/env bash
# ============================================================================
# RootScope — modules/credentials/cred_enum.sh
# Credential enumeration module.
# Enumerates: SSH keys, password files, history files, cloud tokens,
#             .env files, browser creds, config files with credentials.
# ============================================================================

MODULE_NAME="credentials"

run_credentials_enum() {
    print_section "Credential Enumeration"
    log_info "${MODULE_NAME}" "Starting credential enumeration"
    _enum_ssh_keys
    _enum_history_files
    _enum_credential_files
    _enum_env_files
    _enum_cloud_tokens
    _enum_password_stores
    log_info "${MODULE_NAME}" "Credential enumeration complete"
}

# ---------------------------------------------------------------------------
# SSH key enumeration
# ---------------------------------------------------------------------------
_enum_ssh_keys() {
    print_subsection "SSH Keys"

    # Search for private keys in common locations
    local key_locations=("$HOME/.ssh" "/root/.ssh" "/etc/ssh" "/tmp" "/opt" "/var")
    for loc in "${key_locations[@]}"; do
        local keys
        keys=$(find "${loc}" -maxdepth 3 -type f \
            \( -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" \
               -o -name "id_ed25519" -o -name "*.pem" -o -name "*.key" \) \
            -readable 2>/dev/null)

        while IFS= read -r key; do
            [[ -z "${key}" ]] && continue
            # Check if key is encrypted
            local encrypted="no"
            if head -5 "${key}" 2>/dev/null | grep -qi "ENCRYPTED"; then
                encrypted="yes"
            fi
            local sev="HIGH"
            [[ "${encrypted}" == "yes" ]] && sev="MEDIUM"

            register_finding "${sev}" "${MODULE_NAME}" "ssh_private_key" \
                "Private key found: ${key} (encrypted: ${encrypted})" \
                "Use key for SSH lateral movement"
        done <<< "${keys}"
    done

    # Check authorized_keys for other users
    local auth_keys
    auth_keys=$(find /home -maxdepth 3 -name "authorized_keys" -readable 2>/dev/null)
    while IFS= read -r ak; do
        [[ -z "${ak}" ]] && continue
        local key_count
        key_count=$(wc -l < "${ak}" 2>/dev/null || echo 0)
        emit_finding "INFO" "${MODULE_NAME}" "authorized_keys" \
            "authorized_keys: ${ak} (${key_count} keys)" ""
    done <<< "${auth_keys}"

    # Check for SSH agent forwarding socket
    if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
        register_finding "MEDIUM" "${MODULE_NAME}" "ssh_agent" \
            "SSH agent socket: ${SSH_AUTH_SOCK}" \
            "Agent forwarding active — potential for key hijacking"
    fi
}

# ---------------------------------------------------------------------------
# History files (may contain credentials)
# ---------------------------------------------------------------------------
_enum_history_files() {
    print_subsection "History Files"

    local hist_files=(
        "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.sh_history"
        "$HOME/.mysql_history" "$HOME/.psql_history" "$HOME/.python_history"
        "$HOME/.node_repl_history" "$HOME/.lesshst" "$HOME/.viminfo"
    )

    for hf in "${hist_files[@]}"; do
        if [[ -f "${hf}" ]] && can_read "${hf}"; then
            # grep for credential patterns
            local cred_lines
            cred_lines=$(grep -inE \
                '(password|passwd|pass=|pwd=|secret|token|api.?key|mysql.*-p|sshpass|curl.*-u)' \
                "${hf}" 2>/dev/null | head -5)

            if [[ -n "${cred_lines}" ]]; then
                register_finding "HIGH" "${MODULE_NAME}" "history_credentials" \
                    "Credentials in ${hf}: $(echo "${cred_lines}" | head -3)" \
                    "Extract and test discovered credentials"
            else
                emit_finding "INFO" "${MODULE_NAME}" "history_file" \
                    "History file readable: ${hf}" ""
            fi
        fi
    done
}

# ---------------------------------------------------------------------------
# Credential and config files
# ---------------------------------------------------------------------------
_enum_credential_files() {
    print_subsection "Configuration Files with Credentials"

    local search_paths=("/etc" "/opt" "/var/www" "/home" "/srv" "/usr/local")
    local patterns='(password|passwd|pass|secret|token|api_key|db_pass|credential)'

    for sp in "${search_paths[@]}"; do
        [[ ! -d "${sp}" ]] && continue
        local found
        found=$(find "${sp}" -maxdepth 4 -type f \
            \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.yml" \
               -o -name "*.yaml" -o -name "*.xml" -o -name "*.properties" \
               -o -name "*.json" -o -name "wp-config.php" \) \
            -readable 2>/dev/null | head -30)

        while IFS= read -r cf; do
            [[ -z "${cf}" ]] && continue
            local matches
            matches=$(grep -ilE "${patterns}" "${cf}" 2>/dev/null)
            if [[ -n "${matches}" ]]; then
                local sample
                sample=$(grep -iE "${patterns}" "${cf}" 2>/dev/null | head -2 | \
                    sed 's/password.*=.*/password=<REDACTED>/gi')
                register_finding "HIGH" "${MODULE_NAME}" "config_credentials" \
                    "Potential creds in ${cf}" \
                    "Review file for plaintext credentials"
            fi
        done <<< "${found}"
    done
}

# ---------------------------------------------------------------------------
# .env files
# ---------------------------------------------------------------------------
_enum_env_files() {
    print_subsection ".env Files"

    local env_files
    env_files=$(find / -maxdepth 5 -name ".env" -readable -type f \
        ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -15)

    while IFS= read -r ef; do
        [[ -z "${ef}" ]] && continue
        register_finding "HIGH" "${MODULE_NAME}" "env_file" \
            ".env file found: ${ef}" \
            "Often contains database credentials, API keys, and secrets"
    done <<< "${env_files}"
}

# ---------------------------------------------------------------------------
# Cloud credential tokens
# ---------------------------------------------------------------------------
_enum_cloud_tokens() {
    print_subsection "Cloud Credentials"

    local cloud_paths=(
        "$HOME/.aws/credentials" "$HOME/.aws/config"
        "$HOME/.azure/accessTokens.json" "$HOME/.azure/azureProfile.json"
        "$HOME/.config/gcloud/credentials.db"
        "$HOME/.config/gcloud/application_default_credentials.json"
        "$HOME/.kube/config"
        "$HOME/.docker/config.json"
    )

    for cp in "${cloud_paths[@]}"; do
        if [[ -f "${cp}" ]] && can_read "${cp}"; then
            register_finding "HIGH" "${MODULE_NAME}" "cloud_credentials" \
                "Cloud credential file: ${cp}" \
                "Extract credentials for cloud service access"
        fi
    done
}

# ---------------------------------------------------------------------------
# Password stores
# ---------------------------------------------------------------------------
_enum_password_stores() {
    print_subsection "Password Stores"

    local stores=(
        "$HOME/.gnupg" "$HOME/.password-store"
        "$HOME/.local/share/keyrings"
    )
    for st in "${stores[@]}"; do
        if [[ -d "${st}" ]] && [[ -r "${st}" ]]; then
            emit_finding "LOW" "${MODULE_NAME}" "password_store" \
                "Password store directory: ${st}" \
                "May contain encrypted credentials"
        fi
    done
}
