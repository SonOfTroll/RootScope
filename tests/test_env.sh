#!/usr/bin/env bash
# ============================================================================
# RootScope — tests/test_env.sh
# Test environment setup — creates a sandboxed directory with dummy files
# simulating common privilege escalation vectors for safe testing.
#
# Usage: sudo bash tests/test_env.sh [setup|teardown]
# ============================================================================
set -euo pipefail

TEST_DIR="/tmp/rootscope_test_env"

setup_test_env() {
    echo "[*] Setting up RootScope test environment in ${TEST_DIR}"

    mkdir -p "${TEST_DIR}"/{bin,etc,scripts,keys,cron.d,web}

    # --- SUID binaries ---
    echo '#!/bin/bash' > "${TEST_DIR}/bin/custom_suid"
    echo 'echo "I am a custom SUID binary"' >> "${TEST_DIR}/bin/custom_suid"
    chmod 4755 "${TEST_DIR}/bin/custom_suid"
    echo "[+] Created dummy SUID binary: ${TEST_DIR}/bin/custom_suid"

    # Simulate a SUID copy of a known binary
    if [[ -f /usr/bin/find ]]; then
        cp /usr/bin/find "${TEST_DIR}/bin/find_suid" 2>/dev/null || true
        chmod 4755 "${TEST_DIR}/bin/find_suid" 2>/dev/null || true
        echo "[+] Created SUID find: ${TEST_DIR}/bin/find_suid"
    fi

    # --- Capabilities ---
    echo '#!/usr/bin/env python3' > "${TEST_DIR}/bin/cap_python"
    echo 'print("Python with capabilities")' >> "${TEST_DIR}/bin/cap_python"
    chmod 755 "${TEST_DIR}/bin/cap_python"
    if command -v setcap &>/dev/null; then
        setcap cap_setuid+ep "${TEST_DIR}/bin/cap_python" 2>/dev/null || true
        echo "[+] Set cap_setuid on: ${TEST_DIR}/bin/cap_python"
    fi

    # --- World-writable files ---
    echo "# Dummy shadow file" > "${TEST_DIR}/etc/shadow_test"
    chmod 666 "${TEST_DIR}/etc/shadow_test"
    echo "[+] Created world-writable shadow: ${TEST_DIR}/etc/shadow_test"

    mkdir -p "${TEST_DIR}/world_writable_dir"
    chmod 777 "${TEST_DIR}/world_writable_dir"
    echo "[+] Created world-writable dir (no sticky): ${TEST_DIR}/world_writable_dir"

    # --- Weak cron entries ---
    cat > "${TEST_DIR}/cron.d/weak_cron" <<'CRON'
# Weak cron job — script is world-writable
* * * * * root /tmp/rootscope_test_env/scripts/backup.sh
CRON
    echo '#!/bin/bash' > "${TEST_DIR}/scripts/backup.sh"
    echo 'echo "backup running"' >> "${TEST_DIR}/scripts/backup.sh"
    chmod 777 "${TEST_DIR}/scripts/backup.sh"
    echo "[+] Created writable cron script: ${TEST_DIR}/scripts/backup.sh"

    # --- SSH keys ---
    ssh-keygen -t rsa -b 2048 -f "${TEST_DIR}/keys/id_rsa" -N "" -q 2>/dev/null || {
        echo "-----BEGIN OPENSSH PRIVATE KEY-----" > "${TEST_DIR}/keys/id_rsa"
        echo "DUMMY_KEY_FOR_TESTING" >> "${TEST_DIR}/keys/id_rsa"
        echo "-----END OPENSSH PRIVATE KEY-----" >> "${TEST_DIR}/keys/id_rsa"
    }
    chmod 600 "${TEST_DIR}/keys/id_rsa"
    echo "[+] Created test SSH key: ${TEST_DIR}/keys/id_rsa"

    # --- .env file with dummy creds ---
    cat > "${TEST_DIR}/web/.env" <<'ENV'
DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=SuperSecretPass123!
API_KEY=sk-test-1234567890abcdef
SECRET_KEY=mysecretkey
ENV
    chmod 644 "${TEST_DIR}/web/.env"
    echo "[+] Created .env with dummy creds: ${TEST_DIR}/web/.env"

    # --- History file with credentials ---
    cat > "${TEST_DIR}/.bash_history_test" <<'HIST'
ls -la
mysql -u root -pMyDBPassword123
sshpass -p 'RemotePass!' ssh user@10.0.0.1
curl -u admin:password123 http://api.internal/data
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI
HIST
    chmod 644 "${TEST_DIR}/.bash_history_test"
    echo "[+] Created history file with creds: ${TEST_DIR}/.bash_history_test"

    # --- NFS exports (simulated) ---
    echo "/home/shared *(rw,no_root_squash)" > "${TEST_DIR}/etc/exports_test"
    echo "[+] Created NFS exports with no_root_squash: ${TEST_DIR}/etc/exports_test"

    echo ""
    echo "[✓] Test environment ready at ${TEST_DIR}"
    echo "    Run RootScope to test: bash main.sh -v"
    echo "    Teardown: bash tests/test_env.sh teardown"
}

teardown_test_env() {
    echo "[*] Tearing down test environment..."
    rm -rf "${TEST_DIR}"
    echo "[✓] Test environment removed: ${TEST_DIR}"
}

# --- Entry point ---
case "${1:-setup}" in
    setup)    setup_test_env ;;
    teardown) teardown_test_env ;;
    *)
        echo "Usage: $0 [setup|teardown]"
        exit 1
        ;;
esac
