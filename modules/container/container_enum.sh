#!/usr/bin/env bash
# ============================================================================
# RootScope — modules/container/container_enum.sh
# Container enumeration module.
# Detects: Docker, Podman, LXC, Kubernetes environments.
# Checks: container breakout vectors, mount analysis, cgroup checks.
# ============================================================================

MODULE_NAME="container"

run_container_enum() {
    print_section "Container Enumeration"
    log_info "${MODULE_NAME}" "Starting container enumeration"
    _detect_container_environment
    _enum_docker
    _enum_podman
    _enum_lxc
    _enum_kubernetes
    _enum_cgroup_analysis
    log_info "${MODULE_NAME}" "Container enumeration complete"
}

_detect_container_environment() {
    print_subsection "Container Detection"
    local inside=false

    if [[ -f /.dockerenv ]]; then
        register_finding "INFO" "${MODULE_NAME}" "inside_docker" \
            "Running inside a Docker container" ""
        inside=true
    fi
    if grep -qiE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null; then
        register_finding "INFO" "${MODULE_NAME}" "container_cgroup" \
            "Container cgroup detected: $(grep -oiE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null | head -1)" ""
        inside=true
    fi
    if [[ "${inside}" == "false" ]]; then
        emit_finding "INFO" "${MODULE_NAME}" "not_container" \
            "Not running inside a container" ""
    fi
}

_enum_docker() {
    print_subsection "Docker"

    # Check docker socket access
    if [[ -S /var/run/docker.sock ]]; then
        if [[ -r /var/run/docker.sock ]]; then
            register_finding "CRITICAL" "${MODULE_NAME}" "docker_socket" \
                "Docker socket accessible: /var/run/docker.sock" \
                "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
        fi
    fi

    # Check if user is in docker group
    if id -nG 2>/dev/null | grep -qw docker; then
        register_finding "CRITICAL" "${MODULE_NAME}" "docker_group" \
            "Current user is in docker group" \
            "Full root access via: docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    fi

    # Docker info if available
    if cmd_exists docker; then
        local containers
        containers=$(docker ps --format '{{.Names}}' 2>/dev/null | head -10)
        [[ -n "${containers}" ]] && emit_finding "INFO" "${MODULE_NAME}" "docker_containers" \
            "Running containers: $(echo "${containers}" | tr '\n' ', ')" ""

        # Check for privileged containers
        local priv
        priv=$(docker ps --format '{{.Names}}' 2>/dev/null | while read -r c; do
            docker inspect "${c}" 2>/dev/null | grep -q '"Privileged": true' && echo "${c}"
        done)
        [[ -n "${priv}" ]] && register_finding "CRITICAL" "${MODULE_NAME}" "privileged_container" \
            "Privileged container(s): ${priv}" "Container breakout possible"
    fi

    # Inside Docker — check for breakout vectors
    if [[ -f /.dockerenv ]]; then
        # Check for host mounts
        local host_mounts
        host_mounts=$(mount 2>/dev/null | grep -E 'type (ext4|xfs|btrfs)')
        [[ -n "${host_mounts}" ]] && register_finding "HIGH" "${MODULE_NAME}" "host_mount" \
            "Host filesystem mounted inside container" \
            "Access host filesystem via mount point"

        # Check if running as root inside container
        is_root && register_finding "MEDIUM" "${MODULE_NAME}" "container_root" \
            "Running as root inside container" \
            "Check for additional breakout techniques"

        # Check for dangerous capabilities
        if can_read /proc/self/status; then
            local capeff
            capeff=$(grep 'CapEff' /proc/self/status 2>/dev/null | awk '{print $2}')
            if [[ "${capeff}" == "0000003fffffffff" ]]; then
                register_finding "CRITICAL" "${MODULE_NAME}" "full_capabilities" \
                    "Container has full capabilities (privileged)" \
                    "Container breakout via nsenter or mount"
            fi
        fi
    fi
}

_enum_podman() {
    print_subsection "Podman"
    if cmd_exists podman; then
        local pods
        pods=$(podman ps --format '{{.Names}}' 2>/dev/null | head -5)
        [[ -n "${pods}" ]] && emit_finding "INFO" "${MODULE_NAME}" "podman_containers" \
            "Podman containers: $(echo "${pods}" | tr '\n' ', ')" ""
    fi
}

_enum_lxc() {
    print_subsection "LXC/LXD"

    if id -nG 2>/dev/null | grep -qw lxd; then
        register_finding "CRITICAL" "${MODULE_NAME}" "lxd_group" \
            "User is in lxd group" \
            "lxc init ubuntu:22.04 privesc -c security.privileged=true && lxc config device add privesc host-root disk source=/ path=/mnt/root && lxc start privesc && lxc exec privesc -- /bin/sh"
    fi

    if cmd_exists lxc; then
        local lxc_list
        lxc_list=$(lxc list --format csv 2>/dev/null | head -5)
        [[ -n "${lxc_list}" ]] && emit_finding "INFO" "${MODULE_NAME}" "lxc_containers" \
            "LXC containers found" ""
    fi
}

_enum_kubernetes() {
    print_subsection "Kubernetes"

    # Check for K8s service account token
    if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]; then
        register_finding "HIGH" "${MODULE_NAME}" "k8s_token" \
            "Kubernetes service account token found" \
            "Use kubectl with token for cluster reconnaissance"
    fi

    if cmd_exists kubectl; then
        local can_list
        can_list=$(kubectl auth can-i list pods 2>/dev/null)
        [[ "${can_list}" == "yes" ]] && register_finding "HIGH" "${MODULE_NAME}" "k8s_access" \
            "kubectl can list pods" "Enumerate cluster resources"
    fi
}

_enum_cgroup_analysis() {
    print_subsection "Cgroup Analysis"

    if can_read /proc/1/cgroup; then
        local cgroup_content
        cgroup_content=$(cat /proc/1/cgroup 2>/dev/null)
        # Check for cgroup v2 writable release_agent (CVE-2022-0492)
        local release_agent="/sys/fs/cgroup/*/release_agent"
        for ra in ${release_agent}; do
            if [[ -f "${ra}" ]] && can_write "${ra}"; then
                register_finding "CRITICAL" "${MODULE_NAME}" "cgroup_escape" \
                    "Writable cgroup release_agent: ${ra}" \
                    "CVE-2022-0492: cgroup escape via release_agent"
            fi
        done
    fi
}
