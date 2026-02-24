#!/usr/bin/env bash
# ============================================================================
# RootScope — utils/helpers.sh
# Reusable utility functions: command checks, text processing, safe reads,
# parallel execution, privilege detection, and OS fingerprinting.
# ============================================================================

[[ -n "${_ROOTSCOPE_HELPERS_LOADED:-}" ]] && return 0
readonly _ROOTSCOPE_HELPERS_LOADED=1

# ---------------------------------------------------------------------------
# Command & capability checks
# ---------------------------------------------------------------------------

# Check if a command exists on the system
cmd_exists() { command -v "$1" &>/dev/null; }

# Check if current user is root
is_root() { [[ "$(id -u)" -eq 0 ]]; }

# Check if we can read a file
can_read() { [[ -r "$1" ]]; }

# Check if we can write to a path
can_write() { [[ -w "$1" ]]; }

# Check if running inside a container
is_container() {
    [[ -f /.dockerenv ]] ||
    grep -qiE 'docker|lxc|kubepods|containerd' /proc/1/cgroup 2>/dev/null ||
    [[ "$(cat /proc/1/sched 2>/dev/null | head -1)" != "systemd"* ]]
}

# ---------------------------------------------------------------------------
# OS & kernel fingerprinting
# ---------------------------------------------------------------------------

get_os_family() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release 2>/dev/null
        echo "${ID:-unknown}"
    elif cmd_exists lsb_release; then
        lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]'
    else
        echo "unknown"
    fi
}

get_os_version() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release 2>/dev/null
        echo "${VERSION_ID:-unknown}"
    else
        echo "unknown"
    fi
}

get_kernel_version() {
    uname -r 2>/dev/null || echo "unknown"
}

get_arch() {
    uname -m 2>/dev/null || echo "unknown"
}

# ---------------------------------------------------------------------------
# Text processing
# ---------------------------------------------------------------------------

# Trim leading/trailing whitespace
trim() {
    local str="$*"
    str="${str#"${str%%[![:space:]]*}"}"
    str="${str%"${str##*[![:space:]]}"}"
    echo "${str}"
}

# Join array elements with delimiter
# Usage: join_array "," "${arr[@]}"
join_array() {
    local delim="$1"; shift
    local first="$1"; shift
    printf '%s' "$first" "${@/#/$delim}"
}

# Convert string to uppercase
to_upper() { echo "${1}" | tr '[:lower:]' '[:upper:]'; }

# Convert string to lowercase
to_lower() { echo "${1}" | tr '[:upper:]' '[:lower:]'; }

# ---------------------------------------------------------------------------
# Safe file reading (avoids errors on missing/unreadable files)
# ---------------------------------------------------------------------------

# Read file contents safely, returns empty on failure
safe_read() {
    local file="$1"
    if [[ -f "${file}" ]] && [[ -r "${file}" ]]; then
        cat "${file}" 2>/dev/null
    fi
}

# Read first N lines of a file safely
safe_head() {
    local file="$1" lines="${2:-10}"
    if [[ -f "${file}" ]] && [[ -r "${file}" ]]; then
        head -n "${lines}" "${file}" 2>/dev/null
    fi
}

# Grep a file safely (no error on missing file)
safe_grep() {
    local pattern="$1" file="$2"
    shift 2
    if [[ -f "${file}" ]] && [[ -r "${file}" ]]; then
        grep "$@" "${pattern}" "${file}" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

# Run a command with a timeout (fallback if timeout command unavailable)
run_timeout() {
    local seconds="$1"; shift
    if cmd_exists timeout; then
        timeout "${seconds}" "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
}

# Run command silently, return only exit code
run_silent() { "$@" &>/dev/null; }

# Run command and capture output, suppressing errors
run_capture() { "$@" 2>/dev/null; }

# ---------------------------------------------------------------------------
# Parallel execution engine
# Runs a list of functions with a configurable worker pool.
# Usage: run_parallel <max_jobs> <func1> <func2> ...
# ---------------------------------------------------------------------------
run_parallel() {
    local max_jobs="${1}"; shift
    local -a pids=()
    local func

    for func in "$@"; do
        # Run function in background
        "${func}" &
        pids+=($!)

        # Throttle: wait if we hit max concurrent jobs
        if (( ${#pids[@]} >= max_jobs )); then
            wait "${pids[0]}" 2>/dev/null
            pids=("${pids[@]:1}")
        fi
    done

    # Wait for remaining background jobs
    for pid in "${pids[@]}"; do
        wait "${pid}" 2>/dev/null
    done
}

# ---------------------------------------------------------------------------
# Finding record builder
# Builds a standardized pipe-delimited finding string
# Usage: build_finding "SEVERITY" "module" "category" "detail" "hint"
# ---------------------------------------------------------------------------
build_finding() {
    local sev="${1}" module="${2}" cat="${3}" detail="${4}" hint="${5:-none}"
    echo "FINDING|${sev}|${module}|${cat}|${detail}|${hint}"
}

# ---------------------------------------------------------------------------
# Emit finding to both stdout (for report pipeline) and log
# ---------------------------------------------------------------------------
emit_finding() {
    local sev="${1}" module="${2}" cat="${3}" detail="${4}" hint="${5:-}"

    # Structured record to stdout (captured by pipeline)
    build_finding "${sev}" "${module}" "${cat}" "${detail}" "${hint}"

    # Human-readable to terminal
    if [[ "${ROOTSCOPE_QUIET:-0}" != "1" ]]; then
        print_finding "${sev}" "${cat}" "${detail}" "${hint}"
    fi

    # Log it
    log_finding "${sev}" "${module}" "${cat}" "${detail}" "${hint}"
}

# ---------------------------------------------------------------------------
# Counting / stats helpers
# ---------------------------------------------------------------------------
declare -gA _FINDING_COUNTS=()

increment_finding_count() {
    local sev="${1^^}"
    _FINDING_COUNTS["${sev}"]=$(( ${_FINDING_COUNTS["${sev}"]:-0} + 1 ))
}

get_finding_count() {
    echo "${_FINDING_COUNTS["${1^^}"]:-0}"
}

get_total_findings() {
    local total=0
    for count in "${_FINDING_COUNTS[@]}"; do
        (( total += count ))
    done
    echo "${total}"
}

# ---------------------------------------------------------------------------
# Path resolution (resolve ROOTSCOPE_BASE relative to main.sh location)
# ---------------------------------------------------------------------------
resolve_base_dir() {
    local source="${BASH_SOURCE[0]}"
    while [[ -L "${source}" ]]; do
        local dir
        dir="$(cd -P "$(dirname "${source}")" && pwd)"
        source="$(readlink "${source}")"
        [[ "${source}" != /* ]] && source="${dir}/${source}"
    done
    cd -P "$(dirname "${source}")/.." && pwd
}

# ---------------------------------------------------------------------------
# Stealth helpers (reduce system artifacts)
# ---------------------------------------------------------------------------
stealth_read() {
    # Read file via /proc/self/fd to minimize access log footprint
    local file="$1"
    if [[ -r "${file}" ]]; then
        exec 3< "${file}"
        cat <&3
        exec 3<&-
    fi
}
