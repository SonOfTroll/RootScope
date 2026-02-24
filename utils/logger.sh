#!/usr/bin/env bash
# ============================================================================
# RootScope — utils/logger.sh
# Timestamped, leveled logging system with file + stderr output.
# ============================================================================

[[ -n "${_ROOTSCOPE_LOGGER_LOADED:-}" ]] && return 0
readonly _ROOTSCOPE_LOGGER_LOADED=1

# ---------------------------------------------------------------------------
# Log level constants (numeric for comparison)
# ---------------------------------------------------------------------------
readonly LOG_LEVEL_DEBUG=0
readonly LOG_LEVEL_INFO=1
readonly LOG_LEVEL_WARN=2
readonly LOG_LEVEL_ERROR=3
readonly LOG_LEVEL_SILENT=4

# Current log level (default: INFO, overridden by config)
ROOTSCOPE_LOG_LEVEL="${ROOTSCOPE_LOG_LEVEL:-${LOG_LEVEL_INFO}}"

# Log file path (set by main controller after config load)
ROOTSCOPE_LOG_FILE="${ROOTSCOPE_LOG_FILE:-}"

# ---------------------------------------------------------------------------
# Internal: Convert level name to numeric
# ---------------------------------------------------------------------------
_log_level_num() {
    case "${1^^}" in
        DEBUG) echo "${LOG_LEVEL_DEBUG}" ;;
        INFO)  echo "${LOG_LEVEL_INFO}" ;;
        WARN)  echo "${LOG_LEVEL_WARN}" ;;
        ERROR) echo "${LOG_LEVEL_ERROR}" ;;
        *)     echo "${LOG_LEVEL_INFO}" ;;
    esac
}

# ---------------------------------------------------------------------------
# Core log function
# Usage: _log "LEVEL" "component" "message"
# ---------------------------------------------------------------------------
_log() {
    local level="${1}" component="${2}" message="${3}"
    local level_num
    level_num=$(_log_level_num "${level}")

    # Skip messages below current threshold
    (( level_num < ROOTSCOPE_LOG_LEVEL )) && return 0

    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local formatted="[${timestamp}] [${level^^}] [${component}] ${message}"

    # Write to log file if configured
    if [[ -n "${ROOTSCOPE_LOG_FILE}" ]]; then
        echo "${formatted}" >> "${ROOTSCOPE_LOG_FILE}" 2>/dev/null
    fi

    # Write to stderr based on verbosity
    if [[ "${ROOTSCOPE_VERBOSE:-0}" == "1" ]] || (( level_num >= LOG_LEVEL_WARN )); then
        echo "${formatted}" >&2
    fi
}

# ---------------------------------------------------------------------------
# Public API — convenience wrappers
# ---------------------------------------------------------------------------
log_debug() { _log "DEBUG" "${1}" "${2}"; }
log_info()  { _log "INFO"  "${1}" "${2}"; }
log_warn()  { _log "WARN"  "${1}" "${2}"; }
log_error() { _log "ERROR" "${1}" "${2}"; }

# ---------------------------------------------------------------------------
# Initialize logging subsystem
# Creates log directory and file, sets rotation if file exists
# ---------------------------------------------------------------------------
logger_init() {
    local log_dir="${1:-output/raw}"
    local log_name="${2:-rootscope.log}"

    # Ensure log directory exists
    mkdir -p "${log_dir}" 2>/dev/null || {
        echo "[WARN] Cannot create log directory: ${log_dir}" >&2
        return 1
    }

    ROOTSCOPE_LOG_FILE="${log_dir}/${log_name}"

    # Rotate existing log (keep last run)
    if [[ -f "${ROOTSCOPE_LOG_FILE}" ]]; then
        mv "${ROOTSCOPE_LOG_FILE}" "${ROOTSCOPE_LOG_FILE}.bak" 2>/dev/null
    fi

    # Write header
    {
        echo "================================================================"
        echo "  RootScope Log — $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "  PID: $$  |  User: $(whoami)  |  Host: $(hostname)"
        echo "================================================================"
    } > "${ROOTSCOPE_LOG_FILE}" 2>/dev/null

    log_info "logger" "Logging initialized → ${ROOTSCOPE_LOG_FILE}"
}

# ---------------------------------------------------------------------------
# Log structured finding (for machine-parseable audit trail)
# Usage: log_finding "SEVERITY" "module" "category" "detail" "hint"
# ---------------------------------------------------------------------------
log_finding() {
    local sev="${1}" module="${2}" cat="${3}" detail="${4}" hint="${5:-}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    local record="FINDING|${timestamp}|${sev}|${module}|${cat}|${detail}|${hint}"

    if [[ -n "${ROOTSCOPE_LOG_FILE}" ]]; then
        echo "${record}" >> "${ROOTSCOPE_LOG_FILE}" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Set log level from string
# ---------------------------------------------------------------------------
set_log_level() {
    ROOTSCOPE_LOG_LEVEL=$(_log_level_num "${1}")
    log_debug "logger" "Log level set to ${1^^} (${ROOTSCOPE_LOG_LEVEL})"
}
