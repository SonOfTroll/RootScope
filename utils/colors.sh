#!/usr/bin/env bash
# ============================================================================
# RootScope — utils/colors.sh
# Colored output helper with severity-tagged printing and stealth passthrough.
# ============================================================================

# Guard against double-sourcing
[[ -n "${_ROOTSCOPE_COLORS_LOADED:-}" ]] && return 0
readonly _ROOTSCOPE_COLORS_LOADED=1

# ---------------------------------------------------------------------------
# Auto-detect color support
# ---------------------------------------------------------------------------
_supports_color() {
    [[ -t 1 ]] && [[ "$(tput colors 2>/dev/null)" -ge 8 ]] 2>/dev/null
}

# ---------------------------------------------------------------------------
# ANSI escape sequences (disabled in stealth mode or dumb terminals)
# ---------------------------------------------------------------------------
if _supports_color && [[ "${ROOTSCOPE_STEALTH:-0}" != "1" ]]; then
    readonly RSC_RESET='\033[0m'
    readonly RSC_BOLD='\033[1m'
    readonly RSC_DIM='\033[2m'
    readonly RSC_UNDERLINE='\033[4m'

    # Severity palette
    readonly RSC_CRITICAL='\033[1;97;41m'   # White on red bg
    readonly RSC_HIGH='\033[1;91m'           # Bold bright red
    readonly RSC_MEDIUM='\033[1;93m'         # Bold yellow
    readonly RSC_LOW='\033[1;96m'            # Bold cyan
    readonly RSC_INFO='\033[0;37m'           # Light gray

    # Functional palette
    readonly RSC_SUCCESS='\033[1;92m'        # Bold green
    readonly RSC_HEADER='\033[1;95m'         # Bold magenta
    readonly RSC_BANNER='\033[1;94m'         # Bold blue
    readonly RSC_LABEL='\033[1;33m'          # Bold dark yellow
    readonly RSC_PATH='\033[0;36m'           # Cyan
    readonly RSC_CMD='\033[0;33m'            # Dark yellow
else
    readonly RSC_RESET='' RSC_BOLD='' RSC_DIM='' RSC_UNDERLINE=''
    readonly RSC_CRITICAL='' RSC_HIGH='' RSC_MEDIUM='' RSC_LOW='' RSC_INFO=''
    readonly RSC_SUCCESS='' RSC_HEADER='' RSC_BANNER='' RSC_LABEL=''
    readonly RSC_PATH='' RSC_CMD=''
fi

# ---------------------------------------------------------------------------
# Severity tag strings (used in reports and terminal output)
# ---------------------------------------------------------------------------
severity_tag() {
    local level="${1^^}"
    case "${level}" in
        CRITICAL) echo -e "${RSC_CRITICAL}[CRITICAL]${RSC_RESET}" ;;
        HIGH)     echo -e "${RSC_HIGH}[HIGH]${RSC_RESET}" ;;
        MEDIUM)   echo -e "${RSC_MEDIUM}[MEDIUM]${RSC_RESET}" ;;
        LOW)      echo -e "${RSC_LOW}[LOW]${RSC_RESET}" ;;
        INFO)     echo -e "${RSC_INFO}[INFO]${RSC_RESET}" ;;
        *)        echo "[${level}]" ;;
    esac
}

# ---------------------------------------------------------------------------
# Severity-aware print helpers
# Usage: print_critical "message"
# ---------------------------------------------------------------------------
print_critical() { echo -e "$(severity_tag CRITICAL) ${RSC_BOLD}$*${RSC_RESET}"; }
print_high()     { echo -e "$(severity_tag HIGH) $*${RSC_RESET}"; }
print_medium()   { echo -e "$(severity_tag MEDIUM) $*${RSC_RESET}"; }
print_low()      { echo -e "$(severity_tag LOW) $*${RSC_RESET}"; }
print_info()     { echo -e "$(severity_tag INFO) $*${RSC_RESET}"; }

# ---------------------------------------------------------------------------
# Structural output helpers
# ---------------------------------------------------------------------------
print_banner() {
    local text="$1"
    local width=70
    local pad=$(( (width - ${#text} - 2) / 2 ))
    echo ""
    echo -e "${RSC_BANNER}$(printf '═%.0s' $(seq 1 $width))${RSC_RESET}"
    echo -e "${RSC_BANNER}$(printf ' %.0s' $(seq 1 $pad)) ${RSC_BOLD}${text}${RSC_RESET}${RSC_BANNER} $(printf ' %.0s' $(seq 1 $pad))${RSC_RESET}"
    echo -e "${RSC_BANNER}$(printf '═%.0s' $(seq 1 $width))${RSC_RESET}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${RSC_HEADER}━━━ $* ━━━${RSC_RESET}"
    echo ""
}

print_subsection() {
    echo -e "${RSC_LABEL}  ▸ $*${RSC_RESET}"
}

print_finding() {
    # Usage: print_finding "SEVERITY" "category" "description" ["hint"]
    local sev="${1}" cat="${2}" desc="${3}" hint="${4:-}"
    echo -e "  $(severity_tag "${sev}") ${RSC_LABEL}[${cat}]${RSC_RESET} ${desc}"
    [[ -n "${hint}" ]] && echo -e "         ${RSC_DIM}↳ Hint: ${hint}${RSC_RESET}"
}

print_success() { echo -e "${RSC_SUCCESS}[✓]${RSC_RESET} $*"; }
print_error()   { echo -e "${RSC_CRITICAL}[✗]${RSC_RESET} $*" >&2; }
print_warn()    { echo -e "${RSC_MEDIUM}[!]${RSC_RESET} $*" >&2; }
print_dim()     { echo -e "${RSC_DIM}$*${RSC_RESET}"; }

# ---------------------------------------------------------------------------
# Progress spinner (for long-running operations)
# ---------------------------------------------------------------------------
spin_start() {
    local msg="${1:-Working}"
    _SPIN_MSG="${msg}"
    (
        local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        while true; do
            for (( i=0; i<${#chars}; i++ )); do
                printf "\r${RSC_DIM}  %s %s${RSC_RESET}" "${chars:$i:1}" "${_SPIN_MSG}" >&2
                sleep 0.1
            done
        done
    ) &
    _SPIN_PID=$!
    disown "${_SPIN_PID}" 2>/dev/null
}

spin_stop() {
    [[ -n "${_SPIN_PID:-}" ]] && kill "${_SPIN_PID}" 2>/dev/null
    printf "\r%*s\r" 60 "" >&2
    unset _SPIN_PID _SPIN_MSG
}
