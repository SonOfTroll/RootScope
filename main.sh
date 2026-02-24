#!/usr/bin/env bash
# ============================================================================
# RootScope — main.sh
# Main controller: CLI parsing, config loading, module orchestration,
# parallel scheduling, plugin auto-loading, and output pipeline.
# ============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Resolve project root (works even via symlinks)
# ---------------------------------------------------------------------------
_resolve_base() {
    local src="${BASH_SOURCE[0]}"
    while [[ -L "${src}" ]]; do
        local dir; dir="$(cd -P "$(dirname "${src}")" && pwd)"
        src="$(readlink "${src}")"
        [[ "${src}" != /* ]] && src="${dir}/${src}"
    done
    cd -P "$(dirname "${src}")" && pwd
}
export ROOTSCOPE_BASE
ROOTSCOPE_BASE="$(_resolve_base)"

readonly ROOTSCOPE_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Source utility layer
# ---------------------------------------------------------------------------
source "${ROOTSCOPE_BASE}/utils/colors.sh"
source "${ROOTSCOPE_BASE}/utils/logger.sh"
source "${ROOTSCOPE_BASE}/utils/helpers.sh"

# ---------------------------------------------------------------------------
# Source engine layer
# ---------------------------------------------------------------------------
source "${ROOTSCOPE_BASE}/engine/risk_engine.sh"
source "${ROOTSCOPE_BASE}/engine/exploit_suggester.sh"
source "${ROOTSCOPE_BASE}/engine/parser.sh"

# ---------------------------------------------------------------------------
# Default config values (overridden by settings.conf)
# ---------------------------------------------------------------------------
OUTPUT_DIR="output"
VERBOSE=0; QUIET=0; STEALTH_MODE=0
PARALLEL_JOBS=4; CMD_TIMEOUT=30
ENABLED_MODULES="all"; REPORT_FORMATS="txt,json,html"
REPORT_MIN_SEVERITY="INFO"; AUTOLOAD_PLUGINS=1
LOG_LEVEL="INFO"; LOG_FILE="rootscope.log"

# ---------------------------------------------------------------------------
# Load configuration files
# ---------------------------------------------------------------------------
load_config() {
    local conf="${ROOTSCOPE_BASE}/config/settings.conf"
    [[ -f "${conf}" ]] && source "${conf}"

    local weights="${ROOTSCOPE_BASE}/config/risk_weights.conf"
    [[ -f "${weights}" ]] && source "${weights}"

    # Apply verbosity
    [[ "${VERBOSE}" == "1" ]] && export ROOTSCOPE_VERBOSE=1
    [[ "${QUIET}" == "1" ]]   && export ROOTSCOPE_QUIET=1
    [[ "${STEALTH_MODE}" == "1" ]] && export ROOTSCOPE_STEALTH=1
}

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
show_help() {
    cat <<EOF
${RSC_BANNER}RootScope v${ROOTSCOPE_VERSION}${RSC_RESET} — Linux Privilege Escalation Enumeration Toolkit

Usage: $(basename "$0") [OPTIONS]

Options:
  -m, --modules LIST    Comma-separated modules (default: all)
                        Options: system,filesystem,services,network,
                                 credentials,container,software
  -o, --output  DIR     Output directory (default: output/)
  -f, --format  LIST    Report formats: txt,json,html (default: all)
  -j, --jobs    N       Parallel workers (default: 4, 0=sequential)
  -s, --stealth         Enable stealth mode (minimal disk I/O)
  -q, --quiet           Suppress terminal findings output
  -v, --verbose         Enable verbose/debug output
  -S, --severity LVL    Minimum severity: CRITICAL,HIGH,MEDIUM,LOW,INFO
      --no-plugins      Disable plugin auto-loading
  -h, --help            Show this help message

Examples:
  $(basename "$0")                        # Full scan with defaults
  $(basename "$0") -m system,filesystem   # Scan specific modules
  $(basename "$0") -s -q -f json          # Stealth + JSON only
  $(basename "$0") -j 0 -S HIGH          # Sequential, HIGH+ only
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -m|--modules)   ENABLED_MODULES="$2"; shift 2 ;;
            -o|--output)    OUTPUT_DIR="$2"; shift 2 ;;
            -f|--format)    REPORT_FORMATS="$2"; shift 2 ;;
            -j|--jobs)      PARALLEL_JOBS="$2"; shift 2 ;;
            -s|--stealth)   STEALTH_MODE=1; shift ;;
            -q|--quiet)     QUIET=1; shift ;;
            -v|--verbose)   VERBOSE=1; shift ;;
            -S|--severity)  REPORT_MIN_SEVERITY="${2^^}"; shift 2 ;;
            --no-plugins)   AUTOLOAD_PLUGINS=0; shift ;;
            -h|--help)      show_help; exit 0 ;;
            *)
                print_error "Unknown option: $1"
                show_help; exit 1 ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# Module mapping
# ---------------------------------------------------------------------------
declare -A MODULE_MAP=(
    [system]="modules/system/sys_info.sh|run_system_enum"
    [filesystem]="modules/filesystem/fs_enum.sh|run_filesystem_enum"
    [services]="modules/services/svc_enum.sh|run_services_enum"
    [network]="modules/network/net_enum.sh|run_network_enum"
    [credentials]="modules/credentials/cred_enum.sh|run_credentials_enum"
    [container]="modules/container/container_enum.sh|run_container_enum"
    [software]="modules/software/sw_enum.sh|run_software_enum"
)

# ---------------------------------------------------------------------------
# Run a single module (sources script + calls entry function)
# ---------------------------------------------------------------------------
run_module() {
    local mod_name="$1"
    local entry="${MODULE_MAP[$mod_name]:-}"
    [[ -z "${entry}" ]] && { log_warn "main" "Unknown module: ${mod_name}"; return 1; }

    local script func
    IFS='|' read -r script func <<< "${entry}"
    local path="${ROOTSCOPE_BASE}/${script}"

    if [[ ! -f "${path}" ]]; then
        log_error "main" "Module script not found: ${path}"
        return 1
    fi

    log_info "main" "Loading module: ${mod_name}"
    source "${path}"

    local start_ts
    start_ts=$(date +%s)
    "${func}"
    local elapsed=$(( $(date +%s) - start_ts ))
    log_info "main" "Module ${mod_name} completed in ${elapsed}s"
}

# ---------------------------------------------------------------------------
# Resolve which modules to run
# ---------------------------------------------------------------------------
resolve_modules() {
    if [[ "${ENABLED_MODULES}" == "all" ]]; then
        echo "${!MODULE_MAP[@]}"
    else
        echo "${ENABLED_MODULES}" | tr ',' ' '
    fi
}

# ---------------------------------------------------------------------------
# Plugin auto-loader
# ---------------------------------------------------------------------------
load_plugins() {
    if [[ "${AUTOLOAD_PLUGINS}" != "1" ]]; then
        log_info "main" "Plugin auto-loading disabled"
        return
    fi

    # Load stealth plugin first if stealth mode
    if [[ "${STEALTH_MODE}" == "1" ]]; then
        local stealth_plugin="${ROOTSCOPE_BASE}/plugins/stealth_mode/stealth.sh"
        if [[ -f "${stealth_plugin}" ]]; then
            source "${stealth_plugin}"
            run_plugin
            log_info "main" "Stealth plugin loaded"
        fi
    fi

    # Auto-load plugins from custom_checks/
    local plugin_dir="${ROOTSCOPE_BASE}/plugins/custom_checks"
    if [[ -d "${plugin_dir}" ]]; then
        local plugins
        plugins=$(find "${plugin_dir}" -name "*.sh" -type f 2>/dev/null)
        while IFS= read -r plugin_file; do
            [[ -z "${plugin_file}" ]] && continue
            log_info "main" "Loading plugin: ${plugin_file}"
            (
                source "${ROOTSCOPE_BASE}/utils/colors.sh"
                source "${ROOTSCOPE_BASE}/utils/logger.sh"
                source "${ROOTSCOPE_BASE}/utils/helpers.sh"
                source "${ROOTSCOPE_BASE}/engine/risk_engine.sh"
                source "${ROOTSCOPE_BASE}/engine/parser.sh"
                source "${plugin_file}"
                if declare -f run_plugin &>/dev/null; then
                    run_plugin
                fi
            )
        done <<< "${plugins}"
    fi
}

# ---------------------------------------------------------------------------
# Signal handling (cleanup on interrupt)
# ---------------------------------------------------------------------------
_cleanup() {
    spin_stop 2>/dev/null
    # Kill any background module jobs
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null
    print_warn "Scan interrupted — partial results may be available"
    exit 130
}
trap _cleanup INT TERM

# ---------------------------------------------------------------------------
# Print banner
# ---------------------------------------------------------------------------
show_banner() {
    echo -e "${RSC_BANNER}"
    cat <<'BANNER'
    ____              __  _____                    
   / __ \____  ____  / /_/ ___/_________  ________ 
  / /_/ / __ \/ __ \/ __/\__ \/ ___/ __ \/ __ \/ _ \
 / _, _/ /_/ / /_/ / /_ ___/ / /__/ /_/ / /_/ /  __/
/_/ |_|\____/\____/\__//____/\___/\____/ .___/\___/ 
                                      /_/           
BANNER
    echo -e "${RSC_RESET}"
    echo -e "${RSC_DIM}  Linux Privilege Escalation Enumeration Toolkit v${ROOTSCOPE_VERSION}${RSC_RESET}"
    echo -e "${RSC_DIM}  $(date '+%Y-%m-%d %H:%M:%S %Z') | $(whoami)@$(hostname)${RSC_RESET}"
    echo ""
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
main() {
    # 1. Parse CLI arguments (before config, so CLI overrides config)
    parse_args "$@"

    # 2. Load config files
    load_config

    # 3. Re-apply CLI overrides after config load
    parse_args "$@"

    # 4. Initialize logging
    if [[ "${STEALTH_MODE}" != "1" ]]; then
        logger_init "${ROOTSCOPE_BASE}/${OUTPUT_DIR}/raw" "${LOG_FILE}"
    else
        ROOTSCOPE_LOG_FILE="/dev/null"
    fi
    set_log_level "${LOG_LEVEL}"

    # 5. Initialize exploit DB paths
    _init_exploit_db_paths

    # 6. Show banner
    [[ "${QUIET}" != "1" ]] && show_banner

    # 7. Log scan parameters
    log_info "main" "RootScope v${ROOTSCOPE_VERSION} starting"
    log_info "main" "Modules: ${ENABLED_MODULES} | Jobs: ${PARALLEL_JOBS} | Stealth: ${STEALTH_MODE}"

    # 8. Create output directories
    if [[ "${STEALTH_MODE}" != "1" ]]; then
        mkdir -p "${ROOTSCOPE_BASE}/${OUTPUT_DIR}"/{raw,parsed,reports} 2>/dev/null
    fi

    # 9. Load plugins (stealth first if enabled)
    load_plugins

    # 10. Resolve and execute modules
    local modules
    modules=$(resolve_modules)
    log_info "main" "Modules to run: ${modules}"

    local scan_start
    scan_start=$(date +%s)

    if (( PARALLEL_JOBS > 0 )); then
        # Parallel execution
        print_dim "  Running modules in parallel (${PARALLEL_JOBS} workers)..."
        local -a mod_funcs=()
        for mod in ${modules}; do
            mod_funcs+=("run_module_wrapper_${mod}")
            # Create wrapper functions for parallel execution
            eval "run_module_wrapper_${mod}() { run_module '${mod}'; }"
        done
        run_parallel "${PARALLEL_JOBS}" "${mod_funcs[@]}"
    else
        # Sequential execution
        print_dim "  Running modules sequentially..."
        for mod in ${modules}; do
            run_module "${mod}"
        done
    fi

    local scan_elapsed=$(( $(date +%s) - scan_start ))

    # 11. Generate risk summary
    [[ "${QUIET}" != "1" ]] && generate_risk_summary

    # 12. Generate reports
    if [[ "${STEALTH_MODE}" != "1" ]]; then
        print_dim "  Generating reports..."
        generate_all_reports
    else
        print_info "Stealth mode — reports written to stdout only"
    fi

    # 13. Final summary
    echo ""
    print_success "Scan completed in ${scan_elapsed} seconds"
    print_success "Total findings: $(get_total_findings)"
    if [[ "${STEALTH_MODE}" != "1" ]]; then
        print_success "Reports: ${ROOTSCOPE_BASE}/${OUTPUT_DIR}/reports/"
    fi
    echo ""

    log_info "main" "Scan complete — ${scan_elapsed}s, $(get_total_findings) findings"
}

main "$@"
