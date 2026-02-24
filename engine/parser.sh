#!/usr/bin/env bash
# ============================================================================
# RootScope — engine/parser.sh
# Output parser and report generator.
# Normalizes raw module output into structured records and produces
# text, JSON, and HTML reports.
# ============================================================================

[[ -n "${_ROOTSCOPE_PARSER_LOADED:-}" ]] && return 0
readonly _ROOTSCOPE_PARSER_LOADED=1

# ---------------------------------------------------------------------------
# Global findings storage (in-memory array for report generation)
# ---------------------------------------------------------------------------
declare -ga PARSED_FINDINGS=()

# ---------------------------------------------------------------------------
# Register a finding in the parsed findings array
# Usage: register_finding "SEVERITY" "module" "category" "detail" "hint"
# ---------------------------------------------------------------------------
register_finding() {
    local sev="${1}" module="${2}" cat="${3}" detail="${4}" hint="${5:-none}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    local record="FINDING|${timestamp}|${sev}|${module}|${cat}|${detail}|${hint}"
    PARSED_FINDINGS+=("${record}")

    # Also feed the risk engine
    risk_record_finding "${sev}" "${cat}"
}

# ---------------------------------------------------------------------------
# Write raw output to file
# ---------------------------------------------------------------------------
write_raw_output() {
    local module_name="${1}" content="${2}"
    local raw_dir="${ROOTSCOPE_BASE}/${OUTPUT_DIR}/raw"
    mkdir -p "${raw_dir}" 2>/dev/null
    echo "${content}" >> "${raw_dir}/${module_name}.raw" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Write parsed findings to file
# ---------------------------------------------------------------------------
write_parsed_output() {
    local parsed_dir="${ROOTSCOPE_BASE}/${OUTPUT_DIR}/parsed"
    mkdir -p "${parsed_dir}" 2>/dev/null

    local parsed_file="${parsed_dir}/findings.dat"
    printf '%s\n' "${PARSED_FINDINGS[@]}" > "${parsed_file}" 2>/dev/null
    log_info "parser" "Parsed findings written → ${parsed_file} (${#PARSED_FINDINGS[@]} records)"
}

# ---------------------------------------------------------------------------
# Generate text report
# ---------------------------------------------------------------------------
generate_text_report() {
    local report_dir="${ROOTSCOPE_BASE}/${OUTPUT_DIR}/reports"
    mkdir -p "${report_dir}" 2>/dev/null
    local report_file="${report_dir}/report.txt"

    {
        echo "================================================================"
        echo "  RootScope — Privilege Escalation Enumeration Report"
        echo "  Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "  Host: $(hostname) | User: $(whoami) | Kernel: $(uname -r)"
        echo "================================================================"
        echo ""

        # Risk summary
        local risk_data
        risk_data=$(get_risk_data)
        IFS='|' read -r _ overall score crit high med low info <<< "${risk_data}"
        echo "OVERALL RISK: ${overall} (Score: ${score})"
        echo "Findings: CRITICAL=${crit} HIGH=${high} MEDIUM=${med} LOW=${low} INFO=${info}"
        echo ""
        echo "----------------------------------------------------------------"

        # Group findings by module
        local current_module=""
        local sorted_findings
        sorted_findings=$(printf '%s\n' "${PARSED_FINDINGS[@]}" | sort -t'|' -k3,3r -k4,4)

        while IFS='|' read -r prefix ts sev module cat detail hint; do
            [[ "${prefix}" != "FINDING" ]] && continue

            # Filter by minimum severity
            if ! _meets_min_severity "${sev}"; then
                continue
            fi

            if [[ "${module}" != "${current_module}" ]]; then
                current_module="${module}"
                echo ""
                echo "━━━ MODULE: ${module^^} ━━━"
                echo ""
            fi

            printf "[%-8s] [%s] %s\n" "${sev}" "${cat}" "${detail}"
            [[ "${hint}" != "none" && -n "${hint}" ]] && echo "           ↳ ${hint}"
        done <<< "${sorted_findings}"

        echo ""
        echo "================================================================"
        echo "  End of Report"
        echo "================================================================"
    } > "${report_file}" 2>/dev/null

    log_info "parser" "Text report written → ${report_file}"
}

# ---------------------------------------------------------------------------
# Generate JSON report
# ---------------------------------------------------------------------------
generate_json_report() {
    local report_dir="${ROOTSCOPE_BASE}/${OUTPUT_DIR}/reports"
    mkdir -p "${report_dir}" 2>/dev/null
    local report_file="${report_dir}/report.json"

    local risk_data
    risk_data=$(get_risk_data)
    IFS='|' read -r _ overall score crit high med low info <<< "${risk_data}"

    {
        echo "{"
        echo "  \"report\": {"
        echo "    \"tool\": \"RootScope\","
        echo "    \"version\": \"1.0.0\","
        echo "    \"generated\": \"$(date -u '+%Y-%m-%dT%H:%M:%SZ')\","
        echo "    \"host\": \"$(hostname)\","
        echo "    \"user\": \"$(whoami)\","
        echo "    \"kernel\": \"$(uname -r)\","
        echo "    \"os\": \"$(get_os_family) $(get_os_version)\""
        echo "  },"
        echo "  \"risk_summary\": {"
        echo "    \"overall_rating\": \"${overall}\","
        echo "    \"total_score\": ${score},"
        echo "    \"critical\": ${crit},"
        echo "    \"high\": ${high},"
        echo "    \"medium\": ${med},"
        echo "    \"low\": ${low},"
        echo "    \"info\": ${info}"
        echo "  },"
        echo "  \"findings\": ["

        local first=true
        local finding
        for finding in "${PARSED_FINDINGS[@]}"; do
            IFS='|' read -r prefix ts sev module cat detail hint <<< "${finding}"
            [[ "${prefix}" != "FINDING" ]] && continue

            if ! _meets_min_severity "${sev}"; then
                continue
            fi

            # Escape JSON special characters in detail and hint
            detail=$(_json_escape "${detail}")
            hint=$(_json_escape "${hint}")

            if [[ "${first}" == "true" ]]; then
                first=false
            else
                echo ","
            fi

            printf '    {\n'
            printf '      "timestamp": "%s",\n' "${ts}"
            printf '      "severity": "%s",\n' "${sev}"
            printf '      "module": "%s",\n' "${module}"
            printf '      "category": "%s",\n' "${cat}"
            printf '      "detail": "%s",\n' "${detail}"
            printf '      "hint": "%s"\n' "${hint}"
            printf '    }'
        done

        echo ""
        echo "  ]"
        echo "}"
    } > "${report_file}" 2>/dev/null

    log_info "parser" "JSON report written → ${report_file}"
}

# ---------------------------------------------------------------------------
# Generate HTML dashboard report
# ---------------------------------------------------------------------------
generate_html_report() {
    local report_dir="${ROOTSCOPE_BASE}/${OUTPUT_DIR}/reports"
    mkdir -p "${report_dir}" 2>/dev/null
    local report_file="${report_dir}/report.html"

    local risk_data
    risk_data=$(get_risk_data)
    IFS='|' read -r _ overall score crit high med low info <<< "${risk_data}"

    # Determine overall color
    local overall_color
    case "${overall}" in
        CRITICAL) overall_color="#dc3545" ;;
        HIGH)     overall_color="#fd7e14" ;;
        MEDIUM)   overall_color="#ffc107" ;;
        LOW)      overall_color="#17a2b8" ;;
        *)        overall_color="#28a745" ;;
    esac

    {
        cat <<'HTML_HEADER'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RootScope — Privilege Escalation Report</title>
<style>
  :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --text: #c9d1d9; --text-muted: #8b949e; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  .header { text-align: center; margin-bottom: 2rem; padding: 2rem; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; }
  .header h1 { font-size: 2rem; color: #58a6ff; margin-bottom: 0.5rem; }
  .header .meta { color: var(--text-muted); font-size: 0.9rem; }
  .risk-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .risk-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; text-align: center; }
  .risk-card .count { font-size: 2.5rem; font-weight: 700; }
  .risk-card .label { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; margin-top: 0.5rem; }
  .overall-badge { display: inline-block; padding: 0.5rem 2rem; border-radius: 20px; font-size: 1.2rem; font-weight: 700; color: #fff; margin: 1rem 0; }
  .findings-table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
  .findings-table th { background: #21262d; padding: 0.75rem 1rem; text-align: left; font-size: 0.85rem; text-transform: uppercase; color: var(--text-muted); border-bottom: 1px solid var(--border); }
  .findings-table td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; vertical-align: top; }
  .findings-table tr:hover { background: #1c2129; }
  .sev-badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; color: #fff; }
  .sev-CRITICAL { background: #dc3545; } .sev-HIGH { background: #fd7e14; }
  .sev-MEDIUM { background: #ffc107; color: #000; } .sev-LOW { background: #17a2b8; }
  .sev-INFO { background: #6c757d; }
  .hint { color: var(--text-muted); font-size: 0.8rem; margin-top: 4px; font-style: italic; }
  .section-title { font-size: 1.3rem; margin: 2rem 0 1rem; color: #58a6ff; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
  .footer { text-align: center; color: var(--text-muted); font-size: 0.8rem; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); }
</style>
</head>
<body>
<div class="container">
HTML_HEADER

        # Header section
        echo "<div class=\"header\">"
        echo "  <h1>🔍 RootScope Report</h1>"
        echo "  <p class=\"meta\">Generated: $(date '+%Y-%m-%d %H:%M:%S %Z') | Host: $(hostname) | User: $(whoami) | Kernel: $(uname -r)</p>"
        echo "  <div class=\"overall-badge\" style=\"background: ${overall_color};\">${overall} RISK (Score: ${score})</div>"
        echo "</div>"

        # Risk cards
        echo "<div class=\"risk-cards\">"
        echo "  <div class=\"risk-card\"><div class=\"count\" style=\"color:#dc3545;\">${crit}</div><div class=\"label\">Critical</div></div>"
        echo "  <div class=\"risk-card\"><div class=\"count\" style=\"color:#fd7e14;\">${high}</div><div class=\"label\">High</div></div>"
        echo "  <div class=\"risk-card\"><div class=\"count\" style=\"color:#ffc107;\">${med}</div><div class=\"label\">Medium</div></div>"
        echo "  <div class=\"risk-card\"><div class=\"count\" style=\"color:#17a2b8;\">${low}</div><div class=\"label\">Low</div></div>"
        echo "  <div class=\"risk-card\"><div class=\"count\" style=\"color:#6c757d;\">${info}</div><div class=\"label\">Info</div></div>"
        echo "</div>"

        # Findings table
        echo "<h2 class=\"section-title\">Detailed Findings</h2>"
        echo "<table class=\"findings-table\">"
        echo "<thead><tr><th>Severity</th><th>Module</th><th>Category</th><th>Detail</th><th>Timestamp</th></tr></thead>"
        echo "<tbody>"

        # Sort findings: CRITICAL first
        local sorted_findings
        sorted_findings=$(printf '%s\n' "${PARSED_FINDINGS[@]}" | sort -t'|' -k3,3r)

        while IFS='|' read -r prefix ts sev module cat detail hint; do
            [[ "${prefix}" != "FINDING" ]] && continue
            _meets_min_severity "${sev}" || continue

            # HTML-escape the detail and hint
            detail=$(_html_escape "${detail}")
            hint=$(_html_escape "${hint}")

            echo "<tr>"
            echo "  <td><span class=\"sev-badge sev-${sev}\">${sev}</span></td>"
            echo "  <td>${module}</td>"
            echo "  <td>${cat}</td>"
            echo "  <td>${detail}"
            [[ "${hint}" != "none" && -n "${hint}" ]] && echo "    <div class=\"hint\">💡 ${hint}</div>"
            echo "  </td>"
            echo "  <td>${ts}</td>"
            echo "</tr>"
        done <<< "${sorted_findings}"

        echo "</tbody></table>"

        # Footer
        echo "<div class=\"footer\">RootScope v1.0.0 — Linux Privilege Escalation Enumeration Toolkit</div>"
        echo "</div></body></html>"
    } > "${report_file}" 2>/dev/null

    log_info "parser" "HTML report written → ${report_file}"
}

# ---------------------------------------------------------------------------
# Orchestrate all report generation
# ---------------------------------------------------------------------------
generate_all_reports() {
    local formats="${REPORT_FORMATS:-txt,json,html}"

    write_parsed_output

    if [[ "${formats}" == *"txt"* ]]; then
        generate_text_report
    fi
    if [[ "${formats}" == *"json"* ]]; then
        generate_json_report
    fi
    if [[ "${formats}" == *"html"* ]]; then
        generate_html_report
    fi

    print_success "Reports generated in ${ROOTSCOPE_BASE}/${OUTPUT_DIR}/reports/"
}

# ---------------------------------------------------------------------------
# Helper: Check if severity meets minimum threshold
# ---------------------------------------------------------------------------
_meets_min_severity() {
    local sev="${1}" min="${REPORT_MIN_SEVERITY:-INFO}"
    local -A sev_order=([CRITICAL]=5 [HIGH]=4 [MEDIUM]=3 [LOW]=2 [INFO]=1)
    (( ${sev_order[${sev}]:-0} >= ${sev_order[${min}]:-1} ))
}

# ---------------------------------------------------------------------------
# Helper: Escape strings for JSON output
# ---------------------------------------------------------------------------
_json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    echo "${str}"
}

# ---------------------------------------------------------------------------
# Helper: Escape strings for HTML output
# ---------------------------------------------------------------------------
_html_escape() {
    local str="$1"
    str="${str//&/&amp;}"
    str="${str//</&lt;}"
    str="${str//>/&gt;}"
    str="${str//\"/&quot;}"
    echo "${str}"
}
