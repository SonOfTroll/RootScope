#!/usr/bin/env bash
# ============================================================================
# RootScope — engine/risk_engine.sh
# Risk scoring engine — calculates severity scores, classifies findings,
# aggregates results, and produces a risk summary.
# ============================================================================

[[ -n "${_ROOTSCOPE_RISK_ENGINE_LOADED:-}" ]] && return 0
readonly _ROOTSCOPE_RISK_ENGINE_LOADED=1

# ---------------------------------------------------------------------------
# Severity → numeric weight mapping (uses config values)
# ---------------------------------------------------------------------------
_severity_to_weight() {
    local sev="${1^^}"
    case "${sev}" in
        CRITICAL) echo "${WEIGHT_CRITICAL:-100}" ;;
        HIGH)     echo "${WEIGHT_HIGH:-75}" ;;
        MEDIUM)   echo "${WEIGHT_MEDIUM:-40}" ;;
        LOW)      echo "${WEIGHT_LOW:-15}" ;;
        INFO)     echo "${WEIGHT_INFO:-5}" ;;
        *)        echo "0" ;;
    esac
}

# ---------------------------------------------------------------------------
# Get per-check weight multiplier
# Usage: _check_multiplier "CHECK_ID"
# ---------------------------------------------------------------------------
_check_multiplier() {
    local check_id="${1^^}"
    local var_name="CHECK_WEIGHT_${check_id}"
    local multiplier="${!var_name:-1.0}"
    echo "${multiplier}"
}

# ---------------------------------------------------------------------------
# Calculate risk score for a single finding
# Usage: calculate_risk_score "SEVERITY" "CHECK_ID"
# Returns: integer score
# ---------------------------------------------------------------------------
calculate_risk_score() {
    local severity="${1}" check_id="${2:-GENERIC}"
    local base_weight multiplier

    base_weight=$(_severity_to_weight "${severity}")
    multiplier=$(_check_multiplier "${check_id}")

    # Bash doesn't support floats natively — use awk for multiplication
    awk "BEGIN { printf \"%d\", ${base_weight} * ${multiplier} }"
}

# ---------------------------------------------------------------------------
# Classify aggregate score into overall risk level
# Usage: classify_severity <total_score>
# Returns: severity string
# ---------------------------------------------------------------------------
classify_severity() {
    local score="${1}"

    if (( score >= ${THRESHOLD_CRITICAL:-500} )); then
        echo "CRITICAL"
    elif (( score >= ${THRESHOLD_HIGH:-300} )); then
        echo "HIGH"
    elif (( score >= ${THRESHOLD_MEDIUM:-150} )); then
        echo "MEDIUM"
    elif (( score >= ${THRESHOLD_LOW:-50} )); then
        echo "LOW"
    else
        echo "INFO"
    fi
}

# ---------------------------------------------------------------------------
# Aggregate finding counter (global arrays)
# ---------------------------------------------------------------------------
declare -gA RISK_FINDING_COUNTS=()
declare -g  RISK_TOTAL_SCORE=0

# Record a finding in the risk engine
# Usage: risk_record_finding "SEVERITY" "CHECK_ID"
risk_record_finding() {
    local sev="${1^^}" check_id="${2:-GENERIC}"
    local score

    score=$(calculate_risk_score "${sev}" "${check_id}")
    RISK_TOTAL_SCORE=$(( RISK_TOTAL_SCORE + score ))
    RISK_FINDING_COUNTS["${sev}"]=$(( ${RISK_FINDING_COUNTS["${sev}"]:-0} + 1 ))
}

# ---------------------------------------------------------------------------
# Generate risk summary (human-readable)
# ---------------------------------------------------------------------------
generate_risk_summary() {
    local overall_rating
    overall_rating=$(classify_severity "${RISK_TOTAL_SCORE}")

    echo ""
    print_section "RISK ASSESSMENT SUMMARY"

    # Overall risk rating with color
    case "${overall_rating}" in
        CRITICAL) print_critical "Overall Risk Rating: CRITICAL (Score: ${RISK_TOTAL_SCORE})" ;;
        HIGH)     print_high     "Overall Risk Rating: HIGH (Score: ${RISK_TOTAL_SCORE})" ;;
        MEDIUM)   print_medium   "Overall Risk Rating: MEDIUM (Score: ${RISK_TOTAL_SCORE})" ;;
        LOW)      print_low      "Overall Risk Rating: LOW (Score: ${RISK_TOTAL_SCORE})" ;;
        *)        print_info     "Overall Risk Rating: INFO (Score: ${RISK_TOTAL_SCORE})" ;;
    esac

    echo ""
    echo "  Findings by Severity:"
    echo "  ──────────────────────"

    local sev count
    for sev in CRITICAL HIGH MEDIUM LOW INFO; do
        count="${RISK_FINDING_COUNTS["${sev}"]:-0}"
        if (( count > 0 )); then
            printf "    %-10s : %d finding(s)\n" "${sev}" "${count}"
        fi
    done

    local total=0
    for count in "${RISK_FINDING_COUNTS[@]}"; do
        (( total += count ))
    done
    echo "  ──────────────────────"
    printf "    %-10s : %d\n" "TOTAL" "${total}"
    echo ""
}

# ---------------------------------------------------------------------------
# Get risk data as pipe-delimited string (for report generators)
# ---------------------------------------------------------------------------
get_risk_data() {
    local overall
    overall=$(classify_severity "${RISK_TOTAL_SCORE}")
    echo "RISK_SUMMARY|${overall}|${RISK_TOTAL_SCORE}|${RISK_FINDING_COUNTS[CRITICAL]:-0}|${RISK_FINDING_COUNTS[HIGH]:-0}|${RISK_FINDING_COUNTS[MEDIUM]:-0}|${RISK_FINDING_COUNTS[LOW]:-0}|${RISK_FINDING_COUNTS[INFO]:-0}"
}

# ---------------------------------------------------------------------------
# Reset risk engine state (for testing or re-runs)
# ---------------------------------------------------------------------------
risk_engine_reset() {
    RISK_TOTAL_SCORE=0
    RISK_FINDING_COUNTS=()
}
