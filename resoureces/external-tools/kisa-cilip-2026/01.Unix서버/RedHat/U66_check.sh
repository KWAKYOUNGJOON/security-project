#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-66
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : SNMP 서비스 실행 권한 제한
# @Description : SNMP 서비스가 root 권한으로 실행되는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-66"
ITEM_NAME="SNMP 서비스 실행 권한 제한"
SEVERITY="(중)"

GUIDELINE_PURPOSE="SNMP 서비스를 최소 권한(일반 사용자)으로 실행하여 서비스 취약점 공격 시 시스템 전체 권한 탈취를 방지하기 위함"
GUIDELINE_THREAT="SNMP 서비스가 root 권한으로 실행될 경우, SNMP 취약점을 통해 공격자가 시스템 최고 권한을 획득할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스가 root가 아닌 일반 사용자 권한으로 실행 중인 경우"
GUIDELINE_CRITERIA_BAD="SNMP 서비스가 root 권한으로 실행 중인 경우"
GUIDELINE_REMEDIATION="SNMP 실행 옵션에 일반 사용자 계정 지정 (예: snmpd -u snmp)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="SNMP 서비스 실행 권한이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep snmpd"

    local snmp_ps=$(ps -ef | grep "snmpd" | grep -v grep || echo "")
    if [ -n "$snmp_ps" ]; then
        local snmp_user=$(echo "$snmp_ps" | awk '{print $1}')
        if [ "$snmp_user" = "root" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="SNMP 서비스가 root 권한으로 실행 중입니다."
        fi
        command_result="SNMP 실행 계정: [ ${snmp_user} ]"
    else
        command_result="SNMP 서비스가 실행 중이지 않습니다."
    fi
    command_result=$(echo "$command_result" | tr -d '\n\r')

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}
main "$@"
