#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-61
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : SNMP 서비스 접근 제어 설정
# @Description : SNMP 서비스에 대한 호스트/IP 기반 접근 제어 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-61"
ITEM_NAME="SNMP 서비스 접근 제어 설정"
SEVERITY="(중)"

GUIDELINE_PURPOSE="허가되지 않은 호스트의 SNMP 접근을 차단하여 내부 정보 유출을 방지하기 위함"
GUIDELINE_THREAT="접근 제어가 설정되지 않은 경우 네트워크상의 모든 호스트가 시스템 자원 정보 및 모니터링 데이터에 접근할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스에 대해 특정 호스트/IP 대역으로 접근이 제한되어 있는 경우"
GUIDELINE_CRITERIA_BAD="모든 호스트에 대해 SNMP 접근이 허용되어 있는 경우"
GUIDELINE_REMEDIATION="snmpd.conf에서 com2sec 또는 sec.name 설정을 통해 특정 IP 대역만 허용"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="SNMP 접근 제어 설정이 적절하게 구성되어 있습니다."
    local command_result=""
    local command_executed="grep -Ei 'com2sec|sec.name' /etc/snmp/snmpd.conf"

    if [ -f "/etc/snmp/snmpd.conf" ]; then
        local access_check=$(grep -Ei "com2sec|sec.name" /etc/snmp/snmpd.conf | grep "default" | grep -v "^#" || echo "")
        if [ -n "$access_check" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="SNMP 서비스가 'default'(모든 호스트) 대역에 대해 허용되어 있습니다."
            command_result="취약한 설정: [ ${access_check} ]"
        fi
    fi
    command_result=$(echo "${command_result:-접근 제어 양호}" | tr -d '\n\r')

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
