#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-60
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : SNMP 서비스 Community String 복잡성 설정
# @Description : 기본 Community String(public, private) 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-60"
ITEM_NAME="SNMP 서비스 Community String 복잡성 설정"
SEVERITY="(중)"

GUIDELINE_PURPOSE="추측하기 쉬운 SNMP Community String을 변경하여 비인가자의 정보 수집을 차단하기 위함"
GUIDELINE_THREAT="public, private 등 기본 문자열을 사용할 경우 외부 공격자가 시스템 정보를 무단으로 획득하거나 설정을 변경할 수 있음"
GUIDELINE_CRITERIA_GOOD="Community String이 유추하기 어려운 복잡한 문자열로 변경된 경우"
GUIDELINE_CRITERIA_BAD="public, private 등 기본 Community String을 사용 중인 경우"
GUIDELINE_REMEDIATION="snmpd.conf에서 community 문자열을 복잡하게 변경"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="기본 Community String이 발견되지 않았습니다."
    local command_result=""
    local command_executed="grep -Ei 'public|private' /etc/snmp/snmpd.conf"

    if [ -f "/etc/snmp/snmpd.conf" ]; then
        local default_strings=$(grep -Ei "public|private" /etc/snmp/snmpd.conf | grep -v "^#" | xargs || echo "")
        if [ -n "$default_strings" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="추측하기 쉬운 기본 Community String(public/private)이 사용 중입니다."
            command_result="발견된 설정: [ ${default_strings} ]"
        fi
    fi
    command_result=$(echo "${command_result:-설정 안전함}" | tr -d '\n\r')

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
