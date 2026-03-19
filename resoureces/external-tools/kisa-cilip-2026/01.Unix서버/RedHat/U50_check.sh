#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-50
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : DNS Zone Transfer 설정
# @Description : DNS 존 전송(Zone Transfer)을 제한하여 불필요한 영역 정보 노출을 방지하는지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-50"
ITEM_NAME="DNS Zone Transfer 설정"
SEVERITY="(상)"

GUIDELINE_PURPOSE="인가되지 않은 사용자의 존 전송 요청을 제한하여 내부 네트워크 및 서버 정보를 보호하기 위함"
GUIDELINE_THREAT="인가되지 않은 사용자에게 존 전송이 허용될 경우 내부 호스트 정보, IP 주소 등 네트워크 정보가 노출되어 공격의 기초 정보로 활용될 위험이 있음"
GUIDELINE_CRITERIA_GOOD="DNS 존 전송이 제한되어 있거나 특정 Secondary 서버에 대해서만 허용된 경우"
GUIDELINE_CRITERIA_BAD="DNS 존 전송이 모든 호스트(any)에 대해 허용되어 있는 경우"
GUIDELINE_REMEDIATION="named.conf 파일의 options 또는 zone 섹션에 allow-transfer { IP주소; }; 설정 추가"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="DNS 존 전송 설정이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="grep 'allow-transfer' /etc/named.conf"

    if [ -f "/etc/named.conf" ]; then
        local transfer_opt=$(grep -i "allow-transfer" /etc/named.conf | tr -d '[:space:]' || echo "not-set")
        if [[ "$transfer_opt" == "not-set" ]] || [[ "$transfer_opt" =~ "any" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="DNS 존 전송이 제한되지 않았거나 모든 호스트(any)에 허용되어 있습니다."
        fi
        command_result="allow-transfer 설정 현황: [ ${transfer_opt} ]"
    else
        command_result="DNS 설정 파일(/etc/named.conf)이 존재하지 않습니다."
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
