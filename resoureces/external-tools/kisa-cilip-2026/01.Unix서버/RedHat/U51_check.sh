#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-51
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : DNS 서비스의 취약한 동적 업데이트 설정 금지
# @Description : 인가되지 않은 사용자의 DNS 동적 업데이트(Dynamic Update) 허용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-51"
ITEM_NAME="DNS 서비스의 취약한 동적 업데이트 설정 금지"
SEVERITY="(상)"

GUIDELINE_PURPOSE="인가되지 않은 사용자의 동적 업데이트를 금지하여 임의의 레코드 수정을 방지하고 DNS 데이터의 무결성을 유지하기 위함"
GUIDELINE_THREAT="동적 업데이트가 제한되지 않은 경우 공격자가 임의의 DNS 레코드를 등록/수정하여 파밍 공격이나 트래픽 우회 공격을 시도할 수 있음"
GUIDELINE_CRITERIA_GOOD="DNS 동적 업데이트가 제한되어 있거나 특정 호스트에 대해서만 안전하게 허용된 경우"
GUIDELINE_CRITERIA_BAD="DNS 동적 업데이트가 모든 호스트(any)에 대해 허용되어 있는 경우"
GUIDELINE_REMEDIATION="named.conf 파일의 zone 섹션에서 allow-update { none; }; 또는 특정 호스트 설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="DNS 동적 업데이트 설정이 적절하게 제한되어 있습니다."
    local command_result=""
    local command_executed="grep 'allow-update' /etc/named.conf"

    if [ -f "/etc/named.conf" ]; then
        local update_opt=$(grep -i "allow-update" /etc/named.conf | tr -d '[:space:]' || echo "not-set")
        if [[ "$update_opt" =~ "any" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="DNS 동적 업데이트가 모든 호스트(any)에 대해 허용되어 있습니다."
        fi
        command_result="allow-update 설정 현황: [ ${update_opt} ]"
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
