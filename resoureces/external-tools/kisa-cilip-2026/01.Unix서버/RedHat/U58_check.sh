#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-58
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 홈 디렉토리로 지정되지 않은 계정 금지
# @Description : 홈 디렉토리가 존재하지 않거나 잘못 지정된 계정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-58"
ITEM_NAME="홈 디렉토리로 지정되지 않은 계정 금지"
SEVERITY="(중)"

GUIDELINE_PURPOSE="홈 디렉토리가 없는 불필요한 계정을 제거하여 공격자의 시스템 침투 경로를 차단하기 위함"
GUIDELINE_THREAT="홈 디렉토리가 적절히 관리되지 않는 계정은 관리의 사각지대에 놓여 악용될 가능성이 높음"
GUIDELINE_CRITERIA_GOOD="모든 계정에 대해 유효한 홈 디렉토리가 지정되어 있고 존재하는 경우"
GUIDELINE_CRITERIA_BAD="홈 디렉토리가 지정되지 않았거나 존재하지 않는 계정이 있는 경우"
GUIDELINE_REMEDIATION="불필요한 계정 삭제 또는 유효한 홈 디렉토리 생성 및 지정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="모든 계정의 홈 디렉토리 설정이 적절합니다."
    local command_result=""
    local command_executed="awk -F: '\$6 == \"\" || \$6 == \"/\"' /etc/passwd"

    local invalid_users=$(awk -F: '$6 == "" || $6 == "/" {print $1}' /etc/passwd | xargs || echo "")
    if [ -n "$invalid_users" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="홈 디렉토리가 비어있거나 루트(/)로 지정된 계정이 발견되었습니다."
        command_result="대상 계정: [ ${invalid_users} ]"
    else
        command_result="모든 계정에 유효한 홈 디렉토리 경로가 지정되어 있습니다."
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
