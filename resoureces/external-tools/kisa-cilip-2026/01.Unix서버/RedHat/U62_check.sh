#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-62
# @Category    : UNIX > 6. 로그 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (하)
# @Title       : 로그인 시 경고 메시지 설정
# @Description : 서버 접속 시 법적 책임 및 경고 문구가 포함된 배너 출력 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-62"
ITEM_NAME="로그인 시 경고 메시지 설정"
SEVERITY="(하)"

GUIDELINE_PURPOSE="비인가자에게 시스템 사용의 위법성을 알리고 불법적인 접근 시도를 심리적으로 차단하기 위함"
GUIDELINE_THREAT="배너가 설정되지 않은 경우, 비인가자가 호기심이나 무지에 의한 불법 침입을 시도할 가능성이 높으며 법적 대응 시 불리할 수 있음"
GUIDELINE_CRITERIA_GOOD="motd 또는 issue.net 파일 등에 경고 메시지가 설정되어 있는 경우"
GUIDELINE_CRITERIA_BAD="접속 시 아무런 경고 메시지도 출력되지 않는 경우"
GUIDELINE_REMEDIATION="/etc/motd 또는 /etc/issue.net 파일에 경고 문구 삽입"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="로그인 경고 메시지가 적절하게 설정되어 있습니다."
    local command_result=""
    local command_executed="ls -l /etc/motd /etc/issue.net"

    local motd_content=$(cat /etc/motd 2>/dev/null | xargs || echo "")
    local issue_content=$(cat /etc/issue.net 2>/dev/null | xargs || echo "")

    if [ -z "$motd_content" ] && [ -z "$issue_content" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="서버 접속 시 출력되는 경고 메시지(배너)가 비어 있거나 설정되지 않았습니다."
    fi
    command_result=$(echo "motd: [ ${motd_content:-empty} ], issue.net: [ ${issue_content:-empty} ]" | tr -d '\n\r')

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
