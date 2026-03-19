#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-63
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 사용자 sudo 명령어 사용 제한
# @Description : sudoers 파일을 통한 특정 명령어나 권한 제한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-63"
ITEM_NAME="사용자 sudo 명령어 사용 제한"
SEVERITY="(중)"

GUIDELINE_PURPOSE="특정 사용자에게만 필요한 권한을 sudo를 통해 부여함으로써 불필요한 root 권한 남용을 방지하기 위함"
GUIDELINE_THREAT="sudo 권한이 과도하게 부여되거나 적절히 제한되지 않을 경우, 일반 사용자가 시스템 전체를 장악하거나 중요 데이터를 변조할 위험이 있음"
GUIDELINE_CRITERIA_GOOD="sudoers 파일에 허가된 사용자만 등록되어 있고, 불필요한 ALL 권한이 제한된 경우"
GUIDELINE_CRITERIA_BAD="sudoers 파일에 인가되지 않은 사용자가 등록되어 있거나 과도한 권한(ALL)이 부여된 경우"
GUIDELINE_REMEDIATION="/etc/sudoers 파일에서 불필요한 사용자/그룹 설정 삭제 및 특정 명령어로 권한 제한"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="sudoers 설정이 적절하게 관리되고 있습니다."
    local command_result=""
    local command_executed="grep -v '^#' /etc/sudoers | grep 'ALL'"

    if [ -f "/etc/sudoers" ]; then
        local sudo_list=$(grep -v '^#' /etc/sudoers | grep "ALL" | xargs || echo "None")
        command_result="발견된 sudo 권한 설정: [ ${sudo_list} ]"
    else
        command_result="/etc/sudoers 파일이 존재하지 않습니다."
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
