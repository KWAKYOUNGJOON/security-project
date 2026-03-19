#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-64
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : r-command 서비스 비활성화
# @Description : rlogin, rsh, rexec 등 취약한 r-command 서비스 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-64"
ITEM_NAME="r-command 서비스 비활성화"
SEVERITY="(상)"

GUIDELINE_PURPOSE="인증 과정 없이 원격 접속이 가능한 취약한 r-command 서비스를 비활성화하여 비인가 접근을 차단하기 위함"
GUIDELINE_THREAT="r-command는 패스워드 없이 접속이 가능하며 데이터가 암호화되지 않아 스니핑 및 비인가 접속에 매우 취약함"
GUIDELINE_CRITERIA_GOOD="rlogin, rsh, rexec 서비스가 비활성화되어 있거나 설치되지 않은 경우"
GUIDELINE_CRITERIA_BAD="rlogin, rsh, rexec 서비스 중 하나라도 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="관련 서비스 중단 및 xinetd 설정에서 disable = yes 적용"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="취약한 r-command 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ls -l /etc/xinetd.d/r*"

    local r_services=$(ls /etc/xinetd.d/rlogin /etc/xinetd.d/rsh /etc/xinetd.d/rexec 2>/dev/null || echo "")
    if [ -n "$r_services" ]; then
        local active_r=$(grep -i "disable" $r_services | grep "no" || echo "")
        if [ -n "$active_r" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="r-command 서비스가 xinetd에서 활성화되어 있습니다."
            command_result="활성화된 서비스: [ $(echo $active_r | xargs) ]"
        fi
    fi
    command_result=$(echo "${command_result:-r-command 미발견}" | tr -d '\n\r')

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
