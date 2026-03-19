#!/bin/bash
# ============================================================================
# @ID          : U-25
# @Title       : world writable 파일 점검
# ============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"

ITEM_ID="U-25"; ITEM_NAME="world writable 파일 점검"; SEVERITY="(상)"
GUIDELINE_PURPOSE="world writable 파일을 이용한 시스템 접근 및 악의적인 코드 실행을 방지하기 위함"
GUIDELINE_THREAT="중요 파일에 world writable이 적용될 경우, 일반 사용자 및 비인가자가 파일을 임의로 수정하여 시스템 변조 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="world writable 파일이 존재하지 않거나, 존재 시 설정 이유를 인지하고 있는 경우"
GUIDELINE_CRITERIA_BAD="world writable 파일이 존재하나 설정 이유를 인지하지 못하고 있는 경우"
GUIDELINE_REMEDIATION="불필요한 world writable 파일 제거 또는 권한 변경 (chmod o-w <file>)"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local command_result=""; local command_executed="find / -type f -perm -2 -xdev"

    # 시스템 내 world writable 파일 탐색 (최대 5개)
    local ww_files=$(find / -type f -perm -2 -xdev 2>/dev/null | head -n 5 | xargs)

    if [ -n "$ww_files" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        command_result="발견된 World Writable 파일(일부): [ $ww_files ]"
    else
        command_result="World Writable 파일 없음"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "점검 완료" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
