#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-05
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : root 이외의 UID가 ‘0’ 금지
# @Description : root 계정 외에 UID 0을 사용하는 계정 존재 여부 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-05"
ITEM_NAME="root 이외의 UID가 ‘0’ 금지"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="root 계정과 동일한 UID가 존재하는지 점검하여 root 권한이 비인가자의 접근 위협에 안전하게 보호되고 있는지 확인하기 위함"
GUIDELINE_THREAT="root계정과 동일한 UID가 설정된 일반 계정도 관리자가 실행할 수 있는 모든 작업이 가능하여 시스템 장악 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="root계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="root계정과 동일한 UID를 갖는 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="UID가 0인 계정을 확인하여 0 이외의 중복되지 않은 UID로 변경하거나 제거"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="UID 0인 계정이 root만 존재합니다."
    local command_result=""
    local command_executed="awk -F: '\$3 == 0 {print \$1}' /etc/passwd"

    # 1. 실제 데이터 추출: UID 0 계정 리스트
    local uid_zero_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | xargs | sed 's/ /, /g')
    local user_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | wc -l)

    # 2. 판정 로직
    if [ "$user_count" -gt 1 ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="root 이외에 UID 0을 사용하는 계정이 발견되었습니다."
    fi

    # 3. command_result에 실제 데이터 기록
    command_result="UID 0 계정 목록: [ ${uid_zero_users} ] (총 ${user_count}개)"

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
