#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-29
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (하)
# @Title       : hosts.lpd 파일 소유자 및 권한 설정
# @Description : /etc/hosts.lpd 파일의 소유자 및 권한 설정이 적절한지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-29"
ITEM_NAME="hosts.lpd 파일 소유자 및 권한 설정"
SEVERITY="(하)"

# 가이드라인 정보 (제시된 리스트 기준 반영)
GUIDELINE_PURPOSE="프린터 서비스 접근 제어 파일을 보호하여 비인가자의 무단 프린트 이용을 방지하기 위함"
GUIDELINE_THREAT="권한 설정이 부적절할 경우, 비인가자가 파일을 변조하여 허용되지 않은 호스트에서 프린터 서비스를 이용할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/hosts.lpd 파일의 소유자가 root이고 권한이 600 이하인 경우"
GUIDELINE_CRITERIA_BAD="소유자가 root가 아니거나 권한이 600을 초과하는 경우"
GUIDELINE_REMEDIATION="소유자를 root로 변경하고 권한을 600으로 설정 (chmod 600 /etc/hosts.lpd)"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="/etc/hosts.lpd 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/hosts.lpd"

    # 1. 실제 데이터 추출
    local file_path="/etc/hosts.lpd"
    if [ -f "$file_path" ]; then
        local owner=$(stat -c "%U" "$file_path")
        local perm=$(stat -c "%a" "$file_path")
        local ls_out=$(ls -l "$file_path")

        # 2. 판정 로직
        if [ "$owner" != "root" ] || [ "$perm" -gt 600 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="/etc/hosts.lpd 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        command_result="/etc/hosts.lpd 파일이 존재하지 않습니다."
    fi

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
