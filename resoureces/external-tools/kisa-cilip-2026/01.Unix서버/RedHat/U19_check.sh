#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-19
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
# @Description : /etc/hosts 파일의 소유자 및 권한 설정이 적절한지 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-19"
ITEM_NAME="/etc/hosts 파일 소유자 및 권한 설정"
SEVERITY="(상)"

# 가이드라인 정보 (PDF 44페이지 내용 반영)
GUIDELINE_PURPOSE="/etc/hosts 파일의 호스트 이름과 IP 주소 정보를 보호하여 비인가자가 호스트 정보를 변조하는 것을 방지하기 위함"
GUIDELINE_THREAT="/etc/hosts 파일의 권한 설정이 부적절할 경우, 비인가자가 IP 정보를 변조하여 파싱 공격이나 피싱 사이트로 유도하는 등 침해 사고의 원인이 될 수 있음"
GUIDELINE_CRITERIA_GOOD="/etc/hosts 파일의 소유자가 root이고, 권한이 600 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/hosts 파일의 소유자가 root가 아니거나, 권한이 600 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/hosts 파일의 소유자를 root로 변경하고, 권한을 600으로 설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="/etc/hosts 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/hosts"

    local file_path="/etc/hosts"
    if [ -f "$file_path" ]; then
        local owner_name=$(stat -c "%U" "$file_path")
        local file_perm=$(stat -c "%a" "$file_path")
        local ls_out=$(ls -l "$file_path")

        if [ "$owner_name" != "root" ] || [ "$file_perm" -gt 600 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="/etc/hosts 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        command_result="/etc/hosts 파일이 존재하지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && exit 1
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
}

main "$@"
