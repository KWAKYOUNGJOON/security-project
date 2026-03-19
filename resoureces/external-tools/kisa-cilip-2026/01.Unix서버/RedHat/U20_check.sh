#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-20
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : /etc/shadow 파일 소유자 및 권한 설정
# @Description : /etc/shadow 파일의 소유자 및 권한 설정이 적절한지 점검
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

ITEM_ID="U-20"
ITEM_NAME="/etc/shadow 파일 소유자 및 권한 설정"
SEVERITY="(상)"

# 가이드라인 정보 (PDF 49페이지 내용 반영)
GUIDELINE_PURPOSE="/etc/shadow 파일의 암호화된 비밀번호 정보를 보호하여 비인가자가 비밀번호 해시값을 획득하는 것을 방지하기 위함"
GUIDELINE_THREAT="/etc/shadow 파일의 권한 설정이 부적절할 경우, 비인가자가 비밀번호 해시값을 획득하여 오프라인 사전 공격 등을 통해 비밀번호를 복호화할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="/etc/shadow 파일의 소유자가 root이고, 권한이 400 이하인 경우"
GUIDELINE_CRITERIA_BAD="/etc/shadow 파일의 소유자가 root가 아니거나, 권한이 400 이하가 아닌 경우"
GUIDELINE_REMEDIATION="/etc/shadow 파일의 소유자를 root로 변경하고, 권한을 400으로 설정"

diagnose() {
    # 파싱 안정성을 위한 초기값 설정
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="/etc/shadow 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/shadow"

    # 1. 실제 데이터 추출
    local file_path="/etc/shadow"
    if [ -f "$file_path" ]; then
        local owner_name=$(stat -c "%U" "$file_path")
        local file_perm=$(stat -c "%a" "$file_path")
        local ls_out=$(ls -l "$file_path")

        # 2. 판정 로직: 소유자 root 및 권한 400 이하 체크
        # 권한이 400보다 크면(예: 600, 640 등) 취약으로 판정
        if [ "$owner_name" != "root" ] || [ "$file_perm" -gt 400 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="/etc/shadow 파일의 소유자가 root가 아니거나 권한 설정(400)이 부적절합니다."
        fi

        # 3. 결과 기록 (JSON 보호를 위한 개행 및 특수문자 처리)
        command_result="소유자: ${owner_name}, 권한: ${file_perm}, 상세: ${ls_out}"
        command_result=$(echo "$command_result" | tr -d '\n\r' | sed 's/"/ /g')
    else
        status="N/A"
        diagnosis_result="ERROR"
        inspection_summary="/etc/shadow 파일을 찾을 수 없습니다."
        command_result="파일 없음"
    fi

    # U-02와 동일한 12개 인자 전달 방식 유지
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
