#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-19
# ============================================================================
# [점검 항목 상세]
# @ID          : U-10
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : 동일한 UID 금지
# @Description : /etc/passwd 파일 내 UID가 동일한 사용자 계정 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-10"
ITEM_NAME="동일한 UID 금지"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="UID가 동일한 사용자 계정을 점검함으로써 타 사용자 계정 소유의 파일 및 디렉터리로의 악의적 접근 예방 및 침해사고 시 명확한 감사 추적을 하기 위함"
GUIDELINE_THREAT="중복된 UID가 존재할 경우, 시스템은 동일한 사용자로 인식하여 소유자의 권한이 중복되어 불필요한 권한이 부여되며 시스템 로그를 이용한 감사 추적 시 사용자가 구분되지 않는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="동일한 UID로 설정된 사용자 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="동일한 UID를 가진 사용자 계정의 UID를 중복되지 않도록 변경"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    local duplicate_output=""
    local has_duplicates=false
    local duplicates_summary=""

    # Find Duplicate UIDs using awk (Universal for /etc/passwd)
    local duplicate_lines
    duplicate_lines=$(awk -F: '
        NR==FNR {count[$3]++; next} 
        count[$3]>1 {print $0}
    ' /etc/passwd /etc/passwd 2>/dev/null)

    if [ -n "$duplicate_lines" ]; then
        has_duplicates=true
        duplicate_output="[Duplicate UID Accounts Found]${newline}${duplicate_lines}"
        
        local duplicate_uids
        duplicate_uids=$(echo "$duplicate_lines" | cut -d: -f3 | sort -u | tr '\n' ',' | sed 's/,$//')
        duplicates_summary="중복 UID 발견: ${duplicate_uids}"
    else
        duplicate_output="[Duplicate UID Check]${newline}No duplicate UIDs found."
    fi

    # Raw command result
    command_result="${duplicate_output}"
    command_executed="awk -F: '...' /etc/passwd"

    # 최종 판정
    if [ "$has_duplicates" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="동일한 UID를 사용하는 계정이 존재합니다. (${duplicates_summary})"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="동일한 UID를 사용하는 계정이 존재하지 않음"
    fi

    # 결과 저장
    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    return 0
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
