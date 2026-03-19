#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-18
# ============================================================================
# [점검 항목 상세]
# @ID          : U-06
# @Category    : Unix Server
# @Platform    : Solaris
# @Severity    : 상
# @Title       : 사용자 계정 su 기능 제한
# @Description : su 명령어를 특정 그룹에 속한 사용자만 사용할 수 있도록 제한되어 있는지 점검
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

ITEM_ID="U-06"
ITEM_NAME="사용자 계정 su 기능 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="su 관련 그룹만 su 명령어 사용 권한이 부여되어 있는지 점검하여 su 그룹에 포함되지 않은 일반 사용자의 su 명령 사용을 원천적으로 차단하는지 확인하기 위함"
GUIDELINE_THREAT="무분별한 사용자 변경으로 타 사용자 소유의 파일을 변경할 수 있으며 root 계정으로 변경하는 경우 관리자 권한을 획득할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한된 경우"
GUIDELINE_CRITERIA_BAD="su 명령어를 모든 사용자가 사용하도록 설정된 경우"
GUIDELINE_REMEDIATION="PAM 모듈 설정 또는 su 명령어 허용 그룹 생성 후 su 명령어 일반 사용자 권한 제거하도록 설정"

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
    # Solaris: su 명령어의 권한과 그룹 설정 확인 (wheel 그룹, 4750 권한)
    
    local su_bin="/usr/bin/su"
    if [ ! -f "$su_bin" ]; then su_bin="/bin/su"; fi

    local is_secure=false
    local check_type=""
    local wheel_group_output=""
    local su_perm_output=""
    local details=""

    # 1. Wheel Group Check
    if grep -q "^wheel:" /etc/group; then
        wheel_group_output="[Group: wheel]${newline}$(grep "^wheel:" /etc/group)"
        details="wheel 그룹 존재함"
    else
        wheel_group_output="[Group: wheel]${newline}Group not found"
        details="wheel 그룹 없음"
    fi

    # 2. File Permission Assessment (Primary for AIX/HP-UX/Solaris per guide)
    # Check if others permission is 0 (e.g., -rwsr-x---)
    
    if [ -f "$su_bin" ]; then
        local su_ls=$(ls -ld "$su_bin")
        su_perm_output="[File: $su_bin]${newline}${su_ls}"

        # Parse permissions from ls -ld output (e.g. -rwsr-x---)
        local perms=$(echo "$su_ls" | awk '{print $1}')
        # Check last 3 characters (others permissions)
        local others_perm="${perms:7:3}"

        if [[ "$others_perm" == "---" ]]; then
             is_secure=true
             check_type="File Permission"
             details="${details}, su 명령어 실행 권한 제한됨 (Others: ---)"
        else
             is_secure=false
             details="${details}, su 명령어 실행 권한이 일반 사용자에게 허용됨 (Others: ${others_perm})"
        fi
    else
        su_perm_output="[File: $su_bin]${newline}File not found"
        details="${details}, su 실행 파일 찾을 수 없음"
    fi

    # Construct Raw Output
    command_result="${su_perm_output}${newline}${newline}${wheel_group_output}"
    command_executed="ls -ld $su_bin; grep ^wheel: /etc/group"

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="su 명령어가 특정 그룹만 사용 가능하도록 제한됨 ($check_type)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="su 명령어 사용 제한(파일 권한)이 설정되지 않음"
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
