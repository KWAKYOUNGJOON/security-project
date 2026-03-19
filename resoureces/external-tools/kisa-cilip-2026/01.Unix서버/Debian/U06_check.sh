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
# @Platform    : Debian
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
    # Debian: /etc/pam.d/su 파일 설정 확인 (pam_wheel.so)
    
    local pam_file="/etc/pam.d/su"
    local su_bin="/usr/bin/su" # or /bin/su
    if [ ! -f "$su_bin" ]; then su_bin="/bin/su"; fi

    local is_secure=false
    local check_type=""
    local pam_output=""
    local wheel_group_output=""
    local su_perm_output=""
    local details=""

    # 1. PAM 설정 확인 (Primary Check)
    if [ -f "$pam_file" ]; then
        pam_output=$(grep -vE '^#' "$pam_file" | grep "pam_wheel.so")
        
        if [ -n "$pam_output" ]; then
            if echo "$pam_output" | grep -qE "use_uid|group="; then
                is_secure=true
                check_type="PAM"
                details="pam_wheel.so 설정 확인됨"
            elif echo "$pam_output" | grep -q "trust"; then
                 check_type="PAM (Weak)"
                 details="pam_wheel.so trust 옵션 존재 (주의 필요)"
            else
                 is_secure=true
                 check_type="PAM"
                 details="pam_wheel.so 설정 확인됨"
            fi
        fi
    fi

    # 2. File Permission Assessment (Alternative or Secondary)
    local su_stat=$(ls -l "$su_bin")
    local su_perm=$(stat -c "%a" "$su_bin" 2>/dev/null || echo "000")
    local su_group=$(stat -c "%G" "$su_bin" 2>/dev/null || echo "unknown")
    
    su_perm_output="[File: $su_bin]${newline}${su_stat}"

    if [ "$is_secure" = false ]; then
        local others_perm=${su_perm: -1}
        
        if [ "$others_perm" -eq 0 ]; then
             is_secure=true
             check_type="File Permission"
             details="su 명령어 실행 권한이 일반 사용자에게 제한됨 (Others: 0)"
        fi
    fi
    
    # 3. Wheel Group Check
    if getent group wheel >/dev/null 2>&1; then
        wheel_group_output="[Group: wheel]${newline}$(getent group wheel)"
    else
        wheel_group_output="[Group: wheel]${newline}Group not found"
    fi

    # Construct Raw Output
    command_result="[File: $pam_file]${newline}$(grep "pam_wheel.so" "$pam_file" 2>/dev/null || echo "[pam_wheel.so not configured]")${newline}${newline}${su_perm_output}${newline}${newline}${wheel_group_output}"
    command_executed="grep pam_wheel.so $pam_file; ls -l $su_bin; getent group wheel"

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="su 명령어가 특정 그룹(wheel) 또는 권한 제어를 통해 제한되고 있음 ($check_type)"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="su 명령어 사용 제한(PAM pam_wheel.so 또는 파일 권한)이 설정되지 않음"
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
