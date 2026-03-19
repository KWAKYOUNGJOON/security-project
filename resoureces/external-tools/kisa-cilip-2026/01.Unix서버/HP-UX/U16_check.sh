#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-16
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : /etc/passwd 파일 소유자 및 권한 설정
# @Description : root:root 644 확인
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


ITEM_ID="U-16"
ITEM_NAME="/etc/passwd 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="/etc/passwd 파일을 관리자만 제어할 수 있게 하여 비인가자의 임의적인 파일 변조 방지"
GUIDELINE_THREAT="/etc/passwd 파일의 소유권 및 권한 설정이 미흡할 경우 비인가자가 계정 정보 변경 등을 통해 시스템 침입 위험"
GUIDELINE_CRITERIA_GOOD="/etc/passwd 파일 소유자가 root이고 권한이 644 이하인 경우"
GUIDELINE_CRITERIA_BAD=" 소유자가 root가 아니거나 권한이 645 이상인 경우"
GUIDELINE_REMEDIATION="chown root:root /etc/passwd && chmod 644 /etc/passwd 실행"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {


    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직 구현
    # /etc/passwd 파일 소유자 및 권한 설정 확인 (644, root:root)

    local target_file="/etc/passwd"
    local is_secure=false
    local details=""

    # Capture raw ls -l output
    local ls_output=$(ls -l "$target_file" 2>/dev/null)
    local stat_output=$(perl -e '@s=stat(shift); printf "%04o %s:%s\n", $s[2] & 07777, getpwuid($s[4]), getgrgid($s[5])' "$target_file" 2>/dev/null)

    # 파일 존재 확인
    if [ ! -f "$target_file" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/etc/passwd 파일 없음"
        command_result="[Command: ls -l $target_file]${newline}${ls_output}"
        command_executed="ls -l $target_file"
    else
        # 파일 권한 확인 (HP-UX compatible)
        # HP-UX: stat -c format not supported, use ls -l parsing
        local file_info=$(ls -l "$target_file" 2>/dev/null)
        local file_perms=$(echo "$file_info" | awk '{print substr($1, 1, 10)}' | sed 's/-//g' | /usr/bin/tr 'XdTt' '---' | /usr/bin/tr 'rwx' '742' | /usr/bin/tr 'r-' '4-' | /usr/bin/tr '-w' '-2' | /usr/bin/tr '--x' '--1' | /usr/bin/tr 'x' '1')
        # Alternative: use octal directly from ls
        local perms_octal=$(perl -e '@s=stat(shift); printf "%04o\n", $s[2] & 07777' "$target_file" 2>/dev/null)
        local file_owner=$(perl -e '($dev,$ino,$mode,$nlink,$uid,$gid)=stat(shift); print getpwuid($uid).":".getgrgid($gid)' "$target_file" 2>/dev/null)

        # 소유자 및 권한 확인
        if [ "$file_owner" = "root:root" ] && [ "$perms_octal" = "0644" ]; then
            is_secure=true
            details="권한: $perms_octal, 소유자: $file_owner"
        else
            details="권한: $perms_octal, 소유자: $file_owner"
        fi

        # 최종 판정
        if [ "$is_secure" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="/etc/passwd 보안 설정 적절 ($details)"
            command_result="[Command: ls -l $target_file]${newline}${ls_output}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2]&07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file]${newline}${stat_output}"
            command_executed="ls -l $target_file; perl -e 'printf \"%04o %s:%s\\n\", (stat(shift))[2]&07777, getpwuid((stat(shift))[4]), getgrgid((stat(shift))[5])' $target_file"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="/etc/passwd 보안 설정 부적절 ($details)"
            command_result="[Command: ls -l $target_file]${newline}${ls_output}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2]&07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file]${newline}${stat_output}"
            command_executed="ls -l $target_file; perl -e 'printf \"%04o %s:%s\\n\", (stat(shift))[2]&07777, getpwuid((stat(shift))[4]), getgrgid((stat(shift))[5])' $target_file"
        fi
    fi

    # echo ""
    # echo "진단 결과: ${status}"
    # echo "판정: ${diagnosis_result}"
    # echo "설명: ${inspection_summary}"
    # echo ""

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
    # Run-all 모드 확인
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

    # 결과 저장 확인
    verify_result_saved "${ITEM_ID}"


    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
