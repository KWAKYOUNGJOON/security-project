#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-19
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : /etc/hosts 파일 소유자 및 권한 설정
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


ITEM_ID="U-19"
ITEM_NAME="/etc/hosts 파일 소유자 및 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="/etc/hosts 파일을 관리자만 제어할 수 있게 하여 비인가자의 임의적인 파일 변조 방지"
GUIDELINE_THREAT="/etc/hosts 파일의 소유권 및 권한 설정이 미흡할 경우 비인가자가 호스트 정보를 변경하여 피싱 사이트 연결 등 악용 위험"
GUIDELINE_CRITERIA_GOOD="/etc/hosts 파일 소유자가 root이고 권한이 644 이하인 경우"
GUIDELINE_CRITERIA_BAD=" 소유자가 root가 아니거나 권한이 645 이상인 경우"
GUIDELINE_REMEDIATION="chown root:root /etc/hosts && chmod 644 /etc/hosts 실행"

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
    # /etc/hosts 파일 소유자 및 권한 설정 확인 (644, root:root)
    # AIX 추가: /etc/hosts.equiv 확인

    local target_file="/etc/hosts"
    local equiv_file="/etc/hosts.equiv"
    local is_secure=false
    local details=""
    local hosts_secure=true
    local equiv_secure=true
    local equiv_details=""

    # Capture command outputs
    local ls_hosts=$(ls -l "$target_file" 2>/dev/null)
    local stat_hosts=$(perl -e 'printf "%04o %s:%s\n", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' "$target_file" 2>/dev/null)

    # /etc/hosts 파일 확인
    if [ ! -f "$target_file" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="/etc/hosts 파일 없음"
        command_result="[Command: ls -l $target_file]${newline}${ls_hosts}"
        command_executed="ls -l $target_file"
    else
        # 파일 권한 확인 (AIX: ls -l 사용)
        local file_info=$(ls -l "$target_file" 2>/dev/null)
        local file_perms=$(perl -e 'printf "%04o", (stat)[2] & 07777' "$target_file" 2>/dev/null || echo "0000")
        local file_owner=$(echo "$file_info" | awk '{print $3}')

        # 소유자 및 권한 확인
        if [ "$file_owner" = "root" ] && [ "$file_perms" = "0644" ]; then
            hosts_secure=true
            details="/etc/hosts - 권한: $file_perms, 소유자: $file_owner"
        else
            hosts_secure=false
            details="/etc/hosts - 권한: $file_perms, 소유자: $file_owner"
        fi
    fi

    # /etc/hosts.equiv 파일 확인 (AIX 특이사항)
    local ls_equiv=""
    local stat_equiv=""
    if [ -f "$equiv_file" ]; then
        ls_equiv=$(ls -l "$equiv_file" 2>/dev/null)
        stat_equiv=$(perl -e 'printf "%04o %s:%s\n", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' "$equiv_file" 2>/dev/null)
        local equiv_info=$(ls -l "$equiv_file" 2>/dev/null)
        local equiv_perms=$(perl -e 'printf "%04o", (stat)[2] & 07777' "$equiv_file" 2>/dev/null || echo "0000")
        local equiv_owner=$(echo "$equiv_info" | awk '{print $3}')

        # hosts.equiv는 root 소유자이어야 하며 일반 사용자 쓰기 권한 없어야 함
        if [ "$equiv_owner" != "root" ] || [[ "$equiv_perms" =~ [0-9][0-9][2-9][0-9] ]]; then
            equiv_secure=false
            equiv_details=", /etc/hosts.equiv - 권한: $equiv_perms, 소유자: $equiv_owner"
        else
            equiv_details=", /etc/hosts.equiv - 양호 (권한: $equiv_perms, 소유자: $equiv_owner)"
        fi
    fi

    # 최종 판정
    if [ "$hosts_secure" = true ] && [ "$equiv_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="/etc/hosts 보안 설정 적절${equiv_details}"
        if [ -n "$ls_equiv" ]; then
            command_result="[Command: ls -l $target_file]${newline}${ls_hosts}${newline}${newline}[Command: ls -l $equiv_file]${newline}${ls_equiv}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file]${newline}${stat_hosts}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $equiv_file]${newline}${stat_equiv}"
        else
            command_result="[Command: ls -l $target_file]${newline}${ls_hosts}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file]${newline}${stat_hosts}"
        fi
        command_executed="ls -l $target_file ${equiv_file}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="/etc/hosts 보안 설정 부적절${equiv_details}"
        if [ -n "$ls_equiv" ]; then
            command_result="[Command: ls -l $target_file]${newline}${ls_hosts}${newline}${newline}[Command: ls -l $equiv_file]${newline}${ls_equiv}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file]${newline}${stat_hosts}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $equiv_file]${newline}${stat_equiv}"
        else
            command_result="[Command: ls -l $target_file]${newline}${ls_hosts}${newline}${newline}[Command: perl -e 'printf \"%04o %s:%s\", (stat)[2] & 07777, getpwuid((stat)[4]), getgrgid((stat)[5])' $target_file]${newline}${stat_hosts}"
        fi
        command_executed="ls -l $target_file ${equiv_file}"
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
