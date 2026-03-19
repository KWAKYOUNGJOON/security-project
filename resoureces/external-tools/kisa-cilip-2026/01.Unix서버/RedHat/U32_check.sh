#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-32
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : 계정 설정에 명시된 홈 디렉터리가 실제로 존재하는지 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-32"
ITEM_NAME="홈 디렉토리로 지정한 디렉토리의 존재 관리"
SEVERITY="(중)"

GUIDELINE_PURPOSE="실제 존재하지 않는 홈 디렉터리 설정을 정리하여 관리되지 않는 계정에 의한 보안 위협을 방지하기 위함"
GUIDELINE_THREAT="홈 디렉터리가 존재하지 않는 계정은 임시 파일 생성 불가 등으로 서비스 장애를 유발하거나 관리 누락의 통로가 됨"
GUIDELINE_CRITERIA_GOOD="계정별로 설정된 홈 디렉터리가 실제로 시스템에 존재하는 경우"
GUIDELINE_CRITERIA_BAD="설정된 홈 디렉터리가 존재하지 않는 계정이 있는 경우"
GUIDELINE_REMEDIATION="존재하지 않는 홈 디렉터리를 생성하거나 해당 계정의 설정을 올바른 경로로 수정"

diagnose() {
    # 변수 범위 수정 (main에서 읽을 수 있도록 전역 설정)
    status="양호"
    diagnosis_result="GOOD"
    inspection_summary="모든 활성 계정의 홈 디렉터리가 실제로 존재합니다."
    command_result=""
    command_executed="grep -v 'nologin\|false' /etc/passwd | cut -d: -f1,6"

    local checked_details=""
    local missing_homes=""
    local total_checked=0

    # /etc/passwd 점검 루프
    while IFS=: read -r user pass uid gid info home shell; do
        # 점검 대상: UID 1000 이상이면서 로그인이 가능한 계정
        if [ "$uid" -ge 1000 ] && [[ ! "$shell" =~ (nologin|false)$ ]]; then
            ((total_checked++))
            
            if [ -d "$home" ]; then
                checked_details+="${user}: ${home} [EXIST]\n"
            else
                checked_details+="${user}: ${home} [MISSING] !!!\n"
                missing_homes+="${user} "
                status="취약"
                diagnosis_result="VULNERABLE"
            fi
        fi
    done < /etc/passwd

    if [ "$diagnosis_result" = "VULNERABLE" ]; then
        inspection_summary="총 ${total_checked}개 중 일부 계정의 홈 디렉터리가 존재하지 않습니다."
        command_result=$(echo -e "점검 상세 리스트:\n${checked_details}\n결과: 홈 디렉토리 부재 계정 -> [ ${missing_homes} ]")
    else
        command_result=$(echo -e "점검 상세 리스트 (총 ${total_checked}개 계정):\n${checked_details}\n모든 홈 디렉터리가 정상적으로 존재합니다.")
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: root 권한이 필요합니다."
        exit 1
    fi

    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    diagnose || true
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-ERROR}"
    exit 0
}

main "$@"
