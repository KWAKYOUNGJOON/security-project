#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-67
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 홈 디렉토리 소유자 및 권한 설정
# @Description : 사용자 홈 디렉토리의 소유자 일치 여부 및 타인 쓰기 권한 제한 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-67"
ITEM_NAME="홈 디렉토리 소유자 및 권한 설정"
SEVERITY="(중)"

GUIDELINE_PURPOSE="홈 디렉토리 내 개인 파일 및 설정 정보를 보호하여 타 사용자에 의한 변조 및 정보 유출을 차단하기 위함"
GUIDELINE_THREAT="홈 디렉토리 권한이 과도하게 부여될 경우 타인에 의해 중요 파일이 변조되거나 쉘 설정 파일 수정을 통해 권한이 탈취될 수 있음"
GUIDELINE_CRITERIA_GOOD="홈 디렉토리 소유자가 해당 계정이고, 타 사용자 쓰기 권한이 없는 경우"
GUIDELINE_CRITERIA_BAD="홈 디렉토리 소유자가 불일치하거나 타 사용자 쓰기 권한이 허용된 경우"
GUIDELINE_REMEDIATION="홈 디렉토리 소유자 변경(chown) 및 권한 변경(chmod 700)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="모든 홈 디렉터리의 설정이 적절합니다."
    local command_executed="ls -ld /home/*"
    local check_output=""
    local bad_list=""

    # 1. 실제 디렉토리 리스트 추출 (증적용)
    check_output=$(ls -ld /home/* 2>/dev/null)

    # 2. 루프를 돌며 상세 점검 (UID 1000 이상 기준)
    while IFS=: read -r user pass uid gid info home shell; do
        if [ "$uid" -ge 1000 ] && [ -d "$home" ]; then
            local owner=$(stat -c "%U" "$home")
            local perm=$(stat -c "%a" "$home")
            
            # 소유자가 본인이 아니거나, 타인(Others)에게 쓰기 권한(2 이상)이 있는 경우
            if [ "$owner" != "$user" ] || [ "${perm: -1}" -ge 2 ]; then
                status="취약"
                diagnosis_result="VULNERABLE"
                bad_list+="${user}(${perm}, Owner:${owner}) "
            fi
        fi
    done < /etc/passwd

    # 3. 현황값 기록
    if [ "$status" == "취약" ]; then
        inspection_summary="부적절한 권한/소유자의 홈 디렉터리가 발견되었습니다."
        command_result="[취약 리스트]: ${bad_list}\n\n[전체 리스트]:\n${check_output}"
    else
        command_result="[전체 리스트]:\n${check_output}"
    fi

   
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}
main "$@"
