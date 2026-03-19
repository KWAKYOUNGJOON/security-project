#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-18
# ============================================================================
# [점검 항목 상세]
# @ID          : U-05
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : root 이외의 UID가 '0' 금지
# @Description : UID 0인 계정이 root만 있는지 확인
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

ITEM_ID="U-05"
ITEM_NAME="root 이외의 UID가 '0' 금지"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="root 계정과 동일한 UID가 존재하는지 점검하여 root 권한이 일반 사용자 계정이나 비인가자의 접근 위협에 안전하게 보호되고 있는지 확인하기 위함"
GUIDELINE_THREAT="root 계정과 동일한 UID가 설정되어 있는 일반 사용자 계정도 root 권한을 부여받아 관리자가 실행할 수 있는 모든 작업이 가능한 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="root 계정과 동일한 UID를 갖는 계정이 존재하는 경우"
GUIDELINE_REMEDIATION="UID가 0으로 설정된 계정을 0 이외의 중복되지 않은 UID로 변경 또는 불필요한 계정인 경우 제거"

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
    # UID 0인 계정이 root만 있는지 확인 (AIX /etc/passwd)
    
    local uid_zero_accounts=""
    local non_root_uid_zero=false
    
    # /etc/passwd에서 UID 0인 계정 찾기
    local raw_output=$(awk -F: '$3 == "0" {print $1 ":" $3}' /etc/passwd 2>/dev/null)
    
    command_result="${raw_output}"
    command_executed="awk -F: '\$3 == \"0\" {print \$1 \":\" \$3}' /etc/passwd"

    if [ -z "$raw_output" ]; then
        diagnosis_result="MANUAL"
        status="수동 진단"
        inspection_summary="/etc/passwd 파일에서 UID 0 계정을 찾을 수 없음"
    else
        local uid_zero_count=0
        local non_root_list=""
        
        while IFS= read -r line; do
            if [ -n "$line" ]; then
                ((uid_zero_count++))
                local username=$(echo "$line" | cut -d: -f1)
                
                if [ "$username" != "root" ]; then
                    non_root_uid_zero=true
                    non_root_list="${non_root_list}${username}, "
                fi
            fi
        done <<< "$raw_output"
        
        if [ "$non_root_uid_zero" = true ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="root 이외의 UID가 '0'인 계정 존재: ${non_root_list%, }"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="UID가 '0'인 계정은 root 뿐임"
        fi
    fi

    # 크로스 플랫폼 참고
    # ※ AIX: /etc/passwd (동일)

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
