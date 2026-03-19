#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-15
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 파일 및 디렉터리 소유자 설정
# @Description : 소유자가 없는 파일 확인
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


ITEM_ID="U-15"
ITEM_NAME="파일 및 디렉터리 소유자 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자 홈 디렉터리의 적절한 소유자 및 권한 설정을 통한 무단 접근 방지"
GUIDELINE_THREAT="홈 디렉터리 소유자 불일치 또는 타인 쓰기 권한 허용 시 비인가자가 사용자 파일 열람 및 수정 위험"
GUIDELINE_CRITERIA_GOOD="홈 디렉터리 소유자가 사용자 본인이고 others 쓰기 권한 없음"
GUIDELINE_CRITERIA_BAD=" 소유자 불일치 또는 others 쓰기 권한 있음"
GUIDELINE_REMEDIATION="chown username /home/username 및 chmod go-w /home/username 실행"

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
    # /etc/passwd의 사용자 홈 디렉토리 권한 확인

    local vulnerable_homes=""
    local vulnerable_count=0
    local total_users=0

    # /etc/passwd에서 사용자별 홈 디렉토리 권한 확인
    while IFS= read -r user_line; do
        local username=$(echo "$user_line" | cut -d: -f1)
        local uid=$(echo "$user_line" | cut -d: -f3)
        local home_dir=$(echo "$user_line" | cut -d: -f6)

        # 홈 디렉토리가 존재하고, UID가 100 이상인 일반 사용자 확인 (HP-UX: 시스템 UID는 100 미만)
        if [ -d "$home_dir" ] && [ "$uid" -ge 100 ] 2>/dev/null; then
            ((total_users++)) || true

            # HP-UX: ls -ld 사용하여 권한 및 소유자 확인
            local perms_owner=$(ls -ld "$home_dir" 2>/dev/null | awk '{print $1, $3}')
            local perms=$(echo "$perms_owner" | awk '{print $1}')
            local owner=$(echo "$perms_owner" | awk '{print $2}')

            if [ -n "$perms" ] && [ -n "$owner" ]; then
                # 취약한 권한 확인: others에 쓰기 권한이 있거나, 소유자가 해당 사용자가 아닌 경우
                local others_perms=${perms: -1}

                if [ "$owner" != "$username" ]; then
                    ((vulnerable_count++)) || true
                    vulnerable_homes="${vulnerable_homes}${username}: ${home_dir} (소유자: ${owner}, 권한: ${perms}), "
                elif [ "$others_perms" = "w" ]; then
                    ((vulnerable_count++)) || true
                    vulnerable_homes="${vulnerable_homes}${username}: ${home_dir} (권한: ${perms}, others 쓰기 가능), "
                fi
            fi
        fi
    done < /etc/passwd || true

    if [ "$vulnerable_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="사용자 홈 디렉토리 권한 양호 (검사된 사용자: ${total_users}명)"
        local home_check=$(awk -F: '$3 >= 100 {print $1, $3, $6}' /etc/passwd 2>/dev/null | while read user uid home; do ls -ld "$home" 2>/dev/null; done | head -10 || echo "All home directories secure")
        command_result="${home_check}"
        command_executed="awk -F: '\$3 >= 100 {print \$1, \$3, \$6}' /etc/passwd | while read user uid home; do ls -ld \"\$home\" 2>/dev/null; done"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 홈 디렉토리 ${vulnerable_count}개 발견: ${vulnerable_homes%, }"
        command_result="${vulnerable_homes%, }"
        command_executed="awk -F: '\$3 >= 100 {print \$1, \$3, \$6}' /etc/passwd | while read user uid home; do ls -ld \"\$home\" 2>/dev/null; done"
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
