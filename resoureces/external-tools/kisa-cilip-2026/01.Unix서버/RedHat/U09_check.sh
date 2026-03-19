#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-09
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (하)
# @Title       : 계정이 존재하지 않는 GID 금지
# @Description : 그룹 설정 파일(/etc/group)에 불필요한 그룹 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-09"
ITEM_NAME="계정이 존재하지 않는 GID 금지"
SEVERITY="(하)"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 그룹이 소유한 파일 노출로 인해 발생할 수 있는 위험에 대비하기 위함"
GUIDELINE_THREAT="계정이 존재하지 않는 그룹이 있을 경우 해당 그룹 소유 파일을 통한 권한 남용 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="시스템 운영에 불필요한 그룹이 제거된 경우"
GUIDELINE_CRITERIA_BAD="시스템 운영에 불필요한 그룹이 존재하는 경우"
GUIDELINE_REMEDIATION="사용자가 없는 불필요한 그룹 제거"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="불필요한 그룹이 발견되지 않았습니다."
    local command_result=""
    local command_executed="cat /etc/group | cut -d: -f3"

    # 1. 실제 데이터 추출: /etc/group에서 사용자가 배정되지 않은 그룹 확인
    local ghost_groups=""
    while IFS=: read -r gname gpass gid gmembers; do
        if [ "$gid" -ge 1000 ]; then # 일반 사용자 그룹 범위 대상
            if ! grep -q ":${gid}:" /etc/passwd && [ -z "$gmembers" ]; then
                ghost_groups+="${gname}(${gid}) "
            fi
        fi
    done < /etc/group

    # 2. 판정 로직
    if [ -n "$ghost_groups" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="계정이 존재하지 않는 그룹이 발견되었습니다."
    fi

    # 3. command_result에 실제 데이터 기록
    command_result="발견된 그룹: [ ${ghost_groups:-없음} ]"

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
