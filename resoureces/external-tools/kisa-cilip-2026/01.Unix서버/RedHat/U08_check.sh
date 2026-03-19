#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-08
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : 관리자 그룹에 최소한의 계정 포함
# @Description : 관리자 권한이 있는 그룹(root, wheel 등)에 불필요한 계정 포함 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-08"
ITEM_NAME="관리자 그룹에 최소한의 계정 포함"
SEVERITY="(중)"

# 가이드라인 정보
GUIDELINE_PURPOSE="관리자 권한이 있는 그룹에 불필요한 계정 등록을 방지하여 권한 남용을 차단하기 위함"
GUIDELINE_THREAT="권한이 없는 계정이 관리자 그룹에 포함될 경우 시스템 설정 변경 및 중요 정보 탈취 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="관리자 그룹에 최소한의 계정만 포함된 경우"
GUIDELINE_CRITERIA_BAD="관리자 그룹에 불필요한 계정이 포함된 경우"
GUIDELINE_REMEDIATION="관리자 그룹(root, wheel 등)에서 불필요한 계정 삭제"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="관리자 그룹에 불필요한 계정이 없습니다."
    local command_executed="grep -E '^root:|^wheel:' /etc/group"

    # 1. 데이터 추출
    local root_members=$(grep "^root:" /etc/group | cut -d: -f4)
    local wheel_members=$(grep "^wheel:" /etc/group | cut -d: -f4)

    # 2. 판정 로직: root 그룹에 root 외 계정이 있거나, wheel 그룹에 계정이 있는 경우
    # 현업 가이드에서는 관리자 외 계정 존재 시 '취약'으로 간주하고 소명을 받습니다.
    if [[ -n "$wheel_members" ]] || [[ "$root_members" =~ [^root,] ]]; then
        status="취약"  # 또는 "검토필요"
        diagnosis_result="VULNERABLE"
        inspection_summary="관리자 그룹에 등록된 계정이 식별되었습니다. 인가된 사용자인지 수동 점검이 필요합니다. (발견: ${root_members:-root}, ${wheel_members:-wheel없음})"
    fi

    local command_result="[root: ${root_members:-root}] [wheel: ${wheel_members:-none}]"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
