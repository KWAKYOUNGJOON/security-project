#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-30
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : UMASK 설정 관리
# @Description : 신규 파일 및 디렉터리 생성 시 기본 권한을 제어하는 UMASK 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-30"
ITEM_NAME="UMASK 설정 관리"
SEVERITY="(중)"

# 가이드라인 정보
GUIDELINE_PURPOSE="신규 파일이나 디렉터리 생성 시 기본 권한을 제어하여 과도한 권한이 부여되는 것을 방지하기 위함"
GUIDELINE_THREAT="UMASK 값이 취약하게 설정된 경우 생성되는 파일에 과도한 권한이 부여되어 비인가자의 정보 열람 및 변조가 가능함"
GUIDELINE_CRITERIA_GOOD="UMASK 값이 022 이상으로 설정되어 있는 경우"
GUIDELINE_CRITERIA_BAD="UMASK 값이 022 미만으로 설정되어 있는 경우"
GUIDELINE_REMEDIATION="/etc/profile 또는 환경설정 파일에서 UMASK 022 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="UMASK 설정이 022 이상으로 적절하게 설정되어 있습니다."
    local command_result=""
    local command_executed="umask"

    # 1. 실제 데이터 추출
    local current_umask
    current_umask=$(umask)

    # 2. 판정 로직 (022보다 크거나 같은지 확인)
    if [ "$current_umask" -lt 022 ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="UMASK 설정이 022 미만으로 취약하게 설정되어 있습니다."
    fi

    # 3. command_result에 실제 설정값 기록
    command_result="현재 시스템 UMASK: [ ${current_umask} ]"

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
