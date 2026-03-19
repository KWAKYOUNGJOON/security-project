#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-34
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : Finger 서비스 비활성화
# @Description : Finger 서비스(사용자 정보 확인 서비스)의 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-34"
ITEM_NAME="Finger 서비스 비활성화"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자 정보(로그인 아이디, 이름, 접속 시간 등) 유출을 차단하여 공격자의 정보 수집을 방지하기 위함"
GUIDELINE_THREAT="Finger 서비스 활성화 시 외부에서 시스템 사용자 목록을 획득하여 무차별 대입 공격에 활용될 수 있음"
GUIDELINE_CRITERIA_GOOD="Finger 서비스가 비활성화되어 있거나 설치되지 않은 경우"
GUIDELINE_CRITERIA_BAD="Finger 서비스가 실행 중이거나 xinetd 등에서 활성화된 경우"
GUIDELINE_REMEDIATION="관련 서비스 중단 및 xinetd 설정에서 disable = yes 적용"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="Finger 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep fingerd; ls /etc/xinetd.d/finger"

    # 1. 프로세스 실행 여부 확인
    local finger_ps=$(ps -ef | grep -i "fingerd" | grep -v grep || echo "")
    
    # 2. xinetd/inetd 설정 확인 (비활성화 여부)
    local xinetd_file="/etc/xinetd.d/finger"
    local xinetd_status=""
    if [ -f "$xinetd_file" ]; then
        xinetd_status=$(grep -i "disable" "$xinetd_file" | xargs || echo "설정 없음")
    fi

    # 3. 판정 로직
    if [ -n "$finger_ps" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="Finger 서비스 프로세스가 실행 중입니다."
    elif [ -f "$xinetd_file" ] && [[ "$xinetd_status" != *"yes"* ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="Finger 서비스가 xinetd에서 활성화되어 있습니다."
    fi

    # 4. 결과 기록 및 개행 제거 (JSON 보호)
    command_result="[Process: ${finger_ps:-None}] [xinetd: ${xinetd_status:-None}]"
    command_result=$(echo "$command_result" | tr -d '\n\r')

    # 12개의 인자를 모두 전달하여 안정성 확보
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
