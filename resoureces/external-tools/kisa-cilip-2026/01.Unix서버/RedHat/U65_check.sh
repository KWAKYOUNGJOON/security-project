#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-65
# @Category    : UNIX > 5. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : NTP 서비스 설정 및 동기화
# @Description : NTP 서비스 활성화 여부 및 시간 동기화 상태 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-65"
ITEM_NAME="NTP 서비스 설정 및 동기화"
SEVERITY="(중)"

GUIDELINE_PURPOSE="로그 분석 및 침해 사고 조사 시 정확한 시간 정보를 확보하기 위해 시스템 시간을 표준 시간과 동기화하기 위함"
GUIDELINE_THREAT="시스템 시간이 동기화되지 않을 경우 로그 기록의 신뢰성이 저하되어 정확한 침해 사고 분석이 불가능해짐"
GUIDELINE_CRITERIA_GOOD="NTP 서비스가 활성화되어 있고 표준 시간 서버와 동기화 중인 경우"
GUIDELINE_CRITERIA_BAD="NTP 서비스가 비활성화되어 있거나 시간 동기화가 이루어지지 않는 경우"
GUIDELINE_REMEDIATION="ntpd 또는 chronyd 서비스 실행 및 ntp.conf에 타임 서버 등록"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="NTP 서비스가 정상적으로 동작 중입니다."
    local command_executed="chronyc sources || ntpq -p"
    
    # 1. 실행 결과 저장
    local cmd_out
    cmd_out=$(chronyc sources 2>&1 || ntpq -p 2>&1)

    # 2. 판정 로직 
    # - 에러 메시지(Cannot talk to daemon, Connection refused 등)가 포함된 경우
    # - 혹은 동기화 서버 리스트가 아예 없는 경우
    if [[ "$cmd_out" =~ "Cannot talk to daemon" ]] || [[ "$cmd_out" =~ "Connection refused" ]]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="NTP 데몬이 응답하지 않습니다. 서비스 상태를 확인하십시오."
    elif [[ ! "$cmd_out" =~ ^\* ]] && [[ ! "$cmd_out" =~ ^o ]]; then
        # 동기화 중임을 나타내는 기호(* 또는 o)가 없는 경우
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="NTP 서버와 동기화가 이루어지지 않고 있습니다."
    fi

    command_result="[NTP Status]\n${cmd_out}"

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}
main "$@"
