#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-38
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : DoS 공격에 취약한 서비스 비활성화
# @Description : DoS 공격에 악용될 수 있는 echo, discard, daytime, chargen 등의 서비스 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-38"
ITEM_NAME="DoS 공격에 취약한 서비스 비활성화"
SEVERITY="(상)"

GUIDELINE_PURPOSE="시스템 리소스를 과도하게 소모시킬 수 있는 불필요한 DoS 관련 서비스를 차단하여 가용성을 확보하기 위함"
GUIDELINE_THREAT="echo, chargen 등의 서비스가 활성화된 경우 UDP Flooding 공격의 도구가 되어 시스템 서비스 거부 상태를 유발할 수 있음"
GUIDELINE_CRITERIA_GOOD="echo, discard, daytime, chargen 등의 서비스가 비활성화되어 있는 경우"
GUIDELINE_CRITERIA_BAD="DoS 관련 서비스 중 하나라도 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="해당 서비스 비활성화 (/etc/xinetd.d/ 내 파일에서 disable = yes 설정)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="DoS 공격에 취약한 불필요 서비스들이 모두 비활성화되어 있습니다."
    local command_result=""
    local command_executed="grep -r 'disable' /etc/xinetd.d/"

    # 1. 실제 데이터 추출
    local dos_list=("echo" "discard" "daytime" "chargen")
    local active_services=""
    
    for svc in "${dos_list[@]}"; do
        if [ -f "/etc/xinetd.d/$svc" ]; then
            if grep -qi "disable" "/etc/xinetd.d/$svc" | grep -qi "no"; then
                active_services+="$svc "
            fi
        fi
    done

    # 2. 판정 로직
    if [ -n "$active_services" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="DoS 공격에 취약한 일부 서비스가 활성화되어 있습니다."
        command_result="활성 DoS 서비스: [ ${active_services} ]"
    else
        command_result="모든 취약한 DoS 서비스가 비활성화 상태입니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
