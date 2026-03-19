#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-36
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : r 계열 서비스 비활성화
# @Description : rlogin, rsh, rexec 등 보안에 취약한 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-36"
ITEM_NAME="r 계열 서비스 비활성화"
SEVERITY="(상)"

GUIDELINE_PURPOSE="인증 과정에서 암호화되지 않은 평문을 사용하고 취약한 인증 방식을 사용하는 r 계열 서비스를 차단하기 위함"
GUIDELINE_THREAT="r 계열 서비스는 세션 가로채기 및 스니핑을 통해 사용자 계정 및 패스워드를 탈취할 수 있는 위험이 매우 큼"
GUIDELINE_CRITERIA_GOOD="rlogin, rsh, rexec 서비스가 중지되어 있거나 해당 서비스가 존재하지 않는 경우"
GUIDELINE_CRITERIA_BAD="rlogin, rsh, rexec 서비스 중 하나라도 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="rlogin, rsh, rexec 서비스 비활성화 (systemctl stop rsh.socket 등)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="r 계열 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -E 'rlogin|rsh|rexec'"

    # 1. 실제 데이터 추출
    local r_services=$(ps -ef | grep -Ei "rlogin|rsh|rexec" | grep -v grep || echo "")

    # 2. 판정 로직
    if [ -n "$r_services" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 r 계열 서비스가 활성화되어 있습니다."
        command_result="실행 중인 서비스: [ $(echo $r_services | awk '{print $8}' | xargs) ]"
    else
        command_result="r 계열 서비스가 발견되지 않았습니다."
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
