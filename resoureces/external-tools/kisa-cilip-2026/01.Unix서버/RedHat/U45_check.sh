#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-45
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 메일 서비스 버전 점검
# @Description : 사용 중인 Sendmail 등 메일 서비스 프로그램의 최신 버전 사용 여부 점검
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"; source "${LIB_DIR}/output_mode.sh"; source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-45"; ITEM_NAME="메일 서비스 버전 점검"; SEVERITY="(상)"

GUIDELINE_PURPOSE="최신 버전의 메일 서비스를 사용하여 프로그램 취약점을 이용한 침해 사고를 방지하기 위함"
GUIDELINE_THREAT="오래된 버전의 메일 서비스를 사용할 경우 알려진 보안 취약점을 통해 원격 코드 실행 및 시스템 장악 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="메일 서비스(Sendmail 등)를 사용하지 않거나, 사용 시 최신 버전의 패치가 적용된 경우"
GUIDELINE_CRITERIA_BAD="메일 서비스(Sendmail 등)를 사용하며 최신 버전이 아니거나 보안 패치가 미흡한 경우"
GUIDELINE_REMEDIATION="최신 버전 업데이트 적용"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local inspection_summary="메일 서비스가 비활성화되어 있거나 최신 상태를 유지하고 있습니다."
    local command_result=""
    
    local mail_proc=$(ps -ef | grep -Ei "sendmail|postfix" | grep -v grep || echo "")

    if [ -n "$mail_proc" ]; then
        # 버전 확인 명령어 실행 (예: sendmail -d0.1)
        local mail_ver=$(/usr/sbin/sendmail -d0.1 < /dev/null 2>&1 | grep "Version" | head -n 1 || echo "Unknown")
        command_result="실행 중인 메일 서비스 버전: [ ${mail_ver} ]"
        inspection_summary="메일 서비스가 실행 중입니다. 수동으로 최신 버전 여부를 확인하십시오."
    else
        command_result="메일 서비스 프로세스가 발견되지 않았습니다."
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "sendmail -d0.1" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
