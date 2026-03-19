#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-44
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : tftp, talk 서비스 비활성화
# @Description : 인증 절차가 없는 tftp와 보안에 취약한 talk 서비스 비활성화 점검
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"; source "${LIB_DIR}/output_mode.sh"; source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-44"; ITEM_NAME="tftp, talk 서비스 비활성화"; SEVERITY="(상)"

GUIDELINE_PURPOSE="인증 기능이 없거나 보안에 취약한 tftp, talk 서비스 비활성화를 통해 보안을 강화하기 위함"
GUIDELINE_THREAT="tftp는 별도의 인증 절차 없이 파일 전송이 가능하여 중요 파일 유출 위험이 크며, talk는 서비스 거부 공격 등에 악용될 수 있음"
GUIDELINE_CRITERIA_GOOD="tftp, talk 서비스가 비활성화되어 있는 경우"
GUIDELINE_CRITERIA_BAD="tftp, talk 서비스 중 하나라도 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="tftp/talk 서비스 비활성화"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local inspection_summary="tftp 및 talk 서비스가 비활성화되어 있습니다."
    local command_result=""
    
    local active_svcs=$(grep -Ei "tftp|talk" /etc/xinetd.d/* 2>/dev/null | grep "disable" | grep -i "no" | awk -F: '{print $1}' | xargs || echo "")
    local proc_check=$(ps -ef | grep -Ei "tftpd|talkd" | grep -v grep || echo "")

    if [ -n "$active_svcs" ] || [ -n "$proc_check" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="보안에 취약한 tftp 또는 talk 서비스가 활성화되어 있습니다."
        command_result="활성 서비스/프로세스: [ ${active_svcs} ${proc_check} ]"
    else
        command_result="tftp, talk 서비스가 모두 비활성화되어 있습니다."
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "ls /etc/xinetd.d" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
