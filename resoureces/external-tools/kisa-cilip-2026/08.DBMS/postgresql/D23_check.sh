#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-23
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : xp_cmdshell 확장 저장 프로시저 사용 제한
# @Description : xp_cmdshell 확장 저장 프로시저 사용 제한 관리를 통한 DBMS 보안 강화
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

ITEM_ID="D-23"
ITEM_NAME="xp_cmdshell 확장 저장 프로시저 사용 제한"
SEVERITY="상"

GUIDELINE_PURPOSE="xp_cmdshell 확장 저장 프로시저를 비활성화하여 OS 명령 실행 방지"
GUIDELINE_THREAT="xp_cmdshell 활성화 시 DB에서 OS 명령 실행 가능하여 시스템 장악 위험"
GUIDELINE_CRITERIA_GOOD="xp_cmdshell가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD="xp_cmdshell가 활성화된 경우"
GUIDELINE_REMEDIATION="N/A - PostgreSQL에는 xp_cmdshell 기능이 없음"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="이 항목은 MSSQL 전용입니다. PostgreSQL에는 xp_cmdshell 기능이 없습니다."
    local command_result=""
    local command_executed=""

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
