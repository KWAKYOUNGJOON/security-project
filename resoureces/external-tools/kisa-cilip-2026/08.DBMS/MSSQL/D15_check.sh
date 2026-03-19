#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-15
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 하
# @Title       : 관리자이외의사용자가오라클리스너의접속을통해리스너로그및trace파일에대한변경제한
# @Description : 불필요한 접속 경로 제한 및 접근 통제
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

# Initialize MSSQL connection variables
init_mssql_vars
ITEM_ID="D-15"
ITEM_NAME="관리자이외의사용자가오라클리스너의접속을통해리스너로그및trace파일에대한변경제한"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="리스너 로그 및 trace 파일 접근 제한으로 무단 변경 및 정보 유출 방지"
GUIDELINE_THREAT="관리자 외 사용자가 리스너 파일에 접근 가능할 경우 로그 조작 및 정보 유출 위험"
GUIDELINE_CRITERIA_GOOD="리스너 파일이 oracle 소유이며 600/644 권한인 경우"
GUIDELINE_CRITERIA_BAD="리스너 파일에 Other 쓰기 권한이 있는 경우"
GUIDELINE_REMEDIATION="listener.ora에 LOG_DIRECTORY_<listener_name> 설정 및 파일 권한 644로 변경"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # D-15는 Oracle Listener 전용 항목
    # MSSQL은 Listener 개념이 없으므로 N/A 처리

    diagnosis_result="N/A"
    status="N/A"
    inspection_summary="이 항목은 Oracle Listener(listener.log, listener.trc) 전용 항목입니다. MSSQL은 SQL Server Error Log(ERRORLOG), SQL Server Agent Log, Profiler Trace를 사용합니다. MSSQL 로그 점검: EXEC xp_readerrorlog; 또는 Management Studio > Management > SQL Server Logs. 권장: SQLAgentUserRole 역할에만 로그 읽기 권한 부여."
    command_result="MSSQL uses ERRORLOG, not Oracle Listener"
    command_executed="EXEC xp_readerrorlog 0, 1, NULL, NULL, NULL, NULL, N'asc';"

    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
