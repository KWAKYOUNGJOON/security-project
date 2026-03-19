#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-22
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 하
# @Title       : SQL Server 버전 점검
# @Description : SQL Server 버전 점검 관리를 통한 DBMS 보안 강화
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

ITEM_ID="D-22"

ITEM_NAME="SQL Server 버전 점검"
SEVERITY="하"

GUIDELINE_PURPOSE="지원되는 SQL Server 버전 사용으로 보안 패치 적용"
GUIDELINE_THREAT="구버전 사용 시 알려진 보안 취약점 노출 위험"
GUIDELINE_CRITERIA_GOOD="지원되는 최신 버전"
GUIDELINE_CRITERIA_BAD="지원 종료된 구버전"
GUIDELINE_REMEDIATION="최신 SQL Server 버전으로 업그레이드"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="diagnosis_result="MANUAL" (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT @@VERSION;\""
        command_result=$(sqlcmd -Q "SELECT @@VERSION;" 2>/dev/null | head -n 1 || echo "")
        inspection_summary="SQL Server 버전 확인 - 수동 확인 필요\n\n"
        inspection_summary="검출된 버전: ${command_result}\n\n"
        inspection_summary+="지원 버전 확인:\n"
        inspection_summary+="- SQL Server 2022: 양호 (지원 중)\n"
        inspection_summary+="- SQL Server 2019: 양호 (지원 중 - 2025년 1월까지)\n"
        inspection_summary+="- SQL Server 2017: 주의 (지원 종료 예정)\n"
        inspection_summary+="- SQL Server 2016 이하: 취약 (지원 종료)\n\n"
        inspection_summary+="조치 방법: 최신 SQL Server 버전으로 업그레이드"
    else
        inspection_summary="SQL Server 버전 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SSMS 실행: SELECT @@VERSION;\n"
        inspection_summary+="2. 레지스트리 확인:\n"
        inspection_summary+="   - HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLXX.MSSQLServer\\CurrentVersion\n"
        inspection_summary+="3. 제어판 > 프로그램 및 기능 확인\n\n"
        inspection_summary+="조치 방법: 최신 SQL Server 버전으로 업그레이드"
    fi

    diagnosis_result="MANUAL" status="수동진단"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
