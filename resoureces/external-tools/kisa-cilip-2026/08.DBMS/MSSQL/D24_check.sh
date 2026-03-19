#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-24
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 하
# @Title       : DBMS 기본 포트 사용 점검
# @Description : DBMS 기본 포트 사용 점검 관리를 통한 DBMS 보안 강화
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

ITEM_ID="D-24"

ITEM_NAME="DBMS 기본 포트 사용 점검"
SEVERITY="하"
GUIDELINE_PURPOSE="기본 포트 변경으로 스캔 공격 방지"
GUIDELINE_THREAT="기본 포트 사용 시 자동 스캔 도구에 노출 위험"
GUIDELINE_CRITERIA_GOOD="기본 포트가 아닌 경우"
GUIDELINE_CRITERIA_BAD="기본 포트(1433) 사용"
GUIDELINE_REMEDIATION="MSSQL 설정 파일에서 포트 번호 변경 권장"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL"
    local status=""
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Check if MSSQL service is running
    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    fi

    # Check for default port 1433
    if netstat -tuln 2>/dev/null | grep -q ":1433 "; then
        diagnosis_result="VULNERABLE"
        status="취약"
        command_executed="netstat -tuln | grep 1433"
        command_result=$(netstat -tuln 2>/dev/null | grep ":1433 " || echo "")
        inspection_summary="기본 포트 1433 사용 중 (취약 - 포트 변경 권장)\n\n"
        inspection_summary+="검증 결과: ${command_result}\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- SQL Server Configuration Manager 실행\n"
        inspection_summary+="- SQL Server Network Configuration > Protocols for MSSQLSERVER\n"
        inspection_summary+="- Properties > IP Addresses 탭\n"
        inspection_summary+="- IPAll > TCP Port: 기본 포트가 아닌 포트로 변경 (예: 14330)\n"
        inspection_summary+="- SQL Server 서비스 재시작\n"
        inspection_summary+="- 방화벽에서 새 포트 허용 설정"
    else
        diagnosis_result="GOOD"
        status="양호"
        command_executed="netstat -tuln | grep 1433"
        command_result=$(netstat -tuln 2>/dev/null || echo "포트 1433 미사용")
        inspection_summary="기본 포트 1433 미사용 또는 서비스 미실행 (양호)\n\n"
        inspection_summary+="검증 결과: ${command_result}"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
