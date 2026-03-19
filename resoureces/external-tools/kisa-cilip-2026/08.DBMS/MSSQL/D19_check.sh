#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-19
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 상
# @Title       : SA 계정 비밀번호 점검
# @Description : 비밀번호 정책 및 설정 관리를 통한 무단 접근 방지
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

ITEM_ID="D-19"

ITEM_NAME="SA 계정 비밀번호 점검"
SEVERITY="상"

GUIDELINE_PURPOSE="SA 계정 비밀번호 설정 여부 확인하여 무단 접근 방지"
GUIDELINE_THREAT="SA 계정 빈 비밀번호 또는 기본 비밀번호 사용 시 관리자 권한 탈취 위험"
GUIDELINE_CRITERIA_GOOD="강력한 비밀번호 설정된 경우"
GUIDELINE_CRITERIA_BAD="빈 비밀번호 또는 기본값"
GUIDELINE_REMEDIATION="SA 계정 비밀번호 변경: ALTER LOGIN sa WITH PASSWORD = 'strong_password';"

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

    # MSSQL 서비스 확인 (Windows)
    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    # Linux 환경 sqlcmd 확인
    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT name, is_disabled FROM sys.server_principals WHERE name='sa';\""
        inspection_summary="MSSQL SA 계정 비밀번호 점검 - 수동 확인 필요\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. sqlcmd -S localhost -U sa -P 'password' (빈 비밀번호로 시도)\n"
        inspection_summary+="2. SELECT name, is_disabled FROM sys.server_principals WHERE name='sa'\n"
        inspection_summary+="3. SQL Server Management Studio에서 SA 계정 속성 확인\n\n"
        inspection_summary+="조치 방법: ALTER LOGIN sa WITH PASSWORD = 'Strong_P@ssw0rd';"
    else
        inspection_summary="MSSQL SA 계정 비밀번호 점검 - SQL Server Management Studio에서 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SSMS 실행 및 서버 연결\n"
        inspection_summary+="2. Security > Logins > sa 우클릭 > Properties\n"
        inspection_summary+="3. 비밀번호 강도 확인 (8자 이상, 대소문자/숫자/특수문자 혼합)\n\n"
        inspection_summary+="조치 방법: ALTER LOGIN sa WITH PASSWORD = 'Strong_P@ssw0rd';"
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
