#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-20
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 하
# @Title       : 인가되지않은Object Owner의제한
# @Description : 인가되지않은Object Owner의제한 관리를 통한 DBMS 보안 강화
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

ITEM_ID="D-20"
ITEM_NAME="인가되지않은Object Owner의제한"
SEVERITY="하"

GUIDELINE_PURPOSE="Object Owner가 인가된 계정에게만 존재하는지 점검"
GUIDELINE_THREAT="Object Owner가 일반 사용자에게 존재하는 경우 공격자가 이를 이용하여 Object의 수정, 삭제가 가능하여 중요정보의 유출 및 변경의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
GUIDELINE_CRITERIA_BAD="Object Owner가 일반 사용자에게도 존재하는 경우"
GUIDELINE_REMEDIATION="Object Owner를 dbo 또는 sysadmin 권한 계정으로 변경: ALTER AUTHORIZATION ON OBJECT::schema.table TO dbo;"

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
            inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    fi

    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT schema_name(schema_id) AS schema_name, name AS object_name, type_desc, USER_NAME(principal_id) AS owner FROM sys.objects WHERE is_ms_shipped = 0 AND USER_NAME(principal_id) NOT IN ('dbo', 'sys', 'INFORMATION_SCHEMA') ORDER BY schema_name, object_name;\""
        inspection_summary="MSSQL Object Owner 제한 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. sqlcmd 실행:\n"
        inspection_summary+="   sqlcmd -Q \"SELECT schema_name(schema_id) AS schema_name, name AS object_name, type_desc, USER_NAME(principal_id) AS owner FROM sys.objects WHERE is_ms_shipped = 0 AND USER_NAME(principal_id) NOT IN ('dbo', 'sys', 'INFORMATION_SCHEMA') ORDER BY schema_name, object_name;\"\n\n"
        inspection_summary+="2. 결과 분석:\n"
        inspection_summary+="   - 양호: 결과 없음 (모든 객체가 dbo, sys, INFORMATION_SCHEMA가 소유)\n"
        inspection_summary+="   - 취약: 비-dbo 소유자의 객체 발견\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="1. 객체 소유자를 dbo로 변경:\n"
        inspection_summary+="   ALTER AUTHORIZATION ON OBJECT::schema.table TO dbo;\n"
        inspection_summary+="   ALTER AUTHORIZATION ON OBJECT::schema.view TO dbo;\n"
        inspection_summary+="   ALTER AUTHORIZATION ON SCHEMA::schema_name TO dbo;\n\n"
        inspection_summary+="2. 전체 데이터베이스 객체 소유자 일괄 변경:\n"
        inspection_summary+="   EXEC sp_MSforeachtable @command1='ALTER AUTHORIZATION ON OBJECT::''?'' TO dbo;'\n\n"
        inspection_summary+="참고: MSSQL에서는 dbo(Database Owner)가 표준 관리자 소유자입니다."
    else
        inspection_summary="MSSQL Object Owner 제한 확인 - SQL Server Management Studio에서 수동 확인 필요\n\n"
        inspection_summary+="검증 방법(SSMS):\n"
        inspection_summary+="1. SSMS 실행 및 서버 연결\n"
        inspection_summary+="2. 데이터베이스 > Tables(또는 Views, Programmability) 확장\n"
        inspection_summary+="3. 객체 우클릭 > Properties > 소유자 확인\n"
        inspection_summary+="4. 양호: 소유자가 'dbo', 취약: 소유자가 다른 사용자\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- T-SQL: ALTER AUTHORIZATION ON OBJECT::schema.table TO dbo;\n"
        inspection_summary+="- SSMS: 객체 우클릭 > Properties > 소유자 변경 > 'dbo' 선택\n\n"
        inspection_summary+="참고: MSSQL에서는 dbo(Database Owner)가 표준 관리자 소유자입니다."
    fi

    diagnosis_result="MANUAL"
    status="수동진단"

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
