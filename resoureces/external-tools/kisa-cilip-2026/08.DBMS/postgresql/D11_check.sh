#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-11
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : DBA이외의인가되지않은사용자가시스템테이블에접근할수없도록설정
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

ITEM_ID="D-11"
ITEM_NAME="DBA이외의인가되지않은사용자가시스템테이블에접근할수없도록설정"
SEVERITY="상"

GUIDELINE_PURPOSE="DBA 이외의 인가되지 않은 사용자가 시스템 테이블에 접근하지 못하도록 제한"
GUIDELINE_THREAT="일반 사용자의 시스템 테이블 접근 가능 시 중요 메타데이터 유출 및 조작 위험"
GUIDELINE_CRITERIA_GOOD="DBA만 시스템 테이블 접근 가능한 경우"
GUIDELINE_CRITERIA_BAD="DBA 외 사용자가 시스템 테이블에 접근 가능한 경우"
GUIDELINE_REMEDIATION="불필요한 권한 제거: REVOKE ALL ON system_catalogs FROM non_dba_user;"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="GOOD" status="양호" inspection_summary="" command_result="" command_executed=""

    # Initialize PostgreSQL connection variables
    init_postgresql_vars

    # PostgreSQL 서비스 확인
    if ! check_postgresql_service; then
        handle_dbms_not_running "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # PostgreSQL 연결 시도 (FR-018)
    if ! prompt_postgresql_connection; then
        handle_dbms_connection_failed "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    # PostgreSQL에서 시스템 카탈로그 접근 권한 확인
    # pg_catalog 스키마의 테이블에 대한 권한 확인
    local priv_query="SELECT grantee, privilege_type FROM information_schema.role_table_grants WHERE table_schema='pg_catalog' AND table_name IN ('pg_user', 'pg_roles', 'pg_shadow') AND grantee!='PUBLIC';"
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"${priv_query}\""
    command_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "${priv_query}" 2>/dev/null || echo "")

    # 시스템 카탈로그에 대한 과도한 권한 확인
    local excess_priv_query="SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants WHERE table_schema='pg_catalog' AND grantee NOT IN ('postgres', 'PUBLIC') AND privilege_type IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER');"
    local excess_priv_result=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "${excess_priv_query}" 2>/dev/null || echo "")

    if [ -n "$excess_priv_result" ] && echo "$excess_priv_result" | grep -v "^$" | grep -v "grantee" | grep -q -v "^$"; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약: DBA 외 사용자가 시스템 테이블에 과도한 권한 보유"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="양호: 시스템 테이블 접근이 DBA로 제한됨"
    fi

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
