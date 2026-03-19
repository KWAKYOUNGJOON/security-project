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
# @Platform    : MySQL
# @Severity    : 하
# @Title       : 인가되지않은Object Owner의제한
# @Description : Object Owner가 인가된 계정에게만 존재하는지 점검
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


ITEM_ID="D-20"
ITEM_NAME="인가되지않은Object Owner의제한"
SEVERITY="하"

GUIDELINE_PURPOSE="Object Owner가 인가된 계정에게만 존재하는지 점검"
GUIDELINE_THREAT="Object Owner가 일반 사용자에게 존재하는 경우 공격자가 이를 이용하여 Object의 수정, 삭제가 가능하여 중요정보의 유출 및 변경의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="Object Owner가 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우"
GUIDELINE_CRITERIA_BAD="Object Owner가 일반 사용자에게도 존재하는 경우"
GUIDELINE_REMEDIATION="Object Owner를 SYS, SYSTEM, 관리자 계정으로 제한 설정"

# MySQL 연결 정보 초기화 (fallback if library not loaded)
DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_ADMIN_USER="${DB_ADMIN_USER:-${DB_USER}}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-${DB_PASSWORD}}"
diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # Initialize MySQL connection variables (only if library function exists)
    if declare -f init_mysql_vars >/dev/null 2>&1; then
        init_mysql_vars
    fi

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_mysql_tools >/dev/null 2>&1; then
        if ! check_mysql_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local vulnerabilities_found=0

    # MySQL/MariaDB 서비스 확인 (only if library function exists)
    if declare -f check_mysql_service >/dev/null 2>&1; then
        if ! check_mysql_service; then
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="MySQL/MariaDB 서비스가 실행 중이지 않습니다. 서비스 시작 후 진단이 필요합니다."
            command_result="MySQL/MariaDB service not running"
            command_executed="mysqladmin ping -h ${DB_HOST} -P ${DB_PORT}"
            # Save results (only if library function exists)
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            if declare -f verify_result_saved >/dev/null 2>&1; then
                verify_result_saved "${ITEM_ID}"
            fi
            return 0
        fi
    fi

    # 1. 데이터베이스 소유자 확인 (mysql.user를 제외한 일반 사용자가 소유한 DB)
    local db_owner_query="SELECT schema_name, default_character_set_name FROM information_schema.schemata WHERE schema_name NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') ORDER BY schema_name;"
    command_executed="mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${db_owner_query}\""
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${db_owner_query}" 2>/dev/null || echo "")

    # 2. 테이블/뷰/프로시저 소유자 확인 (DEFINER가 일반 사용자인 경우)
    local object_owner_query="SELECT table_schema, table_name, table_type, engine FROM information_schema.tables WHERE table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') AND table_schema NOT IN (SELECT user FROM mysql.user WHERE Super_priv='Y' OR user IN ('root', 'mysql.sys', 'mysql.session')) ORDER BY table_schema, table_name LIMIT 20;"
    command_executed+="; mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${object_owner_query}\""
    local object_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${object_owner_query}" 2>/dev/null || echo "")
    command_result+=$'\n\n'"$object_result"

    # 3. 루틴(프로시저/함션) 소유자 확인
    local routine_query="SELECT routine_schema, routine_name, routine_type, definer FROM information_schema.routines WHERE routine_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') AND definer NOT LIKE 'root@%' AND definer NOT LIKE 'mysql.%@%' ORDER BY routine_schema, routine_name LIMIT 20;"
    command_executed+="; mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"${routine_query}\""
    local routine_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${routine_query}" 2>/dev/null || echo "")
    command_result+=$'\n\n'"$routine_result"

    local non_admin_objects=0
    if [ -n "$object_result" ]; then
        non_admin_objects=$(echo "$object_result" | tail -n +2 | grep -v "^$" | wc -l)
    fi

    local non_admin_routines=0
    if [ -n "$routine_result" ]; then
        non_admin_routines=$(echo "$routine_result" | tail -n +2 | grep -v "^$" | wc -l)
    fi

    local total_unauthorized=$((non_admin_objects + non_admin_routines))

    if [ $total_unauthorized -gt 0 ]; then
        ((vulnerabilities_found++)) || true
        local sample_objects=$(echo "$object_result" | tail -n +2 | grep -v "^$" | head -3 | tr '\n' ', ' || echo "")
        local sample_routines=$(echo "$routine_result" | tail -n +2 | grep -v "^$" | head -3 | tr '\n' ', ' || echo "")
        inspection_summary="취약: 비관리자가 소유한 ${total_unauthorized}개 객체 발견\n"
        inspection_summary+="- 테이블/뷰: ${non_admin_objects}개 ${sample_objects}\n"
        inspection_summary+="- 루틴: ${non_admin_routines}개 ${sample_routines}\n"
        inspection_summary+="\n조치 방법:\n"
        inspection_summary+="1. 객체 소유자를 root 또는 관리자 계정으로 변경: ALTER TABLE db.table OWNER TO 'root';\n"
        inspection_summary+="2. 루틴 DEFINER 변경: ALTER ROUTINE db.proc SQL SECURITY DEFINER;"
    else
        inspection_summary="양호: 모든 객체가 관리자 계정(root 또는 SUPER 권한 있는 계정)이 소유\n"
        inspection_summary+="확인된 데이터베이스: $(echo "$command_result" | tail -n +2 | grep -v "^$" | wc -l)개"
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    else
        diagnosis_result="GOOD"
        status="양호"
    fi

    # Save results (only if library function exists)
    if declare -f save_dual_result >/dev/null 2>&1; then
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    fi
    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi

    return 0
}

main() {
    # MySQL 연결 확인 (FR-018) (only if library function exists)
    if declare -f check_mysql_connection >/dev/null 2>&1; then
        if ! check_mysql_connection; then
            diagnosis_result="MANUAL"
            status="수동진단"
            if declare -f save_dual_result >/dev/null 2>&1; then
                save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
                    "MySQL 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요" \
                    "연결 실패: User=${DB_USER}, Host=${DB_HOST}:${DB_PORT}" \
                    "mysql -u ${DB_USER} -h ${DB_HOST} -P ${DB_PORT}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 1
        fi
    fi

    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
