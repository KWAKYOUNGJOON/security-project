#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-10
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 원격에서DB서버로의접속제한
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

ITEM_ID="D-10"
ITEM_NAME="원격에서DB서버로의접속제한"
SEVERITY="중"

GUIDELINE_PURPOSE="불필요한 원격 접속을 제한하여 DB 서버로의 무단 접근 방지"
GUIDELINE_THREAT="원격에서 제한없이 DB 접속 가능 시 무단 접근 및 데이터 유출 위험"
GUIDELINE_CRITERIA_GOOD="원격 접속이 적절하게 제한된 경우"
GUIDELINE_CRITERIA_BAD="원격에서 모든 호스트의 접속이 허용된 경우"
GUIDELINE_REMEDIATION="pg_hba.conf에서 특정 IP 대역만 허용하도록 설정: host all all 192.168.1.0/24 md5"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="GOOD"
    local status="양호"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local vulnerabilities_found=0

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

    # pg_hba.conf 위치 확인
    local pg_hba_path=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "SHOW hba_file;" 2>/dev/null | xargs || echo "")

    if [ -n "$pg_hba_path" ] && [ -f "$pg_hba_path" ]; then
        # 원격 접속 설정 확인 (0.0.0.0/0 또는 ::/0)
        local remote_access=$(grep -E "^\s*host\s+all\s+all\s+0\.0\.0\.0/0\s+" "$pg_hba_path" 2>/dev/null || echo "")
        local remote_access_cidr=$(grep -E "^\s*host\s+all\s+all\s+::/0\s+" "$pg_hba_path" 2>/dev/null || echo "")

        if [ -n "$remote_access" ] || [ -n "$remote_access_cidr" ]; then
            ((vulnerabilities_found++)) || true
            inspection_summary="취약: 모든 원격 호스트 접속 허용됨 (0.0.0.0/0 또는 ::/0)"
        else
            # 특정 호스트만 허용되는지 확인
            local remote_host_access=$(grep -E "^\s*host\s+" "$pg_hba_path" | grep -v "127\.0\.0\.1" | grep -v "::1" | grep -v "localhost" || echo "")
            if [ -n "$remote_host_access" ]; then
                inspection_summary="양호: 특정 원격 호스트만 접속 허용됨"
            else
                inspection_summary="양호: 원격 접속 제한됨 (로컬만 허용)"
            fi
        fi
    else
        # pg_hba.conf를 찾을 수 없는 경우 기본 위치 확인
        local default_paths=("/etc/postgresql/*/main/pg_hba.conf" "/var/lib/pgsql/data/pg_hba.conf" "/usr/local/pgsql/data/pg_hba.conf")
        local found_conf=0

        for path in "${default_paths[@]}"; do
            if ls $path &>/dev/null; then
                found_conf=1
                pg_hba_path=$(ls $path 2>/dev/null | head -1)
                break
            fi
        done

        if [ $found_conf -eq 1 ] && [ -f "$pg_hba_path" ]; then
            local remote_access=$(grep -E "^\s*host\s+all\s+all\s+0\.0\.0\.0/0\s+" "$pg_hba_path" 2>/dev/null || echo "")
            if [ -n "$remote_access" ]; then
                ((vulnerabilities_found++)) || true
                inspection_summary="취약: 모든 원격 호스트 접속 허용됨"
            else
                inspection_summary="양호: 원격 접속 제한됨"
            fi
        else
            inspection_summary="수동진단: pg_hba.conf 파일 위치 확인 필요"
        fi
    fi

    if [ $vulnerabilities_found -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
    else
        diagnosis_result="GOOD"
        status="양호"
    fi
    command_executed="grep host ${pg_hba_path:-/etc/postgresql/*/main/pg_hba.conf}"

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
