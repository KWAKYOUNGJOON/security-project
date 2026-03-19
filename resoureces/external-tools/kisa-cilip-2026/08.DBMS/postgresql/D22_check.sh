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
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : DBMS 데이터 디렉터리 권한 점검
# @Description : 과도한 권한 부여 방지 및 최소 권한 원칙 적용
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

ITEM_ID="D-22"
ITEM_NAME="DBMS 데이터 디렉터리 권한 점검"
SEVERITY="중"

GUIDELINE_PURPOSE="데이터 디렉터리 접근 권한 제한으로 무단 접근 방지"
GUIDELINE_THREAT="데이터 디렉터리 권한 미흡 시 데이터 파일 무단 접근 가능"
GUIDELINE_CRITERIA_GOOD="데이터 디렉터리 권한이 적절히 설정된 경우"
GUIDELINE_CRITERIA_BAD="권한이 열려 있는 경우"
GUIDELINE_REMEDIATION="chmod 700 /var/lib/postgresql/[version]/main && chown postgres:postgres /var/lib/postgresql/[version]/main"

# PostgreSQL 연결 정보 초기화
DB_ADMIN_USER="${DB_ADMIN_USER:-postgres}"
DB_ADMIN_PASS="${DB_ADMIN_PASS:-}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5432}"

# PostgreSQL 연결 프롬프트 (FR-018)
check_postgresql_connection() {
    if [ -z "${DB_ADMIN_PASS}" ] && [ -t 0 ]; then
        echo "[INFO] PostgreSQL 연결 정보 입력이 필요합니다."
        read -p "PostgreSQL Host [${DB_HOST}]: " input_host
        DB_HOST="${input_host:-$DB_HOST}"

        read -p "PostgreSQL Port [${DB_PORT}]: " input_port
        DB_PORT="${input_port:-$DB_PORT}"

        read -p "PostgreSQL Username [${DB_ADMIN_USER}]: " input_user
        DB_ADMIN_USER="${input_user:-$DB_ADMIN_USER}"

        read -s -p "PostgreSQL Password: " input_pass
        echo ""
        DB_ADMIN_PASS="${input_pass}"
    fi

    # 3회 재시도 로직
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        # Try Unix socket connection first (peer authentication in Docker)
        if psql -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] PostgreSQL 연결 성공 (Unix socket)"
            export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
            return 0
        fi

        # Fall back to TCP connection with password
        if PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] PostgreSQL 연결 성공 (TCP)"
            export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
            return 0
        fi

        ((retry_count++)) || true
        if [ $retry_count -lt $max_retries ]; then
            echo "[WARN] PostgreSQL 연결 실패 (${retry_count}/${max_retries}). 2초 후 재시도..."
            sleep 2
        fi
    done

    return 1
}

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

    if ! pg_isready -h "${DB_HOST}" -p "${DB_PORT}" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="PostgreSQL 서비스 미실행"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 데이터 디렉터리 위치 확인
    local data_dir=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -c "SHOW data_directory;" 2>/dev/null | xargs || echo "")

    if [ -z "$data_dir" ]; then
        data_dir=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -c "SHOW data_directory;" 2>/dev/null | xargs || echo "")
    fi

    if [ -n "$data_dir" ] && [ -d "$data_dir" ]; then
        local dir_perms=$(stat -c "%a" "$data_dir" 2>/dev/null || echo "000")
        local dir_owner=$(stat -c "%U:%G" "$data_dir" 2>/dev/null || echo "unknown")

        if [ "$dir_perms" != "700" ] && [ "$dir_perms" != "0700" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="취약: 데이터 디렉터리 권한이 ${dir_perms}로 설정됨 (권장: 700)"
        elif [ "$dir_owner" != "postgres:postgres" ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="취약: 데이터 디렉터리 소유자가 ${dir_owner}임 (권장: postgres:postgres)"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="양호: 데이터 디렉터리 권한 및 소유자 적절히 설정됨 (${dir_perms}, ${dir_owner})"
        fi
    else
        inspection_summary="수동진단: 데이터 디렉터리 위치 확인 필요"
    fi
    command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -t -c \"SHOW data_directory;\" && stat -c \"%a %U:%G\" ${data_dir:-/var/lib/postgresql}"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    # PostgreSQL 연결 확인 (FR-018)
    if ! check_postgresql_connection; then
        diagnosis_result="MANUAL"
        status="수동진단"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
            "PostgreSQL 연결 실패 - 데이터베이스 관리자 비밀번호 확인 필요" \
            "연결 실패: User=${DB_ADMIN_USER}, Host=${DB_HOST}:${DB_PORT}" \
            "psql -U ${DB_ADMIN_USER} -h ${DB_HOST} -p ${DB_PORT} -d postgres" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 1
    fi

    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
