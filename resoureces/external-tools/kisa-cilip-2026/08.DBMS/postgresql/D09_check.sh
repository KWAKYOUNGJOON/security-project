#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-09
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 중
# @Title       : 일정횟수의로그인실패시이에대한잠금정책설정
# @Description : PostgreSQL auth_delay 확장 및 pg_hba.conf로 로그인 실패 잠금 정책 확인
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

ITEM_ID="D-09"
ITEM_NAME="일정횟수의로그인실패시이에대한잠금정책설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="일정 횟수의 로그인 실패 시 계정 잠금 정책을 설정하여 비인가자의 무차별 대입 공격, 사전 대입 공격 등을 통한 사용자 계정 비밀번호 유출 방지"
GUIDELINE_THREAT="일정한 횟수의 로그인 실패 횟수를 설정하여 제한하지 않으면 자동화된 방법으로 계정 및 비밀번호를 획득하여 데이터베이스에 접근하여 정보가 유출될 위험 존재"
GUIDELINE_CRITERIA_GOOD="로그인시도횟수를제한하는값을설정한경우"
GUIDELINE_CRITERIA_BAD="로그인시도횟수를제한하는값을설정하지않은경우"
GUIDELINE_REMEDIATION="auth_delay 확장 모듈 설치 및 pg_hba.conf에서 연결 제한 설정"

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

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_postgresql_tools; then
        handle_missing_tools "postgresql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # PostgreSQL 서비스 확인
    local postgres_running=false
    if command -v pgrep >/dev/null 2>&1; then
        if pgrep -x "postmaster" >/dev/null 2>&1 || pgrep -x "postgres" >/dev/null 2>&1; then
            postgres_running=true
        fi
    fi

    if [ "$postgres_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="PostgreSQL 서비스 미실행"
        command_result="PostgreSQL process not found"
        command_executed="pgrep -x postmaster; pgrep -x postgres"

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
    fi

    # auth_delay 확장 모듈 확인
    local auth_delay_installed=false
    local auth_delay_configured=false
    local pg_hba_has_limits=false
    local details=""

    # 1. auth_delay 확장 설치 여부 확인
    local auth_delay_check=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SELECT * FROM pg_available_extensions WHERE name='auth_delay';" 2>/dev/null || echo "")

    if [ -z "$auth_delay_check" ]; then
        auth_delay_check=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SELECT * FROM pg_available_extensions WHERE name='auth_delay';" 2>/dev/null || echo "")
    fi

    if [ -n "$auth_delay_check" ]; then
        # 확장이 설치 가능한지 확인
        local auth_delay_installed_check=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SELECT * FROM pg_extension WHERE extname='auth_delay';" 2>/dev/null || echo "")

        if [ -z "$auth_delay_installed_check" ]; then
            auth_delay_installed_check=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SELECT * FROM pg_extension WHERE extname='auth_delay';" 2>/dev/null || echo "")
        fi
        if [ -n "$auth_delay_installed_check" ]; then
            auth_delay_installed=true
            details="[auth_delay 확장] 설치됨"
        else
            details="[auth_delay 확장] 설치 가능하지만 활성화되지 않음"
        fi
    else
        details="[auth_delay 확장] 미설치 (PostgreSQL 14+에서 사용 가능)"
    fi

    # 2. pg_hba.conf 연결 제한 설정 확인
    local pg_hba_conf=""
    pg_hba_conf=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SHOW hba_file;" 2>/dev/null | head -1 || echo "")

    if [ -z "$pg_hba_conf" ]; then
        pg_hba_conf=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SHOW hba_file;" 2>/dev/null | head -1 || echo "")
    fi

    if [ -f "$pg_hba_conf" ]; then
        # pg_hba.conf에서 connection limit 설정 확인
        local max_connections=$(psql -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SHOW max_connections;" 2>/dev/null || echo "")

        if [ -z "$max_connections" ]; then
            max_connections=$(PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -t -A -c "SHOW max_connections;" 2>/dev/null || echo "")
        fi

        # pg_hba.conf 내용 확인 (주석 제외)
        local hba_content=$(grep -v "^#" "$pg_hba_conf" | grep -v "^$" | head -20 || echo "")

        if [ -n "$hba_content" ]; then
            details="${details}
[pg_hba.conf] ${pg_hba_conf}
"

            # max_conn 설정 확인
            if [ -n "$max_connections" ]; then
                details="${details}max_connections=${max_connections}"
            fi

            # 연결 제한 설정이 있는지 확인
            if echo "$hba_content" | grep -q "max_conn"; then
                pg_hba_has_limits=true
                details="${details}, 연결 제한 설정 있음"
            else
                details="${details}, 연결 제한 설정 없음"
            fi
        fi

        command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"SELECT * FROM pg_extension WHERE extname='auth_delay';\"; cat ${pg_hba_conf}"
    else
        details="${details}
[pg_hba.conf] 파일을 찾을 수 없음"
        command_executed="psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres -c \"SHOW hba_file;\""
    fi

    command_result="${details}"

    # 최종 판정
    # auth_delay가 설치되어 있거나 pg_hba.conf에 연결 제한이 있으면 양호
    if [ "$auth_delay_installed" = true ] || [ "$pg_hba_has_limits" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="PostgreSQL 로그인 실패 방어 정책이 설정되어 있습니다. (${details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="PostgreSQL 로그인 실패 잠금 정책이 미설정되었습니다. 1) auth_delay 확장 설치: CREATE EXTENSION auth_delay; 2) pg_hba.conf에 연결 제한 설정 권장. (${details})"
    fi

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
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
