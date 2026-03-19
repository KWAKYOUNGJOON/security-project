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
# @Platform    : MySQL
# @Severity    : 중
# @Title       : 일정횟수의로그인실패시이에대한잠금정책설정
# @Description : MySQL connection_control 플러그인으로 로그인 실패 잠금 정책 확인
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
GUIDELINE_REMEDIATION="connection_control 플러그인 설치 및 임계값 설정"

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

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # MySQL/MariaDB 서비스 확인
    local mysql_running=false
    if command -v pgrep >/dev/null 2>&1; then
        if pgrep -x "mysqld" >/dev/null 2>&1 || pgrep -x "mariadbd" >/dev/null 2>&1; then
            mysql_running=true
        fi
    fi

    if [ "$mysql_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="MySQL/MariaDB 서비스 미실행"
        command_result="MySQL/MariaDB process not found"
        command_executed="pgrep -x mysqld; pgrep -x mariadbd"

        # Save results (only if library function exists)
        if declare -f save_dual_result >/dev/null 2>&1; then
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
        fi

        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # connection_control 플러그인 확인 및 설정 검사
    local plugin_check=""
    local threshold_value=""
    local delay_value=""
    local is_secure=false
    local details=""

    # MySQL 버전 확인 (5.7+ 또는 8.0+ 필요)
    command_executed="mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e \"SELECT VERSION(); SHOW PLUGINS LIKE '%connection_control%'; SHOW VARIABLES LIKE 'connection_control%';\" 2>/dev/null"

    # 플러그인 설치 여부 확인
    plugin_check=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "SHOW PLUGINS LIKE '%connection_control%';" 2>/dev/null || echo "")

    if [ -z "$plugin_check" ]; then
        # MySQL 접속 실패 또는 플러그인 미설치
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="MySQL connection_control 플러그인 확인을 수동으로 진행해야 합니다. MySQL에 접속하여 다음을 확인하세요: 1) INSTALL PLUGIN CONNECTION_CONTROL SONAME 'connection_control.so'; 2) SHOW VARIABLES LIKE 'connection_control_failed_connections_threshold';. 값이 0보다 크면 양호입니다."
        command_result="MySQL 접속 불가 또는 connection_control 플러그인 미설치"

        save_dual_result \
            "${ITEM_ID}" \
            "${ITEM_NAME}" \
            "${status}" \
            "${diagnosis_result}" \
            "${inspection_summary}" \
            "$command_result" \
            "${command_executed}" \
            "${GUIDELINE_PURPOSE}" \
            "${GUIDELINE_THREAT}" \
            "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" \
            "${GUIDELINE_REMEDIATION}"

        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # 플러그인이 설치된 경우 설정값 확인
    threshold_value=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "SHOW VARIABLES LIKE 'connection_control_failed_connections_threshold';" 2>/dev/null | tail -n +2 | awk '{print $2}' || echo "")
    delay_value=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "SHOW VARIABLES LIKE 'connection_control_min_connection_delay';" 2>/dev/null | tail -n +2 | awk '{print $2}' || echo "")

    details="[connection_control 플러그인] 설치됨"
    details="${details}, connection_control_failed_connections_threshold=${threshold_value}"
    details="${details}, connection_control_min_connection_delay=${delay_value}ms"

    # 설정값 분석
    if [ -n "$threshold_value" ] && [ "$threshold_value" != "0" ]; then
        # 실패 횟수 제한이 설정된 경우
        is_secure=true
        details="${details} (임계값 설정됨: ${threshold_value}회)"
    else
        # 실패 횟수 제한이 설정되지 않은 경우
        is_secure=false
        details="${details} (임계값 미설정 또는 0)"
    fi

    if [ -n "$delay_value" ] && [ "$delay_value" != "0" ]; then
        details="${details}, 지연 시간 설정됨: ${delay_value}ms"
    fi

    command_result="${details}"

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="MySQL 로그인 실패 잠금 정책이 적절하게 설정되어 있습니다. (${details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="MySQL connection_control 플러그인이 설치되었지만 실패 잠금 정책이 설정되지 않았습니다. SET GLOBAL connection_control_failed_connections_threshold=3;으로 설정하세요. (${details})"
    fi

    # Save results (only if library function exists)
    if declare -f save_dual_result >/dev/null 2>&1; then
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
    fi

    if declare -f verify_result_saved >/dev/null 2>&1; then
        verify_result_saved "${ITEM_ID}"
    fi

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    if declare -f show_diagnosis_start >/dev/null 2>&1; then
        show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    fi
    if declare -f check_disk_space >/dev/null 2>&1; then
        check_disk_space
    fi

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
    if declare -f show_diagnosis_complete >/dev/null 2>&1; then
        show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
    fi
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
