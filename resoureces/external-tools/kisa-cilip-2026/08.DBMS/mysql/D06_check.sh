#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-06
# @Category    : DBMS (Database Management System)
# @Platform    : MySQL
# @Severity    : 상
# @Title       : DB사용자계정을개별적으로부여하여사용
# @Description : 공유 계정 사용 유무를 점검하여 개별 계정 사용을 확인
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드 (실패 시 계속 진행)
for lib in common.sh command_validator.sh timeout_handler.sh result_manager.sh output_mode.sh db_connection_helpers.sh; do
    [ -f "${LIB_DIR}/${lib}" ] && source "${LIB_DIR}/${lib}" || true
done

ITEM_ID="D-06"
ITEM_NAME="DB사용자계정을개별적으로부여하여사용"
SEVERITY="상"

GUIDELINE_PURPOSE="DB 사용자 계정을 개별 부여하여 공유 계정 사용을 방지하고 사용자별 책임성을 확보하기 위함"
GUIDELINE_THREAT="공유 계정 사용 시 보안 incident 발생 시 책임 소재 파악 어려움"
GUIDELINE_CRITERIA_GOOD="사용자별 개별 계정을 부여하여 사용하는 경우"
GUIDELINE_CRITERIA_BAD="다중 사용자가 공유 계정을 사용하는 경우"
GUIDELINE_REMEDIATION="사용자별 개별 계정 생성 및 공유 계정 삭제"

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

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # MySQL/MariaDB 서비스 확인 (only if library function exists)
    if declare -f check_mysql_service >/dev/null 2>&1; then
        if ! check_mysql_service; then
            if declare -f handle_dbms_not_running >/dev/null 2>&1; then
                handle_dbms_not_running "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    # MySQL 연결 시도 (FR-018) (only if library function exists)
    if declare -f prompt_mysql_connection >/dev/null 2>&1; then
        if ! prompt_mysql_connection; then
            if declare -f handle_dbms_connection_failed >/dev/null 2>&1; then
                handle_dbms_connection_failed "mysql" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    # 전체 계정 목록 확인
    local users_query="SELECT user, host FROM mysql.user ORDER BY user, host;"
    command_executed="mysql -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p*** -e \"${users_query}\""
    command_result=$(mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "${users_query}" 2>/dev/null || echo "")

    # 공유 계정 의심 이름 확인 (shared, public, common 등)
    local shared_accounts=$(echo "$command_result" | tail -n +2 | grep -v "^$" | grep -iE "^(shared|public|common|generic|group|team)" || echo "")

    if [ -n "$shared_accounts" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="의심되는 공유 계정 발견: $(echo "$shared_accounts" | head -5 | tr '\n' ', ')"
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="공유 계정 여부는 수동 확인 필요 (계정 목록: $(echo "$command_result" | wc -l)개)"
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
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
