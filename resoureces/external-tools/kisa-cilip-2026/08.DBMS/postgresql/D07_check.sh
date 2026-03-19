#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-07
# @Category    : DBMS (Database Management System)
# @Platform    : PostgreSQL
# @Severity    : 상
# @Title       : root권한으로서비스구동제한
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

ITEM_ID="D-07"
ITEM_NAME="root권한으로서비스구동제한"
SEVERITY="상"

GUIDELINE_PURPOSE="DBMS 서비스가 root 권한으로 구동되지 않도록 하여 root 권한 탈취 시 피해 최소화"
GUIDELINE_THREAT="root 권한으로 DBMS 구동 시 DBMS 취약점 악용 시 root 권한 탈취 가능"
GUIDELINE_CRITERIA_GOOD="DBMS가 root가 아닌 전용 계정으로 구동되는 경우"
GUIDELINE_CRITERIA_BAD="DBMS가 root 권한으로 구동되는 경우"
GUIDELINE_REMEDIATION="PostgreSQL 전용 계정(postgres)으로 서비스 구동: systemctl restart postgresql"

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

    # PostgreSQL 프로세스 확인
    if ! pgrep -f "postgres" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="PostgreSQL 서비스 미실행"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # PostgreSQL 프로세스 소유자 확인
    command_executed="ps -ef | grep 'postgres' | grep -v grep | awk '{print \$1}' | sort -u"
    command_result=$(ps -ef | grep 'postgres' | grep -v grep | awk '{print $1}' | sort -u || echo "")

    if [ -n "$command_result" ]; then
        # root로 실행 중인지 확인
        if echo "$command_result" | grep -q "^root$"; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="취약: PostgreSQL 프로세스가 root 권한으로 실행 중"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="양호: PostgreSQL이 $(echo "$command_result" | tr '\n' ' ' | xargs) 계정으로 실행 중 (root 아님)"
        fi
    else
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="수동진단: PostgreSQL 프로세스 확인 불가"
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
