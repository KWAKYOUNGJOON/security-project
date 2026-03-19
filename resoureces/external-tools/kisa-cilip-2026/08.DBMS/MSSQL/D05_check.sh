#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-05
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 중
# @Title       : 비밀번호재사용에대한제약설정
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

ITEM_ID="D-05"
ITEM_NAME="비밀번호재사용에대한제약설정"
SEVERITY="중"

GUIDELINE_PURPOSE="비밀번호 변경 시 이전 비밀번호를 재사용할 수 없도록 비밀번호 제약 설정이 되어있는지 점검"
GUIDELINE_THREAT="비밀번호 재사용 제약 설정이 적용되어 있지 않을 경우 비밀번호 변경 전 사용했던 비밀번호를 재사용함으로써 비인가자의 계정 비밀번호 추측 공격에 대한 시간을 더 많이 허용하여 비밀번호 유출 위험이 증가함"
GUIDELINE_CRITERIA_GOOD="Windows 비밀번호 정책에서 비밀번호 기억 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="비밀번호 재사용 제한 설정이 적용되지 않은 경우"
GUIDELINE_REMEDIATION="Windows 로컬 보안 정책 > 계정 정책 > 비밀번호 정책 > '비밀번호 기억' 값 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # MSSQL 서비스 확인
    if command -v powershell.exe &> /dev/null; then
        local mssql_running=$(powershell.exe -Command "Get-Service | Where-Object {\$_.Name -like '*SQL*' -and \$_.Status -eq 'Running'} | Measure-Object | Select-Object -ExpandProperty Count" 2>/dev/null || echo "0")

        if [ "$mssql_running" = "0" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="MSSQL 서비스 미실행"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"
            return 0
        fi
    else
        inspection_summary="MSSQL 진단 스크립트는 Windows 환경에서 실행해야 합니다"
        diagnosis_result="MANUAL"
        status="수동진단"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # Windows 비밀번호 정책 확인
    inspection_summary="MSSQL 비밀번호 재사용 제약 설정 확인\n\n"
    inspection_summary+="검증 방법:\n"
    inspection_summary+="1. Windows 로컬 보안 정책 실행:\n"
    inspection_summary+="   - secpol.msc 실행\n"
    inspection_summary+="   - 보안 설정 > 계정 정책 > 비밀번호 정책\n\n"
    inspection_summary+="2. '비밀번호 기억(Enforce Password History)' 설정 확인:\n"
    inspection_summary+="   - 양호: 0 이상의 값으로 설정 (예: 24 = 최근 24개 비밀번호 재사용 금지)\n"
    inspection_summary+="   - 취약: 0으로 설정 (비밀번호 재사용 제한 없음)\n\n"
    inspection_summary+="조치 방법:\n"
    inspection_summary+="'비밀번호 기억' 값을 24 이상으로 설정\n"
    inspection_summary+="- 기본값: 0 (최근 비밀번호 기억 안함)\n"
    inspection_summary+="- 권장값: 24 (최근 24개 비밀번호 재사용 금지)\n\n"
    inspection_summary+="참고: MSSQL은 Windows 비밀번호 정책을 따르므로 CHECK_POLICY와 CHECK_EXPIRATION 옵션이 활성화된 경우 Windows 정책이 적용됨"

    command_executed="MSSQL 비밀번호 정책 확인 (수동 점검 필요)"
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
