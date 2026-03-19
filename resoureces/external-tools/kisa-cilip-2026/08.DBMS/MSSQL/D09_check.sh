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
# @Platform    : MSSQL
# @Severity    : 중
# @Title       : 일정횟수의로그인실패시이에대한잠금정책설정
# @Description : 보안 감사 로그 기록 및 관리를 통한 추적성 확보
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

ITEM_ID="D-09"
ITEM_NAME="일정횟수의로그인실패시이에대한잠금정책설정"
SEVERITY="중"

GUIDELINE_PURPOSE="DBMS 설정 중 일정 횟수의 로그인 실패 시 계정 잠금 정책에 대한 설정이 되어있는지 점검"
GUIDELINE_THREAT="일정한 횟수의 로그인 실패 횟수를 설정하여 제한하지 않으면 자동화된 방법으로 계정 및 비밀번호를 획득하여 데이터베이스에 접근하여 정보가 유출될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그인 시도 횟수를 제한하는 값을 설정한 경우"
GUIDELINE_CRITERIA_BAD="로그인 시도 횟수를 제한하는 값을 설정하지 않은 경우"
GUIDELINE_REMEDIATION="로그인 시도 횟수 제한값 설정"

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

    # Windows 계정 잠금 정책 확인
    inspection_summary="MSSQL 로그인 잠금 정책 확인\n\n"
    inspection_summary="MSSQL은 Windows 계정 정책을 따르므로 계정 잠금 정책 설정 필요\n\n"
    inspection_summary="검증 방법:\n"
    inspection_summary+="1. Windows 로컬 보안 정책 실행:\n"
    inspection_summary+="   - secpol.msc 실행\n"
    inspection_summary+="   - 보안 설정 > 계정 정책 > 계정 잠금 정책\n\n"
    inspection_summary+="2. 계정 잠금 임계값(Account Lockout Threshold) 확인:\n"
    inspection_summary+="   - 양호: 3~5회 이하로 설정 (예: 3 = 3회 실패 시 잠금)\n"
    inspection_summary+="   - 취약: 0으로 설정 (잠금 정책 없음)\n\n"
    inspection_summary+="3. 계정 잠금 기간(Account Lockout Duration) 확인:\n"
    inspection_summary+="   - 권장: 15분~30분 (예: 30 = 30분 동안 잠금)\n\n"
    inspection_summary+="4. 잠금 카운터 재설정 시간(Reset Account Lockout Counter After) 확인:\n"
    inspection_summary+="   - 계정 잠금 기간과 동일하게 설정 권장\n\n"
    inspection_summary="조치 방법:\n"
    inspection_summary+="1. 계정 잠금 임계값: 3~5회 설정\n"
    inspection_summary+="2. 계정 잠금 기간: 15~30분 설정\n"
    inspection_summary+="3. 잠금 카운터 재설정 시간: 잠금 기간과 동일하게 설정\n\n"
    inspection_summary="참고:\n"
    inspection_summary+="- Windows 인증 모드 사용 시 Windows 계정 정책 적용\n"
    inspection_summary+="- SQL Server 인증 사용 시 별도 정책 설정 필요"

    if command -v net.exe &> /dev/null; then
        command_executed="net accounts"
        command_result=$(net.exe 2>/dev/null || echo "")
        if [ -n "$command_result" ]; then
            inspection_summary+="\n\n검증 결과:\n${command_result}"
        fi
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
