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
# @Platform    : MSSQL
# @Severity    : 중
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

# Initialize MSSQL connection variables
init_mssql_vars

ITEM_ID="D-07"
ITEM_NAME="root권한으로서비스구동제한"
SEVERITY="중"

GUIDELINE_PURPOSE="서비스 구동 시 root 계정 또는 root 권한으로 구동되는지 점검"
GUIDELINE_THREAT="root 권한으로 서비스를 구동할 경우 시스템 손상, 데이터 유출 및 변조, 감사 및 추적의 어려움 등으로 인해 서비스 공격의 표적이 될 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DBMS가 root 계정 또는 root 권한이 아닌 별도의 계정 및 권한으로 구동되고 있는 경우"
GUIDELINE_CRITERIA_BAD="DBMS가 root 계정 또는 root 권한으로 구동되고 있는 경우"
GUIDELINE_REMEDIATION="DBMS 구동 계정 변경"

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

    # MSSQL 서비스 계정 확인
    inspection_summary="MSSQL 서비스 계정 권한 점검\n\n"
    inspection_summary+="검증 방법:\n\n"
    inspection_summary+="1. SQL Server Configuration Manager 실행:\n"
    inspection_summary+="   - SQL Server Services > SQL Server(MSSQLSERVER) > 속성\n\n"
    inspection_summary+="2. 'Built-in account' 또는 'This account' 확인:\n"
    inspection_summary+="   - 양호: Local System, Local Service, Network Service 이외의 전용 계정 사용\n"
    inspection_summary+="   - 취약: Local System 계정 사용 (권한 상승 위험)\n\n"
    inspection_summary+="3. PowerShell 명령어로 확인:\n"
    inspection_summary+="   Get-WmiObject win32_service | Where-Object {\$_.Name -like '*SQL*'} | Select-Object Name, StartName, State\n\n"
    inspection_summary+="보안 가이드:\n"
    inspection_summary+="- Local System: 최고 권한 (사용 권장하지 않음)\n"
    inspection_summary+="- Network Service: 네트워크 리소스 접근 가능\n"
    inspection_summary+="- Local Service: 제한된 로컬 권한 (권장)\n"
    inspection_summary+="- 전용 서비스 계정: 최소 권한으로 구성 (가장 권장)\n\n"
    inspection_summary+="조치 방법:\n"
    inspection_summary+="1. SQL Server Configuration Manager 실행\n"
    inspection_summary+="2. SQL Server 서비스 > 속성 > 로그온 탭\n"
    inspection_summary+="3. 'This account' 선택 > 전용 서비스 계정 입력\n"
    inspection_summary+="4. 서비스 재시작"

    if command -v powershell.exe &> /dev/null; then
        command_executed="powershell.exe -Command \"Get-WmiObject win32_service | Where-Object {\\$_.Name -like '*SQL*'} | Select-Object Name, StartName, State\""
        command_result=$(powershell.exe -Command "Get-WmiObject win32_service | Where-Object {\$_.Name -like '*SQL*'} | Select-Object Name, StartName, State" 2>/dev/null || echo "")
        inspection_summary+="\n\n검증 결과:\n${command_result}"
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
