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
# @Platform    : MSSQL
# @Severity    : 상
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

# Initialize MSSQL connection variables
init_mssql_vars

ITEM_ID="D-10"
ITEM_NAME="원격에서DB서버로의접속제한"
SEVERITY="상"

GUIDELINE_PURPOSE="지정된 IP 주소만 DB 서버에 접근 가능하도록 설정되어있는지 점검"
GUIDELINE_THREAT="DB 서버 접속 시 IP 주소 제한이 적용되지 않은 경우 비인가자가 내·외부망 위치에 상관없이 DB 서버에 접근할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한한 경우"
GUIDELINE_CRITERIA_BAD="DB 서버에 지정된 IP 주소에서만 접근 가능하도록 제한하지 않은 경우"
GUIDELINE_REMEDIATION="DB 서버에 대해 지정된 IP 주소에서만 접근 가능하도록 설정"

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

    # sqlcmd 명령 확인
    if ! command -v sqlcmd &> /dev/null; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="sqlcmd 도구를 찾을 수 없습니다. SQL Server Command Line Tools 설치 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="SQL Server Configuration Manager에서 IP 주소 제한 확인"
        save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        verify_result_saved "${ITEM_ID}"
        return 0
    fi

    # 방화벽 규칙 확인
    inspection_summary="MSSQL 원격 접속 제한 확인\n\n"
    inspection_summary+="검증 방법:\n\n"
    inspection_summary+="1. SQL Server Configuration Manager:\n"
    inspection_summary+="   - SQL Server Network Configuration > Protocols for MSSQLSERVER\n"
    inspection_summary+="   - Properties > IP Addresses 탭\n"
    inspection_summary+="   - IPAll > TCP Dynamic Ports: 비움\n"
    inspection_summary+="   - IPAll > TCP Port: 특정 포트 지정\n\n"
    inspection_summary+="2. Windows 방화벽 규칙 확인:\n"
    inspection_summary+="   - PowerShell: Get-NetFirewallRule | Where-Object {\$_.DisplayName -like '*SQL*'}\n"
    inspection_summary+="   - 양호: 특정 IP 주소에서만 허용하는 규칙 존재\n"
    inspection_summary+="   - 취약: 모든 IP(0.0.0.0/0)에서 접속 허용\n\n"
    inspection_summary+="조치 방법:\n"
    inspection_summary+="1. SQL Server Configuration Manager에서 IP 제한 설정\n"
    inspection_summary+="2. Windows Firewall에서 특정 IP만 허용하는 인바운드 규칙 생성\n"
    inspection_summary+="3. 원격 접속이 필요없으면 TCP/IP 비활성화"

    if command -v powershell.exe &> /dev/null; then
        command_executed="powershell.exe -Command \"Get-NetFirewallRule | Where-Object {\\$_.DisplayName -like '*SQL*'} | Select-Object DisplayName, Enabled, Direction\""
        command_result=$(powershell.exe -Command "Get-NetFirewallRule | Where-Object {\$_.DisplayName -like '*SQL*'} | Select-Object DisplayName, Enabled, Direction" 2>/dev/null || echo "")
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
