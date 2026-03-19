#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-23
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 중
# @Title       : DBMS 네트워크 리스너 암호화
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

ITEM_ID="D-23"

ITEM_NAME="DBMS 네트워크 리스너 암호화"
SEVERITY="중"
GUIDELINE_PURPOSE="DBMS 연결 시 SSL/TLS 암호화로 데이터 유출 방지"
GUIDELINE_THREAT="암호화 미사용 시 네트워크 스니핑으로 데이터 유출 위험"
GUIDELINE_CRITERIA_GOOD="SSL/TLS 활성화된 경우"
GUIDELINE_CRITERIA_BAD="암호화 미사용"
GUIDELINE_REMEDIATION="DBMS SSL/TLS 설정 활성화 (수동 설정 필요)"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if command -v sc.exe &>/dev/null; then
        if ! sc.exe query MSSQLSERVER &>/dev/null && ! sc.exe query SQLServerAgent &>/dev/null; then
            diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="MSSQL 서비스 미실행 (서비스 시작 후 수동 확인 필요)"
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            verify_result_saved "${ITEM_ID}"; return 0
        fi
    fi

    if command -v sqlcmd &>/dev/null; then
        command_executed="sqlcmd -Q \"SELECT name, value FROM sys.dm_server_registry WHERE registry_key LIKE '%ForceEncryption%';\""
        inspection_summary="MSSQL 네트워크 암호화 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. 레지스트리 확인:\n"
        inspection_summary+="   - HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLXX.MSSQLServer\\SuperSocketNetLib\\Certificate\n"
        inspection_summary+="   - HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLXX.MSSQLServer\\SuperSocketNetLib\\ForceEncryption\n"
        inspection_summary+="2. ForceEncryption = 1: 양호 (암호화 활성화)\n"
        inspection_summary+="3. ForceEncryption = 0: 취약 (암호화 비활성화)\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- SQL Server Configuration Manager > SQL Server Network Configuration > Protocols > Properties\n"
        inspection_summary+="- Force Encryption: Yes 설정\n"
        inspection_summary+="- Certificate: SSL 인증서 선택\n"
        inspection_summary+="- SQL Server 서비스 재시작"
    else
        inspection_summary="MSSQL 네트워크 암호화 확인 - 수동 확인 필요\n\n"
        inspection_summary+="검증 방법:\n"
        inspection_summary+="1. SQL Server Configuration Manager 실행\n"
        inspection_summary+="2. SQL Server Network Configuration > Protocols for MSSQLSERVER\n"
        inspection_summary+="3. Properties > Flag Protocols 탭 확인\n"
        inspection_summary+="4. Force Encryption = Yes: 양호\n"
        inspection_summary+="5. Force Encryption = No: 취약\n\n"
        inspection_summary+="조치 방법:\n"
        inspection_summary+="- Force Encryption: Yes 설정\n"
        inspection_summary+="- Certificate 탭에서 SSL 인증서 선택\n"
        inspection_summary+="- SQL Server 서비스 재시작\n"
        inspection_summary+="- 클라이언트 연결 시 Encrypt=True 옵션 사용"
    fi

    diagnosis_result="MANUAL" status="수동진단"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"; return 0
}

main() {
    diagnose
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
