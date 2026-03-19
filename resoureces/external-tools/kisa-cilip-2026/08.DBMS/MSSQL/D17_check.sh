#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-17
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 하
# @Title       : AuditTable은데이터베이스관리자계정으로접근하도록제한
# @Description : 불필요한 계정 관리 및 권한 제어를 통한 보안 강화
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
ITEM_ID="D-17"
ITEM_NAME="AuditTable은데이터베이스관리자계정으로접근하도록제한"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="Audit Table 접근권한을 관리자 계정으로 제한하여 비인가자의 감사 데이터 수정/삭제 방지"
GUIDELINE_THREAT="Audit Table이 DBA 외 계정으로 접근 가능 시 감사 데이터 무결성 훼손 및 보안 사고 원인 분석 불가"
GUIDELINE_CRITERIA_GOOD="Audit Table 접근권한이 SYS/SYSTEM 등 DBA 계정으로만 설정된 경우"
GUIDELINE_CRITERIA_BAD="Audit Table 접근권한이 일반 계정으로 설정된 경우"
GUIDELINE_REMEDIATION="REVOKE privilege ON AUD$ FROM username; 명령어로 일반 계정 권한 취소"

# ============================================================================
# 진단 함수
# ============================================================================

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools
    if ! check_mssql_tools; then
        handle_missing_tools "mssql" "${ITEM_ID}" "${ITEM_NAME}" \
            "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
            "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        return 0
    fi


    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # D-17은 Oracle AUD$ 테이블 전용 항목
    # MSSQL은 다른 감사 메커니즘을 사용하므로 N/A 처리

    diagnosis_result="N/A"
    status="N/A"
    inspection_summary="이 항목은 Oracle AUD$ 테이블 전용 항목입니다. MSSQL은 SQL Server Audit 기능을 사용합니다. MSSQL 감사 활성화 여부 확인: SELECT * FROM sys.dm_server_audit_status;. 감사 로그 접근 제한: GRANT ALTER, CONTROL ON SERVER AUDIT::[AuditName] TO [login];. 권장: sysadmin 역할의 멤버만 감사 로그에 접근하도록 제한."
    command_result="MSSQL uses SQL Server Audit, not Oracle AUD$ table"
    command_executed="SELECT name, audit_file_path FROM sys.dm_server_audit_status;"

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
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
