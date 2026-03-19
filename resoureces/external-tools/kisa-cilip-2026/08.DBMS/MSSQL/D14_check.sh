#!/bin/bash

# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : D-14
# @Category    : DBMS (Database Management System)
# @Platform    : MSSQL
# @Severity    : 중
# @Title       : 데이터베이스의주요설정파일,비밀번호파일등과같은주요파일들의접근권한이적절하게설정
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
ITEM_ID="D-14"
ITEM_NAME="데이터베이스의주요설정파일,비밀번호파일등과같은주요파일들의접근권한이적절하게설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="주요 파일들의 접근권한을 제한하여 무단 접근 및 데이터 유출 방지"
GUIDELINE_THREAT="주요 파일의 접근권한이 과도하게 열려있을 경우 민감정보 유출 위험"
GUIDELINE_CRITERIA_GOOD="주요 파일이 oracle 소유이며 600/640 권한인 경우"
GUIDELINE_CRITERIA_BAD="주요 파일에 Other/Group 쓰기 권한이 있는 경우"
GUIDELINE_REMEDIATION="chmod 600 file 명령어로 권한 변경 및 chown oracle:oinstall file로 소유자 변경"

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

    # D-14는 Oracle/PostgreSQL/Cubrid용 항목 (listener.ora, tnsnames.ora, pg_hba.conf 등)
    # MSSQL은 완전히 다른 파일 구조를 사용하므로 N/A 처리

    diagnosis_result="N/A"
    status="N/A"
    inspection_summary="이 항목은 Oracle(listener.ora, tnsnames.ora), PostgreSQL(pg_hba.conf), Cubrid용 항목입니다. MSSQL은 다음 파일들을 확인하세요: 1) Windows: %PROGRAMFILES%\\Microsoft SQL Server\\MSSQL\\Data\\ 2) Linux: /var/opt/mssql/data/. 권장: SQL Server 서비스 계정만 읽기/쓰기 권한, 관리자 외 제한."
    command_result="MSSQL uses different file structure (mssql.conf, .mdf/.ldf files)"
    command_executed="ls -la /var/opt/mssql/data/ (Linux) or dir %PROGRAMFILES%\\Microsoft SQL Server\\MSSQL\\Data\\ (Windows)"

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
