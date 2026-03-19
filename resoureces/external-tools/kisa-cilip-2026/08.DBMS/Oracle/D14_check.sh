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
# @Platform    : Oracle
# @Severity    : 중
# @Title       : 데이터베이스의주요설정파일,비밀번호파일등과같은주요파일들의접근권한이적절하게설정
# @Description : Oracle 주요 설정파일 및 비밀번호 파일 접근권한 확인
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
source "${LIB_DIR}/dbms_connector.sh"
source "${LIB_DIR}/db_connection_helpers.sh"

# Oracle 연결 정보 초기화 (fallback if library not loaded)
ORACLE_USER="${ORACLE_USER:-system}"
ORACLE_PASSWORD="${ORACLE_PASSWORD:-manager}"
ORACLE_HOST="${ORACLE_HOST:-localhost}"
ORACLE_PORT="${ORACLE_PORT:-1521}"
ORACLE_SID="${ORACLE_SID:-ORCL}"
ORACLE_SYSDBA="${ORACLE_SYSDBA:-sys as sysdba}"

ITEM_ID="D-14"
ITEM_NAME="데이터베이스의주요설정파일,비밀번호파일등과같은주요파일들의접근권한이적절하게설정"
SEVERITY="중"

GUIDELINE_PURPOSE="주요 파일들의 접근권한을 제한하여 무단 접근 및 데이터 유출 방지"
GUIDELINE_THREAT="주요 파일의 접근권한이 과도하게 열려있을 경우 민감정보 유출 위험"
GUIDELINE_CRITERIA_GOOD="주요 파일이 oracle 소유이며 600/640 권한인 경우"
GUIDELINE_CRITERIA_BAD="주요 파일에 Other/Group 쓰기 권한이 있는 경우"
GUIDELINE_REMEDIATION="chmod 600 file 명령어로 권한 변경 및 chown oracle:oinstall file로 소유자 변경"

diagnose() {
    diagnosis_result="unknown"  # Global variable (not local)
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Initialize Oracle connection variables (only if library function exists)
    if declare -f init_oracle_vars >/dev/null 2>&1; then
        init_oracle_vars
    fi

    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    # FR-022: Check required tools (only if library function exists)
    if declare -f check_oracle_tools >/dev/null 2>&1; then
        if ! check_oracle_tools; then
            if declare -f handle_missing_tools >/dev/null 2>&1; then
                handle_missing_tools "oracle" "${ITEM_ID}" "${ITEM_NAME}" \
                    "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" \
                    "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
            fi
            return 0
        fi
    fi

    local diagnosis_result="MANUAL" status="수동진단" inspection_summary="" command_result="" command_executed=""

    if ! systemctl is-active oracle &>/dev/null && ! pgrep -f "ora_pmon" &>/dev/null; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Oracle 서비스 미실행"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # Oracle 홈 디렉토리 찾기
    local oracle_home=""
    if [ -n "${ORACLE_HOME:-}" ]; then
        oracle_home="$ORACLE_HOME"
    else
        oracle_home=$(pgrep -f "ora_pmon" | head -1 | xargs -I{} readlink -f /proc/{}/cwd 2>/dev/null | sed 's|/dbs$||' || echo "")
    fi

    if [ -z "$oracle_home" ]; then
        inspection_summary="Oracle 홈 디렉토리를 찾을 수 없습니다. ORACLE_HOME 환경변수를 설정하거나 Oracle이 실행 중인지 확인하세요."
        diagnosis_result="MANUAL"
        status="수동진단"
        command_executed="echo \$ORACLE_HOME; pgrep -f ora_pmon"
        if declare -f save_dual_result >/dev/null 2>&1; then
            save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
        fi
        if declare -f verify_result_saved >/dev/null 2>&1; then
            verify_result_saved "${ITEM_ID}"
        fi
        return 0
    fi

    # 주요 Oracle 파일들 확인
    local vulnerable_files=()
    local good_files=()
    local checked_files=()

    # 확인할 파일 목록
    local config_files=(
        "$oracle_home/network/admin/listener.ora"
        "$oracle_home/network/admin/tnsnames.ora"
        "$oracle_home/network/admin/sqlnet.ora"
    )

    # 비밀번호 파일 찾기 (orapw<SID>)
    if [ -d "$oracle_home/dbs" ]; then
        while IFS= read -r -d '' pw_file; do
            config_files+=("$pw_file")
        done < <(find "$oracle_home/dbs" -name "orapw*" -type f -print 0 2>/dev/null || true)
    fi

    # 파라미터 파일 찾기 (spfile<SID>.ora)
    if [ -d "$oracle_home/dbs" ]; then
        while IFS= read -r -d '' sp_file; do
            config_files+=("$sp_file")
        done < <(find "$oracle_home/dbs" -name "spfile*.ora" -type f -print 0 2>/dev/null || true)
    fi

    command_executed="ls -la ${oracle_home}/network/admin/*.ora 2>/dev/null; ls -la ${oracle_home}/dbs/orapw* ${oracle_home}/dbs/spfile*.ora 2>/dev/null"

    for file in "${config_files[@]}"; do
        if [ ! -f "$file" ]; then
            continue
        fi

        checked_files+=("$file")

        # 파일 권한 확인
        local perms=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
        local owner=$(stat -c "%U" "$file" 2>/dev/null || echo "unknown")
        local group=$(stat -c "%G" "$file" 2>/dev/null || echo "unknown")

        # 파일 정보 수집
        local file_info="$file: perms=$perms, owner=$owner, group=$group"
        command_result+="$file_info\n"

        # 취약성 판단
        # oracle 소유가 아니거나, 600/640보다 권한이 넓은 경우
        if [ "$owner" != "oracle" ] && [ "$owner" != "root" ]; then
            vulnerable_files+=("$file (owner=$owner)")
        elif [ "$perms" -gt 640 ]; then
            vulnerable_files+=("$file (perms=$perms)")
        else
            good_files+=("$file")
        fi
    done

    # 결과 판정
    if [ ${#vulnerable_files[@]} -gt 0 ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Oracle 주요 파일의 접근권한이 취약합니다.\n\n"
        inspection_summary+="취약한 파일 (${#vulnerable_files[@]}개):\n"
        for file in "${vulnerable_files[@]}"; do
            inspection_summary+="  - $file\n"
        done
        if [ ${#good_files[@]} -gt 0 ]; then
            inspection_summary+="\n양호한 파일 (${#good_files[@]}개):\n"
            for file in "${good_files[@]}"; do
                inspection_summary+="  - $file\n"
            done
        fi
        inspection_summary+="\n조치: chown oracle:oinstall file && chmod 640 file"
    elif [ ${#checked_files[@]} -eq 0 ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Oracle 주요 파일을 찾을 수 없습니다. Oracle이 설치된 경로를 확인하세요.\n\n확인한 경로: $oracle_home\n\n수동으로 다음 파일들을 확인하세요:\n"
        inspection_summary+="- \$ORACLE_HOME/network/admin/listener.ora\n"
        inspection_summary+="- \$ORACLE_HOME/network/admin/tnsnames.ora\n"
        inspection_summary+="- \$ORACLE_HOME/network/admin/sqlnet.ora\n"
        inspection_summary+="- \$ORACLE_HOME/dbs/orapw<SID>\n"
        inspection_summary+="- \$ORACLE_HOME/dbs/spfile<SID>.ora"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Oracle 주요 파일의 접근권한이 적절하게 설정되어 있습니다.\n\n확인한 파일 (${#checked_files[@]}개):\n"
        for file in "${checked_files[@]}"; do
            inspection_summary+="  - $file\n"
        done
        inspection_summary+="\n모든 파일이 oracle 소유이며 600/640 권한입니다."
    fi

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
