#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-09
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : 웹서비스프로세스권한제한
# @Description : 웹 서비스 프로세스의 권한 제한 설정 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==========================================================================

set -euo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/command_validator.sh"
source "${LIB_DIR}/timeout_handler.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="WEB-09"
ITEM_NAME="웹서비스프로세스권한제한"
SEVERITY="상"

GUIDELINE_PURPOSE="웹서비스 프로세스가 관리자 권한이 아닌 최소 권한으로 구동되는지 확인"
GUIDELINE_THREAT="웹 프로세스가 관리자 권한으로 구동 시 취약점 악용 시 시스템 권한 탈취 위험"
GUIDELINE_CRITERIA_GOOD="웹 프로세스가 관리자 권한이 아닌 별도 계정으로 구동"
GUIDELINE_CRITERIA_BAD="웹 프로세스가 root 또는 Administrator 권한으로 구동"
GUIDELINE_REMEDIATION="Apache 서비스를 root가 아닌 www-data, daemon 등 전용 계정으로 구동하도록 envvars 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local apache_user=""
    local is_root=false

    # Apache 프로세스 확인
    # Process check (Updated for Docker)
    if command -v pgrep >/dev/null && ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Apache 웹 서버가 실행 중이 아닙니다."
        command_result="Apache process not found"
        command_executed="pgrep -x httpd; pgrep -x apache2"
        # Run-all 모드 확인
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

    # 결과 저장 확인
    verify_result_saved "${ITEM_ID}"

        return 0
    fi

    # Apache 프로세스 실행 사용자 확인 (httpd 또는 apache2)
    if pgrep -x "httpd" > /dev/null; then
        apache_user=$(ps aux | grep '[h]ttpd' | awk '{print $1}' | head -1 || true)
    elif pgrep -x "apache2" > /dev/null; then
        apache_user=$(ps aux | grep '[a]pache2' | awk '{print $1}' | head -1 || true)
    fi

    command_executed="ps aux | grep -E 'httpd|apache2' | awk '{print \$1}' | head -1"
    command_result="${apache_user}"

    if [ -z "${apache_user}" ]; then
        diagnosis_result="MANUAL"
        status="수동진단"
        inspection_summary="Apache 프로세스 실행 사용자를 확인할 수 없습니다. 수동 확인이 필요합니다."
    elif [ "${apache_user}" = "root" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        is_root=true
        inspection_summary="Apache 프로세스가 root 권한으로 구동 중입니다. 보안 권고사항 미준수."
    else
        # www-data, daemon, apache 등 전용 계정인 경우
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Apache 프로세스가 ${apache_user} 계정으로 구동 중입니다. (보안 권고사항 준수)"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    verify_result_saved "${ITEM_ID}"

    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if true; then
    main "$@"
fi
