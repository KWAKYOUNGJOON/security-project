#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-21
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : 동적페이지요청및응답값검증
# @Description : 동적 페이지 요청 및 응답값에 대한 입력값 검증 구현 여부 점검
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

ITEM_ID="WEB-21"
ITEM_NAME="동적페이지요청및응답값검증"
SEVERITY="상"

GUIDELINE_PURPOSE="동적 페이지의 요청 및 응답 값에 대한 입력값 검증 및 메타문자 필터링을 구현하여 SQL Injection, XSS 등 취약점을 방지하기 위함"
GUIDELINE_THREAT="입력값 검증이 미흡할 경우 SQL Injection, Cross-site Scripting(XSS), Command Injection 등 공격으로 시스템 장악 및 정보 유출 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="입력값 검증이 구현된 경우"
GUIDELINE_CRITERIA_BAD="입력값 검증이 미구현된 경우"
GUIDELINE_REMEDIATION="웹 애플리케이션 소스 코드에서 모든 사용자 입력에 대한 검증 로직 구현 (길이 제한, 메타문자 필터링, 타입 검사 등)"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Apache process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache 웹 서버가 실행 중이 아닙니다."
            command_result="Apache process not found"
            command_executed="pgrep -x httpd; pgrep -x apache2"
            # Run-all 모드 확인

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
    else
        echo "[INFO] pgrep command missing, skipping process check."
    fi

    # This is MANUAL diagnosis - application-level validation cannot be checked via config
    inspection_summary="동적 페이지 입력값 검증은 웹 애플리케이션 소스 코드 수준에서 구현되어야 합니다. Apache 설정 파일만으로는 이 항목을 진단할 수 없습니다. 다음 사항을 수동으로 확인하세요:\n"
    inspection_summary="${inspection_summary}\n1. 모든 사용자 입력(GET, POST, Cookie, Header 등)에 대한 검증 로직 구현 여부\n"
    inspection_summary="${inspection_summary}2. 특수문자 및 메타문자(', \", <, >, ;, &, |, $, etc.) 필터링 여부\n"
    inspection_summary="${inspection_summary}3. 입력값 길이 제한 구현 여부\n"
    inspection_summary="${inspection_summary}4. SQL Injection 방지를 위한 Prepared Statement 또는 Parameterized Query 사용 여부\n"
    inspection_summary="${inspection_summary}5. XSS 방지를 위한 출력값 이스케이프 처리 여부\n"
    inspection_summary="${inspection_summary}6. 웹 방화벽(WAF) 또는 mod_security 등 입력값 필터링 모듈 사용 여부"

    command_result="Application-level validation cannot be detected via Apache configuration"
    command_executed="N/A - Manual review of application source code required"

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
