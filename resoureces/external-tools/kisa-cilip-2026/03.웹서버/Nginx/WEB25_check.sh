#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-25
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : 주기적보안패치및벤더권고사항적용
# @Description : 주기적 보안 패치 및 벤더 권고 사항 적용 여부 점검
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

ITEM_ID="WEB-25"
ITEM_NAME="주기적보안패치및벤더권고사항적용"
SEVERITY="상"

GUIDELINE_PURPOSE="최신 보안 패치 적용으로 알려진 취약점 방지"
GUIDELINE_THREAT="오래된 버전 사용 시 알려진 취약점 공격 위험"
GUIDELINE_CRITERIA_GOOD="최신 안정 버전 사용"
GUIDELINE_CRITERIA_BAD="오래된 버전 사용"
GUIDELINE_REMEDIATION="Nginx를 최신 버전으로 업그레이드하고 주기적 패치 적용"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""

    # Process check
    if command -v pgrep >/dev/null; then
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
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

    # Get Nginx version
    local nginx_version=""
    local version_output=""

    if command -v nginx >/dev/null 2>&1; then
        version_output=$(nginx -v 2>&1 || true)
        nginx_version=$(echo "${version_output}" | grep -oE "nginx/[0-9]+\.[0-9]+\.[0-9]+" || echo "version detection failed")
        command_executed="nginx -v"
        command_result="${version_output}"
    else
        command_executed="nginx -v"
        command_result="nginx command not found"
    fi

    # Version check guidance (this is MANUAL diagnosis)
    local manual_check_guidance=""
    manual_check_guidance=$'\n'"[수동진단 가이드]"$'\n'
    manual_check_guidance+="1. 현재 버전: ${nginx_version}"$'\n'
    manual_check_guidance+="2. Nginx 공식 웹사이트(https://nginx.org)에서 최신 안정 버전 확인"$'\n'
    manual_check_guidance+="3. Nginx 보안 권고사항 확인: https://nginx.org/en/security_advisories.html"$'\n'
    manual_check_guidance+="4. 주요 보안 업데이트 확인"$'\n'
    manual_check_guidance+="   - 1.18.0 이상: 안정 버전 권장"$'\n'
    manual_check_guidance+="   - 1.20.0+ 이상: 최신 보안 패치 포함"$'\n'
    manual_check_guidance+="5. OS 패키지 매니저로 업데이트: apt-get upgrade nginx 또는 yum update nginx"

    inspection_summary="Nginx 버전 확인 및 주기적 보안 패치는 수동 진단이 필요합니다.${manual_check_guidance}"

    # Run-all 모드 확인
    # 결과 저장 (run_all 모드는 라이브러리에서 판단)
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
