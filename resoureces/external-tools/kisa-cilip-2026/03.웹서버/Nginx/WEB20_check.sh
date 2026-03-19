#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-20
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 상
# @Title       : SSL/TLS활성화
# @Description : 웹 서비스 SSL/TLS 활성화 여부 점검
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

ITEM_ID="WEB-20"
ITEM_NAME="SSL/TLS활성화"
SEVERITY="상"

GUIDELINE_PURPOSE="HTTPS(SSL/TLS) 활성화로 암호화 통신 보장"
GUIDELINE_THREAT="HTTP 미사용 시 평문 통신으로 정보 노출 위험"
GUIDELINE_CRITERIA_GOOD="HTTPS가 활성화된 경우"
GUIDELINE_CRITERIA_BAD="HTTPS가 비활성화된 경우"
GUIDELINE_REMEDIATION="ssl_certificate 및 ssl_certificate_key 설정으로 HTTPS 활성화"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_ssl=false
    local has_https=false

        # Process check (Updated for Docker)
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

    local nginx_conf_locations=(
        "/etc/nginx/nginx.conf"
        "/etc/nginx/conf.d/*.conf"
        "/etc/nginx/sites-enabled/*.conf"
    )

    local ssl_settings=""

    for conf_pattern in "${nginx_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                # SSL 인증서 설정 확인
                local found_ssl=$(grep -E "^\s*ssl_certificate" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_ssl}" ]; then
                    ssl_settings="${ssl_settings}"$'\n'"${found_ssl}"
                    has_ssl=true
                fi

                # 443 포트 Listen 확인
                local found_https=$(grep -E "(listen.*443|listen.*ssl)" "${conf_file}" 2>/dev/null | grep -v "^\s*#" || true)
                if [ -n "${found_https}" ]; then
                    has_https=true
                fi
            fi
        done
    done

    command_executed="grep -E '(ssl_certificate|listen.*443|listen.*ssl)' /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null | grep -v '^\\s*#' | head -3"
    command_result="${ssl_settings:-No SSL found}"

    if [ "${has_ssl}" = true ] && [ "${has_https}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="HTTPS(SSL/TLS)가 활성화되어 있습니다. (보안 권고사항 준수)"
    elif [ "${has_ssl}" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="SSL 인증서가 설정되었으나 HTTPS(443) 리스너가 발견되지 않았습니다."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="HTTPS가 활성화되어 있지 않습니다. SSL/TLS 설정 권장."
    fi

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
