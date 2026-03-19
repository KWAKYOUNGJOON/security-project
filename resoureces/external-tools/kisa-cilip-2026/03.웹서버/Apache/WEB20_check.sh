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
# @Platform    : Apache
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
GUIDELINE_REMEDIATION="mod_ssl 모듈 활성화 및 443 포트 HTTPS VirtualHost 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_ssl=false

        # Process check
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
    # Check if mod_ssl module is loaded
    if command -v apache2ctl >/dev/null 2>&1; then
        if apache2ctl -M 2>/dev/null | grep -q "ssl_module"; then
            has_ssl=true
        fi
    elif command -v httpd >/dev/null 2>&1; then
        if httpd -M 2>/dev/null | grep -q "ssl_module"; then
            has_ssl=true
        fi
    fi

    local apache_conf_locations=(
        "/etc/apache2/ports.conf"
        "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
        "/etc/apache2/sites-enabled/*.conf"
    )

    local has_https=false
    for conf_pattern in "${apache_conf_locations[@]}"; do
        for conf_file in $conf_pattern; do
            if [ -f "${conf_file}" ]; then
                local found_https=$(grep -E "(Listen.*443|VirtualHost.*:443)" "${conf_file}" 2>/dev/null | head -1 || true)
                if [ -n "${found_https}" ]; then
                    has_https=true
                    break 2
                fi
            fi
        done
    done

    command_executed="apache2ctl -M | grep ssl_module; grep -r 'Listen.*443' /etc/apache2 /etc/httpd 2>/dev/null | head -3"
    command_result="${has_ssl:+SSL module loaded}, ${has_https:+HTTPS configured}"

    if [ "${has_ssl}" = true ] && [ "${has_https}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="HTTPS(SSL/TLS)가 활성화되어 있습니다. (보안 권고사항 준수)"
    elif [ "${has_ssl}" = true ] && [ "${has_https}" = false ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="SSL 모듈이 로드되었으나 HTTPS(443) 설정이 발견되지 않았습니다."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="HTTPS가 활성화되어 있지 않습니다. SSL/TLS 설정 권장."
    fi

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
