#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-20
# @Category    : Server
# @Platform    : Tomcat
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

GUIDELINE_PURPOSE="HTTPS(SSL/TLS) 활성화로 통신 암호화 및 데이터 보호"
GUIDELINE_THREAT="HTTP 사용 시 평문 통신으로 중간자 공격 및 데이터 도청 위험"
GUIDELINE_CRITERIA_GOOD="HTTPS(443)가 활성화된 경우"
GUIDELINE_CRITERIA_BAD="HTTP(80/8080)만 사용하는 경우"
GUIDELINE_REMEDIATION="server.xml에 SSL Connector 설정(SSLEngine, scheme, secure) 및 443 포트 Listen"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_ssl=false
    local has_https_port=false

    # Process check (Updated for Docker)
    if command -v pgrep >/dev/null; then
        if ! pgrep -f "catalina|tomcat" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Tomcat 웹 서버가 실행 중이 아닙니다."
            command_result="Tomcat process not found"
            command_executed="pgrep -f 'catalina|tomcat'"

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

    local server_xml_locations=(
        "/etc/tomcat*/server.xml"
        "/var/lib/tomcat*/conf/server.xml"
        "/usr/share/tomcat*/conf/server.xml"
    )

    local ssl_config=""

    for xml_pattern in "${server_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                # SSL Connector 확인
                local found_ssl=$(grep -i "SSLEngine\|scheme=\"https\"\|secure=\"true\"" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_ssl}" ]; then
                    ssl_config="${ssl_config}"$'\n'"${found_ssl}"
                    has_ssl=true
                fi

                # 443 포트 Listen 확인
                local found_443=$(grep -i "Connector.*443" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_443}" ]; then
                    ssl_config="${ssl_config}"$'\n'"Port 443: ${found_443}"
                    has_https_port=true
                fi

                break 2
            fi
        done
    done

    command_executed="grep -iE 'SSLEngine|Connector.*443|scheme=\"https\"' /etc/tomcat*/server.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${ssl_config:-No SSL/TLS configuration found}"

    if [ "${has_ssl}" = true ] && [ "${has_https_port}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSL/TLS가 활성화되어 있으며 443 포트가 Listen 중입니다. (보안 권고사항 준수)"
    elif [ "${has_ssl}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SSL/TLS 설정이 존재합니다. HTTPS 연결을 위해 443 포트 Listen 설정 확인 권장."
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="SSL/TLS가 활성화되지 않았습니다. HTTPS 연결을 위한 SSL Connector 설정 필수."
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
