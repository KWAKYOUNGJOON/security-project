#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-12
# @Category    : Server
# @Platform    : Tomcat
# @Severity    : 상
# @Title       : 웹서비스설정파일노출제한
# @Description : 웹 서비스 설정 파일 노출 제한 여부 점검
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

ITEM_ID="WEB-12"
ITEM_NAME="웹서비스설정파일노출제한"
SEVERITY="중"

GUIDELINE_PURPOSE="web.xml 설정 파일에 대한 접근 제한으로 정보 노출 방지"
GUIDELINE_THREAT="설정 파일 노출 시 시스템 구조 및 보안 설정 정보 유출 위험"
GUIDELINE_CRITERIA_GOOD="WEB-INF/web.xml 접근이 제한된 경우"
GUIDELINE_CRITERIA_BAD="설정 파일에 직접 접근 가능한 경우"
GUIDELINE_REMEDIATION="web.xml에 security-constraint 설정으로 WEB-INF 및 메타데이터 접근 제한"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_security_constraint=false

        # Process check (Updated for Docker)
    if command -v pgrep >/dev/null; then
    if ! pgrep -f "catalina|tomcat" > /dev/null; then
        diagnosis_result="N/A"
        status="N/A"
        inspection_summary="Tomcat 웹 서버가 실행 중이 아닙니다."
        command_result="Tomcat process not found"
        command_executed="pgrep -f 'catalina|tomcat'"

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

    local web_xml_locations=(
        "/etc/tomcat*/web.xml"
        "/var/lib/tomcat*/conf/web.xml"
        "/usr/share/tomcat*/conf/web.xml"
    )

    local security_constraints=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                local found_constraint=$(grep -E "security-constraint|web-resource-collection" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_constraint}" ]; then
                    security_constraints="${security_constraints}"$'\n'"${found_constraint}"
                    has_security_constraint=true
                fi
                break 2
            fi
        done
    done

    command_executed="grep -E 'security-constraint|web-resource-collection' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -3"
    command_result="${security_constraints:-No security constraints found}"

    if [ "${has_security_constraint}" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="web.xml에 security-constraint 설정이 존재합니다. 설정 파일 접근 제한이 적용되어 있습니다. (보안 권고사항 준수)"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Tomcat은 기본적으로 WEB-INF 디렉토리에 대한 접근을 제한합니다. 추가 보안 강화를 위해 security-constraint 설정 권장."
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
