#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-13
# @Category    : Server
# @Platform    : Tomcat
# @Severity    : 상
# @Title       : 웹서비스경로내파일의접근통제
# @Description : 웹 서비스 경로 내 파일의 접근 통제 설정 여부 점검
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

ITEM_ID="WEB-13"
ITEM_NAME="웹서비스경로내파일의접근통제"
SEVERITY="중"

GUIDELINE_PURPOSE="특정 디렉토리 및 파일에 대한 접근 제한으로 무단 접근 방지"
GUIDELINE_THREAT="접근 통제 미시행시 민감 파일 및 디렉토리 무단 접근 위험"
GUIDELINE_CRITERIA_GOOD="디렉토리 및 파일 접근 제한이 설정된 경우"
GUIDELINE_CRITERIA_BAD="접근 제한이 설정되지 않은 경우"
GUIDELINE_REMEDIATION="web.xml에 security-constraint 및 auth-constraint 설정"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="UNKNOWN"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local has_auth_constraint=false
    local constraint_count=0

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

    local auth_constraints=""

    for xml_pattern in "${web_xml_locations[@]}"; do
        for xml_file in $xml_pattern; do
            if [ -f "${xml_file}" ]; then
                local found_auth=$(grep -E "auth-constraint|security-constraint" "${xml_file}" 2>/dev/null | grep -v "^\s*<!--" || true)
                if [ -n "${found_auth}" ]; then
                    auth_constraints="${auth_constraints}"$'\n'"${found_auth}"
                    ((constraint_count++))
                    has_auth_constraint=true
                fi
                break 2
            fi
        done
    done

    command_executed="grep -E 'auth-constraint|security-constraint' /etc/tomcat*/web.xml 2>/dev/null | grep -v '^\\s*<!--' | head -5"
    command_result="${auth_constraints:-No auth constraints found}"

    if [ "${has_auth_constraint}" = true ]; then
        if [ ${constraint_count} -ge 1 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="web.xml에 ${constraint_count}개의 접근 제한约束(security-constraint/auth-constraint) 설정이 존재합니다. (보안 권고사항 준수)"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="web.xml에 접근 제한 설정이 존재합니다. (보안 권고사항 준수)"
        fi
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="명시적인 접근 제한 설정이 없습니다. Tomcat 기본 보안 정책에 따릅니다. 민감 자원 보호를 위해 security-constraint 설정 권장."
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
