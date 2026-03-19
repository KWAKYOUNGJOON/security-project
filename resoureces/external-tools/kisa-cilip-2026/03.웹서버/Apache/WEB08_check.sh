#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-08
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : Apache .htaccess 오버라이드
# @Description : Apache .htaccess 파일의 오버라이드 권한 제한 여부 점검
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

ITEM_ID="WEB-08"
ITEM_NAME="Apache .htaccess 오버라이드 제한"
SEVERITY="중"

GUIDELINE_PURPOSE=".htaccess 파일을 통한 설정 변경 제한"
GUIDELINE_THREAT="AllowOverride All인 경우 사용자가 설정 파일로 보안 우회 가능"
GUIDELINE_CRITERIA_GOOD="AllowOverride None 또는 제한적"
GUIDELINE_CRITERIA_BAD="AllowOverride All"
GUIDELINE_REMEDIATION="httpd.conf에서 AllowOverride None 설정 권장"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"
    local diagnosis_result="MANUAL"
    local status="수동진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local allowoverride_all=0

        # Process check
    if command -v pgrep >/dev/null; then
        if ! pgrep -x "httpd" > /dev/null && ! pgrep -x "apache2" > /dev/null; then
            diagnosis_result="N/A"
            status="N/A"
            inspection_summary="Apache \xec\x9b\xb9 \xec\x84\x9c\xeb\xb2\x84\xea\xb0\x80 \xec\x8b\xa4\xed\x96\x89 \xec\xa4\x91\xec\x9d\xb4 \xec\x95\x84\xeb\x8b\x99\xeb\x8b\x88\xeb\x8b\xa4."
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
        local apache_conf_locations=(
            "/etc/apache2/apache2.conf"
            "/etc/httpd/conf/httpd.conf"
        "/usr/local/apache2/conf/httpd.conf"
            "/etc/apache2/sites-enabled/*"
            "/etc/httpd/conf.d/*"
        )

        for conf_pattern in "${apache_conf_locations[@]}"; do
            if ls ${conf_pattern} 1> /dev/null 2>&1; then
                local ao=$(grep -rhE "^\s*AllowOverride\s+All" ${conf_pattern} 2>/dev/null | grep -v "^\s*#" | head -5 || true)
                if [ -n "${ao}" ]; then
                    allowoverride_all=1
                    command_result="${ao}"
                    break
                fi
            fi
        done

        command_executed="grep -rhE '^\s*AllowOverride' /etc/apache2/apache2.conf /etc/apache2/sites-enabled/ 2>/dev/null | grep -v '^\s*#'"

        if [ ${allowoverride_all} -eq 1 ]; then
            diagnosis_result="VULNERABLE"
            status="취약"
            inspection_summary="AllowOverride All 설정이 발견되었습니다. 사용자가 .htaccess로 보안 설정을 변경할 수 있습니다. AllowOverride None을 권장합니다."
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="AllowOverride가 제한적으로 설정되어 있거나 All이 아닙니다. .htaccess 오버라이드가 적절히 제한됩니다."
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
