#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-13
# @Category    : Web Server
# @Platform    : Nginx
# @Severity    : 중
# @Title       : Nginx 디렉토리 리스팅(autoindex) 비활성화
# @Description : Nginx 웹 서버에서 디렉토리 리스팅 기능(autoindex)을 비활성화하여 디렉토리 내 파일 목록이 외부에 노출되지 않도록 합니다. autoindex off 설정으로 정보 유출을 방지해야 합니다.
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../../lib"
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
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
ITEM_NAME="Nginx 디렉토리 리스팅(autoindex) 비활성화"
SEVERITY="중"
GUIDELINE_PURPOSE="디렉토리 내용 노출 방지"
GUIDELINE_THREAT="autoindex on인 경우 디렉토리 내 파일 목록 노출"
GUIDELINE_CRITERIA_GOOD="autoindex off 또는 설정되지 않음"
GUIDELINE_CRITERIA_BAD="autoindex on"
GUIDELINE_REMEDIATION="nginx.conf에서 autoindex off; 설정"
diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"
    local diagnosis_result="VULNERABLE"
    local status="취약"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    if ! pgrep -x "nginx" > /dev/null; then
        diagnosis_result="N/A"; status="N/A"
        inspection_summary="Nginx 웹 서버가 실행 중이 아닙니다."
        command_result="Nginx process not found"
        command_executed="pgrep -x nginx"
    else
        local autoindex=$(grep -rhE "autoindex.*on" /etc/nginx/nginx.conf /etc/nginx/sites-enabled/ 2>/dev/null | grep -v "^\s*#" | head -1 || true)
        command_result="${autoindex}"
        command_executed="grep -rhE autoindex /etc/nginx/"
        if [ -n "${autoindex}" ]; then
            diagnosis_result="VULNERABLE"; status="취약"
            inspection_summary="autoindex on 설정이 발견되었습니다. 디렉토리 내 파일 목록이 노출됩니다. autoindex off;로 변경하세요."
        else
            diagnosis_result="GOOD"; status="양호"
            inspection_summary="autoindex가 off로 설정되어 있거나 on 설정이 없습니다. 디렉토리 리스팅이 비활성화되어 있습니다."
        fi
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
