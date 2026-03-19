#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-52
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat (Apache)
# @Severity    : (중)
# @Title       : Apache HTTPD 버전 정보 숨김
# @Description : ServerTokens 및 ServerSignature 설정을 통한 버전 정보 노출 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-52"
ITEM_NAME="Apache HTTPD 버전 정보 숨김"
SEVERITY="(중)"

GUIDELINE_PURPOSE="웹 서버의 종류 및 버전 정보를 노출하지 않음으로써 공격자가 특정 버전에 존재하는 알려진 취약점을 이용하는 것을 차단하기 위함"
GUIDELINE_THREAT="에러 페이지나 응답 헤더에 버전 정보가 노출될 경우 공격자가 해당 버전의 취약점을 악용하여 공격을 시도할 수 있음"
GUIDELINE_CRITERIA_GOOD="ServerTokens Prod 및 ServerSignature Off 설정이 적용된 경우"
GUIDELINE_CRITERIA_BAD="ServerTokens 또는 ServerSignature 설정이 노출 위주로 설정되어 있는 경우"
GUIDELINE_REMEDIATION="httpd.conf 파일에서 ServerTokens Prod, ServerSignature Off 설정 추가 및 수정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="Apache 버전 정보 숨김 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -E 'ServerTokens|ServerSignature' /etc/httpd/conf/httpd.conf"

    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        local tokens=$(grep -v '^#' "$httpd_conf" | grep -i "ServerTokens" | awk '{print $2}' || echo "NotSet")
        local signature=$(grep -v '^#' "$httpd_conf" | grep -i "ServerSignature" | awk '{print $2}' || echo "NotSet")
        
        if [[ "$tokens" != "Prod" ]] || [[ "$signature" != "Off" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="ServerTokens(Prod) 또는 ServerSignature(Off) 설정이 부적절합니다."
        fi
        command_result="ServerTokens: ${tokens}, ServerSignature: ${signature}"
    else
        command_result="Apache 설정 파일이 존재하지 않습니다."
    fi

    command_result=$(echo "$command_result" | tr -d '\n\r')

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    verify_result_saved "${ITEM_ID}"
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && { echo "root 권한이 필요합니다."; exit 1; }
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
    exit 0
}

main "$@"
