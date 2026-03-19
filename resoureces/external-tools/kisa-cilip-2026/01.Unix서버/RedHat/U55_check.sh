#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-55
# @Category    : UNIX > 4. 웹 서비스 관리
# @Platform    : RedHat (Apache)
# @Severity    : (상)
# @Title       : Apache 링크 사용 금지
# @Description : 웹 서버의 심볼릭 링크 사용 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-55"
ITEM_NAME="Apache 링크 사용 금지"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="심볼릭 링크 기능을 제한하여 웹 루트 디렉토리 외부의 파일이 웹 서비스에 노출되는 것을 방지하기 위함"
GUIDELINE_THREAT="심볼릭 링크가 허용될 경우, 공격자가 시스템 주요 파일에 대한 링크를 생성하여 웹을 통해 기밀 정보를 획득할 위험이 있음"
GUIDELINE_CRITERIA_GOOD="Options 설정에서 FollowSymLinks 옵션을 제거하거나 제한한 경우"
GUIDELINE_CRITERIA_BAD="Options 설정에서 FollowSymLinks 옵션이 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="httpd.conf 파일의 <Directory> 섹션에서 Options -FollowSymLinks 설정"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="Apache 심볼릭 링크 사용 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -r 'Options' /etc/httpd/conf*"

    # 1. 실제 데이터 추출 (RHEL httpd.conf 및 conf.d 점검)
    local httpd_conf="/etc/httpd/conf/httpd.conf"
    if [ -f "$httpd_conf" ]; then
        local follow_sym=$(grep -v '^#' "$httpd_conf" | grep "Options" | grep "FollowSymLinks" | head -n 1 || echo "")
        
        # 2. 판정 로직
        if [ -n "$follow_sym" ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="Options 설정에서 FollowSymLinks가 활성화되어 있습니다."
            command_result="발견된 설정: [ ${follow_sym} ]"
        else
            command_result="심볼릭 링크 허용 설정이 발견되지 않았습니다."
        fi
    else
        command_result="Apache 설정 파일을 찾을 수 없습니다."
    fi

    # [보정] JSON 파싱 에러 방지
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
