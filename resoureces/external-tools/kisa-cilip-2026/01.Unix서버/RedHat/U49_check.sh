#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-49
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : DNS 보안 버전 패치
# @Description : DNS 서비스(BIND)의 최신 보안 패치 적용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-49"
ITEM_NAME="DNS 보안 버전 패치"
SEVERITY="(상)"

GUIDELINE_PURPOSE="DNS 서비스의 알려진 취약점을 보완하기 위해 최신 보안 패치를 적용하여 시스템 보안성을 강화하기 위함"
GUIDELINE_THREAT="취약한 버전의 DNS 서비스를 사용할 경우 알려진 취약점을 악용한 공격(DDoS, 원격 코드 실행 등)으로 시스템이 장악될 위험이 있음"
GUIDELINE_CRITERIA_GOOD="DNS 서비스가 최신 버전이거나 알려진 취약점이 없는 버전을 사용 중인 경우"
GUIDELINE_CRITERIA_BAD="DNS 서비스가 구버전이거나 알려진 취약점이 포함된 버전을 사용 중인 경우"
GUIDELINE_REMEDIATION="BIND 배포처 또는 OS 제조사에서 제공하는 최신 보안 패치 적용"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="DNS 서비스가 최신 버전이거나 설치되지 않았습니다."
    local command_result=""
    local command_executed="named -v"

    local bind_ver=$(named -v 2>/dev/null || echo "Not Installed")
    if [ "$bind_ver" != "Not Installed" ]; then
        command_result="현재 BIND 버전: [ ${bind_ver} ]"
        inspection_summary="DNS 서비스(BIND)가 실행 중입니다. 최신 보안 패치 여부를 수동으로 확인하십시오."
    else
        command_result="BIND(DNS) 서비스가 설치되어 있지 않습니다."
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
