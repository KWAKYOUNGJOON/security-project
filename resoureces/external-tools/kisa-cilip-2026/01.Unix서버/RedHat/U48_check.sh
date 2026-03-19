#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-48
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (중)
# @Title       : expn, vrfy 명령어 제한
# @Description : SMTP 서버의 EXPN 및 VRFY 명령어 비활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-48"
ITEM_NAME="expn, vrfy 명령어 제한"
SEVERITY="(중)"

GUIDELINE_PURPOSE="사용자 계정 정보 확인 명령어(EXPN, VRFY)를 제한하여 공격자의 사용자 정보 수집을 차단하기 위함"
GUIDELINE_THREAT="EXPN, VRFY 명령어가 활성화된 경우, 외부에서 사용자 계정 존재 여부 및 메일링 리스트 정보를 수집하여 공격에 활용될 수 있음"
GUIDELINE_CRITERIA_GOOD="SMTP 설정에서 EXPN 및 VRFY 명령어가 제한(noexpn, novrfy)되어 있는 경우"
GUIDELINE_CRITERIA_BAD="SMTP 설정에서 EXPN 또는 VRFY 명령어가 허용되어 있는 경우"
GUIDELINE_REMEDIATION="Sendmail 설정 파일(sendmail.cf)의 PrivacyOptions에 noexpn, novrfy 옵션 추가"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="EXPN, VRFY 명령어 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep 'PrivacyOptions' /etc/mail/sendmail.cf"

    local cf_file="/etc/mail/sendmail.cf"
    if [ -f "$cf_file" ]; then
        local privacy_opts=$(grep "O PrivacyOptions" "$cf_file" | cut -d= -f2 || echo "")
        if [[ ! "$privacy_opts" =~ "noexpn" ]] || [[ ! "$privacy_opts" =~ "novrfy" ]]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="PrivacyOptions 설정에서 noexpn 또는 novrfy 옵션이 누락되었습니다."
        fi
        command_result="PrivacyOptions 설정 값: [ ${privacy_opts} ]"
    else
        command_result="메일 설정 파일(/etc/mail/sendmail.cf)이 없습니다."
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
