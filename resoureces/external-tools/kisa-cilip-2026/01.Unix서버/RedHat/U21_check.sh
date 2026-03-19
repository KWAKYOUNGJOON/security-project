#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-21
# @Category    : UNIX > 2. 파일 및 디렉토리 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : /etc/syslog.conf 파일 소유자 및 권한 설정
# @Description : 로그 설정 파일(/etc/syslog.conf 또는 /etc/rsyslog.conf)의 소유자 및 권한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-21"
ITEM_NAME="/etc/syslog.conf 파일 소유자 및 권한 설정"
SEVERITY="(상)"

# 가이드라인 정보 (PDF 가이드 내용 반영)
GUIDELINE_PURPOSE="로그 설정 파일을 보호하여 비인가자가 로그 기록을 중지하거나 변조하는 것을 방지하기 위함"
GUIDELINE_THREAT="로그 설정이 변조될 경우, 공격자가 자신의 침입 흔적을 지우거나 로그 수집을 방해하여 사후 조사를 어렵게 만들 수 있음"
GUIDELINE_CRITERIA_GOOD="/etc/syslog.conf(또는 rsyslog.conf) 파일의 소유자가 root이고, 권한이 640 이하인 경우"
GUIDELINE_CRITERIA_BAD="소유자가 root가 아니거나, 권한이 640 이하가 아닌 경우"
GUIDELINE_REMEDIATION="소유자를 root로 변경하고 권한을 640으로 설정 (chmod 640 <file>)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="로그 설정 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/syslog.conf /etc/rsyslog.conf"

    # 1. 실제 데이터 추출 (OS에 따라 syslog.conf 또는 rsyslog.conf 사용)
    local target="/etc/rsyslog.conf"
    [ ! -f "$target" ] && target="/etc/syslog.conf"

    if [ -f "$target" ]; then
        local owner=$(stat -c "%U" "$target")
        local perm=$(stat -c "%a" "$target")
        local ls_out=$(ls -l "$target")

        # 2. 판정 로직: 소유자 root 및 권한 640 이하
        if [ "$owner" != "root" ] || [ "$perm" -gt 640 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="로그 설정 파일의 소유자 또는 권한 설정이 부적절합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        command_result="로그 설정 파일(/etc/syslog.conf 또는 rsyslog.conf)이 존재하지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    [ "$EUID" -ne 0 ] && exit 1
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result}"
}

main "$@"
