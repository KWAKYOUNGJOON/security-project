#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-37
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : crontab 설정파일 권한 설정 미흡
# @Description : 정기적인 작업을 수행하는 crontab 관련 파일의 권한 설정 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-37"
ITEM_NAME="crontab 설정파일 권한 설정 미흡"
SEVERITY="(상)"

GUIDELINE_PURPOSE="정기적으로 실행되는 작업 설정 파일을 보호하여 비인가자의 악의적인 명령어 등록을 차단하기 위함"
GUIDELINE_THREAT="crontab 파일의 권한이 부적절할 경우 비인가자가 악성 스크립트를 주기적으로 실행하도록 등록하여 시스템을 장악할 수 있음"
GUIDELINE_CRITERIA_GOOD="crontab 관련 파일의 소유자가 root이고 권한이 640 이하인 경우"
GUIDELINE_CRITERIA_BAD="crontab 관련 파일의 소유자가 root가 아니거나 권한이 640을 초과하는 경우"
GUIDELINE_REMEDIATION="crontab 파일의 소유자를 root로 변경하고 권한을 640으로 설정 (chmod 640 /etc/crontab)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="crontab 관련 파일의 권한 및 소유자 설정이 적절합니다."
    local command_result=""
    local command_executed="ls -l /etc/crontab"

    # 1. 실제 데이터 추출
    local cron_file="/etc/crontab"
    if [ -f "$cron_file" ]; then
        local owner=$(stat -c "%U" "$cron_file")
        local perm=$(stat -c "%a" "$cron_file")
        local ls_out=$(ls -l "$cron_file")

        # 2. 판정 로직
        if [ "$owner" != "root" ] || [ "$perm" -gt 640 ]; then
            status="취약"
            diagnosis_result="VULNERABLE"
            inspection_summary="crontab 설정 파일의 권한 또는 소유자 설정이 미흡합니다."
        fi
        command_result="설정 현황: [ ${ls_out} ]"
    else
        command_result="crontab 파일을 찾을 수 없습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
