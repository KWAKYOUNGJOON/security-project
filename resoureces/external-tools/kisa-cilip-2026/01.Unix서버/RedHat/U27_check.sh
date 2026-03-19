#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-27
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : $HOME/.rhosts, hosts.equiv 사용 금지
# @Description : 원격 접속 시 인증 없이 접근 가능한 설정 파일 존재 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"

ITEM_ID="U-27"; ITEM_NAME="\$HOME/.rhosts, hosts.equiv 사용 금지"; SEVERITY="(상)"
GUIDELINE_PURPOSE="r-command를 통한 별도의 인증 없는 관리자 권한 원격 접속을 차단하기 위함"
GUIDELINE_THREAT="보안 설정이 적용되지 않을 경우, 원격지의 공격자가 관리자 권한으로 임의의 명령을 수행하거나 중요 정보를 유출할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="rlogin, rsh 서비스를 사용하지 않거나, 관련 파일 소유자가 root이고 권한이 600 이하이며 '+' 설정이 없는 경우"
GUIDELINE_CRITERIA_BAD="해당 서비스를 사용하며 소유자/권한이 부적절하거나 '+' 설정이 존재하는 경우"
GUIDELINE_REMEDIATION="/etc/hosts.equiv 및 .rhosts 파일 소유자 및 권한 변경, 또는 서비스 비활성화"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local command_result=""; local command_executed="ls -l /etc/hosts.equiv $HOME/.rhosts"

    local equiv="/etc/hosts.equiv"
    local rhosts="$HOME/.rhosts"
    local evidence=""

    if [ -f "$equiv" ]; then
        local owner=$(stat -c "%U" "$equiv")
        local perm=$(stat -c "%a" "$equiv")
        local content=$(grep "+" "$equiv")
        evidence+="/etc/hosts.equiv(Owner:${owner}, Perm:${perm}) "
        if [ "$owner" != "root" ] || [ "$perm" -gt 600 ] || [ -n "$content" ]; then status="취약"; diagnosis_result="VULNERABLE"; fi
    fi

    command_result="설정 현황: ${evidence:-파일 없음}"

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "점검 완료" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
