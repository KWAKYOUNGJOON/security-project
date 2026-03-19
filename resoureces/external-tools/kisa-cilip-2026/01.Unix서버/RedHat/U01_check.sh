#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-01
# @Category    : UNIX > 1. 계정 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : root 계정 원격 접속 제한
# @Description : 원격 터미널을 이용한 root 계정의 직접 접속 제한 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

# 스크립트 디렉토리 설정
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

# 필수 라이브러리 로드
source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-01"
ITEM_NAME="root 계정 원격 접속 제한"
SEVERITY="(상)"

# 가이드라인 정보
GUIDELINE_PURPOSE="root 계정의 직접 원격 접속을 차단하여 공격자의 무차별 대입 공격을 통한 관리자 권한 탈취를 방지하기 위함"
GUIDELINE_THREAT="root 계정은 시스템의 모든 권한을 가지므로, 원격 접속이 허용될 경우 계정 탈취 시 시스템 전체가 장악될 수 있음"
GUIDELINE_CRITERIA_GOOD="원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 제한한 경우"
GUIDELINE_CRITERIA_BAD="원격 터미널 서비스 사용 시 root 직접 접속을 제한하지 않은 경우"
GUIDELINE_REMEDIATION="원격 접속 설정 파일(sshd_config 등)에서 PermitRootLogin을 no로 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="root 계정 원격 접속 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -i '^PermitRootLogin' /etc/ssh/sshd_config"

    # 1. 실제 데이터 추출
    local ssh_val=$(grep -i "^PermitRootLogin" /etc/ssh/sshd_config | awk '{print $2}' || echo "no-setting")
    local securetty_pts=$(grep -E "^pts/" /etc/securetty || echo "no-pts")

    # 2. 판정 로직
    if [[ "$ssh_val" =~ ^[Yy]es ]] || [ "$ssh_val" = "no-setting" ] || [ "$securetty_pts" != "no-pts" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="root 계정 원격 접속 제한 설정이 미설정 또는 부적절합니다."
    fi

    # 3. command_result에 실제 설정값 기록 (증적 데이터)
    command_result="[SSH] PermitRootLogin=${ssh_val} | [Telnet] /etc/securetty PTS=${securetty_pts}"

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
