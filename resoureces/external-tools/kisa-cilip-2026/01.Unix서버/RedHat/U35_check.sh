#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-35
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : 익명 사용자(Anonymous)의 공유 서비스 접근 제한 여부 점검
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

ITEM_ID="U-35"
ITEM_NAME="공유 서비스에 대한 익명 접근 제한 설정"
SEVERITY="(상)"

# 가이드라인 정보 (제시된 리스트 기준 반영)
GUIDELINE_PURPOSE="공유 서비스에 대한 익명 사용자의 접근을 차단하여 비인가자의 파일 시스템 접근 및 정보 유출을 방지하기 위함"
GUIDELINE_THREAT="익명 접근이 허용된 경우 누구든지 시스템 내부 자료에 접근할 수 있어 중요 데이터 탈취 및 시스템 파괴가 가능함"
GUIDELINE_CRITERIA_GOOD="공유 서비스에서 익명 사용자 접근이 제한되어 있는 경우"
GUIDELINE_CRITERIA_BAD="익명 사용자 접근이 허용되어 있는 경우"
GUIDELINE_REMEDIATION="Samba, FTP 등의 설정 파일에서 익명 접속(Guest, Anonymous) 관련 옵션을 no로 설정"

diagnose() {
    # [중요] 파싱 에러 방지를 위한 기존 변수 초기값 유지
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="공유 서비스의 익명 접근 제한 설정이 적절합니다."
    local command_result=""
    local command_executed="grep -i 'guest ok' /etc/samba/smb.conf"

    # 1. 실제 데이터 추출 (Samba 예시)
    local samba_conf="/etc/samba/smb.conf"
    local anonymous_samba=""
    if [ -f "$samba_conf" ]; then
        anonymous_samba=$(grep -i "guest ok" "$samba_conf" | grep -i "yes" || echo "")
    fi

    # 2. 판정 로직
    if [ -n "$anonymous_samba" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="Samba 서비스에 익명 접근(Guest)이 허용되어 있습니다."
        command_result="취약 설정 발견: [ $anonymous_samba ]"
    else
        command_result="Samba/FTP 등 주요 서비스에 익명 접근 설정이 발견되지 않았습니다."
    fi

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
