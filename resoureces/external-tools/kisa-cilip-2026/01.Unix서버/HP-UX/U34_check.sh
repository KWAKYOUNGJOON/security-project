#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-34
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : Finger 서비스 비활성화
# @Description : Finger 서비스가 비활성화되어 있는지 확인하여 사용자 정보 노출 방지
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================

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


ITEM_ID="U-34"
ITEM_NAME="Finger 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="무차별 대입 공격(Brute-force)을 방지하여 계정 잠금 및 서비스 거부(DoS) 상태를 방지하기 위함"
GUIDELINE_THREAT="로그온 시도 횟수 제한이 미흡할 경우, 공격자가 무차별 대입 공격을 통해 계정을 잠금시키거나, 서비스 거부 상태로 만들어 시스템 가용성을 저해할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="로그온 시도 횟수 제한(deny)이 5회 이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="로그온 시도 횟수 제한이 설정되어 있지 않거나, deny 값이 5회를 초과하는 경우"
GUIDELINE_REMEDIATION="/etc/security/faillock.conf 파일 또는 PAM 설정 파일(/etc/pam.d/common-auth 등)에서 deny 값을 5 이하로 설정"

# ============================================================================
# 진단 함수
# ============================================================================

# 진단 수행
diagnose() {

    diagnosis_result="unknown"
    local status="미진단"
    local inspection_summary=""
    local command_result=""
    local command_executed=""
    local newline=$'\n'

    # 진단 로직: HP-UX Finger 서비스 비활성화 확인
    # HP-UX에서는 inetd.conf 또는 별도 서비스 설정 확인

    local finger_enabled=false
    local service_status=""
    local inetd_info=""
    local services_info=""

    # 1) inetd.conf에서 finger 서비스 확인
    if [ -f /etc/inetd.conf ]; then
        # 주석 처리되지 않은 finger 라인 확인
        local finger_lines=$(grep -E "^[^#]*finger" /etc/inetd.conf 2>/dev/null || echo "")

        if [ -n "$finger_lines" ]; then
            finger_enabled=true
            inetd_info="/etc/inetd.conf에서 finger 서비스 활성화 발견:${newline}${finger_lines}"
        else
            inetd_info="/etc/inetd.conf에서 finger 서비스 주석 처리됨 또는 미설정"
        fi
    else
        inetd_info="/etc/inetd.conf 파일 없음"
    fi

    # 2) /etc/services에서 finger 포트 확인 (참고 정보)
    if [ -f /etc/services ]; then
        local finger_service=$(grep -E "^finger\s" /etc/services 2>/dev/null | head -1 || echo "")
        if [ -n "$finger_service" ]; then
            services_info="서비스 정의: ${finger_service}"
        fi
    fi

    # 3) 실행 중인 finger 프로세스 확인
    local finger_processes=$(ps -ef | grep -E "[f]inger[d]?" | grep -v grep || echo "")

    # 4) HP-UX 특정: inetd 또는 기타 서비스 관리자 확인
    # HP-UX는 주로 inetd를 사용하므로 inetd.conf 확인이 중요

    # 최종 판정
    if [ "$finger_enabled" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="Finger 서비스 활성화됨 - 사용자 정보 노출 위험"

        # 결과 조합
        if [ -n "$finger_processes" ]; then
            service_status="${inetd_info}${newline}실행 중인 프로세스:${newline}${finger_processes}"
        else
            service_status="${inetd_info}"
        fi

        if [ -n "$services_info" ]; then
            service_status="${service_status}${newline}${services_info}"
        fi

        command_result="${service_status}"
        command_executed="grep -E '^[^#]*finger' /etc/inetd.conf; ps -ef | grep finger"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="Finger 서비스 비활성화됨"

        # 결과 조합
        service_status="${inetd_info}"
        if [ -n "$services_info" ]; then
            service_status="${service_status}${newline}${services_info}"
        fi

        command_result="${service_status}"
        command_executed="grep finger /etc/inetd.conf; ps -ef | grep finger"
    fi

    save_dual_result \
        "${ITEM_ID}" \
        "${ITEM_NAME}" \
        "${status}" \
        "${diagnosis_result}" \
        "${inspection_summary}" \
        "${command_result}" \
        "${command_executed}" \
        "${GUIDELINE_PURPOSE}" \
        "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" \
        "${GUIDELINE_CRITERIA_BAD}" \
        "${GUIDELINE_REMEDIATION}"

    # 결과 저장 확인
    verify_result_saved "${ITEM_ID}"

    return 0
}

# ============================================================================
# 메인 실행
# ============================================================================

main() {
    # 진단 시작 표시
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"

    # 디스크 공간 확인
    check_disk_space

    # 진단 수행
    diagnose

    # 진단 완료 표시
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
