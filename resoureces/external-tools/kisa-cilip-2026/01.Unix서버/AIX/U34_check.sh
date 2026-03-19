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
# @Platform    : AIX
# @Severity    : 상
# @Title       : 로그온 시도 횟수 제한
# @Description : loginretries 설정 확인 (AIX /etc/security/user)
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

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
ITEM_NAME="로그온 시도 횟수 제한"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="비인가자의 무차별 대입 공격 방지를 위한 로그온 시도 횟수 제한"
GUIDELINE_THREAT="로그온 시도 횟수 제한이 없을 경우 비인가자의 무차별 대입 공격으로 계정 탈취 위험"
GUIDELINE_CRITERIA_GOOD="loginretries가 5회 이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="loginretries가 5회 초과이거나 설정되지 않은 경우"
GUIDELINE_REMEDIATION="/etc/security/user에서 loginretries = 5 설정"

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

    # 진단 로직 구현
    # AIX: /etc/security/user에서 loginretries 설정 확인

    local is_secure=false
    local config_details=""
    local loginretries_value=""

    # 1) /etc/security/user 확인 (AIX)
    if [ -f /etc/security/user ]; then
        # 기본 설정 확인 (default 스탠자)
        local default_loginretries=$(grep -A 10 "^default:" /etc/security/user | grep "loginretries" | awk '{print $3}')

        if [ -n "$default_loginretries" ]; then
            loginretries_value=$default_loginretries
            config_details="/etc/security/user default: loginretries=${loginretries_value}"
        else
            # 특정 사용자 설정 확인
            local user_loginretries=$(grep -v "^#" /etc/security/user | grep "loginretries" | head -1 | awk '{print $3}')
            if [ -n "$user_loginretries" ]; then
                loginretries_value=$user_loginretries
                config_details="/etc/security/user: loginretries=${loginretries_value}"
            fi
        fi
    fi

    # 2) lsuser 명령어로 기본값 확인 (AIX)
    if [ -z "$loginretries_value" ]; then
        if command -v lsuser &>/dev/null; then
            # root 사용자의 loginretries 확인
            local root_loginretries=$(lsuser -a loginretries root 2>/dev/null | awk -F= '{print $2}')
            if [ -n "$root_loginretries" ]; then
                loginretries_value=$root_loginretries
                config_details="lsuser root: loginretries=${loginretries_value}"
            fi
        fi
    fi

    # 3) AIX 기본값 확인 (설정되지 않은 경우 기본값은 3 또는 무제한)
    if [ -z "$loginretries_value" ]; then
        # AIX 기본값 확인을 위한 방법
        if command -v lssecfg &>/dev/null; then
            loginretries_value="3"  # AIX 일반적 기본값
            config_details="AIX 기본값: loginretries=${loginretries_value}"
        fi
    fi

    # 최종 판정 (5회 이하이면 양호)
    if [ -n "$loginretries_value" ]; then
        if [ "$loginretries_value" -le 5 ]; then
            is_secure=true
        fi
    fi

    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그온 시도 횟수 제한 적절히 설정됨 (loginretries=${loginretries_value} <= 5)"
        command_result="${config_details}"
        command_executed="grep -i loginretries /etc/security/user; lsuser -a loginretries root"
    elif [ -n "$loginretries_value" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그온 시도 횟수 제한 설정됨但 임계값 초과 (loginretries=${loginretries_value} > 5)"
        command_result="${config_details}"
        command_executed="grep -i loginretries /etc/security/user"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그온 시도 횟수 제한 미설정 (기본값 무제한 또는 5회 초과)"
        local grep_raw=$(grep -i loginretries /etc/security/user 2>/dev/null || echo "loginretries not found")
        local lsuser_raw=$(lsuser -a loginretries root 2>/dev/null || echo "lsuser failed")
        command_result="[Command: grep -i loginretries /etc/security/user]${newline}${grep_raw}${newline}${newline}[Command: lsuser -a loginretries root]${newline}${lsuser_raw}"
        command_executed="grep -i loginretries /etc/security/user; lsuser -a loginretries root"
    fi

    # echo ""
    # echo "진단 결과: ${status}"
    # echo "판정: ${diagnosis_result}"
    # echo "설명: ${inspection_summary}"
    # echo ""

    # 결과 생성 (PC 패턴: 스크립트에서 모드 확인 후 처리)
    # Run-all 모드 확인
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
