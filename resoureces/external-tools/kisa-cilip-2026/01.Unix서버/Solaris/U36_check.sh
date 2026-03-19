#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-36
# @Category    : Unix Server
# @Platform    : Solaris (Oracle)
# @Severity    : 중
# @Title       : 자동 로그아웃 설정
# @Description : TMOUT <= 600 seconds 확인
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


ITEM_ID="U-36"
ITEM_NAME="자동 로그아웃 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="사용자의 부주의로 인한 정보 유출을 방지하고, 불필요한 세션 점유를 방지하기 위함"
GUIDELINE_THREAT="자동 로그아웃 설정이 미흡할 경우, 사용자가 부주의하여 자리를 비웠을 때 타인이 해당 시스템에 접근하여 중요 정보를 탈취하거나, 불필요한 세션 점유로 인한 시스템 자원 낭비가 발생할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="자동 로그아웃 시간이 600초(10분) 이하로 설정된 경우"
GUIDELINE_CRITERIA_BAD="자동 로그아웃 설정이 되어 있지 않거나, 설정 시간이 600초를 초과하는 경우"
GUIDELINE_REMEDIATION="/etc/profile, /etc/bash.bashrc 또는 /etc/profile.d/*.sh 파일에 TMOUT 또는 TIMEOUT 값을 600 이하로 설정"

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
    # /etc/profile, /etc/bash.bashrc에서 TMOUT 또는 TIMEOUT 확인

    local is_secure=false
    local config_details=""
    local tmout_value=""
    local timeout_value=""

    # 1) /etc/profile 확인
    if [ -f /etc/profile ]; then
        local profile_tmout=$(grep -E "^TMOUT=" /etc/profile | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$profile_tmout" ]; then
            tmout_value=$profile_tmout
        fi
        local profile_timeout=$(grep -E "^TIMEOUT=" /etc/profile | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$profile_timeout" ]; then
            timeout_value=$profile_timeout
        fi
    fi

    # 2) /etc/.login 확인 (Solaris csh)
    if [ -z "$tmout_value" ] && [ -f /etc/.login ]; then
        local login_tmout=$(grep -E "^setenv TMOUT" /etc/.login | awk '{print $3}' | tr -d ' ')
        if [ -n "$login_tmout" ]; then
            tmout_value=$login_tmout
        fi
    fi

    # 값 검증 (TMOUT 또는 TIMEOUT)
    local final_value=""
    if [ -n "$tmout_value" ]; then
        final_value=$tmout_value
        config_details="TMOUT=${tmout_value} seconds"
    elif [ -n "$timeout_value" ]; then
        final_value=$timeout_value
        config_details="TIMEOUT=${timeout_value} seconds"
    fi

    # 최종 판정 (600초 = 10분 이하이면 양호)
    if [ -n "$final_value" ]; then
        if [ "$final_value" -le 600 ]; then
            is_secure=true
        fi
    fi

    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="자동 로그아웃 설정 적절함 (${config_details} <= 600초)"
        command_result="${config_details}"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile; grep '^setenv TMOUT' /etc/.login"
    elif [ -n "$final_value" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="자동 로그아웃 설정됨但 시간 초과 (${config_details} > 600초)"
        command_result="${config_details}"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile; grep '^setenv TMOUT' /etc/.login"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="자동 로그아웃 미설정 (TMOUT 또는 TIMEOUT 변수 미설정)"
        command_result="TMOUT/TIMEOUT setting not found"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile; grep '^setenv TMOUT' /etc/.login"
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
