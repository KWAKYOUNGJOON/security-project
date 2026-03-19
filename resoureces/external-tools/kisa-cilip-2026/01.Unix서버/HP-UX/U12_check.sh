#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-12
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 하
# @Title       : 세션 종료시간 설정
# @Description : TMOUT 또는 /etc/profile 설정 확인
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


ITEM_ID="U-12"
ITEM_NAME="세션 종료시간 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="일정시간동 nail론작업이없을경우자동으로세션을종료하여무단접근을방지하기위함"
GUIDELINE_THREAT="사용자인증후자동로그아웃기능이비활성화된경우부재중시비인가자가시스템에접근하여정보유출및파괴위험이존재함"
GUIDELINE_CRITERIA_GOOD="TMOUT값이600초(10분)이하로설정된경우"
GUIDELINE_CRITERIA_BAD=" TMOUT값이설정되어있지않거나600초(10분)초과로설정된경우"
GUIDELINE_REMEDIATION="/etc/profile또는/etc/bash.bashrc파일에TMOUT=600설정추가"

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
    # 세션 타임아웃 설정 확인 (TMOUT)
    # GOOD: TMOUT이 600초(10분) 이하로 설정됨
    # VULNERABLE: TMOUT 미설정 또는 600초 초과

    local is_secure=false
    local config_details=""
    local tmout_value=""
    local tmout_source=""

    # 1) /etc/profile에서 TMOUT 확인
    if [ -f /etc/profile ]; then
        local profile_tmout=$(grep "^TMOUT=" /etc/profile 2>/dev/null | sed 's/TMOUT=//;s/[[:space:]]*//g')
        if [ -n "$profile_tmout" ]; then
            tmout_value="$profile_tmout"
            tmout_source="/etc/profile"
        fi
    fi

    # 2) /etc/bash.bashrc에서 TMOUT 확인 (HP-UX에서는 존재하지 않을 수 있음)
    if [ -z "$tmout_value" ] && [ -f /etc/bash.bashrc ]; then
        local bashrc_tmout=$(grep "^TMOUT=" /etc/bash.bashrc 2>/dev/null | sed 's/TMOUT=//;s/[[:space:]]*//g')
        if [ -n "$bashrc_tmout" ]; then
            tmout_value="$bashrc_tmout"
            tmout_source="/etc/bash.bashrc"
        fi
    fi

    # 3) 현재 세션의 TMOUT 환경변수 확인
    if [ -z "$tmout_value" ] && [ -n "${TMOUT:-}" ]; then
        tmout_value="$TMOUT"
        tmout_source="현재 세션 환경변수"
    fi

    # TMOUT 값 판정 (600초 = 10분 이하 양호)
    if [ -n "$tmout_value" ]; then
        # TMOUT 값이 숫자인지 확인
        if [[ "$tmout_value" =~ ^[0-9]+$ ]]; then
            if [ "$tmout_value" -le 600 ]; then
                is_secure=true
                config_details="TMOUT=${tmout_value}초 (${tmout_source}) - 600초(10분) 이하 [양호]"
            else
                config_details="TMOUT=${tmout_value}초 (${tmout_source}) - 600초(10분) 초과 [취약]"
            fi
        else
            config_details="TMOUT=${tmout_value} (${tmout_source}) - 유효하지 않은 값"
        fi
    else
        config_details="TMOUT 설정 없음 (/etc/profile, /etc/bash.bashrc 확인)"
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="세션 타임아웃 적절히 설정됨 (${config_details})"
        command_result="${config_details}"
        command_executed="grep '^TMOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null; echo \$TMOUT"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="세션 타임아웃 설정 미흡 (${config_details})"
        command_result="${config_details}"
        command_executed="grep '^TMOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null; echo \$TMOUT"
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
