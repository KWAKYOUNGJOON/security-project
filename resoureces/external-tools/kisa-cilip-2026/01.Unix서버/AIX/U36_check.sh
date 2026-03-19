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
# @Platform    : AIX
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
GUIDELINE_PURPOSE="r-command 사용을 통한 원격 접속은 NET Backup 또는 클러스터링 등 용도로 사용되기도 하나, 인증없이관리자원격접속이가능하여이에대한보안위협을방지하기위함"
GUIDELINE_THREAT="rlogin, rsh, rexec 등의r-command를이용하여원격에서인증절차없이터미널접속, 쉘명령어를 실행이가능한위험이존재함"
GUIDELINE_CRITERIA_GOOD="불필요한r계열서비스가비활성화된경우"
GUIDELINE_CRITERIA_BAD="불필요한r계열서비스가활성화된경우"
GUIDELINE_REMEDIATION="불필요한r계열서비스중지및비활성화설정 ※ NET Backup 등특별한용도로사용하지않는다면shell(514), login(513), exec(512)서비스중 지 ※ rlogin, rsh, rexec 서비스는backup,클러스터링등의용도로종종사용되고있으므로해당서비 스사용유무를확인하여미사용시서비스중지 ※ /etc/hosts.equiv 또는 $HOME/.rhosts 파일을 통해 해당 서비스 사용 여부 확인 (파일이 존재 하지않거나해당파일내에설정이없다면사용하지않는것으로간주)"

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

    # 2) /etc/bash.bashrc 확인
    if [ -z "$tmout_value" ] && [ -f /etc/bash.bashrc ]; then
        local bashrc_tmout=$(grep -E "^TMOUT=" /etc/bash.bashrc | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$bashrc_tmout" ]; then
            tmout_value=$bashrc_tmout
        fi
        local bashrc_timeout=$(grep -E "^TIMEOUT=" /etc/bash.bashrc | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$bashrc_timeout" ]; then
            timeout_value=$bashrc_timeout
        fi
    fi

    # 3) /etc/profile.d/*.sh 확인
    if [ -z "$tmout_value" ] && [ -d /etc/profile.d ]; then
        local profile_d_tmout=$(grep -h -E "^TMOUT=" /etc/profile.d/*.sh 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -1)
        if [ -n "$profile_d_tmout" ]; then
            tmout_value=$profile_d_tmout
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
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc"
    elif [ -n "$final_value" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="자동 로그아웃 설정됨但 시간 초과 (${config_details} > 600초)"
        command_result="${config_details}"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="자동 로그아웃 미설정 (TMOUT 또는 TIMEOUT 변수 미설정)"
        local grep_raw=$(grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc 2>/dev/null || echo "No TMOUT/TIMEOUT found")
        command_result="[Command: grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc]${newline}${grep_raw}"
        command_executed="grep -E '^TMOUT=|^TIMEOUT=' /etc/profile /etc/bash.bashrc"
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
