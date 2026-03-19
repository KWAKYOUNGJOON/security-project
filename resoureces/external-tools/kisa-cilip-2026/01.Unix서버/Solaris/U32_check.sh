#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-32
# @Category    : Unix Server
# @Platform    : Solaris (Oracle)
# @Severity    : 중
# @Title       : 홈 디렉토리로 지정한 디렉토리의 존재 관리
# @Description : /etc/passwd에 설정된 홈 디렉토리가 실제로 존재하는지 확인
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


ITEM_ID="U-32"
ITEM_NAME="홈 디렉토리로 지정한 디렉토리의 존재 관리"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="/home디렉토리이외의사용자의홈디렉토리존재여부를점검하여비인가자가시스템명령어의무단 사용을방지하기위함"
GUIDELINE_THREAT="/etc/passwd 파일에 설정된 홈 디렉토리가 존재하지 않는 경우, 해당 계정으로 로그인 시 홈 디렉토리가루트디렉토리(/)로할당되어접근이가능한위험이존재함"
GUIDELINE_CRITERIA_GOOD="홈디렉토리가존재하지않는계정이발견되지않는경우"
GUIDELINE_CRITERIA_BAD="홈디렉토리가존재하지않는계정이발견된경우"
GUIDELINE_REMEDIATION="홈디렉토리가존재하지않는계정에홈디렉토리설정또는계정제거하도록설정"

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
    # /etc/passwd에 설정된 홈 디렉토리가 실제로 존재하는지 확인

    local missing_homedirs=""
    local total_users=0
    local checked_users=0
    local system_uid_threshold=100
    local raw_check_output=""

    # /etc/passwd 파일 파싱
    while IFS=: read -r username password uid gid gecos home shell; do
        ((total_users++)) || true

        # 시스템 계정 제외 (UID >= 100인 일반 사용자만 확인, Solaris)
        if [ "$uid" -lt "$system_uid_threshold" ]; then
            continue
        fi

        # 로그인 쉘이 없는 계정 제외 (/bin/false, /sbin/nologin)
        if [ "$shell" = "/bin/false" ] || [ "$shell" = "/sbin/nologin" ]; then
            continue
        fi

        ((checked_users++)) || true

        # 홈 디렉토리 존재 확인
        if [ ! -d "$home" ]; then
            missing_homedirs="${missing_homedirs}${username}(${home}), "
            raw_check_output="${raw_check_output}${username}: ${home} (NOT FOUND)${newline}"
        else
            raw_check_output="${raw_check_output}${username}: ${home} (exists)${newline}"
        fi
    done < /etc/passwd || true

    command_executed="while IFS=: read -r user pw uid gid gecos home shell; do [ -d \"\$home\" ] || echo \"\$user \$home\"; done < /etc/passwd" || true

    # 최종 판정
    if [ -z "$missing_homedirs" ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="모든 사용자 계정의 홈 디렉토리가 존재합니다. (확인된 사용자: ${checked_users}명, 시스템 계정 제외)"
        command_result="[Home directory existence check]${newline}${raw_check_output}"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="일부 사용자의 홈 디렉토리가 존재하지 않습니다: ${missing_homedirs%, }. 홈 디렉토리를 생성하거나 불필요한 계정을 제거하세요: mkdir -m 700 /home/<user> && chown <user>:<gid> /home/<user> 또는 userdel <user>"
        command_result="[Home directory existence check]${newline}${raw_check_output}"
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
