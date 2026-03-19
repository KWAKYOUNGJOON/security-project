#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-02
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : 비밀번호 관리 정책 설정
# @Description : 비밀번호 복잡성 설정 및 최소/최대 사용 기간 확인
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


ITEM_ID="U-02"
ITEM_NAME="비밀번호 관리 정책 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="비밀번호 복잡성 및 사용 기간 설정을 통한 무차별 대입 공격 및 사전 대입 공격 방지"
GUIDELINE_THREAT="비밀번호 관리 정책 미설정 시 무차별 대입 공격, 사전 대입 공격 등으로 인한 비밀번호 노출 및 계정 탈취 위험"
GUIDELINE_CRITERIA_GOOD="비밀번호 복잡성(8자리 이상, 영문/숫자/특수문자 조합) 및 사용 기간(최소 1일, 최대 90일) 설정된 경우"
GUIDELINE_CRITERIA_BAD=" 정책 미설정 또는 부적절하게 설정된 경우"
GUIDELINE_REMEDIATION="/etc/security/user 파일에 minlen=8, minalpha=1, minother=1, maxage=90 설정 추가"

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

    # 진단 로직 구현
    # AIX는 /etc/security/user 파일에서 비밀번호 정책 확인
    # 확인 항목: minlen, minalpha, minother, maxage

    local is_secure=false
    local config_details=""
    local has_policy=false
    local complexity_ok=false
    local age_ok=false

    # Raw command outputs
    local security_user_output=""
    local newline=$'\n'

    # ============================================================================
    # 1) /etc/security/user 파일 확인
    # ============================================================================
    local security_user_file="/etc/security/user"

    if [ -f "$security_user_file" ]; then
        # Raw output 저장 (root 섹션 추출)
        security_user_output=$(awk '/^root:/,/^$/ {print}' "$security_user_file" 2>/dev/null || echo "")

        # 각 설정값 추출 (root 계정 기준)
        local minlen=$(awk '/^root:/,/^$/ {print}' "$security_user_file" | grep "minlen" | awk '{print $3}')
        local minalpha=$(awk '/^root:/,/^$/ {print}' "$security_user_file" | grep "minalpha" | awk '{print $3}')
        local minother=$(awk '/^root:/,/^$/ {print}' "$security_user_file" | grep "minother" | awk '{print $3}')
        local maxage=$(awk '/^root:/,/^$/ {print}' "$security_user_file" | grep "maxage" | awk '{print $3}')

        # AIX 기본값 (설정되지 않은 경우)
        # minlen: 기본값 0 (제한 없음), minalpha/minother: 기본값 0, maxage: 기본값 0
        minlen=${minlen:-0}
        minalpha=${minalpha:-0}
        minother=${minother:-0}
        maxage=${maxage:-0}

        config_details="[AIX /etc/security/user] root account: "
        config_details="${config_details}minlen=${minlen}, "
        config_details="${config_details}minalpha=${minalpha}, "
        config_details="${config_details}minother=${minother}, "
        config_details="${config_details}maxage=${maxage}"

        # 판정: minlen >= 8, minalpha >= 1, minother >= 1, maxage <= 90
        local minlen_ok=false
        local minalpha_ok=false
        local minother_ok=false
        local maxage_ok=false

        # 설정이 하나라도 있는지 확인
        if [ -n "$(awk '/^root:/,/^$/ {print}' "$security_user_file" | grep -E 'minlen|minalpha|minother|maxage')" ]; then
            has_policy=true
        fi

        # minlen 검증: 8자 이상
        if [ "$minlen" -ge 8 ]; then
            minlen_ok=true
        fi

        # minalpha 검증: 1자 이상 (영문자)
        if [ "$minalpha" -ge 1 ]; then
            minalpha_ok=true
        fi

        # minother 검증: 1자 이상 (숫자+특수문자)
        if [ "$minother" -ge 1 ]; then
            minother_ok=true
        fi

        # maxage 검증: 90일 이하 (0이면 무제한이므로 취약)
        if [ "$maxage" -gt 0 ] && [ "$maxage" -le 90 ]; then
            maxage_ok=true
        fi

        # 복잡성: minlen, minalpha, minother 모두 충족
        if [ "$minlen_ok" = true ] && [ "$minalpha_ok" = true ] && [ "$minother_ok" = true ]; then
            complexity_ok=true
        fi

        # 사용 기간: maxage 설정 확인
        if [ "$maxage_ok" = true ]; then
            age_ok=true
        fi
    else
        config_details="[AIX /etc/security/user] 파일 없음"
        # 원본 ls -l 출력 저장 (파일 존재 여부 확인)
        security_user_output=$(ls -l "$security_user_file" 2>/dev/null || echo "File not found: ${security_user_file}")
        has_policy=false
    fi

    # ============================================================================
    # 최종 판정
    # ============================================================================
    # 복잡성 설정과 사용 기간 설정 모두 확인되어야 양호
    if [ "$complexity_ok" = true ] && [ "$age_ok" = true ]; then
        is_secure=true
    fi

    if [ "$has_policy" = false ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 관리 정책 미설정 (/etc/security/user 설정 없음)"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 관리 정책이 적절하게 설정됨 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 관리 정책이 부적절하게 설정됨 (${config_details})"
    fi

    # 명령어 실행 결과 결합 (raw output)
    local awk_output=$(awk '/^root:/,/^$/ {print}' "$security_user_file" 2>/dev/null || echo "No root section found")
    command_result="[Command: awk '/^root:/,/^$/' /etc/security/user]${newline}${awk_output}"

    command_executed="awk '/^root:/,/^$/ {print}' /etc/security/user"

    #echo ""
    #echo "진단 결과: ${status}"
    #echo "판정: ${diagnosis_result}"
    #echo "설명: ${inspection_summary}"
    #echo ""

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
