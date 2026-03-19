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
# @Platform    : HP-UX
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
GUIDELINE_REMEDIATION="/etc/default/security에 MIN_PASSWORD_LENGTH=8, PASSWORD_HISTORY_DEPTH=10 등 설정 및 /etc/pam.d/passwd에 pam_unix.so 모듈 확인"

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
    # 1) HP-UX PAM 설정 확인 (/etc/pam.d/passwd)
    # 2) /etc/default/security의 비밀번호 복잡성 설정 확인

    local is_secure=false
    local config_details=""
    local found_pam_module=false
    local complexity_ok=false
    local age_ok=false

    # Raw command outputs
    local pam_output=""
    local security_output=""
    local newline=$'\n'

    # ============================================================================
    # 1) HP-UX PAM 설정 확인
    # ============================================================================
    local pam_file="/etc/pam.d/passwd"
    local active_pam_file=""
    local pam_module=""

    if [ -f "$pam_file" ]; then
        # HP-UX는 pam_unix.so 또는 pam_hpsec.so 확인
        if grep -q "pam_unix.so" "$pam_file"; then
            pam_module="pam_unix.so"
            found_pam_module=true
            active_pam_file="$pam_file"
        elif grep -q "pam_hpsec.so" "$pam_file"; then
            pam_module="pam_hpsec.so"
            found_pam_module=true
            active_pam_file="$pam_file"
        fi

        if [ "$found_pam_module" = true ]; then
            # PAM 설정의 raw output 저장
            pam_output=$(grep -E "^[\s]*password.*${pam_module}" "$active_pam_file" 2>/dev/null || echo "")
            config_details="[PAM 모듈] ${pam_module} 확인됨"
        else
            config_details="[PAM 모듈] pam_unix.so 또는 pam_hpsec.so 미발견"
            # 원본 grep 출력 저장 (검사 결과 보존)
            pam_output=$(grep -E "pam_unix.so|pam_hpsec.so" "$pam_file" 2>/dev/null || echo "검사한 모듈 미발견")
        fi
    else
        config_details="[PAM 모듈] /etc/pam.d/passwd 파일 없음"
        # 원본 ls -l 출력 저장 (파일 존재 여부 확인)
        pam_output=$(ls -l "$pam_file" 2>/dev/null || echo "File not found: ${pam_file}")
    fi

    # ============================================================================
    # 2) HP-UX 비밀번호 정책 확인 (/etc/default/security)
    # ============================================================================
    local security_file="/etc/default/security"
    local min_password_length=""
    local password_history_depth=""
    local password_max_weeks=""
    local password_min_weeks=""

    if [ -f "$security_file" ]; then
        # Raw output 저장
        security_output=$(grep -E "^[\s]*(MIN_PASSWORD_LENGTH|PASSWORD_HISTORY_DEPTH|PASSWORD_MAX_WEEKS|PASSWORD_MIN_WEEKS)" "$security_file" 2>/dev/null || echo "")

        min_password_length=$(echo "$security_output" | grep "MIN_PASSWORD_LENGTH" | awk -F= '{print $2}' | tr -d ' ')
        password_history_depth=$(echo "$security_output" | grep "PASSWORD_HISTORY_DEPTH" | awk -F= '{print $2}' | tr -d ' ')
        password_max_weeks=$(echo "$security_output" | grep "PASSWORD_MAX_WEEKS" | awk -F= '{print $2}' | tr -d ' ')
        password_min_weeks=$(echo "$security_output" | grep "PASSWORD_MIN_WEEKS" | awk -F= '{print $2}' | tr -d ' ')

        config_details="${config_details} | [복잡성] MIN_PASSWORD_LENGTH=${min_password_length:-미설정}, "
        config_details="${config_details}PASSWORD_HISTORY_DEPTH=${password_history_depth:-미설정}"
        config_details="${config_details} | [사용 기간] PASSWORD_MAX_WEEKS=${password_max_weeks:-미설정}, "
        config_details="${config_details}PASSWORD_MIN_WEEKS=${password_min_weeks:-미설정}"

        # 판정: MIN_PASSWORD_LENGTH >= 8
        # 주: HP-UX는 주(week) 단위로 사용 기간을 관리
        local minlen_ok=false
        local max_weeks_ok=false
        local min_weeks_ok=false

        if [ -n "$min_password_length" ] && [ "$min_password_length" -ge 8 ]; then
            minlen_ok=true
        fi

        # 90일 = 약 12.86주, 1일 = 약 0.14주
        # HP-UX에서는 주 단위이므로 13주 이하, 1주 이상으로 판정
        if [ -n "$password_max_weeks" ] && [ "$password_max_weeks" -le 13 ]; then
            max_weeks_ok=true
        fi

        if [ -n "$password_min_weeks" ] && [ "$password_min_weeks" -ge 1 ]; then
            min_weeks_ok=true
        fi

        # 모든 조건 충족 시 양호
        if [ "$minlen_ok" = true ] && [ "$max_weeks_ok" = true ] && [ "$min_weeks_ok" = true ]; then
            complexity_ok=true
            age_ok=true
        fi
    else
        config_details="${config_details} | [보안 정책] /etc/default/security 파일 없음"
        # 원본 ls -l 출력 저장 (파일 존재 여부 확인)
        security_output=$(ls -l "$security_file" 2>/dev/null || echo "File not found: ${security_file}")
    fi

    # ============================================================================
    # 최종 판정
    # ============================================================================
    # 복잡성 설정과 사용 기간 설정 모두 확인되어야 양호
    if [ "$complexity_ok" = true ] && [ "$age_ok" = true ]; then
        is_secure=true
    fi

    if [ "$found_pam_module" = false ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 복잡성 정책 미설정 (PAM 모듈 없음)"
    elif [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="비밀번호 관리 정책 적절하게 설정됨 (${config_details})"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="비밀번호 관리 정책 부적절하게 설정됨 (${config_details})"
    fi

    # 명령어 실행 결과 결합 (raw output)
    command_result="[HP-UX PAM File: ${active_pam_file:-[not found]}]${newline}${pam_output}${newline}${newline}"
    command_result="${command_result}[/etc/default/security]${newline}${security_output}"

    command_executed="grep -E 'pam_unix.so|pam_hpsec.so' /etc/pam.d/passwd; grep -E '^MIN_PASSWORD_LENGTH|^PASSWORD_HISTORY_DEPTH|^PASSWORD_MAX_WEEKS|^PASSWORD_MIN_WEEKS' /etc/default/security"

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
