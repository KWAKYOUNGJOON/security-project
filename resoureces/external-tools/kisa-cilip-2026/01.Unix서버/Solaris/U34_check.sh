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
# @Platform    : Solaris (Oracle)
# @Severity    : 상
# @Title       : 로그온 시도 횟수 제한
# @Description : faillock 설정 확인 deny <= 5
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

    # 진단 로직 구현
    # Solaris: /etc/default/passwd에서 RETRIES 확인

    local is_secure=false
    local config_details=""
    local deny_value=""

    # Solaris: /etc/default/passwd에서 RETRIES 설정 확인
    if [ -f /etc/default/passwd ]; then
        local retries_setting=$(grep "^RETRIES=" /etc/default/passwd | awk -F= '{print $2}' | tr -d ' ')
        if [ -n "$retries_setting" ]; then
            deny_value=$retries_setting
            if [ "$deny_value" -le 5 ]; then
                is_secure=true
            fi
            config_details="/etc/default/passwd: RETRIES=${deny_value}"
        else
            # 기본값 확인 (Solaris는 보통 3-5회)
            deny_value="3"
            config_details="/etc/default/passwd: 기본값 RETRIES=3 (설정 없음)"
            is_secure=true
        fi
    else
        # PAM 폴백 (Solaris는 PAM도 지원)
        local pam_files=(
            "/etc/pam.d/common-auth"
            "/etc/pam.d/system-auth"
            "/etc/pam.d/login"
        )

        for pam_file in "${pam_files[@]}"; do
            if [ -f "$pam_file" ]; then
                if grep -q "pam_faillock.so" "$pam_file"; then
                    deny_value=$(grep "pam_faillock.so" "$pam_file" | grep -oP 'deny=\K[0-9]+' | head -1)
                    if [ -n "$deny_value" ]; then
                        if [ "$deny_value" -le 5 ]; then
                            is_secure=true
                        fi
                        config_details="pam_faillock.so: deny=${deny_value}"
                    fi
                    break
                fi
            fi
        done || true
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="로그온 시도 횟수 제한 적절히 설정됨 (RETRIES=${deny_value} <= 5)"
        command_result="${config_details}"
        command_executed="grep '^RETRIES' /etc/default/passwd; grep pam_faillock.so /etc/pam.d/common-auth"
    elif [ -n "$deny_value" ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그온 시도 횟수 제한 설정됨但 임계값 초과 (RETRIES=${deny_value} > 5)"
        command_result="${config_details}"
        command_executed="grep '^RETRIES' /etc/default/passwd"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="로그온 시도 횟수 제한 미설정"
        command_result="RETRIES setting not found"
        command_executed="ls -la /etc/default/passwd 2>/dev/null; grep pam_faillock.so /etc/pam.d/common-auth"
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
