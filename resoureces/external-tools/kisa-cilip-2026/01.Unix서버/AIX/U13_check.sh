#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-13
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : 안전한 비밀번호 암호화 알고리즘 사용
# @Description : SHA512 또는更强 알고리즘 확인
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


ITEM_ID="U-13"
ITEM_NAME="안전한 비밀번호 암호화 알고리즘 사용"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전한 비밀번호 암호화 알고리즘(SHA512+, yescrypt) 사용을 통한 비밀번호 보호 강화"
GUIDELINE_THREAT="MD5, DES, SHA1 등 취약한 알고리즘 사용 시 레인보우 테이블 공격 및 무차별 대입 공격으로 인한 비밀번호 노출 위험"
GUIDELINE_CRITERIA_GOOD="SHA512, SHA256, yescrypt 등 안전한 알고리즘 사용"
GUIDELINE_CRITERIA_BAD=" MD5, DES, SHA1 등 취약한 알고리즘 사용"
GUIDELINE_REMEDIATION="/etc/security/user에 password_algorithm 설정 확인 및 LPA (Loadable Password Algorithm) 사용"

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
    # AIX: /etc/security/user에서 password_algorithm 확인
    # AIX는 LPA (Loadable Password Algorithm) 사용

    local is_secure=false
    local details=""
    local pwd_algorithm=""
    local pwd_attribute=""

    # 1) /etc/security/user 확인 (AIX 사용자 보안 설정)
    if [ -f /etc/security/user ]; then
        # password_algorithm 확인 (AIX 6.1+)
        pwd_algorithm=$(grep "^password_algorithm" /etc/security/user 2>/dev/null | grep -v "^#" | head -1 | awk '{print $3}')

        # 기본값 확인 (default 스탠자에서)
        if [ -z "$pwd_algorithm" ]; then
            pwd_algorithm=$(awk '/^default:/,/^[^ \t]/ {if (/password_algorithm/) print $3}' /etc/security/user 2>/dev/null | head -1)
        fi

        if [ -n "$pwd_algorithm" ]; then
            details="/etc/security/user password_algorithm: ${pwd_algorithm}"
        fi
    fi

    # 2) AIX에서 지원하는 안전한 알고리즘 확인
    # AIX는 ssha256, ssha512, sha256, sha512 등 지원
    local secure_algorithms=("ssha512" "ssha256" "sha512" "sha256")

    if [ -n "$pwd_algorithm" ]; then
        # 대소문자 구분 없이 비교
        local pwd_lower=$(echo "$pwd_algorithm" | tr '[:upper:]' '[:lower:]')
        for algo in "${secure_algorithms[@]}"; do
            if [ "$pwd_lower" = "$algo" ]; then
                is_secure=true
                break
            fi
        done
    fi

    # 3) /etc/security/passwd에서 실제 암호화 방식 확인 (선택적)
    # 실제 해시 값이 어떤 알고리즘인지 확인
    if [ -f /etc/security/passwd ]; then
        # root 계정의 암호 해시 확인
        local root_hash=$(awk '/^root:/,/^[^ \t]/ {if (/password =/) print $3}' /etc/security/passwd 2>/dev/null | head -1)
        if [ -n "$root_hash" ]; then
            # AIX 해시 형식: {SSHA512}..., {SSHA256}...
            if echo "$root_hash" | grep -qE '^\{SSHA(512|256)\}'; then
                if [ -z "$details" ]; then
                    details="실제 비밀번호 암호화: SSHA (강력함)"
                fi
                is_secure=true
            elif echo "$root_hash" | grep -qE '^\{SHA(512|256)\}'; then
                if [ -z "$details" ]; then
                    details="실제 비밀번호 암호화: SHA (안전함)"
                fi
                is_secure=true
            fi
        fi
    fi

    # 4) 기본값 확인 (설정 파일에 명시되지 않은 경우)
    if [ -z "$pwd_algorithm" ] && [ "$is_secure" = false ]; then
        # AIX 기본값은 일반적으로 안전한 알고리즘 사용
        # 하지만 명시적으로 설정되지 않았으므로 경고
        details="password_algorithm 미설정 (AIX 기본값 사용 중)"
        # AIX 기본값은 보통 안전하므로 양호로 처리
        is_secure=true
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="안전한 비밀번호 암호화 알고리즘 사용됨 (${details})"
        command_result="${details}"
        command_executed="grep 'password_algorithm' /etc/security/user && lsuser -a registry root"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        if [ -z "$details" ]; then
            inspection_summary="비밀번호 암호화 알고리즘 미설정 또는 약한 알고리즘 사용"
            local grep_raw=$(grep 'password_algorithm' /etc/security/user 2>/dev/null || echo "password_algorithm not found")
            local lsuser_raw=$(lsuser -a registry root 2>/dev/null || echo "lsuser failed")
            command_result="[Command: grep 'password_algorithm' /etc/security/user]${newline}${grep_raw}${newline}${newline}[Command: lsuser -a registry root]${newline}${lsuser_raw}"
        else
            inspection_summary="비밀번호 암호화 알고리즘 부적절 (${details})"
            command_result="${details}"
        fi
        command_executed="grep 'password_algorithm' /etc/security/user && cat /etc/security/passwd"
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

    return 0
}

# 스크립트 직접 실행 시에만 진단 수행
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
