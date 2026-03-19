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
# @Platform    : HP-UX
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
GUIDELINE_REMEDIATION="/etc/login.defs에 ENCRYPT_METHOD SHA512 설정 및 PAM 설정에 sha512 추가"

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
    # SHA512 또는更强 알고리즘 확인

    local is_secure=false
    local details=""
    local encrypt_method=""
    local pam_algorithm=""

    # 1) HP-UX: /etc/default/security 확인 (PASSWORD_* 파라미터)
    if [ -f /etc/default/security ]; then
        # HP-UX에서는 CRYPT_* 또는 PASSWORD_ALGORITHM 파라미터 확인
        encrypt_method=$(grep "^PASSWORD_ALGORITHM\|^CRYPT_ALGORITHM\|^CRYPT_ALGORITHMS_ALLOW" /etc/default/security 2>/dev/null | head -1)
        if [ -n "$encrypt_method" ]; then
            details="/etc/default/security: ${encrypt_method}"
        fi
    fi

    # 2) HP-UX PAM 설정 확인 (/etc/pam.d/passwd, /etc/pam.d/login, /etc/pam.d/su)
    local pam_files=(
        "/etc/pam.d/passwd"
        "/etc/pam.d/login"
        "/etc/pam.d/su"
    )

    for pam_file in "${pam_files[@]}"; do
        if [ -f "$pam_file" ]; then
            # HP-UX PAM에서 pam_unix.so 알고리즘 확인
            # SHA512 확인 (우선)
            if grep -q "pam_unix.so.*sha512" "$pam_file" 2>/dev/null; then
                pam_algorithm="sha512"
                is_secure=true
                if [ -n "$details" ]; then
                    details="${details}, PAM (${pam_file}): ${pam_algorithm}"
                else
                    details="PAM (${pam_file}) pam_unix.so 알고리즘: ${pam_algorithm}"
                fi
                break
            # SHA256 확인 (최소 허용)
            elif grep -q "pam_unix.so.*sha256" "$pam_file" 2>/dev/null; then
                pam_algorithm="sha256"
                is_secure=true
                if [ -n "$details" ]; then
                    details="${details}, PAM (${pam_file}): ${pam_algorithm}"
                else
                    details="PAM (${pam_file}) pam_unix.so 알고리즘: ${pam_algorithm}"
                fi
                break
            # yescrypt 확인 (더 강력함)
            elif grep -q "pam_unix.so.*yescrypt" "$pam_file" 2>/dev/null; then
                pam_algorithm="yescrypt"
                is_secure=true
                if [ -n "$details" ]; then
                    details="${details}, PAM (${pam_file}): ${pam_algorithm}"
                else
                    details="PAM (${pam_file}) pam_unix.so 알고리즘: ${pam_algorithm}"
                fi
                break
            fi
        fi
    done || true

    # 3) /etc/default/security의 알고리즘 확인
    if [ "$is_secure" = false ] && [ -n "$encrypt_method" ]; then
        # HP-UX에서 지원하는 안전한 알고리즘 확인
        if echo "$encrypt_method" | grep -qiE "sha512|sha256|yescrypt|blowfish"; then
            is_secure=true
        fi
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="안전한 비밀번호 암호화 알고리즘 사용됨 (${details})"
        command_result="${details}"
        command_executed="grep -E '^PASSWORD_ALGORITHM|^CRYPT_' /etc/default/security && grep 'pam_unix.so' /etc/pam.d/passwd /etc/pam.d/login"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        if [ -z "$details" ]; then
            inspection_summary="비밀번호 암호화 알고리즘 미설정 또는 약한 알고리즘 사용 (MD5, DES 등)"
            local encrypt_check=$(grep -E '^PASSWORD_ALGORITHM|^CRYPT_' /etc/default/security 2>/dev/null || echo "No encryption algorithm configured")
            command_result="${encrypt_check}"
        else
            inspection_summary="비밀번호 암호화 알고리즘 부적절 (${details})"
            command_result="${details}"
        fi
        command_executed="grep -E '^PASSWORD_ALGORITHM|^CRYPT_' /etc/default/security && grep 'pam_unix.so' /etc/pam.d/passwd /etc/pam.d/login"
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
