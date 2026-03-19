#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-37
# @Category    : Unix Server
# @Platform    : Solaris (Oracle)
# @Severity    : 상
# @Title       : crontab 설정 파일 권한 설정 미흡
# @Description : /etc/crontab 권한 600 확인
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


ITEM_ID="U-37"
ITEM_NAME="crontab 설정 파일 권한 설정 미흡"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="crontab 설정 파일을 관리자만 제어하여 비인가자의 예약 작업 등록 방지"
GUIDELINE_THREAT="crontab 파일의 권한 설정 미흡 시 비인가자가 악의적인 예약 작업을 등록하여 주기적 악성코드 실행 및 시스템 장악 위험"
GUIDELINE_CRITERIA_GOOD="crontab 파일 소유자가 root이고 권한이 600 이하인 경우"
GUIDELINE_CRITERIA_BAD=" 소유자가 root가 아니거나 권한이 601 이상인 경우"
GUIDELINE_REMEDIATION="chown root:root /etc/crontab && chmod 600 /etc/crontab 실행, crontab 파일 접근 제한 설정"

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

    # crontab 파일 권한 확인 (Solaris: /var/spool/cron/crontabs 사용)
    local crontab_files=(
        "/etc/cron.deny"
        "/etc/cron.allow"
        "/etc/at.deny"
        "/etc/at.allow"
    )

    local is_secure=true
    local issues=()
    local file_info=""

    for file in "${crontab_files[@]}"; do
        if [ -f "$file" ]; then
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$file" 2>/dev/null || echo "unknown")

            file_info="${file_info}${file}: 권한=${perms}, 소유자=${owner}\\n"

            # cron.deny, at.deny는 600 이하 권장 (Solaris: /etc/crontab 없음)
            if [[ "$file" =~ (cron.deny|at.deny)$ ]]; then
                if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                    is_secure=false
                    issues+=("${file} 권한=${perms} (600 권장)")
                fi
                # root 소유여부 확인
                if [ "$owner" != "root" ]; then
                    is_secure=false
                    issues+=("${file} 소유자=${owner} (root여야 함)")
                fi
            fi

            # cron.allow, at.allow는 600 권장
            if [[ "$file" =~ (cron.allow|at.allow)$ ]]; then
                if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                    is_secure=false
                    issues+=("${file} 권한=${perms} (600 권장)")
                fi
                if [ "$owner" != "root" ]; then
                    is_secure=false
                    issues+=("${file} 소유자=${owner} (root여야 함)")
                fi
            fi
        fi
    done || true

    # /etc/cron.d 디렉토리 내 파일 권한 확인 (Solaris: /var/spool/cron/crontabs 사용)
    if [ -d /etc/cron.d ]; then
        file_info="${file_info}\\n/etc/cron.d 디렉토리 파일:\\n"
        while IFS= read -r -d '' file; do
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$file" 2>/dev/null || echo "unknown")
            file_info="${file_info}  $(basename "$file"): ${perms}, ${owner}\\n"

            if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                is_secure=false
                issues+=("cron.d/$(basename "$file") 권한=${perms}")
            fi
        done < <(find /etc/cron.d -type f -print0 2>/dev/null) || true
    fi

    # Solaris: /var/spool/cron/crontabs 확인
    if [ -d /var/spool/cron/crontabs ]; then
        file_info="${file_info}\\n/var/spool/cron/crontabs 디렉토리 파일:\\n"
        while IFS= read -r -d '' file; do
            local perms=$(perl -e 'if (-f $ARGV[0]) { printf "%04o\n", (stat($ARGV[0]))[2] & 07777; }' "$file" 2>/dev/null || echo "000")
            local owner=$(perl -e 'if (-f $ARGV[0]) { $uid = (stat($ARGV[0]))[4]; print getpwuid($uid); }' "$file" 2>/dev/null || echo "unknown")
            file_info="${file_info}  $(basename "$file"): ${perms}, ${owner}\\n"

            if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
                is_secure=false
                issues+=("crontabs/$(basename "$file") 권한=${perms}")
            fi
        done < <(find /var/spool/cron/crontabs -type f -print0 2>/dev/null) || true
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="crontab 관련 파일 권한 적절함"
        command_result="${file_info}"
        command_executed="perl -e 'for $f (@ARGV) { if (-f $f) { printf \"%04o %s\\n\", (stat($f))[2] & 07777, (getpwuid((stat($f))[4]))[0]; } }' /etc/cron.deny /etc/cron.allow /etc/at.deny /etc/at.allow 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="crontab 파일 권한 미흡: ${issues[*]}"
        command_result="${file_info}"
        command_executed="perl -e 'for $f (@ARGV) { if (-f $f) { printf \"%04o %s\\n\", (stat($f))[2] & 07777, (getpwuid((stat($f))[4]))[0]; } }' /etc/cron.deny /etc/cron.allow /etc/at.deny /etc/at.allow 2>/dev/null; find /var/spool/cron/crontabs -type f 2>/dev/null"
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
