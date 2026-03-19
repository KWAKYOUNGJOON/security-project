#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-27
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 상
# @Title       : .rhosts, hosts.equiv 사용 금지
# @Description : .rhosts, hosts.equiv 파일 확인
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


ITEM_ID="U-27"
ITEM_NAME=".rhosts, hosts.equiv 사용 금지"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="r-command를통한별도의인증없는관리자권한원격접속을차단하기위함"
GUIDELINE_THREAT="Ÿ r-command(rlogin, rsh 등)에 보안 설정이 적용되지 않을 경우, 원격지의 공격자가 관리자 권한으로 목표 시스템상 임의의 명령을 수행시킬 수 있으며, 명령어 원격실행을 통해 중요 정보유출 및시스템장애를유발또는공격자의백도어등으로도활용될수있는위험이존재함 Ÿ 해당 파일은 r-command 서비스의 접근통제에 관련된 파일이며, 권한 설정이 부적절한 경우 r-command서비스사용권한을임의로등록하여무단사용위험이존재함"
GUIDELINE_CRITERIA_GOOD="rlogin,rsh,rexec서비스를사용하지않거나,사용시아래와같은설정이적용된경우 1. /etc/hosts.equiv 및$HOME/.rhosts파일소유자가root또는해당계정인경우 2. /etc/hosts.equiv 및$HOME/.rhosts파일권한이600이하인경우 3. /etc/hosts.equiv 및$HOME/.rhosts파일설정에'+'설정이없는경우"
GUIDELINE_CRITERIA_BAD=" rlogin,rsh,rexec서비스를사용하며아래와같은설정이적용되지않은경우 1. /etc/hosts.equiv및$HOME/.rhosts파일소유자가root또는해당계정이아닌경우"
GUIDELINE_REMEDIATION="/etc/hosts.equiv,$HOME/.rhosts파일소유자및권한변경,허용호스트및계정등록설정"

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
    # .rhosts, hosts.equiv 파일 사용 금지 확인

    local rhosts_files=""
    local rhosts_count=0
    local hosts_equiv_exists=0
    local hosts_equiv_details=""
    local details=""

    # Capture raw find output for .rhosts files
    local rhosts_find=$(find /home -name '.rhosts' 2>/dev/null)
    # Capture ls output for hosts.equiv
    local hosts_equiv_ls=$(ls -l /etc/hosts.equiv 2>&1)
    # Build command_result
    command_result="[Command: find /home -name '.rhosts']${newline}${rhosts_find}${newline}${newline}[Command: ls -l /etc/hosts.equiv]${newline}${hosts_equiv_ls}"

    # /etc/hosts.equiv 파일 확인
    if [ -f "/etc/hosts.equiv" ]; then
        ((hosts_equiv_exists++)) || true
        local perms=$(stat -c "%a" "/etc/hosts.equiv" 2>/dev/null)
        local owner=$(stat -c "%U:%G" "/etc/hosts.equiv" 2>/dev/null)
        local size=$(stat -c "%s" "/etc/hosts.equiv" 2>/dev/null)

        hosts_equiv_details="/etc/hosts.equiv 파일 존재 (권한: ${perms}, 소유자: ${owner}, 크기: ${size}bytes)"
    fi

    # 사용자 홈 디렉터리에서 .rhosts 파일 검색
    while IFS= read -r user_line; do
        local username=$(echo "$user_line" | cut -d: -f1)
        local uid=$(echo "$user_line" | cut -d: -f3)
        local home_dir=$(echo "$user_line" | cut -d: -f6)

        # 홈 디렉터리가 존재하고, UID가 1000 이상인 일반 사용자 확인
        if [ -d "$home_dir" ] && [ "$uid" -ge 1000 ] 2>/dev/null; then
            local rhosts_path="${home_dir}/.rhosts"

            if [ -f "$rhosts_path" ]; then
                ((rhosts_count++)) || true
                local perms=$(stat -c "%a" "$rhosts_path" 2>/dev/null)
                local owner=$(stat -c "%U" "$rhosts_path" 2>/dev/null)
                local size=$(stat -c "%s" "$rhosts_path" 2>/dev/null)

                rhosts_files="${rhosts_files}${rhosts_path} (권한: ${perms}, 소유자: ${owner}, 크기: ${size}bytes), "
            fi
        fi
    done < /etc/passwd || true

    # 결과 판정
    if [ "$hosts_equiv_exists" -eq 0 ] && [ "$rhosts_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary=".rhosts 및 hosts.equiv 파일 없음 (r 계정 사용 제어 양호)"
        command_result="[No .rhosts or hosts.equiv files found]"
        command_executed="find /home -name '.rhosts' 2>/dev/null; ls -l /etc/hosts.equiv 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        details=""

        if [ "$hosts_equiv_exists" -gt 0 ]; then
            details="${details}${hosts_equiv_details}. "
        fi

        if [ "$rhosts_count" -gt 0 ]; then
            details="${details}.rhosts 파일 ${rhosts_count}개 발견: ${rhosts_files%, }. "
        fi

        inspection_summary="취약: ${details}"
        command_result="hosts.equiv: ${hosts_equiv_exists} found, .rhosts: ${rhosts_count} found"
        command_executed="find /home -name '.rhosts' 2>/dev/null; ls -l /etc/hosts.equiv 2>/dev/null"
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
