#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-33
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 하
# @Title       : 숨겨진 파일 및 디렉토리 검색 및 제거
# @Description : 숨겨진 파일(.) 및 의심스러운 파일 탐지
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


ITEM_ID="U-33"
ITEM_NAME="숨겨진 파일 및 디렉토리 검색 및 제거"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="숨겨진파일및디렉토리중의심스러운내용은정상사용자가아닌공격자에의해생성되었을가능성이 높으므로이를제거하여보안위협을방지하기위함"
GUIDELINE_THREAT="숨겨진파일및디렉토리를방치할경우,비인가자가생성한악성파일또는백도어등을탐지하지못할 위험이존재함"
GUIDELINE_CRITERIA_GOOD="불필요하거나의심스러운숨겨진파일및디렉토리를제거한경우"
GUIDELINE_CRITERIA_BAD="불필요하거나의심스러운숨겨진파일및디렉토리를제거하지않은경우"
GUIDELINE_REMEDIATION="ls-al명령어로숨겨진파일존재파악후불법적이거나의심스러운파일을제거하도록설정".*\^" -ls로 확인 후 rm -rf로 제거"

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
    # 사용자 홈 디렉토리 내 숨겨진 파일(.) 및 디렉토리 검색
    # 의심스러운 파일 패턴 확인 (.ssh, .bashrc 등 제외한 숨김파일)

    local suspicious_files=""
    local total_hidden=0
    local suspicious_count=0
    local checked_homedirs=0
    local system_uid_threshold=200  # AIX system UID: < 200
    local raw_find_output=""  # 원본 find 명령어 결과 누적

    # 정상적인 숨겨진 파일 목록 (백도어 후보에서 제외)
    local normal_hidden_patterns=(
        "\.bashrc"
        "\.bash_profile"
        "\.bash_logout"
        "\.profile"
        "\.ssh"
        "\.gitconfig"
        "\.gitignore"
        "\.vimrc"
        "\.viminfo"
        "\.cache"
        "\.config"
        "\.local"
        "\.mozilla"
        "\.gnupg"
    )

    # 사용자 홈 디렉토리 확인
    while IFS=: read -r username password uid gid gecos home shell; do
        # 시스템 계정 제외 (UID >= 200인 일반 사용자만 확인)
        if [ "$uid" -lt "$system_uid_threshold" ]; then
            continue
        fi

        # 로그인 쉘이 없는 계정 제외
        if [ "$shell" = "/bin/false" ] || [ "$shell" = "/sbin/nologin" ]; then
            continue
        fi

        # 홈 디렉토리 존재 확인
        if [ ! -d "$home" ]; then
            continue
        fi

        ((checked_homedirs++)) || true

        # 숨겨진 파일 및 디렉토리 검색 (.)
        # 원본 find 명령어 실행 및 결과 저장
        local find_result=$(find "$home" -maxdepth 1 -name ".*" 2>/dev/null)

        if [ -n "$find_result" ]; then
            raw_find_output="${raw_find_output}[Directory: $home]${newline}${find_result}${newline}${newline}"
        fi

        while IFS= read -r hidden_file; do
            if [ -z "$hidden_file" ]; then
                continue
            fi

            ((total_hidden++)) || true

            # 파일명만 추출
            local filename=$(basename "$hidden_file")

            # 정상적인 숨겨진 파일인지 확인
            local is_normal=false
            for pattern in "${normal_hidden_patterns[@]}"; do
                if [[ "$filename" =~ $pattern ]]; then
                    is_normal=true
                    break
                fi
            done || true

            # 의심스러운 숨겨진 파일
            if [ "$is_normal" = false ]; then
                # 파일 타입 확인
                local filetype=""
                if [ -f "$hidden_file" ]; then
                    filetype="file"
                elif [ -d "$hidden_file" ]; then
                    filetype="dir"
                elif [ -L "$hidden_file" ]; then
                    filetype="symlink"
                fi

                # 실행 가능한 파일인 경우 더 의심스러움
                local perms=""
                if [ -f "$hidden_file" ]; then
                    perms=$(ls -ld "$hidden_file" 2>/dev/null | awk '{print $1}' | cut -c2-10 | sed 's/rwx/7/g; s/rw-/6/g; s/r-x/5/g; s/r--/4/g; s/-wx/3/g; s/-w-/2/g; s/--x/1/g; s/---/0/g' || echo "000")
                    if [[ "$perms" =~ ^[0-9]*[1357][0-9]*$ ]]; then
                        # 실행 가능한 파일
                        suspicious_files="${suspicious_files}${home}/${filename}(${filetype}, executable: ${perms}), "
                        ((suspicious_count++)) || true
                    else
                        suspicious_files="${suspicious_files}${home}/${filename}(${filetype}), "
                        ((suspicious_count++)) || true
                    fi
                else
                    suspicious_files="${suspicious_files}${home}/${filename}(${filetype}), "
                    ((suspicious_count++)) || true
                fi
            fi
        done < <(find "$home" -maxdepth 1 -name ".*" 2>/dev/null | head -50) || true
    done < /etc/passwd || true

    command_executed="while IFS=: read -r user pw uid gid gecos home shell; do find \"\$home\" -maxdepth 1 -name \".*\" 2>/dev/null; done < /etc/passwd | grep -v -E '\.(bashrc|bash_profile|profile|ssh|gitconfig|gitignore|vimrc|viminfo)$'" || true

    # 최종 판정
    if [ "$suspicious_count" -eq 0 ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="의심스러운 숨겨진 파일이 발견되지 않았습니다. (확인된 홈 디렉토리: ${checked_homedirs}개, 전체 숨겨진 파일: ${total_hidden}개)"
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[No suspicious files found (checked ${checked_homedirs} home directories, ${total_hidden} total hidden files)]"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="의심스러운 숨겨진 파일 ${suspicious_count}개가 발견되었습니다: ${suspicious_files%, }. 해당 파일들을 검토한 후 불필요하거나 악성적인 경우 제거하세요: rm -rf <file>"
        command_result="[Hidden files search results]${newline}${raw_find_output}${newline}[Suspicious files found]${newline}${suspicious_files%, }"
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
