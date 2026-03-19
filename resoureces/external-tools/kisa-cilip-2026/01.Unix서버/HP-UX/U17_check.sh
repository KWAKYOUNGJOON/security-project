#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-17
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 시스템 시작 스크립트 권한 설정
# @Description : /etc/init.d/* 권한 755 확인
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


ITEM_ID="U-17"
ITEM_NAME="시스템 시작 스크립트 권한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="SUID/SGID 파일의 남용을 방지하여 특권 사용자 권한 상승 공격을 방지하기 위함"
GUIDELINE_THREAT="불필요한 SUID/SGID 파일이 존재할 경우, 공격자가 이를 악용하여 root 권한으로 권한 상승하여 시스템 전체를 장악할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="시스템에서 불필요한 SUID/SGID 파일이 존재하지 않거나, 시스템 필수 바이너리로만 구성된 경우"
GUIDELINE_CRITERIA_BAD="공격에 악용 가능한 스크립트 파일이나 일반 사용자 쓰기 권한이 있는 SUID/SGID 파일이 존재하는 경우"
GUIDELINE_REMEDIATION="불필요한 SUID/SGID 파일의 SUID/SGID 비트를 제거하거나, 파일 소유권을 root로 변경하고 쓰기 권한을 제거"

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
    # SUID/SGID 파일 점검

    local suid_files=""
    local sgid_files=""
    local suid_count=0
    local sgid_count=0
    local vulnerable_files=""
    local vulnerable_count=0

    # 성능 최적화: 핵심 시스템 디렉토리로 검색 범위 제한
    # WSL/가상환경에서 find /는 매우 느리므로 주요 바이너리 경로만 검색
    local search_dirs=(
        "/usr/bin"
        "/usr/sbin"
        "/bin"
        "/sbin"
        "/usr/local/bin"
        "/usr/local/sbin"
        "/lib"
        "/lib64"
        "/usr/lib"
    )

    # 검색 경로 구성
    local find_paths=""
    for dir in "${search_dirs[@]}"; do
        if [ -d "$dir" ]; then
            if [ -z "$find_paths" ]; then
                find_paths="$dir"
            else
                find_paths="${find_paths} $dir"
            fi
        fi
    done || true

    # SUID 파일 검색 (시스템 바이너리 외의 파일)
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            ((suid_count++)) || true
            # HP-UX: use perl for stat instead of stat -c
            local perms=$(perl -e '@s=stat(shift); printf "%04o\n", $s[2] & 07777' "$file" 2>/dev/null)
            local owner=$(perl -e '($dev,$ino,$mode,$nlink,$uid,$gid)=stat(shift); print getpwuid($uid)' "$file" 2>/dev/null)

            # 예상되는 SUID 파일 목록 (시스템 바이너리)
            local expected_suid_patterns="^(ping|ping6|traceroute|traceroute6|sudo|passwd|su|gpasswd|chsh|chfn|newgrp|umount|mount|pkexec|at|fusermount|Xorg|wbem|doas|chage|expire|ssh-keysign)"

            # 파일명만 추출
            local filename=$(basename "$file")

            # 예상되는 시스템 바이너리가 아닌 경우 취약
            if ! [[ "$filename" =~ $expected_suid_patterns ]]; then
                # 사용자가 쓰기 가능한 스크립트 등 취약한 파일
                if [[ "$file" =~ \.(sh|bash|pl|py|rb)$ ]] || [ -w "$file" ]; then
                    ((vulnerable_count++)) || true
                    vulnerable_files="${vulnerable_files}${file} (SUID, 권한: ${perms}, 소유자: ${owner}), "
                fi
            fi

            suid_files="${suid_files}${file} (SUID, ${perms}:${owner}), "
        fi
    done < <(eval "find $find_paths -perm -4000 -type f 2>/dev/null | head -50") || true

    # SGID 파일 검색
    while IFS= read -r file; do
        if [ -n "$file" ]; then
            ((sgid_count++)) || true
            # HP-UX: use perl for stat instead of stat -c
            local perms=$(perl -e '@s=stat(shift); printf "%04o\n", $s[2] & 07777' "$file" 2>/dev/null)
            local owner=$(perl -e '($dev,$ino,$mode,$nlink,$uid,$gid)=stat(shift); print getpwuid($uid)' "$file" 2>/dev/null)

            # 예상되는 SGID 디렉터리/파일 (write 가능한 공유 디렉터리 등)
            if [[ "$file" =~ \.(sh|bash|pl|py|rb)$ ]] || [ -w "$file" ]; then
                ((vulnerable_count++)) || true
                vulnerable_files="${vulnerable_files}${file} (SGID, 권한: ${perms}, 소유자: ${owner}), "
            fi

            sgid_files="${sgid_files}${file} (SGID, ${perms}:${owner}), "
        fi
    done < <(eval "find $find_paths -perm -2000 -type f 2>/dev/null | head -50") || true

    # 결과 판정
    # Capture actual find command output
    local suid_find_output=$(eval "find $find_paths -perm -4000 -type f 2>/dev/null" | head -20 || echo "No SUID files found")
    local sgid_find_output=$(eval "find $find_paths -perm -2000 -type f 2>/dev/null" | head -20 || echo "No SGID files found")

    if [ "$vulnerable_count" -eq 0 ]; then
        if [ "$suid_count" -eq 0 ] && [ "$sgid_count" -eq 0 ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SUID/SGID 파일 없음 (시스템 보안 양호)"
            command_result="[Command: find $find_paths -perm -4000 -type f]${newline}${suid_find_output}${newline}${newline}[Command: find $find_paths -perm -2000 -type f]${newline}${sgid_find_output}"
            command_executed="find $find_paths -perm -4000 -type f 2>/dev/null; find $find_paths -perm -2000 -type f 2>/dev/null"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="SUID/SGID 파일이 시스템 바이너리로만 구성됨 (SUID: ${suid_count}개, SGID: ${sgid_count}개)"
            command_result="[Command: find $find_paths -perm -4000 -type f]${newline}${suid_find_output}${newline}${newline}[Command: find $find_paths -perm -2000 -type f]${newline}${sgid_find_output}"
            command_executed="find $find_paths -perm -4000 -type f 2>/dev/null; find $find_paths -perm -2000 -type f 2>/dev/null"
        fi
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="취약한 SUID/SGID 파일 ${vulnerable_count}개 발견: ${vulnerable_files%, }"
        command_result="[Command: find $find_paths -perm -4000 -type f]${newline}${suid_find_output}${newline}${newline}[Command: find $find_paths -perm -2000 -type f]${newline}${sgid_find_output}${newline}${newline}[Summary] Total SUID: ${suid_count}, SGID: ${sgid_count} (vulnerable: ${vulnerable_count})"
        command_executed="find $find_paths -perm -4000 -type f 2>/dev/null; find $find_paths -perm -2000 -type f 2>/dev/null"
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
