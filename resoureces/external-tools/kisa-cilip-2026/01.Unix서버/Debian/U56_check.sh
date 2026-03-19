#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-56
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 하
# @Title       : FTP 서비스 접근 제어 설정
# @Description : /etc/ftpusers 설정 확인
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


ITEM_ID="U-56"
ITEM_NAME="FTP 서비스 접근 제어 설정"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP 서비스 접근 제어 설정을 통한 비인가자 FTP 접속 차단"
GUIDELINE_THREAT="FTP 접근 제어 미흡 시 비인가자가 무단 접속을 시도하여 정보 유출 및 시스템 침해 위험"
GUIDELINE_CRITERIA_GOOD="FTP 접근 제어가 적절하게 설정된 경우"
GUIDELINE_CRITERIA_BAD=" FTP 접근 제어가 설정되지 않은 경우 / N/A: FTP 서비스 미사용"
GUIDELINE_REMEDIATION="/etc/hosts.allow, /etc/hosts.deny에 FTP 접근 허용 IP 설정 및 ftpusers 파일에 시스템 계정 등록"

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
    # FTP 서비스 접근 제어 설정 확인

    local ftp_installed=false
    local access_configured=false
    local access_details=""
    local config_files=""
    local raw_output=""

    # Capture raw output from FTP config files
    raw_output=$(cat /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/proftpd/proftpd.conf /etc/ftpusers /etc/ftpdusers 2>/dev/null || echo "No FTP config files found")

    # FTP 설정 파일 확인
    if [ -f /etc/vsftpd.conf ] || [ -f /etc/vsftpd/vsftpd.conf ]; then
        ftp_installed=true
        local vsftpd_conf="/etc/vsftpd.conf"
        [ ! -f "$vsftpd_conf" ] && vsftpd_conf="/etc/vsftpd/vsftpd.conf"

        # vsftpd 접근 제어 확인
        # 1) /etc/ftpusers 또는 /etc/vsftpd.ftpusers 확인
        if [ -f /etc/ftpusers ]; then
            local blocked_users=$(wc -l < /etc/ftpusers 2>/dev/null)
            if [ "$blocked_users" -gt 0 ]; then
                access_configured=true
                access_details="/etc/ftpusers에 ${blocked_users}개 차단된 사용자"
                config_files="${config_files}/etc/ftpusers "
            fi
        fi

        # 2) vsftpd.conf에서 userlist_deny, userlist_file 확인
        if grep -q "^userlist_enable=YES" "$vsftpd_conf" 2>/dev/null; then
            access_configured=true
            local userlist_file=$(grep "^userlist_file" "$vsftpd_conf" 2>/dev/null | awk '{print $2}' | head -1)
            if [ -n "$userlist_file" ] && [ -f "$userlist_file" ]; then
                local userlist_count=$(wc -l < "$userlist_file" 2>/dev/null)
                access_details="${access_details}, ${userlist_file}에 ${userlist_count}개 사용자"
            fi
            config_files="${config_files}${vsftpd_conf} "
        fi
    fi

    if [ -f /etc/proftpd/proftpd.conf ]; then
        ftp_installed=true
        # proftpd 접근 제어 확인
        if grep -qE "^[\s]*<Limit.*LOGIN>" /etc/proftpd/proftpd.conf 2>/dev/null; then
            access_configured=true
            access_details="${access_details}, proftpd <Limit LOGIN> 설정됨"
        fi
        config_files="${config_files}/etc/proftpd/proftpd.conf "
    fi

    # /etc/ftpusers 또는 /etc/ftpdusers 확인 (일반적인 FTP 차단 파일)
    for users_file in /etc/ftpusers /etc/ftpdusers; do
        if [ -f "$users_file" ]; then
            ftp_installed=true
            local user_count=$(grep -v "^#" "$users_file" 2>/dev/null | grep -v "^$" | wc -l)
            if [ "$user_count" -gt 0 ]; then
                access_configured=true
                access_details="${access_details}, ${users_file}에 ${user_count}개 차단 사용자"
                config_files="${config_files}${users_file} "
            fi
        fi
    done || true

    if [ "$ftp_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 서비스가 설치되지 않음"
        command_result="FTP: [not installed]"
        command_executed="ls /etc/{vsftpd*,proftpd*,ftpusers} 2>/dev/null"
    elif [ "$access_configured" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 접근 제어가 설정됨: ${access_details#, }"
        command_result="${raw_output}"
        command_executed="cat ${config_files} 2>/dev/null | grep -E 'userlist|ftpusers'"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FTP 접근 제어가 설정되지 않음 (root 등 관리자 계정 접근 가능)"
        command_result="${raw_output}"
        command_executed="cat /etc/{vsftpd*,proftpd*,ftpusers,ftpdusers} 2>/dev/null"
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
