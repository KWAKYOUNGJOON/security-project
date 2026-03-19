#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-53
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 하
# @Title       : FTP 서비스 정보 노출 제한
# @Description : FTP 배너 정보 제거 확인
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


ITEM_ID="U-53"
ITEM_NAME="FTP 서비스 정보 노출 제한"
SEVERITY="하"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP서비스접속배너를통한불필요한정보노출을방지하기위함"
GUIDELINE_THREAT="서비스 접속 배너가 차단되지 않을 경우, 비인가자가 FTP 접속 시도 시 노출되는 접속 배너 정보를 수집하여악의적인공격에이용할위험이존재함"
GUIDELINE_CRITERIA_GOOD="FTP접속배너에노출되는정보가없는경우"
GUIDELINE_CRITERIA_BAD="FTP접속배너에노출되는정보가있는경우"
GUIDELINE_REMEDIATION="Ÿ FTP서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ FTP서비스사용시FTP설정파일을통해접속배너설정 ※ 접속배너에서비스이름이나버전정보를노출하지않는것을권고"

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
    # FTP 배너 정보 제거 확인

    local ftp_banner_issue=false
    local banner_details=""
    local ftp_config_files=()

    # FTP 설정 파일 검색
    if [ -f /etc/proftpd/proftpd.conf ]; then
        ftp_config_files+=("/etc/proftpd/proftpd.conf")
    fi
    if [ -f /etc/vsftpd.conf ]; then
        ftp_config_files+=("/etc/vsftpd.conf")
    fi
    if [ -f /etc/vsftpd/vsftpd.conf ]; then
        ftp_config_files+=("/etc/vsftpd/vsftpd.conf")
    fi
    if [ -f /etc/pure-ftpd/conf/DisplayLogin ]; then
        ftp_config_files+=("/etc/pure-ftpd/conf/DisplayLogin")
    fi
    if [ -f /etc/pure-ftpd/conf/FortunesFile ]; then
        ftp_config_files+=("/etc/pure-ftpd/conf/FortunesFile")
    fi

    # 각 설정 파일에서 배너 정보 확인
    for config_file in "${ftp_config_files[@]}"; do
        local banner_value=""

        # vsftpd 배너 설정 확인
        if [[ "$config_file" == *"vsftpd"* ]]; then
            banner_value=$(grep -E "^[\s]*ftpd_banner|^[\s]*banner_file" "$config_file" 2>/dev/null | grep -v "^#" | head -1)
            if [ -n "$banner_value" ]; then
                # 배너에 버전 정보가 포함되어 있는지 확인
                if echo "$banner_value" | grep -qiE "version|vsftpd|proftpd"; then
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: ${banner_value}, "
                fi
            fi
        fi

        # proftpd 배너 설정 확인
        if [[ "$config_file" == *"proftpd"* ]]; then
            banner_value=$(grep -E "^[\s]*ServerIdent" "$config_file" 2>/dev/null | grep -v "^#" | head -1)
            if [ -n "$banner_value" ]; then
                if echo "$banner_value" | grep -qiE "On|PROFTPD"; then
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: ${banner_value}, "
                fi
            fi
        fi

        # pure-ftpd 배너 설정 확인
        if [[ "$config_file" == *"pure-ftpd"* ]]; then
            banner_value=$(cat "$config_file" 2>/dev/null)
            if [ -n "$banner_value" ]; then
                if echo "$banner_value" | grep -qiE "version|Welcome|FTP"; then
                    ftp_banner_issue=true
                    banner_details="${banner_details}${config_file}: 배너 설정됨, "
                fi
            fi
        fi
    done || true

    # 기본 배너 메시지 파일 확인
    if [ -f /etc/ftpwelcome ]; then
        local ftpwelcome_content=$(cat /etc/ftpwelcome 2>/dev/null)
        if [ -n "$ftpwelcome_content" ]; then
            ftp_banner_issue=true
            banner_details="${banner_details}/etc/ftpwelcome 파일 존재, "
        fi
    fi

    if [ "$ftp_banner_issue" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FTP 배너에 버전/시스템 정보 노출: ${banner_details%, }"
        command_result="${banner_details%, }"
        command_executed="grep -E 'ftpd_banner|ServerIdent' /etc/{vsftpd,vsftpd/vsftpd,proftpd/proftpd}.conf 2>/dev/null"
    else
        # FTP 서비스가 설치되지 않았거나 배너가 적절하게 설정됨
        local ftp_installed=false
        for config_file in "${ftp_config_files[@]}"; do
            ftp_installed=true
            break
        done || true

        if [ "$ftp_installed" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 배너 정보가 제거되거나 적절하게 설정됨"
            local grep_banner=$(grep -iE 'banner|version' /etc/ssh/sshd_config 2>/dev/null | head -10 || echo "No banner/version settings found")
            command_result="[Command: grep banner sshd_config]${newline}${grep_banner}"
            command_executed="grep -E 'ftpd_banner|ServerIdent' /etc/{vsftpd,vsftpd/vsftpd,proftpd/proftpd}.conf 2>/dev/null"
        else
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 서비스가 설치되지 않음"
            local lssrc_out=$(lssrc -s ftpd 2>/dev/null || echo "FTP service not found")
            local cmd_check=$(command -v ftpd 2>/dev/null || echo "ftpd command not found")
            command_result="[Command: lssrc -s ftpd]${newline}${lssrc_out}${newline}${newline}[Command: command -v ftpd]${newline}${cmd_check}"
            command_executed="ls /etc/{vsftpd.conf,proftpd/proftpd.conf} 2>/dev/null"
        fi
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
