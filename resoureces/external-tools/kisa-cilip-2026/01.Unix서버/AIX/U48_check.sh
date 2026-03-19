#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-48
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 중
# @Title       : FTP 서비스 버전 확인
# @Description : FTP 서비스 버전 및 보안 취약점 확인
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


ITEM_ID="U-48"
ITEM_NAME="FTP 서비스 버전 확인"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="SMTP서비스의expn,vrfy명령을통한정보유출을방지하기위함"
GUIDELINE_THREAT="expn, vrfy 명령어를 통하여 특정 사용자 계정의 존재 여부를 알 수 있고, 사용자의 정보를 외부로 유출할수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="noexpn, novrfy옵션이설정된경우"
GUIDELINE_CRITERIA_BAD="noexpn, novrfy옵션이설정되어있지않은경우"
GUIDELINE_REMEDIATION="Ÿ 메일서비스를사용하지않는경우서비스중지및비활성화설정 Ÿ 메일서비스사용시메일서비스설정파일에noexpn,novrfy또는goaway옵션추가설정"

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
    # FTP 서비스 상태 및 버전 확인

    local ftp_running=false
    local ftp_version=""
    local ftp_details=""

    # 1) vsftpd 확인
    if lssrc -s vsftpd 2>/dev/null | grep -q "active" &>/dev/null || lssrc -s pure-ftpd 2>/dev/null | grep -q "active" &>/dev/null || lssrc -s proftpd 2>/dev/null | grep -q "active" &>/dev/null; then
        ftp_running=true

        # vsftpd 버전 확인
        if command -v vsftpd &>/dev/null; then
            ftp_version=$(vsftpd -version 2>&1 || echo "unknown")
            ftp_details="vsftpd: ${ftp_version}"
        # proftpd 버전 확인
        elif command -v proftpd &>/dev/null; then
            ftp_version=$(proftpd -v 2>&1 | grep -oP "ProFTPD \K[0-9.]+" || echo "unknown")
            ftp_details="proftpd: ${ftp_version}"
        # pure-ftpd 버전 확인
        elif command -v pure-ftpd &>/dev/null; then
            ftp_version=$(pure-ftpd -v 2>&1 | grep -oP "Pure-FTPd \K[0-9.]+" || echo "unknown")
            ftp_details="pure-ftpd: ${ftp_version}"
        fi

        # 패키지 버전 확인 (Debian/Ubuntu)
        if [ -f /etc/debian_version ]; then
            local pkg_version=$(lslpp -L | grep -E "vsftpd|proftpd|pure-ftpd" | awk '{print $2, $3}' || echo "")
            if [ -n "$pkg_version" ]; then
                ftp_details="${ftp_details}\\n패키지: ${pkg_version}"
            fi
        fi
    fi

    # 2) 포트 확인 (FTP: 21)
    if command -v ss &>/dev/null; then
        local ftp_port=$(ss -tuln | grep ":21 " || echo "")
        if [ -n "$ftp_port" ]; then
            ftp_running=true
            ftp_details="${ftp_details}\\nFTP 포트 21 활성화"
        fi
    fi

    # 최종 판정
    if [ "$ftp_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 서비스 비활성화됨"
        local lssrc_out=$(lssrc -s vsftpd pure-ftpd proftpd 2>/dev/null || echo "FTP services not found")
        local ss_out=$(ss -tuln | grep ":21 " 2>/dev/null || echo "Port 21 not listening")
        command_result="[Command: lssrc -s ftp services]${newline}${lssrc_out}${newline}${newline}[Command: ss -tuln | grep :21]${newline}${ss_out}"
        command_executed="lssrc -s vsftpd 2>/dev/null | grep -q "active" pure-ftpd proftpd; ss -tuln | grep ':21 '"
    else
        # 버전 확인이 가능한 경우
        if [ -n "$ftp_version" ] && [ "$ftp_version" != "unknown" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 서비스 실행 중, 버전 확인됨: ${ftp_details}"
            command_result="${ftp_details}"
            command_executed="vsftpd -version 2>/dev/null; proftpd -v 2>/dev/null; lslpp -L | grep -E 'vsftpd|proftpd'"
        else
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="FTP 서비스 실행 중, 버전 확인 필요: ${ftp_details}"
            command_result="${ftp_details}"
            command_executed="lssrc -s vsftpd 2>/dev/null | grep -q "active" pure-ftpd proftpd; vsftpd -version 2>/dev/null"
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
