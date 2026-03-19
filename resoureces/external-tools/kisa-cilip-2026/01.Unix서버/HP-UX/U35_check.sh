#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-35
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 공유 서비스에 대한 익명 접근 제한 설정
# @Description : FTP 익명 접근 제한 확인
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


ITEM_ID="U-35"
ITEM_NAME="공유 서비스에 대한 익명 접근 제한 설정"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="FTP 등 공유 서비스의 익명 접속을 제한하여 무단 액세스 및 데이터 유출 방지"
GUIDELINE_THREAT="익명 FTP 접속 허용 시 비인가자가 시스템 자원 무단 사용 및 정보 유출 위험"
GUIDELINE_CRITERIA_GOOD="익명 접속이 차단된 경우"
GUIDELINE_CRITERIA_BAD=" 익명 접속(anonymous/ftp 계정)이 가능한 경우 / N/A: FTP 서비스 미사용"
GUIDELINE_REMEDIATION="FTP 설정 파일에서 anonymous 접속 차단 및 ftp 계정 사용 중지"

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

    # FTP 익명 접근 제한 확인
    local ftp_installed=false
    local anonymous_enabled=false
    local ftp_config=""
    local issues=()

    # 1) FTP 서비스 설치 확인
    if command -v vsftpd &>/dev/null || command -v proftpd &>/dev/null || command -v pure-ftpd &>/dev/null; then
        ftp_installed=true

        # vsftpd 확인
        if [ -f /etc/vsftpd.conf ]; then
            local anonymous_enable=$(grep -i "^anonymous_enable" /etc/vsftpd.conf | awk '{print $2}' | head -1)
            local anon_enable=$(grep -i "^anon_enable" /etc/vsftpd.conf | awk '{print $2}' | head -1)

            if [ "$anonymous_enable" = "YES" ] || [ "$anon_enable" = "YES" ]; then
                anonymous_enabled=true
                issues+=("vsftpd 익명 접근 허용됨")
            fi

            ftp_config="${ftp_config}$(grep -iE '^anonymous_enable|^anon_enable' /etc/vsftpd.conf 2>/dev/null || echo 'vsftpd: 설정 없음')${newline}"
        fi

        # ProFTPD 확인
        if [ -f /etc/proftpd/proftpd.conf ]; then
            local anonymous=$(grep -i "<Anonymous" /etc/proftpd/proftpd.conf)
            if [ -n "$anonymous" ]; then
                anonymous_enabled=true
                issues+=("ProFTPD 익명 접근 허용됨")
            fi
            ftp_config="${ftp_config}$(grep -iA5 '<Anonymous' /etc/proftpd/proftpd.conf 2>/dev/null || echo 'proftpd: 설정 없음')${newline}"
        fi

        # Pure-FTPD 확인
        if [ -f /etc/pure-ftpd/conf/NoAnonymous ]; then
            local no_anonymous=$(cat /etc/pure-ftpd/conf/NoAnonymous 2>/dev/null)
            if [ "$no_anonymous" != "1" ]; then
                anonymous_enabled=true
                issues+=("Pure-FTPD 익명 접근 허용됨")
            fi
            ftp_config="${ftp_config}Pure-FTPD: NoAnonymous=${no_anonymous}${newline}"
        fi
    fi

    # 2) FTP 서비스 실행 확인
    if /sbin/init.d/vsftpd status 2>/dev/null | grep -q "running" &>/dev/null || /sbin/init.d/proftpd status 2>/dev/null | grep -q "running" &>/dev/null || /sbin/init.d/pure-ftpd status 2>/dev/null | grep -q "running" &>/dev/null; then
        ftp_installed=true
        ftp_config="${ftp_config}FTP 서비스 실행 중${newline}"
    fi

    # 3) 포트 확인 (FTP: 21)
    if command -v ss &>/dev/null; then
        local ftp_port=$(ss -tuln | grep ":21 " || echo "")
        if [ -n "$ftp_port" ]; then
            ftp_installed=true
            ftp_config="${ftp_config}FTP 포트 21 활성화${newline}"
        fi
    fi

    # 최종 판정
    if [ "$ftp_installed" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 서비스 미설치됨"
        local ftp_check=$(command -v vsftpd proftpd pure-ftpd 2>/dev/null; /sbin/init.d/vsftpd status 2>/dev/null | grep -q "running" || echo "FTP service not running")
        command_result="${ftp_check}"
        command_executed="command -v vsftpd proftpd pure-ftpd; /sbin/init.d/vsftpd status 2>/dev/null | grep -q "running" proftpd pure-ftpd"
    elif [ "$anonymous_enabled" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="FTP 익명 접근 허용됨: ${issues[*]}"
        command_result="${ftp_config}"
        command_executed="grep -iE 'anonymous_enable|<Anonymous' /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="FTP 익명 접근 제한됨"
        command_result="${ftp_config}"
        command_executed="grep -iE 'anonymous_enable|<Anonymous' /etc/vsftpd.conf /etc/proftpd/proftpd.conf 2>/dev/null"
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
