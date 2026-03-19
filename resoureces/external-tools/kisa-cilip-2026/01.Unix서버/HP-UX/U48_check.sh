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
# @Platform    : HP-UX
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
GUIDELINE_PURPOSE="FTP 서비스의 취약점을 점검하여 무단 접속 및 데이터 유출을 방지하기 위함"
GUIDELINE_THREAT="FTP 서비스 버전이 노출되거나 취약한 버전이 실행 중일 경우, 공격자가 버전 정보를 이용해 알려진 취약점을 공격하여 시스템 침투나 데이터 유출을 시도할 수 있는 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="FTP 서비스가 비활성화되어 있거나, 최신 보안 버전이 실행 중인 경우"
GUIDELINE_CRITERIA_BAD="FTP 서비스가 활성화되어 있고, 버전 확인이 불가능하거나 취약한 버전이 실행 중인 경우"
GUIDELINE_REMEDIATION="FTP 서비스가 불필요한 경우 서비스 중지 및 패키지 제거, 필요한 경우 최신 보안 패치가 적용된 버전으로 업데이트"

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
    if /sbin/init.d/vsftpd status 2>/dev/null | grep -q "running" &>/dev/null || /sbin/init.d/pure-ftpd status 2>/dev/null | grep -q "running" &>/dev/null || /sbin/init.d/proftpd status 2>/dev/null | grep -q "running" &>/dev/null; then
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
            local pkg_version=$(swlist | grep -E "vsftpd|proftpd|pure-ftpd" | awk '{print $2, $3}' || echo "")
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
        local ftp_check=$(/sbin/init.d/vsftpd status 2>/dev/null | head -2; /sbin/init.d/proftpd status 2>/dev/null | head -2; /sbin/init.d/pure-ftpd status 2>/dev/null | head -2; ss -tuln 2>/dev/null | grep ':21' || echo "FTP service not running")
        command_result="${ftp_check}"
        command_executed="/sbin/init.d/vsftpd status 2>/dev/null | grep -q "running" pure-ftpd proftpd; ss -tuln | grep ':21 '"
    else
        # 버전 확인이 가능한 경우
        if [ -n "$ftp_version" ] && [ "$ftp_version" != "unknown" ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="FTP 서비스 실행 중, 버전 확인됨: ${ftp_details}"
            command_result="${ftp_details}"
            command_executed="vsftpd -version 2>/dev/null; proftpd -v 2>/dev/null; swlist | grep -E 'vsftpd|proftpd'"
        else
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="FTP 서비스 실행 중, 버전 확인 필요: ${ftp_details}"
            command_result="${ftp_details}"
            command_executed="/sbin/init.d/vsftpd status 2>/dev/null | grep -q "running" pure-ftpd proftpd; vsftpd -version 2>/dev/null"
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
