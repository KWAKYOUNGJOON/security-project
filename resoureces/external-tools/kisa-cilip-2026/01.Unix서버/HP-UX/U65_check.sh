#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-65
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 중
# @Title       : NTP 및 시각 동기화 설정
# @Description : NTP 서비스 설정 확인
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


ITEM_ID="U-65"
ITEM_NAME="NTP 및 시각 동기화 설정"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="인증및감사목적을위한시간동기화는필수적이며,안전하고승인된NTP서비스와동기화하기위함"
GUIDELINE_THREAT="시스템 간 시간 동기화 미흡으로 보안 사고 및 장애 발생 시 로그에 대한 신뢰도 확보 미흡 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="NTP및시각동기화설정이기준에따라적용된경우"
GUIDELINE_CRITERIA_BAD="NTP및시각동기화설정이기준에따라적용되어있지않은경우"
GUIDELINE_REMEDIATION="NTP설정및동기화주기설정"

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
    # NTP 및 시각 동기화 설정 확인

    local ntp_installed=false
    local ntp_running=false
    local ntp_configured=false
    local ntp_details=""
    local config_files=""

    # 1) NTP 서비스 설치 여부 확인
    if command -v ntpd >/dev/null 2>&1 || [ -f /etc/ntp.conf ] || command -v chronyd >/dev/null 2>&1 || [ -f /etc/chrony.conf ]; then
        ntp_installed=true
    fi

    if [ "$ntp_installed" = false ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="NTP 서비스가 설치되지 않음 (시간 동기화 불가)"
        local ntp_not_installed=$(which ntpd chronyd 2>/dev/null; ls /etc/ntp.conf /etc/chrony.conf 2>/dev/null || echo "NTP not installed")
        command_result="${ntp_not_installed}"
        command_executed="which ntpd chronyd; ls /etc/{ntp.conf,chrony.conf} 2>/dev/null"
    else
        # 2) NTP 설정 파일 확인
        if [ -f /etc/ntp.conf ]; then
            config_files="${config_files}/etc/ntp.conf"

            # NTP 서버 설정 확인 (server 또는 pool 지시자)
            local ntp_servers=$(grep -E "^[\s]*server|^[\s]*pool" /etc/ntp.conf 2>/dev/null | grep -v "^#" | head -5)
            if [ -n "$ntp_servers" ]; then
                ntp_configured=true
                ntp_details="NTP 서버 설정됨: $(echo "$ntp_servers" | head -3 | tr '\n' ' ')"
            else
                ntp_details="NTP 서버 설정 없음"
            fi
        fi

        if [ -f /etc/chrony.conf ]; then
            config_files="${config_files} /etc/chrony.conf"

            # Chrony 서버 설정 확인
            local chrony_servers=$(grep -E "^[\s]*server|^[\s]*pool" /etc/chrony.conf 2>/dev/null | grep -v "^#" | head -5)
            if [ -n "$chrony_servers" ]; then
                ntp_configured=true
                ntp_details="${ntp_details}, Chrony 서버 설정됨"
            fi
        fi

        # systemd-timesyncd 확인 (최신 리눅스 배포판)
        if [ -f /etc/systemd/timesyncd.conf ]; then
            config_files="${config_files} /etc/systemd/timesyncd.conf"

            local timesyncd_servers=$(grep "^[\s]*NTP=" /etc/systemd/timesyncd.conf 2>/dev/null | grep -v "^#" | grep -v "^NTP=$")
            if [ -n "$timesyncd_servers" ]; then
                ntp_configured=true
                ntp_details="${ntp_details}, systemd-timesyncd: ${timesyncd_servers}"
            fi
        fi

        # 3) NTP 서비스 실행 여부 확인
        local ntp_service_running=false
        if [ -f /sbin/init.d/ntp ] || [ -f /sbin/init.d/xntpd ]; then
            if /sbin/init.d/ntp status 2>/dev/null | grep -q "running" >/dev/null 2>&1 || /sbin/init.d/xntpd status 2>/dev/null | grep -q "running" >/dev/null 2>&1; then
                ntp_running=true
                ntp_service_running=true
            fi
        fi

        # 4) NTP 패키지 설치 확인
        local ntp_packages=""
        if swlist 2>/dev/null | grep -q "ntp "; then
            ntp_packages="${ntp_packages}ntp "
        fi

        # 최종 판정
        if [ "$ntp_running" = true ] && [ "$ntp_configured" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="NTP 서비스 실행 중且 시간 동기화 설정됨: ${ntp_details}"
            command_result="${ntp_details}, service: running"
            command_executed="/sbin/init.d/ status ntp chrony systemd-timesyncd 2>/dev/null; cat ${config_files}"
        elif [ "$ntp_installed" = true ] && [ "$ntp_configured" = true ]; then
            diagnosis_result="GOOD"
            status="양호"
            inspection_summary="NTP 설정됨 (서비스 상태: ${ntp_service_running:-실행 중}): ${ntp_details}"
            command_result="${ntp_details}, installed packages: ${ntp_packages:-none}"
            command_executed="/sbin/init.d/ntp status 2>/dev/null | grep -q "running" chrony systemd-timesyncd 2>/dev/null"
        else
            diagnosis_result="VULNERABLE"
            status="취약"
            if [ -z "$ntp_details" ]; then
                inspection_summary="NTP가 설치되어 있으나 서버 설정 안됨"
                local ntp_no_config=$(ls /etc/ntp.conf /etc/chrony.conf 2>/dev/null; cat /etc/ntp.conf 2>/dev/null | grep '^server' | head -3 || echo "NTP installed but not configured")
                command_result="${ntp_no_config}"
            else
                inspection_summary="NTP 설정 또는 서비스 실행 문제: ${ntp_details}"
                command_result="${ntp_details}, service: ${ntp_service_running:-[inactive]}"
            fi
            command_executed="/sbin/init.d/ntp status 2>/dev/null | grep -q "running" chrony systemd-timesyncd 2>/dev/null; grep '^server\|^pool' /etc/ntp.conf /etc/chrony.conf 2>/dev/null"
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
