#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-58
# @Category    : Unix Server
# @Platform    : Debian
# @Severity    : 중
# @Title       : 불필요한 SNMP 서비스 구동 점검
# @Description : SNMP 서비스 활성화 여부 확인
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


ITEM_ID="U-58"
ITEM_NAME="불필요한 SNMP 서비스 구동 점검"
SEVERITY="중"

# 가이드라인 정보
GUIDELINE_PURPOSE="불필요한 SNMP 서비스를 비활성화하여 시스템 정보 노출 방지"
GUIDELINE_THREAT="SNMP 서비스 활성화 시 비인가자가 시스템 정보 수집 및 설정 변경을 통해 공격 대상 선정 및 시스템 장악 위험"
GUIDELINE_CRITERIA_GOOD="SNMP 서비스가 비활성화된 경우"
GUIDELINE_CRITERIA_BAD=" SNMP 서비스가 활성화된 경우 / N/A: SNMP 모니터링 필요"
GUIDELINE_REMEDIATION="SNMP 서비스 중지 및 비활성화: systemctl stop snmpd && systemctl disable snmpd 실행"

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
    # SNMP 서비스 활성화 여부 확인

    local snmp_running=false
    local service_details=""

    # systemctl 사용 가능한지 확인
    if command -v systemctl >/dev/null 2>&1; then
        # SNMP 서비스 목록 확인 (snmpd, snmptrapd 등)
        local snmp_service_list=("snmpd.service" "snmptrapd.service" "net-snmp.service")

        for svc in "${snmp_service_list[@]}"; do
            # 서비스 상태 확인
            if systemctl is-active "$svc" >/dev/null 2>&1; then
                snmp_running=true
                local is_enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "unknown")
                service_details="${service_details}$svc: active (enabled: $is_enabled), "
            fi
        done || true

        command_executed="systemctl list-units --type=service --all | grep -E 'snmp|SNMP'"
    else
        # systemctl이 없는 경우 (legacy init)
        if command -v service >/dev/null 2>&1; then
            if service snmpd status 2>/dev/null | grep -q "running\|active"; then
                snmp_running=true
                service_details="snmpd: running"
            fi
            command_executed="service snmpd status"
        elif [ -f /etc/init.d/snmpd ]; then
            # /etc/init.d/snmpd 스크립트 확인
            if /etc/init.d/snmpd status 2>/dev/null | grep -q "running\|active"; then
                snmp_running=true
                service_details="snmpd: running"
            fi
            command_executed="/etc/init.d/snmpd status"
        else
            # 모든 확인 방법 실패 - 수동 진단으로 설정하고 계속 진행
            diagnosis_result="MANUAL"
            status="수동진단"
            inspection_summary="SNMP 서비스 확인 방법을 알 수 없음 (systemctl, service, init.d 없음)"
            command_result="[Cannot determine]${newline}${newline}Checked commands:${newline}- which systemctl${newline}- which service${newline}- ls /etc/init.d/snmpd"
            command_executed="which systemctl; which service; ls /etc/init.d/snmpd"
            # 조기 return 제거 - 마지막에 save_dual_result 단 한 번만 호출
        fi
    fi

    # 프로세스 확인 (백업 방법)
    if ! $snmp_running && command -v pgrep >/dev/null 2>&1; then
        if pgrep -x "snmpd" >/dev/null 2>&1; then
            snmp_running=true
            service_details="${service_details}snmpd 프로세스 실행 중"
            command_executed="${command_executed}; pgrep -x snmpd"
        fi
    fi

    # 최종 판정
    if [ "$snmp_running" = true ]; then
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="SNMP 서비스가 활성화되어 있습니다 (${service_details%, }). 불필요한 경우 서비스를 중지하고 비활성화해야 합니다: systemctl stop snmpd; systemctl disable snmpd"
        command_result="${service_details%, }"
    else
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="SNMP 서비스가 비활성화되어 있습니다."
        command_result="[SNMP Service Status]${newline}$(systemctl is-active snmpd 2>&1 || echo 'inactive')${newline}$(systemctl is-active snmp 2>&1 || echo 'inactive')"
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
