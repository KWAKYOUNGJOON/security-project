#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-43
# @Category    : Unix Server
# @Platform    : AIX
# @Severity    : 상
# @Title       : r 계열 서비스 비활성화
# @Description : rsh, rlogin, rexec 서비스 비활성화 확인
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


ITEM_ID="U-43"
ITEM_NAME="r 계열 서비스 비활성화"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="안전하지 않은 NIS 서비스를 비활성화하고 안전한 NIS+ 서비스를 활성화하여 시스템의 보안성을 높이기위함"
GUIDELINE_THREAT="NIS서비스가활성화된경우,비인가자가타시스템의root권한까지탈취할수있는위험이존재함"
GUIDELINE_CRITERIA_GOOD="NIS서비스가비활성화되어있거나,불가피하게사용시NIS+서비스를사용하는경우"
GUIDELINE_CRITERIA_BAD="NIS서비스가활성화된경우"
GUIDELINE_REMEDIATION="NIS관련서비스비활성화설정"

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
    # rsh, rlogin, rexec 서비스 상태 확인

    local is_secure=true
    local service_status=""
    local active_services=()

    # 확인할 r 계열 서비스 목록
    local r_services=("rsh" "rlogin" "rexec")

    for service in "${r_services[@]}"; do
        # AIX lssrc로 서비스 상태 확인
        local state=$(lssrc -s "$service" 2>/dev/null | grep "$service" | awk '{print $2}' || echo "inoperative")
        if [ "$state" = "active" ]; then
            is_secure=false
            active_services+=("${service} (active)")
        fi
        service_status="${service_status}${service}: ${state}\\n"
    done || true

    # AIX inetd.conf 확인 (rsh, rlogin, rexec는 inetd에서 관리)
    if [ -f /etc/inetd.conf ]; then
        for inetd_service in rsh rlogin rexec; do
            local inetd_entry=$(grep "^${inetd_service}" /etc/inetd.conf 2>/dev/null | grep -v "^#" || echo "")
            if [ -n "$inetd_entry" ]; then
                is_secure=false
                active_services+=("${inetd_service} (inetd enabled)")
                service_status="${service_status}${inetd_service}: inetd.conf에서 활성화됨\\n"
            fi
        done || true
    fi

    # 포트 확인 (rsh: 514, rlogin: 513, rexec: 512)
    if command -v ss &>/dev/null; then
        local rsh_port=$(ss -tuln | grep -E ":514 " || echo "")
        local rlogin_port=$(ss -tuln | grep -E ":513 " || echo "")
        local rexec_port=$(ss -tuln | grep -E ":512 " || echo "")

        if [ -n "$rsh_port" ] || [ -n "$rlogin_port" ] || [ -n "$rexec_port" ]; then
            is_secure=false
            service_status="${service_status}r 계열 포트 활성화 감지\\n"
        fi
    fi

    # 최종 판정
    if [ "$is_secure" = true ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="r 계열 서비스 비활성화됨"
        command_result="${service_status}"
        command_executed="lssrc -s rsh 2>/dev/null | grep -q "active" rlogin rexec; cat /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="r 계열 서비스 활성화됨: ${active_services[*]}"
        command_result="${service_status}"
        command_executed="lssrc -s rsh 2>/dev/null | grep -q "active" rlogin rexec; cat /etc/xinetd.d/rsh /etc/xinetd.d/rlogin /etc/xinetd.d/rexec 2>/dev/null"
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
