#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : U-41
# @Category    : Unix Server
# @Platform    : HP-UX
# @Severity    : 상
# @Title       : 불필요한 automountd 제거
# @Description : automount 비활성화 확인
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


ITEM_ID="U-41"
ITEM_NAME="불필요한 automountd 제거"
SEVERITY="상"

# 가이드라인 정보
GUIDELINE_PURPOSE="많은 취약점(버퍼 오버플로우, DoS, 원격 실행 등)이 존재하는 RPC 서비스를 비활성화하여 시스템의 보안성을높이기위함"
GUIDELINE_THREAT="RPC서비스의취약점을통해비인가자가root권한획득및각종공격을시도할위험이존재함"
GUIDELINE_CRITERIA_GOOD="불필요한RPC서비스가비활성화된경우"
GUIDELINE_CRITERIA_BAD="불필요한RPC서비스가활성화된경우"
GUIDELINE_REMEDIATION="불필요한RPC서비스중지및비활성화설정"

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

    # automountd/autofs 비활성화 확인
    local automount_running=false
    local automount_info=""

    # 1) autofs 서비스 확인
    if [ -f /sbin/init.d/autofs ]; then
        local active=$(/sbin/init.d/autofs status 2>/dev/null | grep -q "running" 2>/dev/null && echo "active" || echo "inactive")
        automount_info="${automount_info}autofs 서비스: ${active}\\n"

        if [ "$active" = "active" ]; then
            automount_running=true
        fi
    fi

    # 2) amd(Automount Daemon) 서비스 확인
    if [ -f /sbin/init.d/amd ]; then
        local active=$(/sbin/init.d/amd status 2>/dev/null | grep -q "running" 2>/dev/null && echo "active" || echo "inactive")
        automount_info="${automount_info}amd 서비스: ${active}\\n"

        if [ "$active" = "active" ]; then
            automount_running=true
        fi
    fi

    # 3) automountd 서비스 확인 (legacy)
    if [ -f /sbin/init.d/automountd ]; then
        local active=$(/sbin/init.d/automountd status 2>/dev/null | grep -q "running" 2>/dev/null && echo "active" || echo "inactive")
        automount_info="${automount_info}automountd: ${active}\\n"
        if [ "$active" = "active" ]; then
            automount_running=true
        fi
    fi

    # 4) /etc/fstab 확인 (automount 엔트리)
    if [ -f /etc/fstab ]; then
        local automount_entries=$(grep "automount" /etc/fstab 2>/dev/null || echo "")
        if [ -n "$automount_entries" ]; then
            automount_info="${automount_info}/etc/fstab automount 엔트리 발견\\n${automount_entries}\\n"
            automount_running=true
        fi
    fi

    # 5) autofs 설정 파일 확인
    if [ -f /etc/auto.master ] || [ -f /etc/auto.master.d/*.conf ]; then
        automount_info="${automount_info}autofs 설정 파일 존재\\n"
        if [ -f /etc/auto.master ]; then
            automount_info="${automount_info}$(head -5 /etc/auto.master 2>/dev/null)\\n"
        fi
        automount_running=true
    fi

    # 최종 판정
    if [ "$automount_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="automount 서비스 비활성화됨"
        local auto_check=$(/sbin/init.d/autofs status 2>/dev/null | head -2; /sbin/init.d/amd status 2>/dev/null | head -2; grep automount /etc/fstab 2>/dev/null || echo "No automount services found")
        command_result="${auto_check}"
        command_executed="/sbin/init.d/autofs status 2>/dev/null; /sbin/init.d/amd status 2>/dev/null; grep automount /etc/fstab 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="automount 서비스 활성화됨"
        command_result="${automount_info}"
        command_executed="/sbin/init.d/autofs status 2>/dev/null | grep -q "running" amd; cat /etc/auto.master 2>/dev/null; grep automount /etc/fstab"
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
