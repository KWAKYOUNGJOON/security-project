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
# @Platform    : AIX
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

    # automountd/autofs 비활성화 확인 (AIX)
    local automount_running=false
    local automount_info=""

    # 1) AIX automount 서비스 확인 (lssrc -a)
    if lssrc -a 2>/dev/null | grep -q "autof "; then
        local autofs_status=$(lssrc -s autof 2>/dev/null | grep autof | awk '{print $2}' || echo "inoperative")
        automount_info="${automount_info}autof 서비스: ${autofs_status}\\n"

        if [ "$autofs_status" = "active" ]; then
            automount_running=true
        fi
    fi

    # 2) automountd 서비스 확인 (SRC subsystem)
    if lssrc -a 2>/dev/null | grep -q "automountd "; then
        local automountd_status=$(lssrc -s automountd 2>/dev/null | grep automountd | awk '{print $2}' || echo "inoperative")
        automount_info="${automount_info}automountd 서비스: ${automountd_status}\\n"

        if [ "$automountd_status" = "active" ]; then
            automount_running=true
        fi
    fi

    # 3) /etc/filesystems 확인 (automount 엔트리)
    if [ -f /etc/filesystems ]; then
        local automount_entries=$(grep -i "automount\|auto_mount" /etc/filesystems 2>/dev/null || echo "")
        if [ -n "$automount_entries" ]; then
            automount_info="${automount_info}/etc/filesystems automount 엔트리 발견\\n${automount_entries}\\n"
            automount_running=true
        fi
    fi

    # 4) AIX automount 설정 파일 확인
    if [ -f /etc/auto.master ]; then
        automount_info="${automount_info}autofs 설정 파일 존재\\n"
        automount_info="${automount_info}$(head -5 /etc/auto.master 2>/dev/null)\\n"
        automount_running=true
    fi

    # AIX에서 auto.master.d/*.conf glob은 직접 처리
    if [ -d /etc/auto.master.d ]; then
        local auto_conf_files=$(ls /etc/auto.master.d/*.conf 2>/dev/null)
        if [ -n "$auto_conf_files" ]; then
            automount_running=true
            automount_info="${automount_info}autofs 설정 파일 존재\\n"
        fi
    fi

    # 최종 판정
    if [ "$automount_running" = false ]; then
        diagnosis_result="GOOD"
        status="양호"
        inspection_summary="automount 서비스 비활성화됨"
        local lssrc_out=$(lssrc -a | grep -E 'autof|automount' 2>/dev/null || echo "No automount services")
        command_result="[Command: lssrc -a | grep automount]${newline}${lssrc_out}"
        command_executed="lssrc -a | grep -E 'autof|automount'; cat /etc/filesystems 2>/dev/null"
    else
        diagnosis_result="VULNERABLE"
        status="취약"
        inspection_summary="automount 서비스 활성화됨"
        command_result="${automount_info}"
        command_executed="lssrc -s autof automountd; cat /etc/auto.master 2>/dev/null; grep -i automount /etc/filesystems"
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
