#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# [점검 항목 상세]
# @ID          : WEB-01
# @Category    : Web Server
# @Platform    : Apache
# @Severity    : 상
# @Title       : Default 관리자 계정명 변경
# @Description : 웹서비스 설치 시 기본적으로 설정된 관리자 계정의 변경 후 사용 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ============================================================================


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

ITEM_ID="WEB-01"
ITEM_NAME="Default관리자계정명변경"
SEVERITY="상"

GUIDELINE_PURPOSE="기본 관리자 계정명과 같은 알려진 계정명을 유추하기 어려운 계정명으로 변경 후 사용하여 공격자에 의한 추측 공격 및 무단 접근 등을 방지하고 보안을 강화하기 위함"
GUIDELINE_THREAT="기본 관리자 계정명을 변경하지 않고 사용하는 경우, 비인가자의 계정명 유추 공격으로 관리자 권한 탈취 및 시스템 침입 등의 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="대상: Tomcat, IIS, JEUS (Apache는 해당하지 않음)"
GUIDELINE_CRITERIA_BAD="대상: Tomcat, IIS, JEUS (Apache는 해당하지 않음)"
GUIDELINE_REMEDIATION="Apache는 이 항목이 적용되지 않음 (Tomcat/IIS/JEUS만 해당)"

diagnose() {
    echo "진단 항목: ${ITEM_ID} - ${ITEM_NAME}"

    local diagnosis_result="N/A"
    local status="N/A"
    local inspection_summary="이 항목은 Tomcat/IIS/JEUS 대상이며 Apache는 해당하지 않습니다. Apache는 기본 관리자 계정 개념이 없으며 인증은 별도 설정 파일(.htaccess, htpasswd) 또는 모듈(mod_auth)로 관리합니다."
    local command_result="N/A"
    local command_executed="N/A"

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

main() {
    show_diagnosis_start "${ITEM_ID}" "${ITEM_NAME}"
    check_disk_space
    diagnose
    show_diagnosis_complete "${ITEM_ID}" "${diagnosis_result:-UNKNOWN}"
}

if true; then
    main "$@"
fi
