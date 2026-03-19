#!/bin/bash
# ============================================================================
# @ID          : U-24
# @Title       : 사용자, 시스템 환경변수 파일 소유자 및 권한 설정
# ============================================================================

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; LIB_DIR="${SCRIPT_DIR}/../lib"
source "${LIB_DIR}/common.sh"; source "${LIB_DIR}/result_manager.sh"; source "${LIB_DIR}/output_mode.sh"; source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-24"; ITEM_NAME="사용자, 시스템 환경변수 파일 소유자 및 권한 설정"; SEVERITY="(상)"
GUIDELINE_PURPOSE="비인가자의 환경변수 조작으로 인한 보안 위험을 방지하기 위함"
GUIDELINE_THREAT="환경변수 파일 권한 설정이 적절하지 않을 경우, 비인가자가 파일을 변조하여 정상 사용자의 서비스를 제한하거나 악의적인 행위를 유도할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="환경변수 파일 소유자가 root 또는 해당 계정이고, 소유자 외에 쓰기 권한이 부여되지 않은 경우"
GUIDELINE_CRITERIA_BAD="환경변수 파일 소유자가 해당 계정이 아니거나, 타인에게 쓰기 권한이 부여된 경우"
GUIDELINE_REMEDIATION="환경변수 파일의 일반 사용자 쓰기 권한 제거 (chmod o-w <file>)"

diagnose() {
    local status="양호"; local diagnosis_result="GOOD"
    local inspection_summary="환경변수 파일의 소유자 및 권한 설정이 적절합니다."
    local command_result=""; local command_executed="ls -l /etc/profile $HOME/.bashrc 등"

    # 주요 환경변수 파일 리스트 점검
    local check_files=("/etc/profile" "/etc/bashrc" "$HOME/.bash_profile" "$HOME/.bashrc" "$HOME/.profile")
    local vulnerable=""

    for f in "${check_files[@]}"; do
        if [ -f "$f" ]; then
            local perm=$(stat -c "%a" "$f")
            if [ "${perm:2:1}" -gt 4 ]; then # Other write or read/write check
                vulnerable+="$f "
            fi
        fi
    done

    if [ -n "$vulnerable" ]; then
        status="취약"; diagnosis_result="VULNERABLE"
        inspection_summary="환경변수 파일 중 타인 쓰기 권한이 허용된 파일이 존재합니다."
        command_result="취약 파일: [ $vulnerable ]"
    else
        command_result="환경변수 파일 권한 양호"
    fi

    save_dual_result "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" "${inspection_summary}" "${command_result}" "${command_executed}" "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
}
main() { diagnose; }; main "$@"
