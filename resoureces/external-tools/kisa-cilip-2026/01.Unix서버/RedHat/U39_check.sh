#!/bin/bash
# ============================================================================
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-28
# ============================================================================
# [점검 항목 상세]
# @ID          : U-39
# @Category    : UNIX > 3. 서비스 관리
# @Platform    : SOLARIS, LINUX, AIX, HP-UX 등
# @Severity    : (상)
# @Title       : 불필요한 NFS 서비스 비활성화
# @Description : 시스템 보안 강화를 위해 사용하지 않는 NFS 서비스의 활성화 여부 점검
# @Reference   : 2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/../lib"

source "${LIB_DIR}/common.sh"
source "${LIB_DIR}/result_manager.sh"
source "${LIB_DIR}/output_mode.sh"
source "${LIB_DIR}/metadata_parser.sh"

ITEM_ID="U-39"
ITEM_NAME="불필요한 NFS 서비스 비활성화"
SEVERITY="(상)"

GUIDELINE_PURPOSE="보안에 취약한 NFS 서비스를 비활성화하여 원격 파일 시스템 무단 접근 및 정보 유출을 차단하기 위함"
GUIDELINE_THREAT="NFS 서비스가 활성화된 경우 비인가자가 중요 데이터에 접근하거나 시스템 리소스를 임의로 마운트할 위험이 존재함"
GUIDELINE_CRITERIA_GOOD="NFS 서비스 관련 프로세스(nfsd, mountd 등)가 실행 중이지 않은 경우"
GUIDELINE_CRITERIA_BAD="NFS 서비스가 활성화되어 있는 경우"
GUIDELINE_REMEDIATION="NFS 서비스 중단 (systemctl stop nfs-server)"

diagnose() {
    local status="양호"
    local diagnosis_result="GOOD"
    local inspection_summary="NFS 관련 서비스가 비활성화되어 있습니다."
    local command_result=""
    local command_executed="ps -ef | grep -E 'nfsd|mountd'"

    # 1. 실제 데이터 추출
    local nfs_procs=$(ps -ef | grep -Ei "nfsd|mountd" | grep -v grep || echo "")

    # 2. 판정 로직
    if [ -n "$nfs_procs" ]; then
        status="취약"
        diagnosis_result="VULNERABLE"
        inspection_summary="불필요한 NFS 서비스가 활성화되어 있습니다."
        command_result="실행 중인 프로세스: [ $(echo $nfs_procs | awk '{print $8}' | xargs) ]"
    else
        command_result="NFS 관련 서비스가 실행 중이지 않습니다."
    fi

    save_dual_result \
        "${ITEM_ID}" "${ITEM_NAME}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" \
        "${GUIDELINE_PURPOSE}" "${GUIDELINE_THREAT}" \
        "${GUIDELINE_CRITERIA_GOOD}" "${GUIDELINE_CRITERIA_BAD}" "${GUIDELINE_REMEDIATION}"
    
    return 0
}

main() { [ "$EUID" -ne 0 ] && exit 1; diagnose; }
main "$@"
