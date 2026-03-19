#!/bin/bash
# KISA 취약점 진단 시스템 - 공통 라이브러리
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: 진단 결과 생성, 파일 저장, 공통 함수 제공

set -euo pipefail

# 진단 결과 기본 경로
RESULT_DIR_BASE="results"
DATE_SUFFIX=$(date +%Y%m%d)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 호스트네임 가져오기
get_hostname() {
    # 방법 1: hostname 명령 (대부분의 시스템)
    if command -v hostname >/dev/null 2>&1; then
        hostname 2>/dev/null && return 0
    fi

    # 방법 2: HOSTNAME 환경변수 (Docker 컨테이너 등)
    if [ -n "${HOSTNAME:-}" ]; then
        echo "$HOSTNAME"
        return 0
    fi

    # 방법 3: /etc/hostname 파일 (Linux)
    if [ -f /etc/hostname ]; then
        cat /etc/hostname 2>/dev/null | tr -d '\n' && return 0
    fi

    # 방법 4: uname -n (POSIX 표준)
    if command -v uname >/dev/null 2>&1; then
        uname -n 2>/dev/null && return 0
    fi

    # 모든 방법 실패 시
    echo "unknown"
    return 1
}

# 결과 파일 경로 생성
create_result_path() {
    local item_id="$1"
    local platform_dir="${SCRIPT_DIR}/../${RESULT_DIR_BASE}/${DATE_SUFFIX}"
    local hostname=$(get_hostname)

    # 날짜별 폴더 생성
    mkdir -p "${platform_dir}"

    # 결과 파일 경로 반환
    echo "${platform_dir}/${hostname}_${item_id}_result_${TIMESTAMP}"
}

# 디스크 공간 확인 (최소 100MB)
check_disk_space() {
    local required_mb=100
    local available_mb=$(df -m . | tail -1 | awk '{print $4}')

    if [ "$available_mb" -lt "$required_mb" ]; then
        echo "❌ 치명적 오류: 디스크 공간 부족" >&2
        echo "필요: ${required_mb}MB, 가용: ${available_mb}MB" >&2
        exit 1
    fi

    echo "디스크 공간 확인: ${available_mb}MB 가용" >&2
}

# 진단 결과 저장 성공 확인
verify_result_files() {
    local item_id="$1"
    local result_path=$(create_result_path "${item_id}")

    if [ ! -f "${result_path}.json" ] || [ ! -f "${result_path}.txt" ]; then
        echo "❌ 치명적 오류: 결과 파일 생성 실패" >&2
        echo "예상 경로: ${result_path}" >&2
        exit 1
    fi

    echo "✅ 결과 파일 검증 완료"
}

# 라이브러리 로드 확인
ensure_libraries_loaded() {
    local required_libs=(
        "platform_detector.sh"
        "command_validator.sh"
    )

    for lib in "${required_libs[@]}"; do
        if ! type -t check_read_only_command &>/dev/null; then
            echo "❌ 치명적 오류: 필수 라이브러리 미로드" >&2
            echo "필요: ${lib}" >&2
            exit 1
        fi
    done
}
