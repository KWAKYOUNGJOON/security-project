#!/bin/bash
# KISA 취약점 진단 시스템 - 타임아웃 핸들러
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: 명령어 타임아웃 처리 (FR-014: 30초 타임아웃, 사용자 프롬프트) (T035-T037)

set -euo pipefail

# 타임아웃 상수
DEFAULT_TIMEOUT=30
PROMPT_TIMEOUT=60  # 사용자 응답 대기 시간

# 타임아웃 명령어 실행 (T035)
execute_with_timeout() {
    local timeout_seconds="$1"
    local command="$2"
    local description="${3:-명령어}"

    echo "⏱️  실행 중: ${description} (타임아웃: ${timeout_seconds}초)"

    # 타임아웃 적용 명령 실행
    local output
    local exit_code=0

    output=$(timeout "${timeout_seconds}" bash -c "${command}" 2>&1) || exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "✅ 성공: ${description}"
        echo "$output"
        return 0
    elif [ $exit_code -eq 124 ]; then
        echo "⏰ 타임아웃: ${description} (${timeout_seconds}초 경과)"
        return 124
    else
        echo "❌ 실패: ${description} (exit code: ${exit_code})"
        echo "$output"
        return $exit_code
    fi
}

# 대화형 타임아웃 처리 (T036)
handle_interactive_timeout() {
    local command="$1"
    local description="${2:-명령어}"
    local timeout_seconds="${3:-${DEFAULT_TIMEOUT}}"
    local item_id="${4:-UNKNOWN}"

    echo "==================================================================="
    echo "진단 항목: ${item_id}"
    echo "명령어: ${description}"
    echo "==================================================================="
    echo ""

    # 첫 실행 시도
    local output
    local exit_code=0

    output=$(execute_with_timeout "${timeout_seconds}" "${command}" "${description}") || exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "$output"
        return 0
    fi

    # 타임아웃 발생 시 사용자 프롬프트
    if [ $exit_code -eq 124 ]; then
        echo ""
        echo "⚠️  명령어 실행이 ${timeout_seconds}초 동안 완료되지 않았습니다."
        echo ""
        prompt_timeout_action "${item_id}" "${description}"
        local user_choice=$?

        if [ $user_choice -eq 0 ]; then
            # 계속 진행 (더 긴 타임아웃으로 재시도)
            local extended_timeout=$((timeout_seconds * 2))
            echo "🔄 타임아웃 연장 (${extended_timeout}초)으로 재시도..."

            output=$(execute_with_timeout "${extended_timeout}" "${command}" "${description}") || exit_code=$?

            if [ $exit_code -eq 0 ]; then
                echo "$output"
                return 0
            elif [ $exit_code -eq 124 ]; then
                echo "⏰ 연장된 타임아웃에도 실패"
                return 124
            else
                echo "❌ 재시도 실패 (exit code: ${exit_code})"
                return $exit_code
            fi
        elif [ $user_choice -eq 1 ]; then
            # 건너뛰기
            echo "⏭️  항목 건너뜀: ${item_id}"
            return 125  # 특별 exit code: 사용자 건너뜀
        else
            # 종료
            echo "🛑 사용자가 진단을 종료함"
            exit 1
        fi
    fi

    # 기타 에러
    echo "$output"
    return $exit_code
}

# 타임아웃 발생 시 사용자 프롬프트 (T036)
prompt_timeout_action() {
    local item_id="$1"
    local description="$2"

    echo "다음 작업을 선택해주세요:"
    echo "  1) 계속 진행 (타임아웃 2배 연장)"
    echo "  2) 건너뛰기 (다음 항목으로)"
    echo "  3) 종료 (전체 진단 중단)"
    echo ""

    local timeout_prompt_prompt="[${PROMPT_TIMEOUT}초 내 입력, 기본: 건너뛰기]: "

    # 타임아웃과 함께 read 실행 (read 자체에는 타임아웃 없으므로 background 처리)
    local user_input=""
    local pid=""

    # 사용자 입력 대기 (타임아웃 포함)
    read -t "${PROMPT_TIMEOUT}" -p "$timeout_prompt_prompt" user_input 2>/dev/null || pid=$?

    echo ""

    case "$user_input" in
        1|continue|c|C)
            return 0  # 계속 진행
            ;;
        2|skip|s|S|"")
            return 1  # 건너뛰기
            ;;
        3|exit|e|E|quit|q)
            return 2  # 종료
            ;;
        *)
            echo "⚠️  잘못된 입력. 건너뛰기를 선택합니다."
            return 1  # 기본: 건너뛰기
            ;;
    esac
}

# 배치 모드 타임아웃 처리 (T037)
handle_batch_timeout() {
    local command="$1"
    local description="${2:-명령어}"
    local timeout_seconds="${3:-${DEFAULT_TIMEOUT}}"
    local item_id="${4:-UNKNOWN}"

    # 배치 모드에서는 사용자 프롬프트 없이 바로 타임아웃 처리
    echo "⏱️  배치 모드 실행: ${description} (타임아웃: ${timeout_seconds}초)"

    local output
    local exit_code=0

    output=$(timeout "${timeout_seconds}" bash -c "${command}" 2>&1) || exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "✅ ${item_id}: 성공"
        echo "$output"
        return 0
    elif [ $exit_code -eq 124 ]; then
        echo "⏰ ${item_id}: 타임아웃 (${timeout_seconds}초)"
        echo "⚠️  배치 모드: 자동으로 다음 항목으로 진행합니다."
        return 124
    else
        echo "❌ ${item_id}: 실패 (exit code: ${exit_code})"
        echo "$output"
        return $exit_code
    fi
}

# 타임아웃 상태 확인
check_timeout_status() {
    local exit_code="$1"

    case "$exit_code" in
        0)
            echo "정상 완료"
            ;;
        124)
            echo "타임아웃 발생"
            ;;
        125)
            echo "사용자 건너뜀"
            ;;
        *)
            echo "명령어 실패 (exit code: ${exit_code})"
            ;;
    esac
}

# 타임아웃 로그 기록
log_timeout_event() {
    local item_id="$1"
    local command="$2"
    local timeout_duration="$3"
    local result="$4"  # success, timeout, skipped, error

    local log_dir="${SCRIPT_DIR}/../results/$(date +%Y%m%d)"
    mkdir -p "${log_dir}"

    local log_file="${log_dir}/timeout_log.txt"

    echo "[$(date -Iseconds)] ${item_id} | ${command} | ${timeout_duration}s | ${result}" >> "${log_file}"
}
