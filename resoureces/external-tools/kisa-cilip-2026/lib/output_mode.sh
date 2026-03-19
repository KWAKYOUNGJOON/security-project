#!/bin/bash
# KISA 취약점 진단 시스템 - 출력 모드 관리
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: JSON과 텍스트 이중 출력 모드 관리

set -euo pipefail

# 출력 모드 변수
OUTPUT_MODE="dual"  # dual, json, text

# 출력 모드 설정
set_output_mode() {
    OUTPUT_MODE="$1"
    case "$OUTPUT_MODE" in
        dual|json|text)
            ;;
        *)
            echo "❌ 잘못된 출력 모드: $OUTPUT_MODE (dual|json|text)" >&2
            exit 1
            ;;
    esac
}

# 이중 출력 (JSON + 텍스트)
output_dual() {
    echo "🔄 이중 출력 모드: JSON + 텍스트"

    # JSON 출력
    if type -t create_json_result &>/dev/null; then
        create_json_result "$@"
    fi

    # 텍스트 출력
    if type -t create_text_result &>/dev/null; then
        create_text_result "$@"
    fi
}

# JSON 전용 출력
output_json() {
    echo "🔄 JSON 출력 모드"

    if type -t create_json_result &>/dev/null; then
        create_json_result "$@"
    else
        echo "❌ create_json_result 함수 미정의" >&2
        exit 1
    fi
}

# 텍스트 전용 출력
output_text() {
    echo "🔄 텍스트 출력 모드"

    if type -t create_text_result &>/dev/null; then
        create_text_result "$@"
    else
        echo "❌ create_text_result 함수 미정의" >&2
        exit 1
    fi
}

# 결과 생성 (출력 모드에 따라)
create_output() {
    case "$OUTPUT_MODE" in
        dual)
            output_dual "$@"
            ;;
        json)
            output_json "$@"
            ;;
        text)
            output_text "$@"
            ;;
        *)
            echo "❌ 정의되지 않은 출력 모드: $OUTPUT_MODE" >&2
            exit 1
            ;;
    esac
}

# 진행 상황 표시 (stdout)
show_progress() {
    local item_id="$1"
    local message="$2"

    echo "[${item_id}] ${message}"
}

# 진단 시작 표시
show_diagnosis_start() {
    local item_id="$1"
    local item_name="$2"

    echo "===================================================================" >&2
    echo "진단 시작: ${item_id} - ${item_name}" >&2
    echo "시간: $(date '+%Y-%m-%d %H:%M:%S')" >&2
    echo "===================================================================" >&2
}

# 진단 완료 표시
show_diagnosis_complete() {
    local item_id="$1"
    local result="$2"

    echo "===================================================================" >&2
    echo "진단 완료: ${item_id} - 결과: ${result}" >&2
    echo "시간: $(date '+%Y-%m-%d %H:%M:%S')" >&2
    echo "===================================================================" >&2
}
