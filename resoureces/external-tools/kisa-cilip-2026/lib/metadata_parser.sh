#!/bin/bash
# KISA 취약점 진단 시스템 - 메타데이터 파서
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: 스크립트 메타데이터 추출 (@guideline, @item_id, etc.)

set -euo pipefail

# 라이브러리 자신의 경로 저장 (라이브러리 로드를 위해)
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 스크립트 디렉토리 설정 (라이브러리로 직접 호출 시)
if [ -z "${SCRIPT_DIR:-}" ]; then
    SCRIPT_DIR="${LIB_DIR}"
fi

# JSON 포맷터 라이브러리 로드 (라이브러리 경로 사용)
source "${LIB_DIR}/json_formatter.sh"

# 스크립트 헤더에서 메타데이터 추출
parse_metadata() {
    local script_file="$1"

    # 스크립트 파일이 존재하는지 확인
    if [ ! -f "${script_file}" ]; then
        echo "❌ 스크립트 파일 없음: ${script_file}" >&2
        return 1
    fi

    # 메타데이터 변수 초기화
    META_GUIDELINE=""
    META_ITEM_ID=""
    META_ITEM_NAME=""
    META_SEVERITY=""
    META_DESCRIPTION=""

    # 스크립트에서 메타데이터 추출
    while IFS= read -r line; do
        # 주석 내 메타데이터 추출
        if [[ "$line" =~ @guideline:(.*)$ ]]; then
            META_GUIDELINE="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ @item_id:(.*)$ ]]; then
            META_ITEM_ID="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ @item_name:(.*)$ ]]; then
            META_ITEM_NAME="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ @severity:(.*)$ ]]; then
            META_SEVERITY="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ @description:(.*)$ ]]; then
            META_DESCRIPTION="${BASH_REMATCH[1]}"
        fi

        # 함수 시작 부분을 만나면 중단
        if [[ "$line" =~ ^[a-zA-Z_][a-zA-Z0-9_]*\(\)[[:space:]]*\{ ]]; then
            break
        fi
    done < "${script_file}"

    # 필수 메타데이터 검증
    if [ -z "$META_ITEM_ID" ] || [ -z "$META_ITEM_NAME" ]; then
        echo "❌ 필수 메타데이터 누락: @item_id 또는 @item_name" >&2
        return 1
    fi

    echo "✅ 메타데이터 파서 완료: ${META_ITEM_ID} ${META_ITEM_NAME}"
}

# 메타데이터 출력
print_metadata() {
    echo "item_id: ${META_ITEM_ID}"
    echo "item_name: ${META_ITEM_NAME}"
    echo "severity: ${META_SEVERITY}"
    echo "description: ${META_DESCRIPTION}"
}

# 메타데이터를 JSON 형식으로 반환
export_metadata_json() {
    local item_id=$(json_escape "$META_ITEM_ID")
    local item_name=$(json_escape "$META_ITEM_NAME")
    local severity=$(json_escape "$META_SEVERITY")
    local description=$(json_escape "$META_DESCRIPTION")

    cat << EOF
{
  "item_id": "${item_id}",
  "item_name": "${item_name}",
  "severity": "${severity}",
  "description": "${description}"
}
EOF
}
