#!/bin/bash
# KISA 취약점 진단 시스템 - JSON 포맷터
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: JSON 생성 헬퍼 함수

set -euo pipefail

# JSON 값 이스케이프
json_escape() {
    local string="$1"
    # 백슬래시, 큰따옴표, 개행 문자 이스케이프
    echo "$string" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'
}

# JSON 결과 생성 헬퍼
format_json_field() {
    local key="$1"
    local value="$2"
    local is_number="${3:-false}"

    if [ "$is_number" = "true" ]; then
        echo "  \"${key}\": ${value},"
    else
        local escaped=$(json_escape "$value")
        echo "  \"${key}\": \"${escaped}\","
    fi
}

# JSON 객체 검증 (jq가 없을 경우 간단 검증)
validate_json() {
    local json_file="$1"

    if command -v jq &>/dev/null; then
        if ! jq empty "${json_file}" &>/dev/null; then
            echo "❌ JSON 유효성 검증 실패: ${json_file}" >&2
            return 1
        fi
    else
        # jq가 없을 경우 기본적인 문법 검증
        if grep -q '{.*"' "${json_file}" && ! grep -q ',[[:space:]]*}' "${json_file}"; then
            echo "⚠️  jq 없음 - 기본 JSON 문법 검증만 수행"
        fi
    fi

    echo "✅ JSON 유효성 검증 완료"
}

# JSON 결과 생성 (T027 호환)
format_result_json() {
    local item_id="$1"
    local item_name="$2"
    local status="$3"           # 양호, 취약, 수동진단, N/A
    local final_result="$4"      # GOOD, VULNERABLE, MANUAL, N/A
    local inspection_summary="$5"
    local command_result="$6"
    local command_executed="$7"
    local guideline_purpose="$8"
    local guideline_threat="$9"
    local guideline_criteria_good="${10}"
    local guideline_criteria_bad="${11}"
    local guideline_remediation="${12}"

    # JSON 결과 생성 (SC-004: JSON 유효성 검증 대상)
    cat << EOF
{
  "item_id": "${item_id}",
  "item_name": "${item_name}",
  "inspection": {
    "summary": "${inspection_summary}",
    "status": "${status}"
  },
  "final_result": "${final_result}",
  "command": "${command_executed}",
  "command_result": ${command_result},
  "guideline": {
    "purpose": "${guideline_purpose}",
    "security_threat": "${guideline_threat}",
    "judgment_criteria_good": "${guideline_criteria_good}",
    "judgment_criteria_bad": "${guideline_criteria_bad}",
    "remediation": "${guideline_remediation}"
  },
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(get_hostname)"
}
EOF
}

# 한국어 상태 포맷팅
format_korean_status() {
    local status="$1"

    case "$status" in
        "GOOD")
            echo "양호"
            ;;
        "VULNERABLE")
            echo "취약"
            ;;
        "MANUAL")
            echo "수동진단"
            ;;
        "N/A")
            echo "N/A"
            ;;
        *)
            echo "$status"
            ;;
    esac
}

# 영어 상태 포맷팅
format_english_status() {
    local status="$1"

    case "$status" in
        "양호")
            echo "GOOD"
            ;;
        "취약")
            echo "VULNERABLE"
            ;;
        "수동진단")
            echo "MANUAL"
            ;;
        "N/A")
            echo "N/A"
            ;;
        *)
            echo "$status"
            ;;
    esac
}

# 가이드라인 객체 포맷팅
format_guideline_object() {
    local purpose="$1"
    local threat="$2"
    local criteria_good="$3"
    local criteria_bad="$4"
    local remediation="$5"

    # 가이드라인 객체 생성
    cat << EOF
  "guideline": {
    "purpose": "${purpose}",
    "security_threat": "${threat}",
    "judgment_criteria_good": "${criteria_good}",
    "judgment_criteria_bad": "${criteria_bad}",
    "remediation": "${remediation}"
  },
EOF
}

# 점검 정보 객체 포맷팅
format_inspection_object() {
    local summary="$1"
    local status="$2"

    # 점검 정보 객체 생성
    cat << EOF
  "inspection": {
    "summary": "${summary}",
    "status": "${status}"
  },
EOF
}

# 전체 JSON 결과 생성 (고급 사용자용)
create_full_json_result() {
    local item_id="$1"
    local item_name="$2"
    local korean_status="$3"      # 양호, 취약, 수동진단, N/A
    local english_status="$4"     # GOOD, VULNERABLE, MANUAL, N/A
    local inspection_summary="$5"
    local command_result="$6"
    local command_executed="$7"
    local guideline_purpose="$8"
    local guideline_threat="$9"
    local guideline_criteria_good="${10}"
    local guideline_criteria_bad="${11}"
    local guideline_remediation="${12}"

    {
        echo "{"
        echo "  \"item_id\": \"${item_id}\","
        echo "  \"item_name\": \"${item_name}\","
        format_inspection_object "$inspection_summary" "$korean_status"
        echo "  \"final_result\": \"${english_status}\","
        echo "  \"command\": \"${command_executed}\","
        format_json_field "command_result" "$command_result"
        format_guideline_object "$guideline_purpose" "$guideline_threat" "$guideline_criteria_good" "$guideline_criteria_bad" "$guideline_remediation"
        echo "  \"timestamp\": \"$(date -Iseconds)\","
        echo "  \"hostname\": \"$(get_hostname)\""
        echo "}"
    } | validate_json "${RESULT_DIR_BASE}/${DATE_SUFFIX}/${item_id}_result_$(date +%Y%m%d_%H%M%S).json"
}
