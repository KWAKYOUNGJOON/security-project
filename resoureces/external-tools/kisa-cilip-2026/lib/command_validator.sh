#!/bin/bash
# KISA 취약점 진단 시스템 - 명령어 검증기
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: 화이트리스트 기반 명령어 검증 (FR-020: Read-only 명령어만 허용) (T038-T041)

set -euo pipefail

# SCRIPT_DIR이 설정되어 있지 않을 때만 설정 (라이브러리로 호출 시 개별 스크립트의 SCRIPT_DIR 유지)
if [ -z "${SCRIPT_DIR:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

# 화이트리스트: 안전한 읽기 전용 명령어 (T038)
declare -A COMMAND_WHITELIST=(
    # 파일/시스템 정보 조회
    ["cat"]="GOOD"              # 파일 내용 확인
    ["ls"]="GOOD"               # 디렉토리 목록
    ["find"]="GOOD"             # 파일 검색
    ["grep"]="GOOD"             # 텍스트 검색
    ["awk"]="GOOD"              # 텍스트 처리
    ["sed"]="GOOD"              # 텍스트 치환 (읽기 모드)
    ["head"]="GOOD"             # 파일 앞부분
    ["tail"]="GOOD"             # 파일 뒷부분
    ["wc"]="GOOD"               # 라인/단어 수
    ["sort"]="GOOD"             # 정렬
    ["uniq"]="GOOD"             # 중복 제거
    ["cut"]="GOOD"              # 필드 추출
    ["tr"]="GOOD"               # 문자 변환

    # 시스템 정보
    ["uname"]="GOOD"            # 시스템 정보
    ["hostname"]="GOOD"         # 호스트네임
    ["date"]="GOOD"             # 날짜/시간
    ["df"]="GOOD"               # 디스크 사용량
    ["du"]="GOOD"               # 디렉토리 크기
    ["ps"]="GOOD"               # 프로세스 목록
    ["uptime"]="GOOD"           # 가동 시간

    # 네트워크 정보 (읽기 전용)
    ["netstat"]="GOOD"          # 네트워크 상태 (Linux)
    ["ss"]="GOOD"               # 소켓 통계 (Linux)
    ["ip"]="GOOD"               # IP 정보 (읽기 모드)

    # 사용자/그룹 정보
    ["id"]="GOOD"               # 사용자 ID
    ["who"]="GOOD"              # 로그인 사용자
    ["w"]="GOOD"                # 로그인 사용자 상세
    ["whoami"]="GOOD"           # 현재 사용자
    ["groups"]="GOOD"           # 그룹 정보

    # 권한 확인
    ["stat"]="GOOD"             # 파일 상태
    ["getfacl"]="GOOD"          # ACL 확인 (Linux)
    ["namei"]="GOOD"            # 경로 추적

    # DBMS 클라이언트 (읽기 전용 쿼리만)
    ["mysql"]="conditional"     # MySQL (읽기 쿼리 검증 필요)
    ["psql"]="conditional"      # PostgreSQL (읽기 쿼리 검증 필요)
    ["sqlplus"]="conditional"   # Oracle (읽기 쿼리 검증 필요)
    ["sqlcmd"]="conditional"    # MSSQL (읽기 쿼리 검증 필요)

    # Windows 읽기 전용 명령어
    ["powershell"]="conditional" # PowerShell (읽기 명령어 검증 필요)
    ["cmd.exe"]="conditional"   # CMD (읽기 명령어 검증 필요)
)

# 포브든 패턴: 위험한 명령어 패턴 (T039)
declare -a FORBIDDEN_PATTERNS=(
    "rm -rf"                    # 파일 삭제
    "rm -fr"                    # 파일 삭제 (variant)
    ">.*rm"                     # 파일 삭제 (redirection)
    "mkfs\."                    # 파일 시스템 생성
    "dd if="                    # 디스크 쓰기
    ": >"                       # 파일 초기화 (truncation)
    "echo.*>.*\/"               # 파일 쓰기 (path 포함)
    "mv .*\/"                   # 파일 이동 (path 포함)
    "cp .*\/.*\/"               # 파일 복사 (path 포함)
    "chmod 000"                 # 권한 삭제
    "chown root.*\* "           # 소유자 변경 (wildcard)
    "userdel"                   # 사용자 삭제
    "groupdel"                  # 그룹 삭제
    "kill -9"                   # 프로세스 강제 종료
    "killall"                   # 모든 프로세스 종료
    "pkill"                     # 프로세스 종료
    "shutdown"                  # 시스템 종료
    "reboot"                    # 시스템 재부팅
    "init 0"                    # 시스템 종료
    "halt"                      # 시스템 정지
    "iptables.*-F"              # 방화벽 규칙 삭제
    "iptables.*-X"              # 방화벽 체인 삭제
    "DROP"                      # 방화벽 패킷 삭제
    "ACCEPT.*\*"                # 방화벽 모든 패킷 허용
    "DELETE FROM"               # DB 데이터 삭제
    "DROP TABLE"                # DB 테이블 삭제
    "TRUNCATE TABLE"            # DB 테이블 초기화
    "UPDATE.*SET"               # DB 데이터 수정 (if not WHERE 1=0)
    "INSERT INTO"               # DB 데이터 삽입
    "GRANT ALL"                 # DB 권한 부여
    "REVOKE.*\*"                # DB 모든 권한 삭제
    "ALTER TABLE"               # DB 테이블 수정
    "CREATE.*TABLE"             # DB 테이블 생성
    "exec\("                    # 코드 실행
    "eval\("                    # 코드 실행
    "system\("                  # 시스템 명령 실행
    "passthru\("                # 시스템 명령 실행 (PHP)
    "\`.*\`"                    # 백틱 명령 실행
    "\\\$\\\(.*\\\)"            # 명령 치환
    "; *rm"                     # 체이닝 명령 삭제
    "&& *rm"                    # 체이닝 명령 삭제
    "\|\| *rm"                  # 체이닝 명령 삭제
)

# 안전한 플래그: 허용되는 명령어 플래그 (읽기 전용)
declare -A SAFE_FLAGS=(
    ["cat"]="-n -A -s -v -E -T -b"
    ["ls"]="-l -a -h -i -R -d -1"
    ["grep"]="-i -v -c -l -n -E -F -e -f -w -x"
    ["find"]="-name -type -perm -user -group -size -mtime -atime -ctime"
    ["awk"]="-F -v"
    ["sed"]="-n -e -f -E"
    ["head"]="-n -c"
    ["tail"]="-n -c -f"
    ["stat"]="-c -f -L"
    ["mysql"]="-e -h -P -u -p -S -D"
    ["psql"]="-c -h -p -U -d"
    ["netstat"]="-tuln -an -rn -tulpn"
    ["ss"]="-tuln -a"
)

# 명령어 검증 함수 (T040)
check_read_only_command() {
    local command="$1"
    local item_id="${2:-UNKNOWN}"

    echo "🔍 명령어 검증: ${command}"

    # 1단계: 포브든 패턴 검사
    if check_forbidden_patterns "$command"; then
        echo "❌ 위험한 패턴 감지됨: ${command}"
        log_command_violation "$item_id" "$command" "forbidden_pattern"
        return 1
    fi

    # 2단계: 기본 명령어 추출
    local base_command=$(echo "$command" | awk '{print $1}' | sed 's/^[^[:alnum:]]*//;s/[[:space:]].*$//')

    # 3단계: 화이트리스트 확인
    if ! is_command_whitelisted "$base_command"; then
        echo "❌ 화이트리스트 미등록 명령어: ${base_command}"
        log_command_violation "$item_id" "$command" "not_whitelisted"
        return 1
    fi

    # 4단계: 조건부 명령어 추가 검증
    local whitelist_status="${COMMAND_WHITELIST[$base_command]}"
    if [ "$whitelist_status" = "conditional" ]; then
        if ! validate_conditional_command "$base_command" "$command"; then
            echo "❌ 조건부 명령어 검증 실패: ${command}"
            log_command_violation "$item_id" "$command" "conditional_validation_failed"
            return 1
        fi
    fi

    # 5단계: 플래그 검증
    if ! validate_command_flags "$base_command" "$command"; then
        echo "⚠️  안전하지 않은 플래그: ${command}"
        log_command_violation "$item_id" "$command" "unsafe_flag"
        return 1
    fi

    echo "✅ 명령어 검증 통과: ${command}"
    return 0
}

# 포브든 패턴 검사
check_forbidden_patterns() {
    local command="$1"

    for pattern in "${FORBIDDEN_PATTERNS[@]}"; do
        if echo "$command" | grep -qE "$pattern"; then
            echo "⚠️  위험한 패턴 감지: ${pattern}"
            return 0  # 패턴 발견 (위험)
        fi
    done

    return 1  # 안전함
}

# 화이트리스트 확인
is_command_whitelisted() {
    local base_command="$1"

    if [ -n "${COMMAND_WHITELIST[$base_command]:-}" ]; then
        return 0  # 화이트리스트에 있음
    else
        return 1  # 화이트리스트에 없음
    fi
}

# 조건부 명령어 검증 (DBMS, PowerShell 등)
validate_conditional_command() {
    local base_command="$1"
    local full_command="$2"

    case "$base_command" in
        mysql)
            # SELECT, SHOW, DESCRIBE, EXPLAIN만 허용
            if echo "$full_command" | grep -iqE "SELECT|SHOW|DESCRIBE|EXPLAIN|USE"; then
                return 0  # 안전한 쿼리
            else
                echo "⚠️  안전하지 않은 MySQL 쿼리"
                return 1
            fi
            ;;
        psql)
            # SELECT, \d, \dt 등 읽기 전용만 허용
            if echo "$full_command" | grep -iqE "SELECT|\\\d|\\\dt|DESCRIBE|EXPLAIN"; then
                return 0  # 안전한 쿼리
            else
                echo "⚠️  안전하지 않은 PostgreSQL 쿼리"
                return 1
            fi
            ;;
        sqlplus)
            # SELECT만 허용
            if echo "$full_command" | grep -iqE "SELECT.*FROM"; then
                return 0  # 안전한 쿼리
            else
                echo "⚠️  안전하지 않은 Oracle 쿼리"
                return 1
            fi
            ;;
        sqlcmd)
            # SELECT만 허용
            if echo "$full_command" | grep -iqE "SELECT"; then
                return 0  # 안전한 쿼리
            else
                echo "⚠️  안전하지 않은 MSSQL 쿼리"
                return 1
            fi
            ;;
        powershell|cmd.exe)
            # Get-*, Get-* -Property 등 읽기 명령어만 허용
            if echo "$full_command" | grep -iqE "Get-|Select-|Format-|Where-Object"; then
                return 0  # 안전한 PowerShell 명령어
            else
                echo "⚠️  안전하지 않은 PowerShell/CMD 명령어"
                return 1
            fi
            ;;
        *)
            echo "⚠️  알 수 없는 조건부 명령어: ${base_command}"
            return 1
            ;;
    esac
}

# 명령어 플래그 검증
validate_command_flags() {
    local base_command="$1"
    local full_command="$2"

    # 안전한 플래그 목록 확인
    local safe_flags="${SAFE_FLAGS[$base_command]:-}"

    if [ -z "$safe_flags" ]; then
        # 플래그 검증 정의되지 않음 (안전한 것으로 간주)
        return 0
    fi

    # 위험한 플래그 검사 (예: cat > file, ls > file 등 리다이렉션)
    if echo "$full_command" | grep -qE ">|>>|<|<<"; then
        # 허용되는 리다이렉션 (grep, find 등 파이프라인)
        if echo "$full_command" | grep -qE "grep|find|awk|sed"; then
            return 0  # 파이프라인 내 리다이렉션 허용
        else
            echo "⚠️  파일 쓰기 리다이렉션 감지"
            return 1
        fi
    fi

    return 0  # 플래그 안전함
}

# 위반 로그 기록 (T041)
log_command_violation() {
    local item_id="$1"
    local command="$2"
    local violation_type="$3"

    local log_dir="${SCRIPT_DIR}/../results/$(date +%Y%m%d)"
    mkdir -p "${log_dir}"

    local log_file="${log_dir}/command_violations.txt"

    echo "[$(date -Iseconds)] ${item_id} | ${violation_type} | ${command}" >> "${log_file}"

    echo "📝 위반 로그 기록됨: ${log_file}"
}

# 화이트리스트에 명령어 추가 (런타임 확장용)
add_to_whitelist() {
    local command="$1"
    local status="${2:-safe}"

    COMMAND_WHITELIST["$command"]="$status"
    echo "✅ 화이트리스트에 추가됨: ${command} (${status})"
}

# 포브든 패턴 추가 (런타임 확장용)
add_forbidden_pattern() {
    local pattern="$1"

    FORBIDDEN_PATTERNS+=("$pattern")
    echo "✅ 포브든 패턴에 추가됨: ${pattern}"
}

# 명령어 검증기 상태 출력
show_validator_status() {
    echo "==================================================================="
    echo "명령어 검증기 상태"
    echo "==================================================================="
    echo ""
    echo "📋 화이트리스트 등록 명령어: ${#COMMAND_WHITELIST[@]}개"
    echo "🚫 포브든 패턴: ${#FORBIDDEN_PATTERNS[@]}개"
    echo "🔒 안전한 플래그 정의: ${#SAFE_FLAGS[@]}개 명령어"
    echo ""
}
