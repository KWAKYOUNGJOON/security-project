#!/bin/bash
# KISA 취약점 진단 시스템 - DBMS 커넥터
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: DBMS 연결 보안 (FR-011: 3회 재시도, 5초 간격, 30초 타임아웃, stdin 표준 입력) (T030-T034)

set -euo pipefail

# DBMS 연결 상수
DBMS_MAX_RETRIES=3
DBMS_RETRY_INTERVAL=5
DBMS_CONNECTION_TIMEOUT=30

# DBMS 연결 정보 입력 프롬프트 (T030)
prompt_dbms_connection() {
    local dbms_type="$1"  # mysql, postgresql, oracle, mssql

    echo "==================================================================="
    echo "DBMS 연결 정보 입력 (${dbms_type})"
    echo "==================================================================="
    echo ""

    # 호스트네임 (기본값: localhost)
    read -p "호스트네임 [localhost]: " DBMS_HOST
    DBMS_HOST=${DBMS_HOST:-localhost}

    # 포트 (DBMS 유형별 기본값)
    local default_port=3306
    case "$dbms_type" in
        mysql)    default_port=3306 ;;
        postgresql|postgres) default_port=5432 ;;
        oracle)   default_port=1521 ;;
        mssql)    default_port=1433 ;;
    esac

    read -p "포트 [${default_port}]: " DBMS_PORT
    DBMS_PORT=${DBMS_PORT:-$default_port}

    # 사용자명
    read -p "사용자명: " DBMS_USER

    # 비밀번호 (stdin silent 입력 - T031)
    read -s -p "비밀번호: " DBMS_PASSWORD
    echo ""  # 개행

    # 데이터베이스명 (MySQL, PostgreSQL, MSSQL의 경우)
    if [[ "$dbms_type" =~ (mysql|postgres|postgresql|mssql) ]]; then
        read -p "데이터베이스명 [예: mysql, postgres, master]: " DBMS_DATABASE
        DBMS_DATABASE=${DBMS_DATABASE:-${dbms_type}}
    fi

    # SID/서비스명 (Oracle의 경우)
    if [ "$dbms_type" = "oracle" ]; then
        read -p "SID 또는 서비스명 [ORCL]: " DBMS_SID
        DBMS_SID=${DBMS_SID:-ORCL}
    fi

    echo ""
    echo "✅ DBMS 연결 정보 입력 완료"
    echo "호스트: ${DBMS_HOST}:${DBMS_PORT}"
    echo "사용자: ${DBMS_USER}"
}

# stdin silent 입력 함수 (T031)
read_sensitive_input() {
    local prompt="$1"
    local output_var="$2"

    echo -n "${prompt}"
    read -s "$output_var"
    echo ""  # 개행

    # 값이 비어있으면 재요청 (최대 3회)
    local retry_count=0
    while [ -z "${!output_var}" ] && [ $retry_count -lt 2 ]; do
        echo "⚠️  값이 비어있습니다. 다시 입력해주세요."
        echo -n "${prompt}"
        read -s "$output_var"
        echo ""
        ((retry_count++))
    done

    if [ -z "${!output_var}" ]; then
        echo "❌ 입력 실패: 값이 비어있습니다" >&2
        return 1
    fi
}

# DBMS 연결 검증 (T032)
validate_dbms_connection() {
    local dbms_type="$1"

    echo "🔍 DBMS 연결 검증 중..."

    # 필요한 바이너리 존재 확인
    case "$dbms_type" in
        mysql)
            if ! command -v mysql &>/dev/null; then
                echo "❌ MySQL 클라이언트 미설치" >&2
                return 1
            fi
            ;;
        postgresql|postgres)
            if ! command -v psql &>/dev/null; then
                echo "❌ PostgreSQL 클라이언트 미설치" >&2
                return 1
            fi
            ;;
        oracle)
            if ! command -v sqlplus &>/dev/null; then
                echo "❌ Oracle 클라이언트 미설치" >&2
                return 1
            fi
            ;;
        mssql)
            if ! command -v sqlcmd &>/dev/null; then
                echo "❌ MSSQL 클라이언트 미설치" >&2
                return 1
            fi
            ;;
        *)
            echo "❌ 알 수 없는 DBMS 유형: ${dbms_type}" >&2
            return 1
            ;;
    esac

    echo "✅ DBMS 클라이언트 설치 확인됨"
}

# DBMS 연결 시도 (T033: 3회 재시도, 5초 간격)
attempt_dbms_connection() {
    local dbms_type="$1"

    echo "🔗 DBMS 연결 시도 (최대 ${DBMS_MAX_RETRIES}회 재시도)..."

    local retry_count=0
    local connected=false

    while [ $retry_count -lt $DBMS_MAX_RETRIES ] && [ "$connected" = false ]; do
        ((retry_count++))

        echo "연결 시도 ${retry_count}/${DBMS_MAX_RETRIES}..."

        case "$dbms_type" in
            mysql)
                if mysql -h"${DBMS_HOST}" -P"${DBMS_PORT}" -u"${DBMS_USER}" -p"${DBMS_PASSWORD}" -e "SELECT 1" &>/dev/null; then
                    connected=true
                fi
                ;;
            postgresql|postgres)
                if PGPASSWORD="${DBMS_PASSWORD}" psql -h "${DBMS_HOST}" -p "${DBMS_PORT}" -U "${DBMS_USER}" -d "${DBMS_DATABASE}" -c "SELECT 1" &>/dev/null; then
                    connected=true
                fi
                ;;
            oracle)
                if echo "EXIT;" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" &>/dev/null; then
                    connected=true
                fi
                ;;
            mssql)
                if sqlcmd -S "${DBMS_HOST},${DBMS_PORT}" -U "${DBMS_USER}" -P "${DBMS_PASSWORD}" -Q "SELECT 1" &>/dev/null; then
                    connected=true
                fi
                ;;
        esac

        if [ "$connected" = true ]; then
            echo "✅ DBMS 연결 성공"
            return 0
        fi

        if [ $retry_count -lt $DBMS_MAX_RETRIES ]; then
            echo "⚠️  연결 실패. ${DBMS_RETRY_INTERVAL}초 후 재시도..."
            sleep ${DBMS_RETRY_INTERVAL}
        fi
    done

    echo "❌ DBMS 연결 실패 (${retry_count}회 시도)" >&2
    return 1
}

# DBMS 쿼리 실행 (T034: 타임아웃 포함)
execute_dbms_query() {
    local dbms_type="$1"
    local query="$2"

    # 타임아웃 적용
    local result=""
    local status=0

    case "$dbms_type" in
        mysql)
            result=$(timeout ${DBMS_CONNECTION_TIMEOUT} mysql -h"${DBMS_HOST}" -P"${DBMS_PORT}" -u"${DBMS_USER}" -p"${DBMS_PASSWORD}" -D "${DBMS_DATABASE}" -se "${query}" 2>&1)
            status=$?
            ;;
        postgresql|postgres)
            result=$(timeout ${DBMS_CONNECTION_TIMEOUT} PGPASSWORD="${DBMS_PASSWORD}" psql -h "${DBMS_HOST}" -p "${DBMS_PORT}" -U "${DBMS_USER}" -d "${DBMS_DATABASE}" -t -c "${query}" 2>&1)
            status=$?
            ;;
        oracle)
            result=$(timeout ${DBMS_CONNECTION_TIMEOUT} bash -c "echo \"${query};\" | sqlplus -s \"${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}\"" 2>&1)
            status=$?
            ;;
        mssql)
            result=$(timeout ${DBMS_CONNECTION_TIMEOUT} sqlcmd -S "${DBMS_HOST},${DBMS_PORT}" -U "${DBMS_USER}" -P "${DBMS_PASSWORD}" -d "${DBMS_DATABASE}" -Q "${query}" -h -1 2>&1)
            status=$?
            ;;
    esac

    if [ $status -eq 0 ]; then
        echo "$result"
        return 0
    elif [ $status -eq 124 ]; then
        echo "❌ DBMS 쿼리 타임아웃 (${DBMS_CONNECTION_TIMEOUT}초)" >&2
        return 1
    else
        echo "❌ DBMS 쿼리 실패: ${result}" >&2
        return 1
    fi
}

# DBMS 연결 정보 정리
cleanup_dbms_connection() {
    echo "🧹 DBMS 연결 정보 정리 중..."

    # 보안: 연결 정보 변수 삭제
    unset DBMS_HOST
    unset DBMS_PORT
    unset DBMS_USER
    unset DBMS_PASSWORD
    unset DBMS_DATABASE
    unset DBMS_SID

    echo "✅ DBMS 연결 정보 정리 완료"
}

# DBMS 연결 종료
close_dbms_connection() {
    cleanup_dbms_connection
}

# ============================================================================
# T174-T177: DBMS별 특화 진단 함수
# ============================================================================

# MySQL 진단 함수 (T174)
diagnose_mysql() {
    local item_id="${1:-D-01}"

    echo "[점검] MySQL 진단 시작..."

    # MySQL 클라이언트 확인
    if ! command -v mysql &>/dev/null; then
        echo "  [FAIL] MySQL 클라이언트 미설치"
        return 1
    fi

    local mysql_version=$(mysql --version 2>/dev/null)
    echo "  [OK] ${mysql_version}"

    # MySQL 연결 테스트 (이미 입력된 정보 사용)
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        echo "  [INFO] DBMS 연결 정보 없음. 연결 정보 입력 필요..."
        prompt_dbms_connection "mysql"
    fi

    # 연결 시도 (3회 재시도)
    local retry_count=0
    while [ $retry_count -lt $DBMS_MAX_RETRIES ]; do
        if mysql -h"${DBMS_HOST}" -P"${DBMS_PORT}" -u"${DBMS_USER}" -p"${DBMS_PASSWORD}" -e "SELECT 1" &>/dev/null; then
            echo "  [OK] MySQL 연결 성공 (${DBMS_HOST}:${DBMS_PORT})"

            # MySQL 버전 확인
            local server_version=$(execute_dbms_query "mysql" "SELECT VERSION()" 2>/dev/null)
            echo "  [INFO] MySQL 서버 버전: ${server_version}"

            # 보안 설정 확인 (기본 진단)
            echo "  [점검] MySQL 보안 설정 확인..."

            # 1) root 원격 접속 확인
            local root_remote=$(execute_dbms_query "mysql" "SELECT host FROM mysql.user WHERE user='root' AND host NOT IN ('localhost', '127.0.0.1', '::1')" 2>/dev/null | head -5)
            if [ -n "$root_remote" ]; then
                echo "  [WARN] root 원격 접속 허용됨: ${root_remote}"
            else
                echo "  [OK] root 원격 접속 제한됨"
            fi

            # 2) 익명 사용자 확인
            local anonymous_users=$(execute_dbms_query "mysql" "SELECT COUNT(*) FROM mysql.user WHERE user=''" 2>/dev/null)
            if [ "$anonymous_users" -gt 0 ]; then
                echo "  [WARN] 익명 사용자 존재: ${anonymous_users}개"
            else
                echo "  [OK] 익명 사용자 없음"
            fi

            return 0
        fi

        ((retry_count++))
        if [ $retry_count -lt $DBMS_MAX_RETRIES ]; then
            echo "  [RETRY] MySQL 연결 실패. ${DBMS_RETRY_INTERVAL}초 후 재시도 (${retry_count}/${DBMS_MAX_RETRIES})..."
            sleep ${DBMS_RETRY_INTERVAL}
        fi
    done

    echo "  [FAIL] MySQL 연결 실패 (${DBMS_MAX_RETRIES}회 시도)"
    return 1
}

# PostgreSQL 진단 함수 (T175)
diagnose_postgresql() {
    local item_id="${1:-D-01}"

    echo "[점검] PostgreSQL 진단 시작..."

    # PostgreSQL 클라이언트 확인
    if ! command -v psql &>/dev/null; then
        echo "  [FAIL] PostgreSQL 클라이언트 미설치"
        return 1
    fi

    local psql_version=$(psql --version 2>/dev/null)
    echo "  [OK] ${psql_version}"

    # PostgreSQL 연결 테스트
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        echo "  [INFO] DBMS 연결 정보 없음. 연결 정보 입력 필요..."
        prompt_dbms_connection "postgresql"
    fi

    # 연결 시도 (3회 재시도)
    local retry_count=0
    while [ $retry_count -lt $DBMS_MAX_RETRIES ]; do
        if PGPASSWORD="${DBMS_PASSWORD}" psql -h "${DBMS_HOST}" -p "${DBMS_PORT}" -U "${DBMS_USER}" -d "${DBMS_DATABASE}" -c "SELECT 1" &>/dev/null; then
            echo "  [OK] PostgreSQL 연결 성공 (${DBMS_HOST}:${DBMS_PORT})"

            # PostgreSQL 버전 확인
            local server_version=$(PGPASSWORD="${DBMS_PASSWORD}" psql -h "${DBMS_HOST}" -p "${DBMS_PORT}" -U "${DBMS_USER}" -d "${DBMS_DATABASE}" -t -c "SELECT version()" 2>/dev/null | head -1)
            echo "  [INFO] PostgreSQL 서버 버전: ${server_version}"

            # 보안 설정 확인 (기본 진단)
            echo "  [점검] PostgreSQL 보안 설정 확인..."

            # 1) password_encryption 확인
            local enc_setting=$(PGPASSWORD="${DBMS_PASSWORD}" psql -h "${DBMS_HOST}" -p "${DBMS_PORT}" -U "${DBMS_USER}" -d "${DBMS_DATABASE}" -t -c "SHOW password_encryption" 2>/dev/null | tr -d ' ')
            echo "  [INFO] 비밀번호 암호화: ${enc_setting}"

            return 0
        fi

        ((retry_count++))
        if [ $retry_count -lt $DBMS_MAX_RETRIES ]; then
            echo "  [RETRY] PostgreSQL 연결 실패. ${DBMS_RETRY_INTERVAL}초 후 재시도 (${retry_count}/${DBMS_MAX_RETRIES})..."
            sleep ${DBMS_RETRY_INTERVAL}
        fi
    done

    echo "  [FAIL] PostgreSQL 연결 실패 (${DBMS_MAX_RETRIES}회 시도)"
    return 1
}

# Oracle 진단 함수 (T176)
diagnose_oracle() {
    local item_id="${1:-D-01}"

    echo "[점검] Oracle 진단 시작..."

    # Oracle 클라이언트 확인
    if ! command -v sqlplus &>/dev/null; then
        echo "  [FAIL] Oracle SQL*Plus 클라이언트 미설치"
        return 1
    fi

    local sqlplus_version=$(sqlplus -v 2>/dev/null | head -1)
    echo "  [OK] ${sqlplus_version}"

    # Oracle 연결 테스트
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        echo "  [INFO] DBMS 연결 정보 없음. 연결 정보 입력 필요..."
        prompt_dbms_connection "oracle"
    fi

    # 연결 시도 (3회 재시도)
    local retry_count=0
    while [ $retry_count -lt $DBMS_MAX_RETRIES ]; do
        if echo "SELECT 1 FROM DUAL;" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" &>/dev/null; then
            echo "  [OK] Oracle 연결 성공 (${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID})"

            # Oracle 버전 확인
            local server_version=$(echo "SELECT * FROM V\$VERSION;" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -E "Oracle|Release" | head -1)
            echo "  [INFO] Oracle 서버 버전: ${server_version}"

            # 보안 설정 확인 (기본 진단)
            echo "  [점검] Oracle 보안 설정 확인..."

            # 1) FAILED_LOGIN_ATTEMPTS 확인
            local failed_attempts=$(echo "SELECT LIMIT FROM PROFILE\$ WHERE RESOURCE_NAME='FAILED_LOGIN_ATTEMPTS' AND PROFILE='DEFAULT';" | sqlplus -s "${DBMS_USER}/${DBMS_PASSWORD}@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}" 2>/dev/null | grep -v "^$" | tail -1)
            echo "  [INFO] FAILED_LOGIN_ATTEMPTS: ${failed_attempts}"

            return 0
        fi

        ((retry_count++))
        if [ $retry_count -lt $DBMS_MAX_RETRIES ]; then
            echo "  [RETRY] Oracle 연결 실패. ${DBMS_RETRY_INTERVAL}초 후 재시도 (${retry_count}/${DBMS_MAX_RETRIES})..."
            sleep ${DBMS_RETRY_INTERVAL}
        fi
    done

    echo "  [FAIL] Oracle 연결 실패 (${DBMS_MAX_RETRIES}회 시도)"
    return 1
}

# MSSQL 진단 함수 (T177)
diagnose_mssql() {
    local item_id="${1:-D-01}"

    echo "[점검] MSSQL 진단 시작..."

    # MSSQL 클라이언트 확인
    if ! command -v sqlcmd &>/dev/null; then
        echo "  [FAIL] MSSQL sqlcmd 클라이언트 미설치"
        return 1
    fi

    local sqlcmd_version=$(sqlcmd -? 2>/dev/null | head -1)
    echo "  [OK] ${sqlcmd_version}"

    # MSSQL 연결 테스트
    if [ -z "${DBMS_HOST:-}" ] || [ -z "${DBMS_USER:-}" ]; then
        echo "  [INFO] DBMS 연결 정보 없음. 연결 정보 입력 필요..."
        prompt_dbms_connection "mssql"
    fi

    # 연결 시도 (3회 재시도)
    local retry_count=0
    while [ $retry_count -lt $DBMS_MAX_RETRIES ]; do
        if sqlcmd -S "${DBMS_HOST},${DBMS_PORT}" -U "${DBMS_USER}" -P "${DBMS_PASSWORD}" -d "${DBMS_DATABASE}" -Q "SELECT 1" -h -1 &>/dev/null; then
            echo "  [OK] MSSQL 연결 성공 (${DBMS_HOST}:${DBMS_PORT})"

            # MSSQL 버전 확인
            local server_version=$(sqlcmd -S "${DBMS_HOST},${DBMS_PORT}" -U "${DBMS_USER}" -P "${DBMS_PASSWORD}" -d "${DBMS_DATABASE}" -Q "SELECT @@VERSION" -h -1 -W 2>/dev/null | head -1)
            echo "  [INFO] MSSQL 서버 버전: ${server_version}"

            # 보안 설정 확인 (기본 진단)
            echo "  [점검] MSSQL 보안 설정 확인..."

            # 1) sa 계정 상태 확인
            local sa_status=$(sqlcmd -S "${DBMS_HOST},${DBMS_PORT}" -U "${DBMS_USER}" -P "${DBMS_PASSWORD}" -d "${DBMS_DATABASE}" -Q "SELECT is_disabled FROM sys.server_principals WHERE name='sa'" -h -1 -W 2>/dev/null | tr -d ' ')
            if [ "$sa_status" = "0" ]; then
                echo "  [WARN] sa 계정 활성화됨"
            else
                echo "  [OK] sa 계정 비활성화됨"
            fi

            return 0
        fi

        ((retry_count++))
        if [ $retry_count -lt $DBMS_MAX_RETRIES ]; then
            echo "  [RETRY] MSSQL 연결 실패. ${DBMS_RETRY_INTERVAL}초 후 재시도 (${retry_count}/${DBMS_MAX_RETRIES})..."
            sleep ${DBMS_RETRY_INTERVAL}
        fi
    done

    echo "  [FAIL] MSSQL 연결 실패 (${DBMS_MAX_RETRIES}회 시도)"
    return 1
}
