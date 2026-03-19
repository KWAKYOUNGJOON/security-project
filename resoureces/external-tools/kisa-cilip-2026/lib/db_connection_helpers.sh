#!/bin/bash
# ============================================================================
# KISA-CIIP-2026 Database Connection Helpers
# @Project: KISA-CIIP-2026 Vulnerability Assessment Scripts
# @Copyright: Copyright (c) 2026 Yang Uhyeok (양우혁). All rights reserved.
# @Version: 1.0.0
# @Last Updated: 2026-01-16
# ============================================================================
# Purpose: Provide standardized database connection functions for DBMS scripts
# Features:
#   - FR-018 compliance: 3 retries with 2-second intervals
#   - Cross-platform compatibility: Uses DB-native tools (pg_isready, mysqladmin ping)
#   - WSL/Docker support: No systemd dependency
#   - Unified connection handling for PostgreSQL, MySQL, Oracle, MSSQL
# ============================================================================

# Prevent multiple sourcing
if [ -n "${_DB_CONNECTION_HELPERS_SOURCED:-}" ]; then
    return 0
fi
_DB_CONNECTION_HELPERS_SOURCED=true

# ============================================================================
# FR-022: Tool Existence Checking Functions
# ============================================================================

# Check if PostgreSQL client tools are available
check_postgresql_tools() {
    local missing_tools=()

    if ! command -v psql &>/dev/null; then
        missing_tools+=("psql")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        return 1
    fi
    return 0
}

# Check if MySQL client tools are available
check_mysql_tools() {
    local missing_tools=()

    if ! command -v mysql &>/dev/null; then
        missing_tools+=("mysql")
    fi

    if ! command -v mysqladmin &>/dev/null; then
        missing_tools+=("mysqladmin")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        return 1
    fi
    return 0
}

# Check if Oracle client tools are available
check_oracle_tools() {
    if ! command -v sqlplus &>/dev/null; then
        return 1
    fi
    return 0
}

# Check if MSSQL client tools are available
check_mssql_tools() {
    if ! command -v sqlcmd &>/dev/null; then
        return 1
    fi
    return 0
}

# Generic handler for missing tools
handle_missing_tools() {
    local dbms_type="$1"
    local item_id="$2"
    local item_name="$3"
    shift 3
    # Remaining args are guideline variables

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local dbms_name=""
    local required_tools=""

    case "$dbms_type" in
        postgresql|postgres)
            dbms_name="PostgreSQL"
            required_tools="psql, pg_isready (optional)"
            ;;
        mysql|mariadb)
            dbms_name="MySQL/MariaDB"
            required_tools="mysql, mysqladmin"
            ;;
        oracle)
            dbms_name="Oracle"
            required_tools="sqlplus (Oracle Instant Client)"
            ;;
        mssql)
            dbms_name="MSSQL"
            required_tools="sqlcmd (mssql-tools)"
            ;;
    esac

    local inspection_summary="${dbms_name} 클라이언트 도구가 설치되지 않았습니다. ${required_tools} 설치가 필요합니다."
    local command_result="Required tools not found"
    local command_executed="command -v [required_tool]"

    # Pass through guideline variables
    save_dual_result "${item_id}" "${item_name}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" "$@"
    verify_result_saved "${item_id}"
    return 0
}

# ============================================================================
# PostgreSQL Connection Functions
# ============================================================================

# Initialize PostgreSQL connection variables with defaults
init_postgresql_vars() {
    DB_ADMIN_USER="${DB_ADMIN_USER:-postgres}"
    DB_ADMIN_PASS="${DB_ADMIN_PASS:-}"
    DB_HOST="${DB_HOST:-localhost}"
    DB_PORT="${DB_PORT:-5432}"
    export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
}

# Check if PostgreSQL service is running
check_postgresql_service() {
    if ! command -v pg_isready &>/dev/null; then
        echo "WARNING: pg_isready not found. Skipping service check." >&2
        return 0  # Continue, but warn
    fi

    if ! pg_isready -h "${DB_HOST}" -p "${DB_PORT}" &>/dev/null; then
        return 1  # Service not running
    fi
    return 0  # Service running
}

# Prompt for PostgreSQL connection and test (FR-018: 3 retries, 2-second intervals)
prompt_postgresql_connection() {
    init_postgresql_vars

    if [ -z "${DB_ADMIN_PASS}" ]; then
        echo "[INFO] PostgreSQL 연결 정보 입력이 필요합니다."
        read -p "PostgreSQL Host [${DB_HOST}]: " input_host
        DB_HOST="${input_host:-$DB_HOST}"

        read -p "PostgreSQL Port [${DB_PORT}]: " input_port
        DB_PORT="${input_port:-$DB_PORT}"

        read -p "PostgreSQL Username [${DB_ADMIN_USER}]: " input_user
        DB_ADMIN_USER="${input_user:-$DB_ADMIN_USER}"

        read -s -p "PostgreSQL Password: " input_pass
        echo ""
        DB_ADMIN_PASS="${input_pass}"
    fi

    # 3회 재시도 로직 (FR-018)
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        # PostgreSQL 연결 테스트
        if PGPASSWORD="${DB_ADMIN_PASS}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_ADMIN_USER}" -d postgres -c "SELECT 1;" &>/dev/null; then
            echo "[INFO] PostgreSQL 연결 성공"
            export DB_ADMIN_USER DB_ADMIN_PASS DB_HOST DB_PORT
            return 0
        fi

        ((retry_count++)) || true
        if [ $retry_count -lt $max_retries ]; then
            echo "[WARN] PostgreSQL 연결 실패 (${retry_count}/${max_retries}). 2초 후 재시도..."
            sleep 2
        fi
    done

    return 1
}

# Get PostgreSQL connection info for command display
get_postgresql_connection_info() {
    echo "psql -h ${DB_HOST} -p ${DB_PORT} -U ${DB_ADMIN_USER} -d postgres"
}

# ============================================================================
# MySQL Connection Functions
# ============================================================================

# Initialize MySQL connection variables with defaults
init_mysql_vars() {
    DB_HOST="${DB_HOST:-localhost}"
    DB_PORT="${DB_PORT:-3306}"
    DB_USER="${DB_USER:-root}"
    DB_PASSWORD="${DB_PASSWORD:-}"
    export DB_HOST DB_PORT DB_USER DB_PASSWORD
}

# Check if MySQL/MariaDB service is running
check_mysql_service() {
    if ! command -v mysqladmin &>/dev/null; then
        echo "WARNING: mysqladmin not found. Skipping service check." >&2
        return 0  # Continue, but warn
    fi

    if ! mysqladmin ping -h "${DB_HOST}" -P "${DB_PORT}" &>/dev/null; then
        return 1  # Service not running
    fi
    return 0  # Service running
}

# Prompt for MySQL connection and test (FR-018: 3 retries, 2-second intervals)
prompt_mysql_connection() {
    init_mysql_vars

    if [ -z "${DB_PASSWORD}" ]; then
        echo "[INFO] MySQL 연결 정보 입력이 필요합니다."
        read -p "MySQL Host [${DB_HOST}]: " input_host
        DB_HOST="${input_host:-$DB_HOST}"

        read -p "MySQL Port [${DB_PORT}]: " input_port
        DB_PORT="${input_port:-$DB_PORT}"

        read -p "MySQL Username [${DB_USER}]: " input_user
        DB_USER="${input_user:-$DB_USER}"

        read -s -p "MySQL Password: " input_pass
        echo ""
        DB_PASSWORD="${input_pass}"
    fi

    # 3회 재시도 로직 (FR-018)
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        # MySQL 연결 테스트
        if mysql -h "${DB_HOST}" -P "${DB_PORT}" -u "${DB_USER}" -p"${DB_PASSWORD}" -e "SELECT 1;" &>/dev/null; then
            echo "[INFO] MySQL 연결 성공"
            export DB_HOST DB_PORT DB_USER DB_PASSWORD
            return 0
        fi

        ((retry_count++)) || true
        if [ $retry_count -lt $max_retries ]; then
            echo "[WARN] MySQL 연결 실패 (${retry_count}/${max_retries}). 2초 후 재시도..."
            sleep 2
        fi
    done

    return 1
}

# Get MySQL connection info for command display
get_mysql_connection_info() {
    echo "mysql -h ${DB_HOST} -P ${DB_PORT} -u ${DB_USER} -p***"
}

# ============================================================================
# Oracle Connection Functions (Wrappers for dbms_connector.sh)
# ============================================================================

# Initialize Oracle connection variables with defaults
init_oracle_vars() {
    DBMS_HOST="${DBMS_HOST:-localhost}"
    DBMS_PORT="${DBMS_PORT:-1521}"
    DBMS_USER="${DBMS_USER:-}"
    DBMS_PASSWORD="${DBMS_PASSWORD:-}"
    DBMS_SID="${DBMS_SID:-ORCL}"
    export DBMS_HOST DBMS_PORT DBMS_USER DBMS_PASSWORD DBMS_SID
}

# Check if Oracle service is running
check_oracle_service() {
    if ! pgrep -x "tnslsnr" &>/dev/null && ! pgrep -x "oracle" &>/dev/null; then
        return 1  # Service not running
    fi
    return 0  # Service running
}

# Get Oracle connection info for command display
get_oracle_connection_info() {
    echo "sqlplus -s ${DBMS_USER}/***@${DBMS_HOST}:${DBMS_PORT}/${DBMS_SID}"
}

# ============================================================================
# MSSQL Connection Functions
# ============================================================================

# Initialize MSSQL connection variables with defaults
init_mssql_vars() {
    DB_HOST="${DB_HOST:-localhost}"
    DB_PORT="${DB_PORT:-1433}"
    DB_USER="${DB_USER:-sa}"
    DB_PASSWORD="${DB_PASSWORD:-}"
    export DB_HOST DB_PORT DB_USER DB_PASSWORD
}

# Check if MSSQL service is running (via sqlcmd)
check_mssql_service() {
    if ! command -v sqlcmd &>/dev/null; then
        echo "WARNING: sqlcmd not found. Skipping service check." >&2
        return 0  # Continue, but warn
    fi

    # Try to connect to master database to check service
    if ! sqlcmd -S "${DB_HOST},${DB_PORT}" -U "${DB_USER}" -P "${DB_PASSWORD}" -d master -Q "SELECT 1" -h -1 &>/dev/null; then
        return 1  # Service not running or connection failed
    fi
    return 0  # Service running
}

# Prompt for MSSQL connection and test (FR-018: 3 retries, 2-second intervals)
prompt_mssql_connection() {
    init_mssql_vars

    if [ -z "${DB_PASSWORD}" ]; then
        echo "[INFO] MSSQL 연결 정보 입력이 필요합니다."
        echo "[NOTE] MSSQL scripts require bash environment (WSL, Linux, or macOS with sqlcmd installed)"

        read -p "MSSQL Host [${DB_HOST}]: " input_host
        DB_HOST="${input_host:-$DB_HOST}"

        read -p "MSSQL Port [${DB_PORT}]: " input_port
        DB_PORT="${input_port:-$DB_PORT}"

        read -p "MSSQL Username [${DB_USER}]: " input_user
        DB_USER="${input_user:-$DB_USER}"

        read -s -p "MSSQL Password: " input_pass
        echo ""
        DB_PASSWORD="${input_pass}"
    fi

    # 3회 재시도 로직 (FR-018)
    local retry_count=0
    local max_retries=3

    while [ $retry_count -lt $max_retries ]; do
        # MSSQL 연결 테스트
        if sqlcmd -S "${DB_HOST},${DB_PORT}" -U "${DB_USER}" -P "${DB_PASSWORD}" -d master -Q "SELECT 1" -h -1 &>/dev/null; then
            echo "[INFO] MSSQL 연결 성공"
            export DB_HOST DB_PORT DB_USER DB_PASSWORD
            return 0
        fi

        ((retry_count++)) || true
        if [ $retry_count -lt $max_retries ]; then
            echo "[WARN] MSSQL 연결 실패 (${retry_count}/${max_retries}). 2초 후 재시도..."
            sleep 2
        fi
    done

    return 1
}

# Get MSSQL connection info for command display
get_mssql_connection_info() {
    echo "sqlcmd -S ${DB_HOST},${DB_PORT} -U ${DB_USER} -p***"
}

# ============================================================================
# Generic DBMS Service Check Function
# ============================================================================

# Generic function to check if DBMS service is running
# Usage: check_dbms_service <dbms_type>
check_dbms_service() {
    local dbms_type="$1"

    case "$dbms_type" in
        postgresql|postgres)
            check_postgresql_service
            ;;
        mysql|mariadb)
            check_mysql_service
            ;;
        oracle)
            check_oracle_service
            ;;
        mssql)
            check_mssql_service
            ;;
        *)
            echo "ERROR: Unknown DBMS type: $dbms_type" >&2
            return 1
            ;;
    esac
}

# ============================================================================
# Generic DBMS Connection Prompt Function
# ============================================================================

# Generic function to prompt for DBMS connection and test
# Usage: prompt_dbms_connection <dbms_type>
prompt_dbms_connection_generic() {
    local dbms_type="$1"

    case "$dbms_type" in
        postgresql|postgres)
            prompt_postgresql_connection
            ;;
        mysql|mariadb)
            prompt_mysql_connection
            ;;
        oracle)
            # Oracle uses dbms_connector.sh, so we just init vars
            init_oracle_vars
            if [ -z "${DBMS_PASSWORD}" ]; then
                # Use dbms_connector.sh function if available
                if type prompt_dbms_connection &>/dev/null; then
                    prompt_dbms_connection "oracle"
                else
                    echo "[ERROR] dbms_connector.sh not sourced" >&2
                    return 1
                fi
            fi
            ;;
        mssql)
            prompt_mssql_connection
            ;;
        *)
            echo "ERROR: Unknown DBMS type: $dbms_type" >&2
            return 1
            ;;
    esac
}

# ============================================================================
# Helper to get connection info for display
# ============================================================================

# Get connection info string for command display
# Usage: get_dbms_connection_info <dbms_type>
get_dbms_connection_info() {
    local dbms_type="$1"

    case "$dbms_type" in
        postgresql|postgres)
            get_postgresql_connection_info
            ;;
        mysql|mariadb)
            get_mysql_connection_info
            ;;
        oracle)
            get_oracle_connection_info
            ;;
        mssql)
            get_mssql_connection_info
            ;;
        *)
            echo "ERROR: Unknown DBMS type: $dbms_type" >&2
            return 1
            ;;
    esac
}

# ============================================================================
# Service Not Running Handler
# ============================================================================

# Generic handler for when DBMS service is not running
# Usage: handle_dbms_not_running <dbms_type> <item_id> <item_name> <guideline_vars...>
handle_dbms_not_running() {
    local dbms_type="$1"
    local item_id="$2"
    local item_name="$3"
    shift 3
    # Remaining args are guideline variables

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local dbms_name=""

    case "$dbms_type" in
        postgresql|postgres) dbms_name="PostgreSQL" ;;
        mysql|mariadb) dbms_name="MySQL/MariaDB" ;;
        oracle) dbms_name="Oracle" ;;
        mssql) dbms_name="MSSQL" ;;
    esac

    local inspection_summary="${dbms_name} 서비스가 실행 중이지 않습니다. 서비스 시작 후 진단이 필요합니다."
    local command_result="${dbms_name} service not running"
    local command_executed=""

    # Get appropriate check command
    case "$dbms_type" in
        postgresql|postgres)
            command_executed="pg_isready -h ${DB_HOST} -p ${DB_PORT}"
            ;;
        mysql|mariadb)
            command_executed="mysqladmin ping -h ${DB_HOST} -P ${DB_PORT}"
            ;;
        oracle)
            command_executed="pgrep -x 'tnslsnr' || pgrep -x 'oracle'"
            ;;
        mssql)
            command_executed="sqlcmd -S ${DB_HOST},${DB_PORT}"
            ;;
    esac

    # Pass through guideline variables
    save_dual_result "${item_id}" "${item_name}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" "$@"
    verify_result_saved "${item_id}"
    return 0
}

# ============================================================================
# Connection Failed Handler
# ============================================================================

# Generic handler for when DBMS connection fails
# Usage: handle_dbms_connection_failed <dbms_type> <item_id> <item_name> <guideline_vars...>
handle_dbms_connection_failed() {
    local dbms_type="$1"
    local item_id="$2"
    local item_name="$3"
    shift 3
    # Remaining args are guideline variables

    local diagnosis_result="MANUAL"
    local status="수동진단"
    local dbms_name=""

    case "$dbms_type" in
        postgresql|postgres) dbms_name="PostgreSQL" ;;
        mysql|mariadb) dbms_name="MySQL" ;;
        oracle) dbms_name="Oracle" ;;
        mssql) dbms_name="MSSQL" ;;
    esac

    local inspection_summary="${dbms_name} 연결에 실패했습니다. 3회 재시도 후 실패. 수동으로 확인이 필요합니다."
    local command_result="Connection failed after 3 retries"
    local command_executed=$(get_dbms_connection_info "$dbms_type")

    # Pass through guideline variables
    save_dual_result "${item_id}" "${item_name}" "${status}" "${diagnosis_result}" \
        "${inspection_summary}" "${command_result}" "${command_executed}" "$@"
    verify_result_saved "${item_id}"
    return 0
}
