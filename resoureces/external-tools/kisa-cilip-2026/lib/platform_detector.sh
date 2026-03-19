#!/bin/bash
# KISA 취약점 진단 시스템 - 플랫폼 감지기
# Encoding: UTF-8 (BOM 없음), LF
# Purpose: Unix/Linux/Windows 플랫폼 자동 감지

set -euo pipefail

# 감지된 플랫폼 정보
DETECTED_PLATFORM=""
DETECTED_OS=""
DETECTED_VERSION=""

# Unix/Linux 플랫폼 감지
detect_unix_platform() {
    # /etc/os-release가 있으면 사용 (Debian, RedHat 계열)
    if [ -f /etc/os-release ]; then
        source /etc/os-release

        case "$ID" in
            debian|ubuntu)
                DETECTED_PLATFORM="Debian"
                DETECTED_OS="Linux"
                DETECTED_VERSION="${VERSION_ID}"
                ;;
            rhel|centos|almalinux|rocky)
                DETECTED_PLATFORM="RedHat"
                DETECTED_OS="Linux"
                DETECTED_VERSION="${VERSION_ID}"
                ;;
            *)
                DETECTED_PLATFORM="Unknown"
                DETECTED_OS="Linux"
                ;;
        esac
    else
        # 구버 시스템 대체 감지 방법
        if [ -f /etc/debian_version ]; then
            DETECTED_PLATFORM="Debian"
            DETECTED_OS="Linux"
        elif [ -f /etc/redhat-release ]; then
            DETECTED_PLATFORM="RedHat"
            DETECTED_OS="Linux"
        else
            DETECTED_PLATFORM="Unknown"
            DETECTED_OS="Linux"
        fi
    fi

    echo "✅ Unix/Linux 플랫폼 감지: ${DETECTED_PLATFORM} (${DETECTED_OS} ${DETECTED_VERSION})"
}

# Windows 플랫폼 감지
detect_windows_platform() {
    # Windows 환경 변수 확인
    if [ -n "${OS:-}" ] && [[ "$OS" =~ Windows ]]; then
        DETECTED_PLATFORM="Windows"
        DETECTED_OS="Windows"

        # Windows 버전 감지
        if command -v ver &>/dev/null; then
            DETECTED_VERSION=$(ver | head -1)
        elif command -v systeminfo &>/dev/null; then
            DETECTED_VERSION=$(systeminfo | grep "OS Name" | head -1)
        fi

        echo "✅ Windows 플랫폼 감지: ${DETECTED_PLATFORM} (${DETECTED_VERSION})"
    fi
}

# 자동 플랫폼 감지
detect_platform() {
    echo "🔍 플랫폼 자동 감지 시작..."

    # OS 유형 확인
    case "$(uname -s)" in
        Linux*)
            detect_unix_platform
            ;;
        MINGW*|MSYS*|CYGWIN*)
            detect_windows_platform
            ;;
        Darwin*)
            DETECTED_PLATFORM="macOS"
            DETECTED_OS="Darwin"
            echo "⚠️  macOS는 지원하지 않음 (Unix/Linux 대상)"
            ;;
        *)
            echo "❌ 미지원 OS: $(uname -s)" >&2
            return 1
            ;;
    esac

    # 감지 실패 시 사용자 입력 요청 (T023)
    if [ "$DETECTED_PLATFORM" = "Unknown" ]; then
        prompt_manual_platform_detection
    fi
}

# 수동 플랫폼 입력 (감지 실패 시)
prompt_manual_platform_detection() {
    echo "⚠️  플랫폼 자동 감지 실패"
    echo ""
    echo "플랫폼을 수동으로 입력해주세요:"
    echo "  1) Debian"
    echo "  2) RedHat"
    echo "  3) Windows"
    echo ""
    read -p "선택 (1-3): " choice

    case "$choice" in
        1)
            DETECTED_PLATFORM="Debian"
            DETECTED_OS="Linux"
            ;;
        2)
            DETECTED_PLATFORM="RedHat"
            DETECTED_OS="Linux"
            ;;
        3)
            DETECTED_PLATFORM="Windows"
            DETECTED_OS="Windows"
            ;;
        *)
            echo "❌ 잘못된 선택" >&2
            return 1
            ;;
    esac

    read -p "버전 (예: 9, 2019, 10): " DETECTED_VERSION

    echo "✅ 수동 입력: ${DETECTED_PLATFORM} ${DETECTED_VERSION}"
}

# 플랫폼 정보 반환
get_platform() {
    echo "${DETECTED_PLATFORM}"
}

# OS 정보 반환
get_os() {
    echo "${DETECTED_OS}"
}

# 버전 정보 반환
get_version() {
    echo "${DETECTED_VERSION}"
}

# Debian 계열 확인
is_debian() {
    [ "$DETECTED_PLATFORM" = "Debian" ]
}

# RedHat 계열 확인
is_redhat() {
    [ "$DETECTED_PLATFORM" = "RedHat" ]
}

# Windows 확인
is_windows() {
    [ "$DETECTED_PLATFORM" = "Windows" ]
}

# 플랫폼 특화 명령어 가져오기
get_platform_package_manager() {
    if is_debian; then
        echo "apt"
    elif is_redhat; then
        if command -v dnf &>/dev/null; then
            echo "dnf"
        elif command -v yum &>/dev/null; then
            echo "yum"
        else
            echo "rpm"
        fi
    elif is_windows; then
        echo "powershell"
    else
        echo "unknown"
    fi
}

# ============================================================================
# T164-T165: 패키지 관리자 상세 확인 함수
# ============================================================================

# Debian 패키지 관리자 (apt) 확인 (T164)
verify_apt_package_manager() {
    local item_id="${1:-UNKNOWN}"

    echo "[점검] Debian apt 패키지 관리자 확인..."

    # 1) dpkg.lock 파일 존재 확인
    local dpkg_lock="/var/lib/dpkg/lock"
    if [ -f "$dpkg_lock" ]; then
        echo "  [OK] dpkg.lock 파일 존재: $dpkg_lock"
    else
        echo "  [WARN] dpkg.lock 파일 없음: $dpkg_lock"
    fi

    # 2) apt --version 실행으로 apt 설치 검증
    if command -v apt &>/dev/null; then
        local apt_version=$(apt --version 2>/dev/null | head -1)
        echo "  [OK] apt 설치됨: $apt_version"
    else
        echo "  [FAIL] apt 명령어를 찾을 수 없음"
        return 1
    fi

    # 3) apt-get help 명령어로 유효성 확인
    if apt-get help &>/dev/null; then
        echo "  [OK] apt-get 유효함"
    else
        echo "  [FAIL] apt-get 유효하지 않음"
        return 1
    fi

    # 4) apt-cache 사용 가능 확인
    if command -v apt-cache &>/dev/null; then
        echo "  [OK] apt-cache 사용 가능"
    else
        echo "  [WARN] apt-cache를 찾을 수 없음"
    fi

    return 0
}

# RedHat 패키지 관리자 (rpm/yum/dnf) 확인 (T165)
verify_rpm_package_manager() {
    local item_id="${1:-UNKNOWN}"

    echo "[점검] RedHat rpm/yum/dnf 패키지 관리자 확인..."

    # 1) rpm --version 실행으로 rpm 설치 검증
    if command -v rpm &>/dev/null; then
        local rpm_version=$(rpm --version 2>/dev/null)
        echo "  [OK] rpm 설치됨: $rpm_version"
    else
        echo "  [FAIL] rpm 명령어를 찾을 수 없음"
        return 1
    fi

    # 2) yum 또는 dnf 확인
    local pkg_manager=""
    if command -v dnf &>/dev/null; then
        pkg_manager="dnf"
        local dnf_version=$(dnf --version 2>/dev/null | head -1)
        echo "  [OK] dnf 설치됨: $dnf_version"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum"
        local yum_version=$(yum --version 2>/dev/null | head -1)
        echo "  [OK] yum 설치됨: $yum_version"
    else
        echo "  [WARN] yum/dnf를 찾을 수 없음 (rpm만 사용 가능)"
    fi

    # 3) /etc/yum.conf 또는 /etc/dnf/dnf.conf 파일 존재 확인
    if [ -f /etc/dnf/dnf.conf ]; then
        echo "  [OK] /etc/dnf/dnf.conf 존재"
    elif [ -f /etc/yum.conf ]; then
        echo "  [OK] /etc/yum.conf 존재"
    else
        echo "  [WARN] yum/dnf 설정 파일을 찾을 수 없음"
    fi

    # 4) rpm 데이터베이스 확인
    if [ -d /var/lib/rpm ]; then
        echo "  [OK] rpm 데이터베이스 존재: /var/lib/rpm"
    else
        echo "  [WARN] rpm 데이터베이스 없음"
    fi

    return 0
}
