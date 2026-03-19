# KISA 취약점 진단 시스템 - 공통 라이브러리

## Overview

이 폴더는 KISA 2026 취약점 진단 시스템의 공통 라이브러리 스크립트들을 포함합니다.

> **최종 업데이트**: 2026-01-15
> **표준화 상태**: ✅ Unix/PowerShell 라이브러리 표준화 완료

## Library Files Status

### ✅ Unix/Linux 라이브러리 (표준화 완료)

| 라이브러리 | 라인 수 | 참조 횟수 | 설명 |
|-----------|---------|----------|------|
| **common.sh** | 74 | 354 | 진단 결과 생성, 파일 저장 공통 함수 |
| **result_manager.sh** | 357 | 354 | 결과 파일 저장, Run-all 모드 지원 |
| **output_mode.sh** | 111 | 353 | JSON/TXT 이중 출력 모드 관리 |
| **command_validator.sh** | 329 | 321 | 화이트리스트 기반 명령어 검증 |
| **timeout_handler.sh** | 208 | 320 | 30초 타임아웃, 사용자 프롬프트 |
| **metadata_parser.sh** | 90 | 134 | 스크립트 메타데이터 파서 (@guideline, @item_id) |
| **dbms_connector.sh** | 468 | 6 | DBMS 연결 (MySQL/PostgreSQL/Oracle/MSSQL) |
| **platform_detector.sh** | 275 | 1 (내부) | 플랫폼 자동 감지 (common.sh 내부 의존) |
| **json_formatter.sh** | 197 | 1 (내부) | JSON 생성 헬퍼 (metadata_parser.sh 내부 의존) |

### ✅ PowerShell 라이브러리 (표준화 완료)

| 라이브러리 | 라인 수 | 설명 |
|-----------|---------|------|
| **result_manager.ps1** | 638 | 결과 파일 생성, Run-all 모드, Unix 대응 함수 포함 |
| **output_format.ps1** | 184 | TXT 결과 파일 형식 중앙 관리 |

### 🔧 유틸리티 스크립트

| 스크립트 | 설명 |
|---------|------|
| **fix_unix_runall.py** | Unix run-all 스크립트 자동 수정 도구 |
| **standardize_unix_pattern.sed** | Unix 스크립트 표준화 패턴 파일 |

## Standardization Summary

### ✅ 표준화 완료 항목

1. **헤더 주석 표준화**: 모든 라이브러리에 인코딩, 목적, 플랫폼 정보 명시
2. **함수 네이밍 컨벤션**:
   - Unix: `snake_case` (예: `save_json_result`, `is_runall_mode`)
   - PowerShell: `PascalCase` Verb-Noun (예: `Save-JsonResult`, `Test-RunallMode`)
3. **Run-all 모드 환경 변수 표준화** (2026-01-15):
   - Unix/Linux: `UNIX_RUNALL_MODE`, `WS_RUNALL_MODE`, `PC_RUNALL_MODE`, `DBMS_RUNALL_MODE`
   - PowerShell: `POWERSHELL_RUNALL_MODE`, `WS_RUNALL_MODE`, `PC_RUNALL_MODE`, `WINDOWS_RUNALL_MODE`, `DBMS_RUNALL_MODE`
4. **결과 파일 경로 표준화**: `results/YYYYMMDD/{HOSTNAME}_{ITEM_ID}_result_{TIMESTAMP}.{json,txt}`
5. **JSON 이스케이프 처리**: 모든 라이브러리에서 백슬래시, 쿼트, 줄바꿈 처리

### 📊 라이브러리 사용 현황 (2026-01-15 기준)

| 카테고리 | 총 파일 | 라이브러리 | 유틸리티 | 표준화 완료 |
|---------|--------|---------|---------|----------|
| Unix/Linux | 10개 | 9개 | 1개 | 9개 (100%) |
| PowerShell | 2개 | 2개 | 0개 | 2개 (100%) |
| **합계** | **12개** | **11개** | **1개** | **11개 (100%)** |

## Usage

### Unix/Linux 스크립트

모든 진단 스크립트는 필요한 라이브러리를 source로 불러옵니다:

```bash
#!/bin/bash
# scripts/01.Unix서버/Debian/U01_check.sh

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "${SCRIPT_DIR}/../../lib/common.sh"
source "${SCRIPT_DIR}/../../lib/metadata_parser.sh"
source "${SCRIPT_DIR}/../../lib/command_validator.sh"
source "${SCRIPT_DIR}/../../lib/timeout_handler.sh"
source "${SCRIPT_DIR}/../../lib/result_manager.sh"
source "${SCRIPT_DIR}/../../lib/output_mode.sh"
```

### PowerShell 스크립트

```powershell
#Requires -Version 5.1

# 라이브러리 경로 설정
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LibDir = Join-Path $ScriptDir "lib"

# 라이브러리 로드 (Dot-sourcing)
. (Join-Path $LibDir "result_manager.ps1")
. (Join-Path $LibDir "output_format.ps1")
```

## Library Dependencies

### Unix/Linux 의존성 구조

```
진단 스크립트
├── common.sh
│   └── platform_detector.sh (내부 의존)
├── metadata_parser.sh
│   └── json_formatter.sh (내부 의존)
├── command_validator.sh
├── timeout_handler.sh
├── result_manager.sh
└── output_mode.sh
```

### PowerShell 의존성 구조

```
진단 스크립트 (PowerShell)
├── result_manager.ps1
└── output_format.ps1
```

**참고**:
- `json_formatter.sh`와 `platform_detector.sh`는 **내부 헬퍼**로, 직접 import할 필요 없습니다
- `common.sh`를 import하면 자동으로 `platform_detector.sh`가 포함됩니다
- `metadata_parser.sh`를 import하면 자동으로 `json_formatter.sh`가 포함됩니다

## Encoding

- **Unix/Linux scripts**: UTF-8 (BOM 없음), LF 줄바꿈
- **PowerShell scripts**: UTF-8 (BOM 없음), CRLF 줄바꿈

## Run-all Mode Environment Variables

### Unix/Linux (result_manager.sh)

Run-all 모드에서는 다음 환경 변수 **중 하나**를 `1`로 설정하면 됩니다 (모두 선택 사항):

| 환경 변수 | 대상 카테고리 | 설명 |
|-----------|-------------|------|
| `UNIX_RUNALL_MODE` | Unix/Linux 서버 | Unix 카테고리 전용 (권장) |
| `WS_RUNALL_MODE` | 웹서버 (Unix) | Unix 기반 웹서버 진단용 |
| `PC_RUNALL_MODE` | PC (Unix) | Unix 기반 PC 진단용 |
| `DBMS_RUNALL_MODE` | DBMS (Unix) | Unix 기반 DBMS 진단용 |

**사용 예시**:
```bash
# Unix 서버 전체 진단
export UNIX_RUNALL_MODE=1
./run_all.sh

# 웹서버 진단
export WS_RUNALL_MODE=1
./run_all.sh

# DBMS 진단
export DBMS_RUNALL_MODE=1
./run_all.sh
```

### PowerShell (result_manager.ps1)

Run-all 모드에서는 다음 환경 변수 **중 하나**를 `1`로 설정하면 됩니다 (모두 선택 사항):

| 환경 변수 | 대상 카테고리 | 설명 |
|-----------|-------------|------|
| `POWERSHELL_RUNALL_MODE` | 모든 PowerShell | PowerShell 카테고리 전용 (권장) |
| `WS_RUNALL_MODE` | 웹서버 (IIS) | IIS 웹서버 진단용 |
| `PC_RUNALL_MODE` | PC (Windows) | Windows PC 진단용 |
| `WINDOWS_RUNALL_MODE` | Windows Server | Windows Server 진단용 |
| `DBMS_RUNALL_MODE` | DBMS (Windows) | Windows 기반 DBMS 진단용 |

**사용 예시**:
```powershell
# PowerShell 스크립트 전체 진단
$env:POWERSHELL_RUNALL_MODE = "1"
.\run_all.ps1

# IIS 웹서버 진단
$env:WS_RUNALL_MODE = "1"
.\run_all.ps1

# Windows PC 진단
$env:PC_RUNALL_MODE = "1"
.\run_all.ps1
```

### Run-all Mode 동작 방식

Run-all 모드가 활성화되면:
- 결과 파일이 생성되지 않고 JSON만 stdout로 출력
- 통합 결과 파일 (`all_results.json`, `all_results.txt`)로 저장 가능
- 개별 진단 스크립트는 JSON을 출력하고 상위 스크립트가 수집

## Result File Structure

### 개별 실행 모드

```
results/
└── 20260115/
    ├── hostname_U01_result_20260115_143020.json
    ├── hostname_U01_result_20260115_143020.txt
    ├── hostname_U02_result_20260115_143025.json
    └── hostname_U02_result_20260115_143025.txt
```

### Run-all 모드

```
results/
└── 20260115/
    ├── all_results.json      # 모든 진단 결과 JSON 통합
    └── all_results.txt       # 모든 진단 결과 텍스트 통합
```

## Security

- 모든 라이브러리는 읽기 전용으로 설계되었습니다
- `command_validator.sh`가 시스템 수정 명령어 차단
- 비밀번호는 stdin으로 입력받으며 메모리에만 보관됩니다

## Update History

| 날짜 | 변경 사항 |
|------|---------|
| 2026-01-15 | Unix/PowerShell Run-all 모드 환경 변수 표준화 완료 |
| 2026-01-14 | PowerShell 라이브러리 표준화 (108개 스크립트 마이그레이션) |
| 2026-01-12 | 라이브러리 사용 현황 분석 완료 |
