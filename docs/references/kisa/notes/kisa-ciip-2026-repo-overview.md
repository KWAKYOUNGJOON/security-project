# KISA-CIIP-2026 저장소 구조 개요

## 문서 목적

이 문서는 `KISA-CIIP-2026` 계열 외부 저장소를 우리 프로젝트의 웹/API/서버 취약점 진단 자동화 로드맵 관점에서 정적 분석한 결과를 정리한다. 이번 1차 분석의 초점은 `03.웹서버`이며, `01.Unix서버`와 `02.Windows서버`는 개요 중심, `08.DBMS`와 `07.PC`는 후순위 메모 수준으로만 정리한다.

## 분석 범위와 전제

- 확인된 로컬 분석 경로: `D:\security-project\resoureces\external-tools\kisa-cilip-2026`
- 사용자 제공 경로 표기: `D:\security-project\resources\external-tools\kisa-ciip-2026`
- 확인된 사실: 로컬 작업본 경로에는 `resoureces`, `kisa-cilip-2026` 오탈자가 존재한다.
- 확인된 사실: 저장소 루트 `README.md`에는 공식 명칭이 `KISA-CIIP-2026`으로 표기되어 있다.
- 확인된 사실: 이번 분석은 스크립트 실행 없이 `README.md`, 공통 라이브러리, 카테고리별 핵심 스크립트, 결과 저장 구조를 읽는 정적 분석으로 수행했다.
- 미확인: 실제 운영 환경에서 각 스크립트가 100% 정상 실행되는지 여부
- 미확인: KISA 상세가이드의 정확한 장/절 번호와 각 스크립트 ID의 1:1 대응표

## 저장소 개요

확인된 사실 기준으로 이 저장소는 운영체제/미들웨어/DBMS/PC 보안 점검을 카테고리별 스크립트로 분리한 구조다. 공통 라이브러리(`lib`)가 결과 저장, 메타데이터 처리, 플랫폼 판별, DB 연결 보조 기능을 제공하고, 각 카테고리는 `run_all` 스크립트와 개별 점검 스크립트(`Uxx`, `Wxx`, `WEBxx`, `Dxx`, `Pxx`)로 구성된다.

가장 중요한 구조적 특징은 다음과 같다.

- 모든 카테고리가 개별 점검 결과를 `JSON + TXT`로 이중 저장하는 방향으로 설계되어 있다.
- `run_all` 스크립트는 개별 결과를 다시 취합해 카테고리 단위의 집계 `JSON/TXT`를 만든다.
- 개별 점검 스크립트 헤더에는 `@ID`, `@Title`, `@Reference`, `@Severity` 같은 메타데이터가 포함되어 있어 KISA 가이드 매핑의 기반으로 활용할 수 있다.
- 실제 저장소에는 샘플 결과 파일이 없고 `results/.gitkeep`만 존재하므로, 파서 설계는 현재 시점에서는 구조 기반 추정이 일부 포함된다.

## 폴더 구조 요약

| 경로 | 역할 | 이번 분석 깊이 | 비고 |
| --- | --- | --- | --- |
| `01.Unix서버` | Debian/RedHat/AIX/HP-UX/Solaris 점검 | 개요 | 플랫폼별 `U01~U67` 계열 |
| `02.Windows서버` | Windows Server 점검 | 개요 | `W01~W64` 계열 PowerShell |
| `03.웹서버` | Apache/Nginx/Tomcat/IIS 점검 | 상세 | 이번 1차 우선 분석 대상 |
| `07.PC` | Windows PC 보안 점검 | 메모 | `P01~P18` 계열 |
| `08.DBMS` | MySQL/PostgreSQL/Oracle/MSSQL 점검 | 메모 | `D01~D26` 계열 |
| `lib` | 공통 함수, 결과 저장, 메타데이터, DB 연결 보조 | 상세 | 전체 저장소의 핵심 기반 |

## 카테고리별 역할

### 1. `03.웹서버` 상세 분석

확인된 사실: `03.웹서버`는 `Apache`, `Nginx`, `Tomcat`, `IIS` 하위 디렉터리로 구성되며, 각 제품군별로 `WEB01~WEB26` 범위의 점검 스크립트와 `run_all` 스크립트를 가진다. Apache/Nginx/Tomcat은 셸 스크립트, IIS는 PowerShell 기반이다.

| 하위 카테고리 | 주요 스크립트 예시 | 사용 언어 | 외부 의존성/실행 조건 | 예상 실행 환경 | 출력 형태 | KISA 가이드 연결 가능성 |
| --- | --- | --- | --- | --- | --- | --- |
| Apache | `03.웹서버_Apache_run_all.sh`, `run_minimal.sh`, `WEB01_check.sh`, `WEB02_check.sh`, `WEB04_check.sh`, `WEB23_check.sh` | `sh` | `bash/sh`, `grep`, `sed`, `find`, Apache 설정 파일 접근 권한 | Linux/Unix, 관리자 권한 권장 | 개별 `JSON/TXT`, 집계 `JSON/TXT`, 콘솔 출력 | 높음. 헤더 `@ID`, `@Title`, `@Reference` 확인. 정확한 장/절은 미확인 |
| Nginx | `03.웹서버_Nginx_run_all.sh`, `WEB01_check.sh`, `WEB16_check.sh`, `WEB23_check.sh` | `sh` | `bash/sh`, `grep`, Nginx 설정 파일 접근 권한 | Linux/Unix, 관리자 권한 권장 | 개별 `JSON/TXT`, 집계 `JSON/TXT`, 콘솔 출력 | 높음. 동일 방식 |
| Tomcat | `03.웹서버_Tomcat_run_all.sh`, `run_minimal.sh`, `WEB01_check.sh`, `WEB02_check.sh`, `WEB04_check.sh`, `WEB25_check.sh` | `sh` | `bash/sh`, `ps`, `grep`, `find`, `tomcat-users.xml`/`web.xml` 접근 권한 | Linux/Unix, 관리자 권한 권장 | 개별 `JSON/TXT`, 집계 `JSON/TXT`, 콘솔 출력 | 높음. 동일 방식 |
| IIS | `03.웹서버_IIS_run_all.ps1`, `WEB01_check.ps1`, `WEB02_check.ps1`, `WEB04_check.ps1`, `WEB23_check.ps1` | `ps1` | PowerShell, `WebAdministration` 모듈, IIS 설정 조회 권한 | Windows Server, 관리자 권한 권장 | 개별 `JSON/TXT`, 집계 `JSON/TXT`, 콘솔 출력 | 높음. 동일 방식 |

#### `03.웹서버`에서 확인된 점검 패턴

확인된 사실:

- Apache `WEB04_check.sh`는 `Options Indexes` 설정을 grep 기반으로 확인한다.
- Nginx `WEB16_check.sh`는 `server_tokens off` 여부를 설정 파일에서 찾는다.
- Tomcat `WEB01_check.sh`는 `tomcat-users.xml`의 기본 계정 패턴을 찾는다.
- Tomcat `WEB04_check.sh`는 `web.xml`의 directory listing 관련 설정을 확인한다.
- IIS `WEB04_check.ps1`는 디렉터리 브라우징 설정을 `Get-Website`, `Get-WebConfiguration`, `web.config` 등으로 확인한다.
- IIS `WEB23_check.ps1`는 Request Filtering의 허용/차단 메서드 설정을 확인한다.

우리 프로젝트 관점에서 중요한 의미는 다음과 같다.

- 웹 취약점 자동화가 현재 HTTP 요청/응답 중심이라면, 이 저장소의 `03.웹서버`는 서버 설정 계층의 증적을 보완하는 역할을 한다.
- 특히 Apache/Nginx/IIS의 설정형 항목은 `finding` 단위 정규화가 비교적 쉽다.
- 반면 Tomcat `WEB02`, `WEB25`, Apache `WEB23`처럼 스크립트가 명시적으로 `MANUAL` 또는 수동 확인을 요구하는 항목은 자동화보다 검토 워크플로로 보내는 설계가 적합하다.

#### `03.웹서버` 증적 형태

확인된 사실 기준으로 웹서버 카테고리의 증적은 대체로 다음 유형으로 나뉜다.

- 설정 파일 경로와 매칭 라인
- PowerShell/IIS 조회 결과
- 프로세스/서비스 존재 여부
- 버전 문자열
- 파일 탐색 결과
- 수동 검토 안내 문구

미확인:

- HTML, CSV, 이미지 캡처 같은 리치 리포트 출력
- HTTP 요청/응답 원문 저장 기능

즉, 이 카테고리는 현재 웹 모의점검형 증적보다 서버 설정 점검형 증적에 가깝다.

### 2. `01.Unix서버` 개요 중심 분석

확인된 사실: `Debian`, `RedHat`, `AIX`, `HP-UX`, `Solaris` 하위 폴더가 존재하며, 각 플랫폼이 동일한 `U01~U67` 체계를 플랫폼별 명령 차이만 반영해 구현하는 구조다.

| 하위 카테고리 | 주요 스크립트 예시 | 사용 언어 | 외부 의존성/실행 조건 | 예상 실행 환경 | 출력 형태 | 비고 |
| --- | --- | --- | --- | --- | --- | --- |
| Debian | `01.Unix서버_Debian_run_all.sh`, `U01_check.sh` | `sh` | `systemctl`, `service`, `ps`, `netstat`, `ss`, 파일 시스템 접근 | Linux, 관리자 권한 권장 | 개별 `JSON/TXT`, 집계 `JSON/TXT` | 서비스/계정/권한 점검 중심 |
| RedHat | `01.Unix서버_RedHat_run_all.sh`, `U01_check.sh` | `sh` | 위와 유사 | Linux, 관리자 권한 권장 | 개별 `JSON/TXT`, 집계 `JSON/TXT` | 정적 분석상 라이브러리 경로 결함 존재 |
| AIX | `U01_check.sh` | `sh` | `lssrc` 등 AIX 명령 | AIX, 관리자 권한 권장 | 개별 `JSON/TXT` | 개요만 확인 |
| HP-UX | `U01_check.sh` | `sh` | `ps`, `netstat`, `inetd` 확인 | HP-UX, 관리자 권한 권장 | 개별 `JSON/TXT` | 개요만 확인 |
| Solaris | `U01_check.sh` | `sh` | `svcs` 등 Solaris 명령 | Solaris, 관리자 권한 권장 | 개별 `JSON/TXT` | 개요만 확인 |

우리 프로젝트 연결성은 웹서버보다 한 단계 뒤다. 이유는 다음과 같다.

- 현재 우선순위는 웹 취약점 진단 자동화이며, Unix 서버 점검은 웹서버가 실제로 배치되는 기반 OS 하드닝 영역에 가깝다.
- 따라서 `03.웹서버` 결과를 흡수한 뒤, 웹서버와 직접 연결되는 Unix 항목부터 점진적으로 확장하는 순서가 현실적이다.

### 3. `02.Windows서버` 개요 중심 분석

확인된 사실: `02.Windows서버`는 `W01~W64` 계열의 PowerShell 스크립트와 `02.Windows서버_run_all.ps1`로 구성된다.

| 항목 | 내용 |
| --- | --- |
| 주요 스크립트 | `02.Windows서버_run_all.ps1`, `W01_check.ps1`, `W31_check.ps1`, `fix_encoding.ps1` |
| 사용 언어 | `ps1` |
| 외부 의존성/실행 조건 | PowerShell, 로컬 사용자/서비스/레지스트리 접근 권한 |
| 예상 실행 환경 | Windows Server, 관리자 권한 권장 |
| 출력 형태 | 개별 `JSON/TXT`, 집계 `JSON/TXT`, 콘솔 출력 |
| KISA 연결 가능성 | 높음. 스크립트 헤더 메타데이터 존재 |

확인된 사실:

- `W01_check.ps1`는 기본 Administrator 계정(SID `-500`) 점검 패턴을 사용한다.
- `W31_check.ps1`는 SNMP 서비스와 관련 레지스트리 경로를 조회한다.

우리 프로젝트 관점 해석:

- Windows 웹서버(IIS) 확장 시점에는 `03.웹서버\IIS`가 1차 대상이고, 그 다음에 Windows Server 공통 보안 설정을 붙이는 것이 자연스럽다.
- 따라서 이번 단계에서는 상세 파서 설계 대상이 아니라, 향후 IIS 결과에 호스트 수준 보강 증적을 추가하는 후보군으로 보는 편이 적절하다.

### 4. `08.DBMS` 후순위 메모

확인된 사실: `mysql`, `postgresql`, `Oracle`, `MSSQL` 하위 디렉터리와 `D01~D26` 계열 스크립트가 존재한다.

메모 수준 판단:

- MySQL은 `mysql`, `mysqladmin`
- PostgreSQL은 `psql`
- Oracle은 `sqlplus`
- MSSQL은 `sqlcmd`

같은 DB 클라이언트 의존성이 필요하다. 일부 스크립트는 접속 정보 입력이나 자격증명, 환경 변수에 의존한다. 따라서 현재 단계에서 자동 흡수 대상이라기보다, 별도 실행 래퍼와 비밀정보 처리 전략이 마련된 뒤 검토할 영역이다.

미확인:

- 비대화형 실행만으로 모든 항목 수집이 가능한지 여부

### 5. `07.PC` 후순위 메모

확인된 사실: `07.PC`는 `P01~P18` PowerShell 스크립트와 `07.PC_run_all.ps1`로 구성된다.

메모 수준 판단:

- Windows PC 로컬 정책/계정/보안 설정 점검 성격이 강하다.
- 웹 취약점 진단 자동화 로드맵과 직접 연결성은 가장 낮다.
- 서버/웹서버/DBMS 흡수 이후 별도 트랙으로 보는 것이 적절하다.

## `lib` 역할 요약

확인된 사실: `lib` 디렉터리는 실행 공통 기반이다.

| 파일 | 역할 |
| --- | --- |
| `common.sh` | 공통 로그/메시지/환경 초기화 보조 |
| `command_validator.sh` | 명령 존재 여부 점검 보조 |
| `timeout_handler.sh` | 타임아웃 실행 보조 |
| `output_mode.sh` | 출력 모드 보조 |
| `platform_detector.sh` | 플랫폼 식별 |
| `metadata_parser.sh` | 스크립트 헤더 메타데이터 파싱 시도 |
| `result_manager.sh` | 셸 계열 `JSON/TXT` 결과 저장 |
| `result_manager.ps1` | PowerShell 계열 `JSON/TXT` 결과 저장 |
| `dbms_connector.sh`, `db_connection_helpers.sh` | DB 접속 보조 |

특히 `result_manager.sh`와 `result_manager.ps1`는 우리 프로젝트 연계 측면에서 가장 중요하다. 이 파일들이 사실상 외부 저장소의 결과 스키마를 정의한다.

## 사용 언어 및 실행 환경 요약

| 카테고리 | 주 언어 | 주 실행 환경 | 관리자 권한 필요성 | 비고 |
| --- | --- | --- | --- | --- |
| `01.Unix서버` | `sh` | Linux/Unix/AIX/HP-UX/Solaris | 높음 | 시스템 설정/서비스/권한 조회 |
| `02.Windows서버` | `ps1` | Windows Server | 높음 | 사용자/서비스/레지스트리 조회 |
| `03.웹서버` | `sh`, `ps1` | Linux/Unix, Windows Server(IIS) | 높음 | 웹서버 설정 파일/IIS 메타데이터 조회 |
| `08.DBMS` | `sh` | DB 클라이언트가 설치된 Linux/Unix 또는 MSSQL 환경 | 높음 | 자격증명/접속 정보 필요 |
| `07.PC` | `ps1` | Windows 10/11 | 중간 이상 | 로컬 보안 정책 점검 |

## 출력물 및 증적 형태 요약

### 확인된 사실

- 개별 점검 결과: `results/YYYYMMDD/{HOSTNAME}_{ITEM_ID}_result_{TIMESTAMP}.json`
- 개별 점검 결과: 동일 이름의 `.txt`
- 집계 결과: `{hostname}_{category}_{platform}_all_results_{timestamp}.json`
- 집계 결과: 동일한 요약 `.txt`
- `result_manager` 기반 JSON에는 다음 필드가 포함된다.
  - `item_id`
  - `item_name`
  - `inspection.summary`
  - `inspection.status`
  - `final_result`
  - `command`
  - `command_result`
  - `guideline.purpose`
  - `guideline.security_threat`
  - `guideline.judgment_criteria_good`
  - `guideline.judgment_criteria_bad`
  - `guideline.remediation`
  - `timestamp`
  - `hostname`

### 미확인 또는 제한사항

- 실제 결과 파일 샘플은 저장소에 포함되어 있지 않다.
- 런타임 JSON에 `severity`가 항상 포함되는지는 확인되지 않았다.
- 화면 출력이 파일 출력과 완전히 동일한 포맷인지는 미확인이다.
- HTML/CSV 리포트 출력은 확인하지 못했다.

## 리스크 및 주의사항

### 확인된 사실

1. PowerShell 계열 `run_all` 스크립트가 참조하는 `lib/common.ps1` 파일이 저장소에 존재하지 않는다.
2. `01.Unix서버\RedHat` 계열 스크립트 다수가 `../lib`를 참조하지만 실제 공통 라이브러리는 저장소 루트 `lib`에 있다.
3. `03.웹서버\IIS\WEB02_check.ps1`는 `Save-DualResult -Severity`를 호출하지만, `lib\result_manager.ps1`의 `Save-DualResult` 정의에는 해당 파라미터가 없다.
4. `lib\metadata_parser.sh`는 소문자 메타 태그(`@item_id`, `@item_name`)를 찾도록 구현되어 있으나, 실제 스크립트 헤더는 `@ID`, `@Title`, `@Severity` 형식을 사용한다.
5. `03.웹서버\Apache` 디렉터리에 의미가 불분명한 파일 `1`이 존재한다.
6. 결과 샘플이 없어 파서 설계는 현재 구조 기반으로만 가능하다.

### 해석상 주의점

- 위 결함들은 "즉시 실행 성공 여부"를 보장하지 않는다는 신호지만, 이번 과업은 실행이 아니라 정적 구조 분석이므로 문서화와 매핑 설계에는 여전히 활용 가능하다.
- 자동화 연계 시에는 "실행 래퍼"보다 먼저 "정적 카탈로그"와 "결과 파서" 설계를 우선하는 편이 안전하다.

## 우리 프로젝트에 주는 의미

이번 분석에서 가장 의미 있는 결론은 `03.웹서버`가 현재 우리 프로젝트의 웹 취약점 자동화 결과를 보완하는 가장 현실적인 다음 확장 지점이라는 점이다.

이유는 다음과 같다.

- 현재 `report-automation`은 웹 요청/응답 중심 구조다.
- `KISA-CIIP-2026`의 웹서버 스크립트는 설정 파일, 서비스 설정, 서버 옵션, 버전, 금지 메서드 등 "서버 측 보안 상태"를 구조화된 결과로 남긴다.
- 따라서 두 체계를 합치면 "애플리케이션 계층 취약점"과 "웹서버 하드닝 상태"를 한 보고서 안에서 다룰 수 있다.

우선순위 제안은 다음과 같다.

1. `03.웹서버`
2. `01.Unix서버`
3. `02.Windows서버`
4. `08.DBMS`
5. `07.PC`

이 순서는 사용자 요구사항과 현재 로드맵에 부합한다. 특히 1차 흡수 후보는 `03.웹서버` 내부에서도 Apache/Nginx/IIS의 설정형 항목이며, 수동 검토 항목과 버전 검토 항목은 별도 리뷰 큐로 보내는 구성이 적합하다.
