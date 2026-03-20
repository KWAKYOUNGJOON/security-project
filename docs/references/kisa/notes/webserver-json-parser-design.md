# 웹서버 JSON 우선 파서 설계 초안

## 문서 목적

이 문서는 표준 외부 경로 `D:\security-project\resources\external-tools\kisa-ciip-2026\03.웹서버`의 결과 모델을 기준으로, `report-automation`이 1차로 읽을 JSON 우선 파서의 입력/출력 구조와 매핑 규칙을 정의한다.

이번 설계는 정적 분석 기반 가정이며, 실제 런타임 샘플 없이 작성되었다.

## 전제

- 외부 스크립트는 수정하지 않는다.
- JSON이 있으면 JSON을 우선 사용한다.
- TXT는 JSON이 없거나 JSON 파싱이 실패할 때만 보조 입력으로 사용한다.
- `03.웹서버` 1차 범위의 우선 서비스는 Apache, Nginx, IIS다.
- Tomcat은 동일 파서 구조를 따르되, 규칙 기반 자동 finding 생성은 한 단계 뒤에서 적용한다.

## 외부 결과 JSON 구조 해석

## 1. 개별 스크립트 결과 JSON

확정:

`result_manager.sh`와 `result_manager.ps1` 기준으로 개별 결과 JSON은 아래 구조를 가진다.

```json
{
  "item_id": "WEB-04",
  "item_name": "웹서비스디렉터리리스팅방지설정",
  "inspection": {
    "summary": "모든 웹사이트에서 디렉터리 리스팅이 비활성화되어 있습니다.",
    "status": "양호"
  },
  "final_result": "GOOD",
  "command": "Get-Website; Get-WebConfiguration -Filter \"/system.webServer/directoryBrowse\"",
  "command_result": "DirectoryBrowse: Disabled on all sites",
  "guideline": {
    "purpose": "...",
    "security_threat": "...",
    "judgment_criteria_good": "...",
    "judgment_criteria_bad": "...",
    "remediation": "..."
  },
  "timestamp": "2026-03-20T09:00:00+09:00",
  "hostname": "web-01"
}
```

### 필드 해석

| 필드 | 의미 | 파서 정책 |
| --- | --- | --- |
| `item_id` | `WEB-04` 같은 점검 항목 식별자 | 필수 |
| `item_name` | 스크립트 내부 이름 | 필수 |
| `inspection.summary` | 사용자용 판정 요약 | 필수 |
| `inspection.status` | `양호/취약/수동진단/N/A` 같은 한글 상태 | `raw_status`로 보존 |
| `final_result` | `GOOD/VULNERABLE/MANUAL/N/A` | 정규화 기준 핵심 |
| `command` | 실행/조회한 명령 또는 조회 방식 | `executed_command`로 보존 |
| `command_result` | 원문 증적 텍스트 | `command_output`로 보존 |
| `guideline.*` | 설명/위협/기준/조치 | finding 설명 필드로 매핑 |
| `timestamp` | 결과 생성 시각 | 원문 보존, 파싱 가능하면 datetime으로도 보조 저장 |
| `hostname` | 대상 호스트명 | 서버 finding 기본 식별자 |

## 2. `run_all` 집계 JSON

확정:

집계 JSON은 아래 구조를 가진다.

```json
{
  "category": "웹서버",
  "platform": "Apache",
  "total_items": 26,
  "good_items": 10,
  "vulnerable_items": 4,
  "manual_items": 5,
  "error_items": 7,
  "timestamp": "2026-03-20T09:00:00+09:00",
  "hostname": "web-01",
  "items": [
    {
      "item_id": "WEB-04",
      "item_name": "웹서비스디렉터리리스팅방지설정",
      "inspection": {
        "summary": "...",
        "status": "양호"
      },
      "final_result": "GOOD",
      "command": "...",
      "command_result": "...",
      "guideline": {
        "purpose": "...",
        "security_threat": "...",
        "judgment_criteria_good": "...",
        "judgment_criteria_bad": "...",
        "remediation": "..."
      },
      "timestamp": "...",
      "hostname": "web-01"
    }
  ]
}
```

### 집계 JSON 처리 정책

1. envelope(`category`, `platform`, `hostname`, `timestamp`)를 먼저 읽는다.
2. `items[]`를 개별 레코드로 평탄화한다.
3. item 내부에 값이 없으면 envelope 값을 상속한다.
4. 집계 통계값(`good_items`, `manual_items` 등)은 finding 생성이 아니라 ingest 검증/로그 용도로만 사용한다.

## report-automation 입력 모델 초안

이 단계에서 바로 shared schema에 밀어 넣기보다, parser와 schema 사이의 중간 레코드를 먼저 두는 것이 안전하다.

권장 중간 모델 이름:

- `kisa_webserver_raw_record`

권장 shape:

```json
{
  "kind": "kisa_webserver_raw_record",
  "source_kind": "single_json",
  "source_path": "fixtures/kisa-webserver/single/apache/WEB-04_good.json",
  "hostname": "web-01",
  "platform": "apache",
  "service_name": "apache",
  "item_id": "WEB-04",
  "item_name": "웹서비스디렉터리리스팅방지설정",
  "raw_status": "양호",
  "raw_final_result": "GOOD",
  "normalized_result": "PASS",
  "summary": "디렉터리 리스팅이 비활성화되어 있습니다.",
  "check_type": "config",
  "applicability": "applicable",
  "executed_command": "grep -E '^\\s*Options' /etc/apache2/apache2.conf ...",
  "command_output": "/etc/apache2/apache2.conf: Options -Indexes",
  "guideline": {
    "purpose": "...",
    "security_threat": "...",
    "judgment_criteria_good": "...",
    "judgment_criteria_bad": "...",
    "remediation": "..."
  },
  "reference": "2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드",
  "severity_hint": "high",
  "timestamp": "2026-03-20T09:00:00+09:00",
  "parser_confidence": "high",
  "unmapped_fields": {}
}
```

### 최소 필수 필드

| 필드 | 이유 |
| --- | --- |
| `source_kind` | 개별 JSON과 집계 JSON 파이프라인 분기 |
| `source_path` | 추적성 확보 |
| `hostname` | 서버 finding 기본 식별 |
| `platform` | `apache/nginx/iis/tomcat` 구분 |
| `service_name` | 나중에 site/service 단위 확장 여지 |
| `item_id` | 카탈로그 조인 키 |
| `item_name` | 보고서 제목 fallback |
| `raw_status` | 원문 보존 |
| `raw_final_result` | 판정 기준 원문 |
| `normalized_result` | parser 내부 표준 판정 |
| `summary` | finding 요약 |
| `check_type` | parser rule과 review routing에 필요 |
| `applicability` | `N/A`와 실제 FAIL 분리 |
| `executed_command` | evidence 핵심 |
| `command_output` | evidence 핵심 |
| `guideline` | description/impact/remediation 매핑에 필요 |
| `reference` | KISA 가이드 연결 |
| `severity_hint` | 정적 카탈로그 조인 결과 |
| `timestamp` | 실행 시각 보존 |

## 필드 매핑 규칙

### 1. 기본 매핑

| 외부 JSON | parser 중간 모델 | 규칙 |
| --- | --- | --- |
| `item_id` | `item_id` | 그대로 사용 |
| `item_name` | `item_name` | 그대로 사용 |
| `inspection.summary` | `summary` | trim 후 사용 |
| `inspection.status` | `raw_status` | 원문 보존 |
| `final_result` | `raw_final_result` | 원문 보존 |
| `final_result` | `normalized_result` | 아래 표준화 규칙 적용 |
| `command` | `executed_command` | 그대로 보존 |
| `command_result` | `command_output` | 줄바꿈 정책 적용 |
| `guideline.*` | `guideline.*` | 그대로 보존 |
| `hostname` | `hostname` | 없으면 envelope, 그것도 없으면 `"unknown-host"` |
| `timestamp` | `timestamp` | 원문 보존 |

### 2. `final_result` 표준화

| raw | normalized_result | parser 해석 |
| --- | --- | --- |
| `GOOD` | `PASS` | 자동 finding 생성 안 함, checklist/통계용 |
| `VULNERABLE` | `FAIL` | 자동 finding 후보 |
| `MANUAL` | `MANUAL` | review queue 후보 |
| `N/A` | `NOT_APPLICABLE` | 적용 대상 아님 |
| 기타 | `ERROR` | 수집/파싱 오류 또는 미정의 값 |

### 3. `inspection.status` 보존 정책

- `inspection.status`는 `양호`, `취약`, `수동진단`, `N/A`, `미진단` 같은 한글 문자열이다.
- 이 값은 `raw_status`로 그대로 남긴다.
- 보고서용 상태 결정에는 `raw_final_result`를 우선 사용한다.

## `command_result` 멀티라인 처리 정책

정적 분석상 `command_result`는 서비스별로 다음 형태를 가진다.

- Apache/Nginx/Tomcat: grep/find 결과 다중 라인
- IIS: 사이트별 결과를 `\n`로 연결한 PowerShell 문자열
- manual 항목: 수동 점검 안내문 또는 version 정보

권장 정책:

1. JSON 파싱 직후 문자열 그대로 1차 보존
2. `\r\n`를 `\n`으로 정규화
3. 문자열 안에 literal `\\n`만 있고 실제 줄바꿈이 없다면 2차 디코딩 시도
4. 최종 저장 필드는 `command_output` 단일 문자열로 유지
5. line 기반 evidence 추출이 필요할 때만 `command_output_lines`를 파생 생성

추천 구현 규칙:

- `command_output`은 원문 보존이 우선이다.
- parser는 가독성을 위한 LF 정규화까지만 책임진다.
- 설정 파일 경로/라인/값 분리는 evidence extractor가 후처리한다.

## `guideline.*` 처리 정책

확정:

- 런타임 JSON에는 `purpose`, `security_threat`, `judgment_criteria_good`, `judgment_criteria_bad`, `remediation`가 포함되도록 설계되어 있다.

권장 정책:

- 모두 문자열로 그대로 보존
- finding 설명 매핑:
  - `purpose` -> `description`의 일부
  - `security_threat` -> `impact`
  - `judgment_criteria_bad` -> `cause` 또는 `judgment_basis`
  - `remediation` -> `remediation`
- 빈 문자열이어도 키는 유지

## `hostname`, `timestamp`, `platform` 처리 정책

### `hostname`

- item JSON에 있으면 item 값을 사용
- 없으면 run_all envelope 값을 사용
- 둘 다 없으면 `"unknown-host"`

### `timestamp`

- 원문 문자열을 그대로 저장
- 파싱 가능하면 보조 필드 `timestamp_parsed`를 생성할 수 있음
- 파싱 실패 시 원문 보존만 수행

### `platform`

- run_all envelope의 `platform` 또는 파일 경로를 기준으로 `apache`, `nginx`, `iis`, `tomcat` 중 하나로 정규화
- `service_name`은 1차에는 `platform`과 같은 값으로 시작해도 무방
- IIS는 이후 사이트 단위 세분화가 가능하므로 `service_name`을 나중에 site name으로 확장할 여지를 남긴다.

## 카탈로그 enrichment 규칙

런타임 JSON만으로는 부족하므로 parser 이후 static catalog를 조인해야 한다.

필수 enrichment 항목:

- `severity_hint`
- `reference`
- `check_type`
- `normalization_feasible`
- `service_specific_title`

조인 키:

- 기본: `item_id + platform`

이 조인이 필요한 이유:

- `WEB-23 ~ WEB-26`은 서비스별 의미가 다르다.
- severity는 헤더 기준 카탈로그가 더 신뢰할 수 있다.

## TXT fallback 전략

TXT는 1차 범위에서 보조 입력으로만 둔다.

### 사용 조건

1. 같은 basename의 JSON이 존재하지 않을 때
2. JSON이 손상되어 파싱에 실패했을 때
3. 운영상 텍스트 파일만 수집된 특수 상황일 때

### 우선순위

`JSON > TXT`

### TXT 파서 최소 규칙

확정:

- 텍스트 결과는 `[WEB-04-START]`, `[WEB-04]Result : GOOD` 같은 구조를 가진다.
- `command:`와 `command_result:` 블록이 존재한다.

fallback에서 최소 추출할 필드:

- `item_id`
- `item_name`
- `raw_final_result`
- `summary`
- `executed_command`
- `command_output`
- `guideline.*` 가능 범위

### TXT fallback 정책

- `parser_confidence = low`
- `source_kind = text_fallback`
- `severity_hint`는 반드시 static catalog에서 보강
- JSON과 TXT가 동시에 있으면 TXT는 무시

## 샘플 fixture 전략

실제 런타임 샘플이 없으므로, 정적 분석 기반의 가상 fixture를 먼저 설계한다.

### 목표

- Apache 2건
- Nginx 2건
- IIS 2건
- 전체 세트에서 `PASS`, `FAIL`, `MANUAL`을 모두 포함

### 권장 fixture 구조

```text
apps/report-automation/tests/fixtures/kisa-webserver/
  single/
    apache/
      WEB-04_good.json
      WEB-23_manual.json
    nginx/
      WEB-16_good.json
      WEB-23_vulnerable.json
    iis/
      WEB-04_good.json
      WEB-24_vulnerable.json
  aggregated/
    apache_runall_sample.json
    nginx_runall_sample.json
    iis_runall_sample.json
```

### 최소 fixture 세트 설명

| 파일 | 목적 |
| --- | --- |
| `apache/WEB-04_good.json` | 결정형 config PASS 케이스 |
| `apache/WEB-23_manual.json` | manual stub 케이스 |
| `nginx/WEB-16_good.json` | 헤더 노출 제한 PASS 케이스 |
| `nginx/WEB-23_vulnerable.json` | heuristic + FAIL 케이스 |
| `iis/WEB-04_good.json` | PowerShell config PASS 케이스 |
| `iis/WEB-24_vulnerable.json` | 헤더 미설정 FAIL 케이스 |

선택 추가 fixture:

- `iis/WEB-02_manual.json`
- `nginx/WEB-25_manual.json`
- `tomcat/WEB-01_vulnerable.json`

### 단일 fixture 예시 shape

```json
{
  "item_id": "WEB-23",
  "item_name": "웹서비스웹쉘(shell)삭제",
  "inspection": {
    "summary": "2개의 웹쉘 의심 파일이 발견되었습니다.",
    "status": "취약"
  },
  "final_result": "VULNERABLE",
  "command": "find /var/www/html -type f ...",
  "command_result": "/var/www/html/uploads/c99.php\n/var/www/html/tmp/shell.php",
  "guideline": {
    "purpose": "웹쉘 파일 삭제로 시스템 악의적 코드 실행 방지",
    "security_threat": "웹쉘 존재 시 원격 코드 실행 및 시스템 장악 위험",
    "judgment_criteria_good": "웹쉘 파일이 없음",
    "judgment_criteria_bad": "웹쉘 의심 파일 발견",
    "remediation": "발견된 웹쉘 파일 즉시 삭제 및 출처 추적"
  },
  "timestamp": "2026-03-20T09:00:00+09:00",
  "hostname": "web-02"
}
```

### 집계 fixture 예시 shape

```json
{
  "category": "웹서버",
  "platform": "Nginx",
  "total_items": 26,
  "good_items": 10,
  "vulnerable_items": 3,
  "manual_items": 4,
  "error_items": 9,
  "timestamp": "2026-03-20T09:10:00+09:00",
  "hostname": "web-02",
  "items": [
    {
      "item_id": "WEB-16",
      "item_name": "웹서비스헤더정보노출제한",
      "inspection": {
        "summary": "server_tokens가 off로 설정되어 있습니다.",
        "status": "양호"
      },
      "final_result": "GOOD",
      "command": "grep -E '^\\s*server_tokens' /etc/nginx/nginx.conf ...",
      "command_result": "/etc/nginx/nginx.conf: server_tokens off;",
      "guideline": {
        "purpose": "...",
        "security_threat": "...",
        "judgment_criteria_good": "...",
        "judgment_criteria_bad": "...",
        "remediation": "..."
      },
      "timestamp": "2026-03-20T09:10:00+09:00",
      "hostname": "web-02"
    }
  ]
}
```

## 런타임 샘플 부재에 따른 한계

### 미확인

- 실제 JSON 인코딩과 줄바꿈 처리 결과가 정적 분석과 완전히 같은지 여부
- PowerShell `command_result`에 literal `\\n`이 남는지 여부
- 일부 스크립트의 예외 경로에서 `final_result`가 항상 채워지는지 여부
- 실제 `run_all` 실행 환경에서 누락 라이브러리 때문에 JSON 출력이 깨질 가능성

### 설계상 보수적 처리 원칙

1. JSON schema validation을 parser의 첫 단계로 둔다.
2. `raw_final_result` 미존재 시 즉시 `ERROR`로 격리한다.
3. severity는 JSON에서 읽지 않고 static catalog에서 보강한다.
4. `TXT fallback`은 low-confidence 경로로만 사용한다.

## 구현 권장 순서

1. 개별 JSON loader
2. 집계 JSON flatten loader
3. static catalog joiner
4. `normalized_result` 및 `applicability` 결정기
5. TXT fallback parser
6. fixture 기반 snapshot test
