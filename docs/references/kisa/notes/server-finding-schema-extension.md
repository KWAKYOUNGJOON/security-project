# 서버형 normalized finding 확장안

## 문서 목적

이 문서는 `03.웹서버` 결과를 `report-automation`에 연결하기 위해 서버형 normalized finding을 어떻게 확장할지 제안한다. 비교 대상은 현재 `shared/schemas/normalized-finding.schema.json`이며, 이번 문서의 초점은 웹서버 결과를 담기 위한 최소 확장안이다.

## 현재 normalized-finding과의 차이

확인된 사실:

- 현재 shared schema는 `platform = web`로 고정되어 있다.
- `target`은 `base_url`, `target_url`, `auth_context` 등 URL 중심 필드를 요구한다.
- `evidence`는 `request_file`, `response_file`, `screenshots` 중심이다.
- 즉 현재 스키마는 HTTP 트래픽 기반 웹 finding에 맞춰져 있다.

문제점:

- 웹서버 점검 결과는 URL보다 `hostname`, `service_name`, `config_path`, `executed_command`, `command_output`가 핵심이다.
- `PASS/MANUAL/N/A`처럼 체크리스트성 상태를 취급해야 한다.
- 같은 `item_id`라도 `platform`이 다르면 의미가 달라지는 구간이 있다.

## 선택지 비교

| 선택지 | 장점 | 단점 | 이번 단계 적합성 |
| --- | --- | --- | --- |
| 기존 `normalized-finding` 직접 일반화 | 하나의 스키마로 통합 가능 | 현재 웹 파이프라인에 파급 영향 큼 | 낮음 |
| 서버 전용 `normalized-server-finding` 추가 | 기존 웹 흐름을 깨지 않고 확장 가능 | 공통화는 2단계로 미룸 | 높음 |
| 완전한 공통 base schema + 웹/서버 서브스키마 동시 도입 | 장기적으로 가장 깨끗함 | 지금 범위에 비해 과함 | 중간 |

## 권장 결정

이번 단계의 권장안은 다음과 같다.

1. 기존 `normalized-finding.schema.json`은 그대로 둔다.
2. 별도 `normalized-server-finding` 스키마를 추가한다.
3. parser 단계에서는 서버형 intermediate model을 먼저 만든다.
4. 장기적으로 웹/서버 공통 base schema를 설계하되, 이번 단계에서는 문서화까지만 한다.

이 결정을 권장하는 이유는 현재 웹 스키마가 너무 URL/HTTP 증적 중심이라, 바로 일반화하면 기존 구현 전체를 건드릴 가능성이 크기 때문이다.

## 서버형 finding의 기본 방향

### 설계 원칙

1. `FAIL`만 자동 finding 후보로 승격한다.
2. `PASS`는 finding이 아니라 checklist/compliance 결과로 분리한다.
3. `MANUAL`은 review queue 후보로 저장한다.
4. `N/A`는 적용 대상 결과로만 저장하고 본문 finding에는 올리지 않는다.
5. `ERROR`는 수집/파싱 오류로 분리 저장한다.

## 권장 스키마 방향

권장 top-level 개념은 아래와 같다.

```json
{
  "schema_version": "1.0",
  "review_key": "server:web-01:apache:WEB-04",
  "finding_id": "server-web-01-apache-WEB-04",
  "platform": "apache",
  "surface": "webserver",
  "title": "웹서비스디렉터리리스팅방지설정",
  "target": {
    "hostname": "web-01",
    "service_name": "apache",
    "environment": "production"
  },
  "source": {
    "tool": "kisa-ciip-2026",
    "raw_file": "....json",
    "parser": "kisa_webserver_json_v1",
    "raw": {}
  },
  "classification": {
    "code": "WEB-04",
    "severity": "high",
    "canonical_key": "kisa:webserver:apache:WEB-04"
  },
  "summary": "...",
  "description": "...",
  "impact": "...",
  "remediation": "...",
  "references": [
    "2026 KISA 주요정보통신기반시설 기술적 취약점 분석·평가 상세 가이드"
  ],
  "check": {
    "item_id": "WEB-04",
    "check_type": "config",
    "raw_status": "양호",
    "raw_final_result": "GOOD",
    "applicability": "applicable"
  },
  "evidence": {
    "config_path": [
      "/etc/apache2/apache2.conf"
    ],
    "registry_path": [],
    "executed_command": "grep ...",
    "command_output": "..."
  },
  "review": {
    "review_required": false,
    "triage_state": "auto-pass"
  }
}
```

## 필드 필요성 검토

| 필드 | 필요성 | 03.웹서버 1차 적용성 | 설명 |
| --- | --- | --- | --- |
| `hostname` | 필수 | 높음 | URL보다 호스트 기준 식별이 중요 |
| `platform` | 필수 | 높음 | `apache/nginx/iis/tomcat` 분기 키 |
| `service_name` | 필수 | 높음 | 1차에는 `platform`과 같아도 되지만 향후 site/service 이름으로 확장 가능 |
| `config_path` | 권장 필수 | 높음 | Apache/Nginx/Tomcat에서 핵심 evidence |
| `registry_path` | 선택 | 낮음 | `03.웹서버` 1차에서는 거의 비어 있을 가능성 큼, 이후 Windows Server 대비용 |
| `executed_command` | 필수 | 높음 | evidence 재현성과 parser trace에 필요 |
| `command_output` | 필수 | 높음 | 원본 증적 핵심 |
| `applicability` | 필수 | 높음 | `N/A`와 실제 FAIL 분리 |
| `check_type` | 필수 | 높음 | `config/manual/version/heuristic` 분기 필요 |
| `raw_status` | 필수 | 높음 | 한글 원문 보존 |

추가 권장 필드:

- `raw_final_result`
- `surface`
- `review_required`
- `triage_state`
- `severity_source`
- `catalog_version`

## 웹 finding 공통 필드 vs 서버 전용 필드

## 1. 웹/API/서버 공통 필드

아래 필드는 공통 계층으로 유지할 가치가 있다.

| 필드 | 용도 |
| --- | --- |
| `schema_version` | 스키마 버전 |
| `review_key` | 리뷰 dedup 키 |
| `finding_id` | 내부 식별자 |
| `title` | finding 제목 |
| `source.tool` | 원본 도구명 |
| `source.raw_file` | 원본 파일 경로 |
| `source.parser` | 사용 파서 |
| `classification.code` | 항목 코드 (`WEB-04`) |
| `classification.severity` | severity |
| `classification.canonical_key` | 중복 제거 키 |
| `summary` | 한 줄 요약 |
| `description` | 설명 |
| `impact` | 영향 |
| `remediation` | 조치 |
| `references` | 참조 문서 |
| `review.review_required` | 리뷰 필요 여부 |
| `review.triage_state` | 리뷰 상태 |

## 2. 서버 전용 필드

아래 필드는 현재 웹 schema에 없거나, 있어도 의미가 다르므로 서버 전용으로 분리하는 편이 낫다.

| 필드 | 설명 |
| --- | --- |
| `target.hostname` | 대상 호스트 |
| `platform` | `apache/nginx/iis/tomcat` |
| `target.service_name` | 서비스 또는 사이트 이름 |
| `check.item_id` | KISA 항목 ID |
| `check.check_type` | `config/file/command/manual/version/heuristic` |
| `check.raw_status` | `양호/취약/수동진단/N/A` |
| `check.raw_final_result` | `GOOD/VULNERABLE/MANUAL/N/A` |
| `check.applicability` | `applicable/not_applicable/service_not_running/unknown` |
| `evidence.config_path[]` | 설정 파일 경로 |
| `evidence.registry_path[]` | 레지스트리 경로 |
| `evidence.executed_command` | 실행한 명령 |
| `evidence.command_output` | 명령 결과 원문 |

## review 정책 초안

### 1. `FAIL`

- `raw_final_result = VULNERABLE`
- 자동 finding 후보로 생성
- `review_required = false`로 시작할 수 있음
- 단, heuristic 항목은 `review_required = true`로 강등 가능

예:

- Apache `WEB-04`
- Nginx `WEB-16`
- IIS `WEB-23`

### 2. `MANUAL`

- finding 본문에 바로 올리지 않는다.
- `review_required = true`
- `triage_state = needs-manual-review`
- 리뷰어가 `confirmed-vuln`, `confirmed-ok`, `dismissed` 중 하나로 판정하도록 한다.

예:

- Apache `WEB-23 ~ WEB-25`
- Nginx `WEB-25`
- Tomcat `WEB-02`, `WEB-23`, `WEB-24`, `WEB-25`

### 3. `N/A`

- 취약점 finding으로 생성하지 않는다.
- `triage_state = not-applicable`
- 필요 시 checklist appendix에만 남긴다.

예:

- Apache/Nginx/IIS `WEB-01`
- Apache/Nginx `WEB-02` 일부 분기

### 4. `ERROR`

- 취약점으로 생성하지 않는다.
- `triage_state = collection-error`
- 보고서 본문이 아니라 수집 진단 섹션 또는 파이프라인 오류 로그로 보낸다.
- 동일 호스트에서 연속적으로 발생하면 실행 환경 점검 이슈로 별도 추적한다.

## 스키마 설계 대안 비교 상세

### 대안 A: 기존 normalized-finding 일반화

장점:

- 최종적으로는 가장 깔끔하다.

단점:

- `target.base_url`, `target.target_url`, `evidence.request_file`, `evidence.response_file` 같은 필수 필드를 깨야 한다.
- 기존 웹 파이프라인과 템플릿에 파급이 크다.

판단:

- 지금 바로 적용하기에는 리스크가 크다.

### 대안 B: 서버 전용 schema 추가

장점:

- 현재 웹 파이프라인을 유지할 수 있다.
- `03.웹서버`만 먼저 붙일 수 있다.
- 향후 Unix/Windows/DBMS 확장도 같은 방향으로 붙이기 쉽다.

단점:

- 단기적으로 스키마가 2개가 된다.

판단:

- 이번 단계의 최적안이다.

### 대안 C: 공통 base + 웹/서버 서브스키마

장점:

- 장기 구조는 가장 좋다.

단점:

- 지금 범위에서 설계 비용이 크다.
- 웹 기존 구현을 같이 손봐야 할 가능성이 높다.

판단:

- 차기 단계 설계 과제로 적합하다.

## 1차 구현 권장안

1. parser는 `kisa_webserver_raw_record`를 만든다.
2. mapper는 `raw_final_result = VULNERABLE`만 서버형 finding으로 승격한다.
3. `MANUAL`, `N/A`, `ERROR`는 finding과 분리된 review/checklist 흐름으로 보낸다.
4. 새 schema는 `normalized-server-finding`으로 분리한다.
5. 보고서 생성 단계에서는 웹 finding과 서버 finding을 병렬 렌더링하도록 확장한다.

## 남겨둘 TODO

- `normalized-server-finding.schema.json` 초안 작성
- `reviewed-server-findings.schema.json` 필요 여부 판단
- 웹/서버 공통 report payload 계층 정의
- checklist 결과를 finding과 별도 렌더링할지 결정
