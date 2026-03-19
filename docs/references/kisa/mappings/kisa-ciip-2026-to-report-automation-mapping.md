# KISA-CIIP-2026 결과를 report-automation에 연결하는 매핑 설계

## 문서 목적

이 문서는 `KISA-CIIP-2026` 저장소의 점검 결과를 우리 프로젝트의 `report-automation` 파이프라인에 어떻게 연결할지 설계 관점에서 정리한다. 이번 문서는 실제 실행이 아니라 정적 분석 기반 설계안이다.

## 전제

확인된 사실:

- 현재 `apps/report-automation`는 README와 스키마 기준으로 웹 취약점 자동화에 맞춰져 있다.
- 현재 정규화 스키마는 `request_file`, `response_file`, `base_url`, `target_url`, 스크린샷 등 웹 진단 친화적 필드가 많다.
- 외부 저장소의 서버 점검 결과는 HTTP 트래픽 증적보다 설정 파일, 레지스트리, 명령 출력, 버전 정보 중심이다.

따라서 단순 파서 추가만으로는 충분하지 않고, 서버 계열에 맞는 `finding` 공통 모델 확장이 필요하다.

## 어떤 출력이 있으면 finding 스키마로 정규화할 수 있는가

### 1. 입력 소스별 정규화 가능성

| 입력 소스 | 확인된 구조 | finding 정규화 가능성 | 비고 |
| --- | --- | --- | --- |
| 개별 `JSON` 결과 | 높음 | 높음 | 1차 통합 대상 |
| `run_all` 집계 `JSON` | 높음 | 높음 | `items[]` 평탄화 파서 필요 |
| 개별 `TXT` 결과 | 중간 | 중간 | 정규식/패턴 파서 필요 |
| 집계 `TXT` 결과 | 중간 | 낮음~중간 | JSON이 없을 때 보조 입력으로만 권장 |
| 콘솔 출력만 확보된 경우 | 미확인 | 낮음 | 운영 자동화 입력으로 부적합 |

### 2. 우선 사용할 입력

우선순위는 명확하다.

1. 개별 `JSON`
2. 집계 `JSON`
3. 개별 `TXT`
4. 집계 `TXT`

이 순서를 권장하는 이유는 `result_manager`가 이미 결과 구조를 비교적 안정적으로 정의하고 있기 때문이다.

## finding 단위 정규화 기준

### 1. 바로 `finding`으로 만들 수 있는 항목

다음 조건을 만족하면 자동 정규화 가능성이 높다.

- `item_id`, `item_name`, `final_result`, `inspection.summary`가 존재한다.
- `command_result`에 실제 설정값 또는 매칭 결과가 존재한다.
- `guideline.remediation`이 채워져 있다.
- `MANUAL`이 아니라 `GOOD` 또는 `VULNERABLE` 계열 판정이 나온다.

대표 예시:

- Apache `WEB04`: 디렉터리 리스팅 설정
- Nginx `WEB16`: `server_tokens off`
- Tomcat `WEB01`: 기본 계정 존재 여부
- Tomcat `WEB04`: `listings` 설정
- IIS `WEB04`: 디렉터리 브라우징
- IIS `WEB23`: HTTP 메서드 제한

### 2. 추가 파서가 필요한 항목

다음 유형은 정규화는 가능하지만 추가 해석 로직이 필요하다.

- `run_all` 집계 `JSON`의 `items[]` 배열을 개별 finding으로 펼치는 경우
- `command_result`가 다중 라인 텍스트이며, 설정 파일 경로/라인/값을 분리해야 하는 경우
- `TXT` 결과만 확보된 경우
- 웹셸 의심 파일 탐지처럼 탐지 결과와 확증 판단이 분리되는 경우

대표 예시:

- Nginx `WEB23`: 웹셸 의심 파일명 검색
- 여러 설정 파일을 순회하며 다수 매칭 결과를 누적하는 항목

### 3. 수동 검토가 필요한 항목

다음 유형은 자동 판정 결과를 그대로 보고서 finding으로 사용하기보다 수동 리뷰 단계가 필요하다.

- 스크립트 자체가 `MANUAL` 상태를 반환하는 항목
- 버전 문자열만 수집하고 최신 보안 권고와 비교는 사람이 해야 하는 항목
- 비밀번호 복잡도/정책 적정성처럼 텍스트만으로 적합성 판단이 어려운 항목
- `N/A` 결과가 나왔는데, 이는 미적용인지 탐지 실패인지 환경 차이인지 구분이 필요한 경우

대표 예시:

- Tomcat `WEB02`
- Tomcat `WEB25`
- Apache `WEB23`
- 일부 IIS `N/A` 항목

## 체크리스트형/설정형/증적형 구분

| 유형 | 설명 | 자동화 적합성 | 예시 |
| --- | --- | --- | --- |
| 체크리스트형 | 정책 준수 여부를 예/아니오로 판단 | 높음 | 디렉터리 브라우징 비활성화 여부 |
| 설정형 | 설정 파일/레지스트리/메타데이터 값을 읽어 판정 | 높음 | `server_tokens off`, `listings=false` |
| 증적형 | 명령 결과, 파일 경로, 레지스트리 값 등 증적을 그대로 보존 | 높음 | grep 결과, PowerShell 조회 결과 |
| 휴리스틱형 | 의심 파일/패턴/버전 문자열을 제시 | 중간 | 웹셸 의심 파일명 탐지 |
| 수동검토형 | 스크립트가 가이드만 제시하고 판정 확정은 사람 몫 | 낮음 | 비밀번호 정책 적정성 확인 |

실제 연계 설계에서는 "체크리스트형 + 설정형 + 증적형"을 1차 자동화 대상으로 묶고, 휴리스틱형과 수동검토형은 별도 리뷰 큐로 분기하는 것이 적절하다.

## evidence 추출 가능성

### 공통적으로 추출 가능한 evidence

| evidence 유형 | 추출 가능성 | 설명 |
| --- | --- | --- |
| 설정 파일 경로 | 높음 | `command_result` 또는 스크립트 로직에서 확보 가능 |
| 설정 값/매칭 라인 | 높음 | grep/PowerShell 조회 결과에서 추출 가능 |
| 명령 문자열 | 높음 | `command` 필드에 존재 |
| 명령 출력 | 높음 | `command_result` 필드에 존재 |
| 호스트명 | 높음 | `hostname` 필드에 존재 |
| 타임스탬프 | 높음 | `timestamp` 필드에 존재 |

### 현재 기준으로 부족한 evidence

| evidence 유형 | 상태 | 비고 |
| --- | --- | --- |
| HTTP 요청/응답 | 사실상 없음 | 현재 웹 자동화 스키마와 차이 |
| 스크린샷 | 미확인 | 기본 출력에서 확인 못함 |
| 파일 해시/라인 번호 | 미확인 | 후처리 파서에서 보강 가능 |
| 변경 전/후 비교 | 없음 | 점검 도구 성격상 미포함 |

## severity 산정 가능성

### 확인된 사실

- 개별 스크립트 헤더에는 `@Severity` 메타데이터가 존재한다.
- 런타임 결과 저장 로직(`result_manager.sh`, `result_manager.ps1`)에는 severity가 핵심 필드로 보존되는 구조가 명확히 드러나지 않는다.

### 설계 결론

- severity는 "부분 자동화 가능"으로 판단한다.
- 런타임 출력만으로 완전 자동 산정하기보다, 정적 카탈로그를 별도로 만들어야 한다.

권장 방식:

1. 스크립트 헤더에서 `item_id`, `title`, `severity`, `reference`를 정적으로 추출한다.
2. `item_id` 기준 카탈로그를 생성한다.
3. 런타임 `JSON` 결과와 조인해 normalized finding에 severity를 채운다.

즉, severity는 결과 파일만으로는 부족하고 "정적 메타데이터 카탈로그 + 런타임 결과"의 결합이 필요하다.

## manual review 필요 여부

| 조건 | 처리 방안 |
| --- | --- |
| `inspection.status = MANUAL` | 무조건 수동 검토 큐 |
| `final_result = N/A` | 적용 대상 여부 검토 후 보류 또는 제외 |
| 휴리스틱 탐지 결과 | analyst confirm 필요 |
| 설정값은 수집되었지만 적정성 해석이 필요한 경우 | 수동 검토 큐 |

이 로직은 현재 웹 자동화의 "취약점 발견" 모델보다 더 체크리스트 기반 심사 모델에 가깝다. 따라서 `reviewed-findings` 단계에서 "자동 승인"보다 "검토 필요" 상태를 지원하는 편이 적합하다.

## 웹/API/서버 공통 필드와 서버 전용 필드 구분

### 1. 공통화 가능한 필드

| 필드 | 용도 |
| --- | --- |
| `finding_id` | 내부 고유 식별자 |
| `canonical_key` | 중복 제거/재현성 확보 |
| `source.tool` | `kisa-ciip-2026` |
| `source.category` | `webserver`, `unix`, `windows`, `dbms`, `pc` |
| `item_id` | `WEB04`, `U01`, `W31` 등 |
| `title` | 점검 항목명 |
| `summary` | 핵심 판정 요약 |
| `status` | `GOOD`, `VULNERABLE`, `MANUAL`, `N/A`, `ERROR` 등 |
| `severity` | 정적 카탈로그 기반 |
| `description` | 가이드 설명 |
| `impact` | 보안 위협 설명 |
| `remediation` | 조치 방안 |
| `references` | KISA 가이드/참고 문서 |
| `evidence[]` | 증적 목록 |
| `review_required` | 수동 검토 여부 |
| `timestamp` | 수집 시각 |

### 2. 서버 전용 필드

| 필드 | 용도 |
| --- | --- |
| `hostname` | 대상 호스트 |
| `host_ip` | 대상 IP, 미확인 시 공란 |
| `os_family` | Linux, Windows, AIX 등 |
| `platform` | `apache`, `nginx`, `tomcat`, `iis`, `debian`, `redhat` 등 |
| `service_name` | `httpd`, `nginx`, `tomcat`, `w3svc` 등 |
| `product_name` | 웹서버/DBMS/OS 이름 |
| `product_version` | 수집된 버전 |
| `config_path` | 설정 파일 경로 |
| `registry_path` | Windows 계열 설정 경로 |
| `executed_command` | 실제 확인 명령 |
| `command_output` | 원본 출력 |
| `execution_context` | shell/PowerShell/DB client |
| `applicability` | 적용 대상, N/A 사유 |

### 설계 해석

현재 웹 보고서 템플릿은 `URL`, `request/response`, `screenshot` 중심이라 서버형 finding을 바로 표현하기 어렵다. 템플릿 공통 필드는 재사용하되, 서버 전용 필드를 별도 섹션으로 노출해야 한다.

## 카테고리별 연계 전략

| 카테고리 | finding 정규화 가능성 | evidence 추출 가능성 | severity 자동화 가능성 | manual review 비율 | 우선순위 |
| --- | --- | --- | --- | --- | --- |
| `03.웹서버` | 높음 | 높음 | 중간 | 중간 | 1 |
| `01.Unix서버` | 중간~높음 | 높음 | 중간 | 중간 | 2 |
| `02.Windows서버` | 중간~높음 | 높음 | 중간 | 중간 | 3 |
| `08.DBMS` | 중간 | 중간 | 중간 | 높음 | 4 |
| `07.PC` | 중간 | 중간 | 중간 | 중간 | 5 |

## 우선 통합 대상과 후순위 대상

### 우선 통합 대상

1. `03.웹서버`의 설정형/결정형 항목
2. 그 중 Apache/Nginx/IIS 우선
3. Tomcat은 결정형 항목부터 제한적으로

권장 우선 흡수 항목 유형:

- 디렉터리 리스팅/브라우징
- 서버 버전 노출
- 불필요 메서드 제한
- 기본 계정/기본 설정 여부
- 금지 설정값 존재 여부

### 후순위 대상

- Unix/Windows 서버의 전 범위 하드닝
- DBMS 접속 기반 점검
- PC 보안 점검
- 버전 비교/정책 적정성/패턴 탐지 중심 수동 검토 항목

## "바로 통합 가능한 부분 / 추가 파서 필요 / 수동 검토 필요" 평가

### 바로 통합 가능한 부분

- 개별 `JSON` 결과 파일
- `run_all` 집계 `JSON`의 `items[]`
- Apache/Nginx/IIS의 설정형 점검 항목
- Tomcat의 일부 설정형 점검 항목

### 추가 파서가 필요한 부분

- `TXT` 결과 파싱
- 멀티라인 `command_result` 구조화
- 정적 메타데이터(`severity`, `reference`) 추출기
- `N/A`, `ERROR`, `MANUAL` 상태 분류기

### 수동 검토가 필요한 부분

- 버전 비교형 항목
- 휴리스틱 탐지형 항목
- 정책 적정성 해석형 항목
- 적용 대상 판정이 선행되어야 하는 항목

## 결론

`KISA-CIIP-2026`는 "실행기"보다 "결과 구조와 항목 체계"를 흡수하는 방식으로 접근하는 것이 맞다. 현재 우리 프로젝트에 가장 빨리 연결할 수 있는 부분은 `03.웹서버`의 JSON 결과를 서버형 finding으로 정규화하는 작업이다.

핵심 설계 결론은 다음 두 가지다.

1. 결과 파서는 `JSON 우선`, `TXT 보조` 구조로 설계한다.
2. `report-automation`에는 웹 공통 필드를 유지하되, 서버 전용 필드를 수용하는 확장 스키마와 템플릿이 필요하다.
