# 03.웹서버 WEBxx 메타데이터 카탈로그

## 문서 목적

이 문서는 표준 외부 경로 `D:\security-project\resources\external-tools\kisa-ciip-2026\03.웹서버` 기준으로 Apache, Nginx, IIS, Tomcat의 `WEB-01 ~ WEB-26` 점검 항목을 정적 분석한 메타데이터 카탈로그다. 목적은 `report-automation` 다음 구현 단계에서 바로 참조할 수 있는 수준의 항목 단위 기준표를 만드는 것이다.

이번 문서는 `03.웹서버`만 다루며, 우선순위는 Apache, Nginx, IIS 중심이다. Tomcat은 구조 확인과 후속 확장 포인트 위주로 정리한다.

## 판정 기준

- `확정`: 스크립트 헤더 또는 본문 로직에서 직접 확인한 사실
- `추정`: 동일 패턴/타이틀/분기 구조를 기준으로 합리적으로 유추한 값
- `미확인`: 런타임 샘플 부재 또는 코드상 모호성 때문에 확정할 수 없는 값

## 정적 분석 기준 핵심 결론

### 1. 메타데이터 확보 상태

확정:

- `03.웹서버`는 Apache, Nginx, IIS, Tomcat 각각 `WEB-01 ~ WEB-26` 총 26개 스크립트를 가진다.
- 총 104개 스크립트 모두 `@ID`, `@Title`, `@Reference` 헤더를 가진다.
- 총 104개 스크립트 모두 `@Severity` 헤더를 가진다.
- `guideline` 계열 설명은 모든 스크립트가 런타임 결과에 넘길 수 있도록 값을 준비한다.

주의:

- severity는 "헤더에서 확보 가능"하지만 "런타임 결과만으로 안전하게 확보 가능"한 것은 아니다.
- 정적 비교 결과 `@Severity`와 코드 내 `SEVERITY` 값이 불일치하는 스크립트가 다수 있다.
- 정적 비교 결과 `03.웹서버` 전체 104개 중 35개는 헤더/변수 severity 불일치, 9개는 변수 선언 부재가 확인되었다.
- 따라서 severity 카탈로그의 기준 원본은 런타임 JSON이 아니라 스크립트 헤더여야 한다.

### 2. 공통 결과 모델

확정:

- 개별 스크립트 결과는 `result_manager.sh` 또는 `result_manager.ps1`를 통해 `JSON + TXT`로 저장되도록 설계되어 있다.
- 개별 JSON에는 `item_id`, `item_name`, `inspection.summary`, `inspection.status`, `final_result`, `command`, `command_result`, `guideline.*`, `timestamp`, `hostname`가 포함된다.
- `run_all` 집계 JSON에는 `category`, `platform`, `total_items`, `good_items`, `vulnerable_items`, `manual_items`, `error_items`, `timestamp`, `hostname`, `items[]`가 포함된다.

### 3. 결과 판정 해석 기준

확정:

- 스크립트가 직접 사용하는 최종 판정값은 `GOOD`, `VULNERABLE`, `MANUAL`, `N/A`다.

정책 제안:

- `GOOD`를 `PASS`
- `VULNERABLE`을 `FAIL`
- `MANUAL`을 `MANUAL`
- `N/A`를 `NOT_APPLICABLE`
- `ERROR`는 스크립트 판정보다 실행 실패/JSON 파싱 실패/수집 실패를 위한 파서 계층 reserved 값으로 취급

## 서비스별 공통점과 차이점

### 공통점

- Apache, Nginx, IIS 모두 웹서버 설정 점검이라는 공통 축을 가진다.
- 대부분의 자동 판정 가능 항목은 `command_result`에 설정값, 경로, 매칭 라인, 사이트명 등을 증적으로 남길 수 있다.
- `WEB-04`, `WEB-16`, `WEB-20`, `WEB-22` 계열은 서비스별 구현 차이는 있어도 `finding` 정규화 가능성이 높은 대표 구간이다.

### 차이점

- Apache/Nginx는 셸 기반이며 증적이 주로 grep/find 결과다.
- IIS는 PowerShell 기반이며 `Get-Website`, `Get-WebConfiguration`, `web.config` 조회 결과가 중심이다.
- Tomcat은 `tomcat-users.xml`, `web.xml`, `server.xml` 기반 항목 비중이 높고, Apache/Nginx/IIS와 번호가 같아도 의미가 달라지는 구간이 많다.

### 번호 공통성이 높은 구간

아래 번호는 Apache, Nginx, IIS 기준으로 의미가 대체로 유지된다.

- `WEB-01 ~ WEB-06`
- `WEB-09 ~ WEB-12`
- `WEB-15 ~ WEB-18`
- `WEB-20`
- `WEB-22`

### 번호는 같지만 의미가 갈라지는 구간

아래 번호는 서비스별로 제목과 점검 목적이 달라진다.

- `WEB-07`
- `WEB-08`
- `WEB-13`
- `WEB-14`
- `WEB-19`
- `WEB-21`
- `WEB-23 ~ WEB-26`

Tomcat은 특히 `WEB-07` 이후부터 애플리케이션/서버 설정 성격이 강해져 Apache/Nginx/IIS와 직접 1:1 비교하기 어렵다.

## 구현 우선순위 관점 요약

### 1차 자동 흡수 우선

- Apache: `WEB-04`, `WEB-10`, `WEB-14`, `WEB-15`, `WEB-16`, `WEB-17`, `WEB-18`, `WEB-20`, `WEB-22`, `WEB-26`
- Nginx: `WEB-04`, `WEB-05`, `WEB-09`, `WEB-10`, `WEB-11`, `WEB-13`, `WEB-14`, `WEB-15`, `WEB-16`, `WEB-17`, `WEB-18`, `WEB-19`, `WEB-20`, `WEB-21`, `WEB-22`, `WEB-24`, `WEB-26`
- IIS: `WEB-04`, `WEB-05`, `WEB-07`, `WEB-09`, `WEB-11`, `WEB-13`, `WEB-14`, `WEB-15`, `WEB-16`, `WEB-18`, `WEB-20`, `WEB-22`, `WEB-23`, `WEB-24`, `WEB-25`, `WEB-26`

### 수동 또는 후순위

- Apache `WEB-23 ~ WEB-25`
- Nginx `WEB-23`, `WEB-25`
- IIS `WEB-02`, `WEB-06`, `WEB-10`, `WEB-17`, `WEB-19`, `WEB-21`
- Tomcat `WEB-02`, `WEB-21 ~ WEB-25`

## WEBxx 항목 카탈로그

표 해설:

- `유형`은 대표 점검 방식이다. `config`, `file`, `command`, `manual`, `version`, `heuristic` 중 하나 또는 복합으로 적었다.
- `예상 판정`은 스크립트 본문에서 직접 확인 가능한 경로 기준이다. `ERROR`는 parser/runtime reserved이므로 표에는 필요 시에만 주석으로 언급한다.
- `정규화`는 `finding` 생성 가능성을 뜻한다. `예`는 FAIL 결과를 바로 finding으로 만들 수 있다는 의미이고, `부분`은 manual/heuristic/N/A 분기 때문에 추가 로직이 필요하다는 의미다.

| item_id | 공통/분기 | 서비스별 구현 요약 | 유형 | 예상 판정 | severity / reference | finding 정규화 | evidence 추출 포인트 | 확정도 / 메모 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `WEB-01` | 분기 | Apache/Nginx/IIS는 점검 대상 아님 또는 `N/A` 명시, Tomcat만 `tomcat-users.xml`에서 기본 계정명 확인 | `file`, `manual` | `N/A`, `PASS`, `FAIL` | severity: 헤더 기준 확보 가능, reference: 확보 가능 | `부분` | Tomcat `command_result`, `executed_command`, `tomcat-users.xml` 경로 | Apache/Nginx/IIS `N/A`는 확정, Tomcat 구현은 확정 |
| `WEB-02` | 분기 | Apache/Nginx는 사실상 비대상 성격, IIS는 `net accounts`와 App Pool Identity 확인, Tomcat은 `tomcat-users.xml` 수동검토 안내 | `command`, `manual`, `file` | `N/A`, `FAIL`, `MANUAL` | 헤더 기준 확보 가능 | `부분` | IIS `command_result`, Tomcat 파일 존재 경로 | IIS `Save-DualResult -Severity` 파라미터 불일치 주의 |
| `WEB-03` | 분기 | Apache/Nginx/Tomcat은 비밀번호 파일 권한 계열, IIS는 의미상 비대상에 가까움 | `file` | `N/A`, `PASS`, `FAIL`, `MANUAL` | 헤더 기준 확보 가능 | `부분` | 파일 권한 출력, `command_result`, 파일 경로 | Tomcat은 `tomcat-users.xml` 계열, Apache/Nginx는 `.htpasswd`류 추정 |
| `WEB-04` | 공통 | Apache `Options Indexes`, Nginx `autoindex`, IIS `directoryBrowse`, Tomcat `web.xml listings` | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | `command_result`, config path, IIS site name / `web.config` | 1차 핵심 흡수 대상 |
| `WEB-05` | 공통 | Apache CGI/ExecCGI, Nginx CGI/fastcgi/scgi/uwsgi 경로, IIS CGI/ISAPI, Tomcat CGI servlet 점검 | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | grep 결과, IIS script map, `web.xml` | Apache/Nginx/IIS 우선, Tomcat은 후속 |
| `WEB-06` | 공통 | 상위 디렉터리 접근 제한. Apache/Nginx는 설정 파일 grep, IIS는 예외 처리 시 manual 비중, Tomcat은 `allowLinking` 계열 | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | 설정 라인, `command_result`, IIS exception 텍스트 | 서비스별 구현 편차가 있어 parser rule 분기 필요 |
| `WEB-07` | 분기 | Apache/IIS는 불필요 파일 제거, Nginx는 웹 경로 내 불필요 파일 제거, Tomcat은 로그 분석 관리 | `file`, `command` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | 파일 목록, 경로, 삭제 대상 요약 | 번호 동일, 의미는 서비스별 분기 |
| `WEB-08` | 분기 | Apache/IIS는 `.htaccess` 오버라이드 계열, Nginx는 업로드/다운로드 용량 제한, Tomcat은 접속 통제 | `config`, `manual` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | config line, `command_result`, 일부 수동요약 | Apache/Nginx/IIS 공통 항목으로 보기 어려움 |
| `WEB-09` | 공통 | 프로세스 권한 제한. Apache/Nginx/Tomcat은 프로세스 계정/설정 확인, IIS는 App Pool 권한 | `command`, `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | 프로세스 사용자, pool identity, 설정값 | Apache/Nginx/IIS 우선 흡수 가능 |
| `WEB-10` | 공통 | 프록시 설정 제한. Apache `ProxyPass`, Nginx `proxy_pass`, IIS는 proxy 관련 설정 수동/명령 기반, Tomcat은 스크립트 매핑 | `config`, `manual` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | 설정 라인, site config, command output | Tomcat은 의미가 달라 분기 필요 |
| `WEB-11` | 공통에 가까움 | Apache/Nginx/IIS는 웹 경로 설정, Tomcat은 링크 사용 금지 | `config`, `file` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | `DocumentRoot`, `root`, IIS physical path, `web.xml` | Tomcat은 별도 그룹으로 보는 편이 안전 |
| `WEB-12` | 공통에 가까움 | Apache/Nginx/IIS는 링크 사용 금지, Tomcat은 설정 파일 노출 제한 | `config`, `file` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | symlink/alias 관련 결과, `web.xml` 보안 설정 | 번호 공통성은 낮음 |
| `WEB-13` | 분기 | Apache/IIS는 디렉터리/파일 접근통제 계열, Nginx는 `autoindex off`, Tomcat은 `security-constraint` 접근통제 | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | 설정 라인, IIS ACL/설정, `web.xml` 보안 제약 | Nginx `WEB-13`은 1차 흡수 우선 |
| `WEB-14` | 분기 | Apache/IIS는 경로 내 파일 접근통제, Nginx는 `default_server` 구성, Tomcat은 스크립트 매핑 제거 | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | 설정 라인, path access 결과, `web.xml` | 서비스별 title 불일치 큼 |
| `WEB-15` | 공통에 가까움 | Apache/Nginx/IIS는 불필요한 스크립트 매핑 제거, Tomcat도 유사하지만 `web.xml` 중심 | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | handler/mapping 설정 라인, `web.xml` | Apache/Nginx/IIS 중심으로 1차 흡수 가능 |
| `WEB-16` | 공통 | Apache `ServerTokens/ServerSignature`, Nginx `server_tokens`, IIS 응답 헤더, Tomcat `server.xml Connector server=` | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능, 단 severity 일관성 주의 | `예` | 헤더 관련 설정 라인, custom headers, Connector 속성 | 1차 핵심 흡수 대상 |
| `WEB-17` | 공통에 가까움 | 가상 디렉터리/alias/Context 제거. Apache `Alias`, Nginx `alias`, IIS virtual dir, Tomcat `Context` | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | alias/Context/site mapping 결과 | IIS는 severity 변수 미선언, 헤더 기준 사용 필요 |
| `WEB-18` | 공통 | WebDAV 비활성화. Apache mod_dav, Nginx `dav_methods`, IIS WebDAV, Tomcat `WebdavServlet` | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | 모듈/설정 라인, IIS feature config, `web.xml` | Apache/Nginx/IIS 우선 흡수 가능 |
| `WEB-19` | 강한 분기 | Apache는 WebDAV 재등장 성격, Nginx/IIS/Tomcat은 SSI 사용 제한 | `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | SSI/WebDAV 설정 라인 | 번호 충돌이 있어 catalog join 필수 |
| `WEB-20` | 공통 | SSL/TLS 활성화. Apache/Nginx/IIS/Tomcat 모두 HTTPS/SSL 설정 확인 | `config`, `command` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | listen 443, ssl_certificate, IIS binding, Connector SSL | 1차 흡수 우선 대상 |
| `WEB-21` | 분기 | Apache/IIS는 동적 페이지 요청/응답 검증으로 수동 검토 비중, Nginx/Tomcat은 HTTP 리디렉션 | `manual`, `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | 리디렉션 설정 라인 또는 수동요약 | Apache/IIS는 manual 큐 추천 |
| `WEB-22` | 공통 | 에러 페이지 관리. Apache `ErrorDocument`, Nginx `error_page`, IIS error pages, Tomcat `error-page` | `config`, `manual` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `예` | 설정 라인, IIS site config, `web.xml` | 1차 흡수 가능 |
| `WEB-23` | 강한 분기 | Apache는 HTTP 메서드 제한 수동 stub, Nginx는 웹쉘 탐지, IIS는 Request Filtering verbs, Tomcat은 LDAP 알고리즘 | `manual`, `heuristic`, `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | Apache 수동요약, Nginx suspicious file list, IIS site+verb, Tomcat `server.xml` grep | 동일 번호라도 서비스별 완전 분기 |
| `WEB-24` | 강한 분기 | Apache/IIS는 `X-Frame-Options`, Nginx는 관리자 페이지 노출 제한, Tomcat은 업로드 경로/권한 | `manual`, `config`, `heuristic` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | header config, location block, upload dir list | Apache는 manual stub, IIS는 자동 판정 가능 |
| `WEB-25` | 강한 분기 | Apache/IIS는 `X-XSS-Protection`, Nginx/Tomcat은 보안패치/벤더권고 수동진단 | `manual`, `version`, `config` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | header config 또는 version string | Apache도 manual stub, Nginx/Tomcat은 version/manual |
| `WEB-26` | 분기 | Apache/IIS/Tomcat은 로그 디렉터리/파일 권한, Nginx는 로그 기록 저장/검토 | `file`, `config`, `manual` | `PASS`, `FAIL`, `MANUAL`, `N/A` | 헤더 기준 확보 가능 | `부분` | 파일 권한, 로그 경로, 설정값 | Nginx와 나머지의 목적이 조금 다름 |

## evidence 추출 방식 요약

### Apache

확정:

- 주요 evidence는 `command_result`에 담긴 `httpd.conf`, `apache2.conf`, `sites-enabled/*.conf` grep 결과다.
- `config_path`는 `command`와 `command_result`에서 후처리 추출 가능하다.
- `registry_path`는 사용되지 않는다.

### Nginx

확정:

- 주요 evidence는 `nginx.conf`, `conf.d/*.conf`, `sites-enabled/*.conf` grep 결과다.
- `WEB-23`은 `command_result`에 의심 파일 목록이 담길 수 있어 heuristic evidence로 분류해야 한다.
- `WEB-25`는 version string과 수동 가이드가 같이 나오는 구조다.

### IIS

확정:

- 주요 evidence는 `Get-Website`, `Get-WebConfiguration`, `web.config` 조회 결과다.
- `registry_path` 사용 흔적은 `03.웹서버\IIS` 범위에서 확인하지 못했다.
- 따라서 `registry_path`는 서버형 공통 필드로는 유지하되, `03.웹서버` 1차 파서에서는 대부분 빈 값 또는 `null`이 될 가능성이 높다.

### Tomcat

확정:

- `tomcat-users.xml`, `web.xml`, `server.xml`이 evidence 핵심 경로다.
- `command_result`와 `executed_command`는 grep/find 결과 위주다.

## finding 정규화 가능 여부 정리

### 바로 정규화 가능한 구간

- Apache `WEB-04`, `WEB-10`, `WEB-14`, `WEB-15`, `WEB-16`, `WEB-17`, `WEB-18`, `WEB-20`, `WEB-22`
- Nginx `WEB-04`, `WEB-05`, `WEB-09`, `WEB-10`, `WEB-11`, `WEB-13`, `WEB-14`, `WEB-15`, `WEB-16`, `WEB-17`, `WEB-18`, `WEB-19`, `WEB-20`, `WEB-21`, `WEB-22`, `WEB-24`
- IIS `WEB-04`, `WEB-05`, `WEB-07`, `WEB-09`, `WEB-11`, `WEB-13`, `WEB-14`, `WEB-15`, `WEB-16`, `WEB-18`, `WEB-20`, `WEB-22`, `WEB-23`, `WEB-24`, `WEB-25`, `WEB-26`

### 추가 파서/분류기가 필요한 구간

- `WEB-01`, `WEB-02`, `WEB-03`
- `WEB-07`, `WEB-08`, `WEB-12`, `WEB-19`, `WEB-21`
- Nginx `WEB-23`
- Tomcat 전체의 `WEB-21 ~ WEB-25`

### 수동 검토 큐가 필요한 구간

- Apache `WEB-23 ~ WEB-25`
- Nginx `WEB-25`
- IIS `WEB-02`, `WEB-06`, `WEB-10`, `WEB-17`, `WEB-19`, `WEB-21`
- Tomcat `WEB-02`, `WEB-21`, `WEB-22`, `WEB-23`, `WEB-24`, `WEB-25`

## 구현 시 주의사항

1. `item_id`만으로 공통 취약점 분류를 하지 말아야 한다.
   `WEB-23 ~ WEB-26`과 일부 중간 구간은 서비스별 의미가 다르므로 `item_id + service`가 기본 키여야 한다.

2. severity는 헤더 기준 별도 카탈로그로 고정해야 한다.
   런타임 JSON에서 severity를 직접 신뢰하는 설계는 피해야 한다.

3. `N/A`와 `MANUAL`은 취약점 finding과 체크리스트 결과를 분리하는 기준으로 사용해야 한다.

4. IIS는 `registry_path`보다 `site_name`, `web.config`, `Get-WebConfiguration` 결과가 더 중요한 evidence다.

5. Tomcat은 같은 `WEB-xx` 번호라도 Apache/Nginx/IIS와 의미가 달라지는 구간이 많아서 1차 parser의 기본 대상에서 한 단계 뒤로 두는 것이 안전하다.
