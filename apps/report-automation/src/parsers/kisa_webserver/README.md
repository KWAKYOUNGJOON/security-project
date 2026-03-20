# kisa_webserver

입력 파일 종류
- 개별 `item_json`
- `run_all_json`

현재 지원 범위
- `03.웹서버` 기준 raw ingestion
- Apache, Nginx, IIS 우선
- Tomcat은 정적 catalog 인식 위주

미지원 범위
- TXT parser
- 실제 런타임 샘플 검증 전의 세부 필드 보정
- normalized finding 생성

다음 단계
- `FAIL` 전용 adapter
- `MANUAL`/`ERROR` review queue 분리
- 실제 표준 외부 경로 기반 catalog 생성
