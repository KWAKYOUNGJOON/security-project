# adapters

raw ingestion 과 finding candidate adapter 의 차이
- raw ingestion 은 입력 보존이 목적이다.
- adapter 는 raw record 를 `finding_candidates`, `review_queue`, `checklist_items`, `pass_records` 로 분기한다.

왜 FAIL-only 정책을 쓰는가
- 현재 단계는 최종 finding 생성 전의 안전한 분기 계층이다.
- `FAIL` 만 자동 후보로 올리고, 나머지 상태는 review 또는 checklist 로 분리한다.

상태 처리 정책
- `FAIL`: finding candidate
- `MANUAL`: review queue
- `ERROR`: review queue
- `N/A`: checklist
- `PASS`: pass record 보존

현재 한계
- synthetic fixture 기반 검증만 완료된 상태다.
- real catalog, real runtime sample, normalized finding 연결은 다음 단계다.
