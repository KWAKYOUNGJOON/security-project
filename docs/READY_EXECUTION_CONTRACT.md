# READY Execution Contract

`READY` 판정의 단일 소스 오브 트루스는 이 문서다. `apps/report-automation` 계열 문서, 실행 로그, 산출물은 참고 자료일 수는 있어도 `READY(1)` 근거로 사용하지 않는다.

기준일:
- `2026-03-21`

현재 상태 메모:
- canonical 경로 `app/vuln-pipeline`는 존재할 수 있다.
- 그러나 `READY(1)`은 실제 `real` 입력, `3.11.x` Python, canonical smoke 실행 성공, canonical run 증빙이 모두 충족될 때만 선언할 수 있다.
- placeholder, synthetic, dry-run, legacy 결과는 구조 검증용일 뿐 `READY(1)` 증빙이 아니다.

## Canonical Execution Contract

1. 저장소 기준 루트
- `<repo_root>` = 이 Git 저장소 체크아웃 루트
- 현재 로컬 체크아웃 예시: `d:\security-project`

2. 정식 작업 디렉터리
- `<repo_root>/app/vuln-pipeline`

3. 정식 실행 엔트리포인트
- `python -m vuln_pipeline.cli.main`

4. 금지/레거시 경로
- `python apps/report-automation/src/cli/main.py ...`
- `python -m src.cli.main ...`
- `apps/report-automation/**` 기반 결과를 `READY` 증빙으로 사용하는 행위
- `<repo_root>/data/runs/<run_id>` 밖의 결과를 `READY` 증빙으로 사용하는 행위

5. Python 버전
- 정식 계약 버전: `3.11.x`
- `<repo_root>/app/vuln-pipeline/.python-version` 값은 `3.11`이어야 한다.
- `<repo_root>/app/vuln-pipeline/pyproject.toml`의 `requires-python`은 `>=3.11,<3.12`여야 한다.
- 실제 install/test/smoke에서 호출되는 `python`이 `3.11.x`가 아니면 계약 미충족이며 `BLOCKED`다.

6. 환경 준비 명령
- `cd app/vuln-pipeline`
- `python -m pip install -e .`

7. canonical smoke/test 진입점
- `cd app/vuln-pipeline`
- `python -m vuln_pipeline.cli.main smoke --run-id <run_id>`
- `python -m pytest -q -m must_pass tests/test_fixture_smoke_e2e.py`
- 실제 `real` 입력이 없으면 `smoke`는 dry-run 또는 placeholder 평가만 수행할 수 있으며, 이 경우 최종 상태는 `BLOCKED`여야 한다.

8. 정식 real-input schema
- `<repo_root>/data/inputs/real/burp`
- `<repo_root>/data/inputs/real/nuclei`
- `<repo_root>/data/inputs/real/httpx`
- `<repo_root>/data/inputs/real/manual`
- `<repo_root>/data/inputs/real/burp/burp-findings.json`
- `<repo_root>/data/inputs/real/nuclei/nuclei-findings.json`
- `<repo_root>/data/inputs/real/httpx/httpx-hosts.json`
- `<repo_root>/data/inputs/real/manual/manual-findings.json`
- 위 4개 파일이 canonical real-input manifest다. README, `.gitkeep`, `.keep` 등 placeholder는 구조 보존용일 뿐 READY 증빙이 아니다.
- `input_preflight.json`은 각 필수 파일의 경로와 필요 이유를 함께 기록해야 한다.
- 위 4개 파일 또는 상위 canonical 디렉터리 중 하나라도 누락되면 preflight와 submission gate는 `BLOCKED`여야 한다.

9. 정식 run 식별 규칙
- `run_id = run-<YYYYMMDDTHHMMSSZ>`
- 정규식: `^run-\d{8}T\d{6}Z$`
- `run_dir = <repo_root>/data/runs/<run_id>`

10. READY 판단 필수 산출물
- `<run_dir>/input_preflight.json`
- `<run_dir>/release_readiness.json`
- `<run_dir>/submission_gate.json`

11. READY(1) PASS 기준
- 없는 경로 호출 `0`건
- canonical smoke 명령 실행 exit code = `0`
- 동일 real-input manifest로 `3`회 반복 시 최종 판정 동일
- 필수 키 누락 `0`건
- 금지/레거시 경로 흔적 `0`건

12. 비교 제외 필드
- `generated_at`
- `duration_ms`
- temp path
- host/user 정보

## READY 판정 규칙

- `READY(1)`은 10번 필수 산출물이 모두 존재하고 11번 PASS 기준을 모두 만족할 때만 선언할 수 있다.
- `run_id`가 9번 규칙을 벗어나면 해당 실행은 `BLOCKED`다.
- `apps/report-automation` 기반 결과, placeholder 입력, synthetic fixture, dry-run 결과는 `READY(1)` 증빙이 아니다.
- 반복 실행 비교는 `submission_gate.json.decision.status`, `submission_gate.json.required_keys`, `submission_gate.json.forbidden_path_results`, `input_preflight.json.input_fingerprint`만을 기준으로 수행한다.
- `READY` 판정 자동화, CI, 수동 검토 메모 모두 이 문서의 경로와 명령만 사용한다.
