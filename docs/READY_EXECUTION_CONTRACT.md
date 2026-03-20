# READY Execution Contract

`READY` 판정은 이 문서를 단일 기준으로 사용한다. `apps/report-automation` 계열 문서와 실행 예시는 참고 자료이며, `READY(1)` 판정 근거로 사용하지 않는다.

기준일:
- `2026-03-21`

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
- 기타 `app/vuln-pipeline` 이외의 `READY` 판정 경로 호출

5. Python 버전
- 최소 버전: `3.11.x`

6. 환경 준비 명령
- 정식 작업 디렉터리에서 `python -m pip install -e .`

7. 기본 smoke 명령
- 정식 작업 디렉터리에서 `python -m vuln_pipeline.cli.main smoke --output-dir ../../outputs/ready1/smoke`

8. 정식 입력 루트
- `<repo_root>/data/inputs/real`
- 허용 하위 경로: `burp/`, `nuclei/`, `httpx/`, `manual/`

9. READY(1) 최소 real-input 세트
- `burp/burp-findings.json`
- `nuclei/nuclei-findings.json`
- `httpx/httpx-hosts.json`
- `manual/manual-findings.json`

10. 정식 run 디렉터리
- 기본 smoke 출력 예시: `<repo_root>/outputs/ready1/smoke`
- 반복 검증 출력 예시: `<repo_root>/outputs/ready1/run-1`, `<repo_root>/outputs/ready1/run-2`, `<repo_root>/outputs/ready1/run-3`

11. READY 판단 필수 산출물
- `<run_dir>/input_preflight.json`
- `<run_dir>/release_readiness.json`
- `<run_dir>/submission_gate.json`

12. READY(1) PASS 기준
- 없는 경로 호출 `0`건
- 공식 smoke 명령 exit code = `0`
- 동일 real-input 세트로 `2~3`회 반복 시 최종 판정 동일
- 반복 실행 간 필수 키 동일
- 반복 실행 간 금지/레거시 경로 결과 동일

13. 비교 기준
- `submission_gate.json`의 `decision.status`
- `submission_gate.json`의 `required_keys`
- `submission_gate.json`의 `forbidden_path_results`
- `input_preflight.json`의 `input_fingerprint`

## READY 판정 규칙

- `READY(1)`은 11번 필수 산출물이 모두 존재하고 12번 PASS 기준을 모두 만족할 때만 선언할 수 있다.
- 반복 실행 비교는 `python -m vuln_pipeline.cli.main compare-runs --run-dir ../../outputs/ready1/run-1 --run-dir ../../outputs/ready1/run-2 --run-dir ../../outputs/ready1/run-3`로 검증한다.
- `READY` 판정 자동화, CI, 수동 검토 메모 모두 이 문서의 경로와 명령만 사용한다.
