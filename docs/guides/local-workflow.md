# Local Workflow

This guide describes the supported Web-only workflow for the current repository state.

## Scope

- Web only
- `archive/original-sources/**` untouched
- `validate-live-hexstrike` remains file-only parse/validation only
- no external-target testing paths

## Operating States

1. `pre-target`

   No approved local Web target exists. Work stays under `intake/` with synthetic rehearsal or runtime capture only.

2. `live-local-lab`

   An approved local Web target exists, but the live payload is still being classified. Work stays under `intake/web/hexstrike-ai/<run-id>/`.

3. `case-ready`

   A live payload has already been reviewed and is finding-level complete enough for `cases/`.

## Current State

Current approved live-local-lab target:

- `OWASP Juice Shop`
- canonical target: `http://192.168.10.130:3000`
- observed entry route: `http://192.168.10.130:3000/#/`

Current execution state:

- one low-impact smoke run exists
- the live raw payload is summary-only smoke linkage evidence
- validator linkage succeeds
- report readiness is blocked
- case promotion readiness is blocked

## Current Workflow

1. Keep the live run under `intake/web/hexstrike-ai/run-juice-001/`.

2. Use the file-only validator to refresh derived artifacts when code or documentation changes require it.

   Verified commands:

   ```powershell
   python apps\report-automation\src\cli\main.py validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
   python -m src.cli.main validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
   ```

3. Review the derived sidecars:

   - `live-raw-shape-summary.json`
   - `format-observation.json`
   - `shape-bridge-report.json`
   - `synthetic-vs-live-delta.json`
   - `provenance.json`

4. Interpret the result correctly:

   - `validator success != report readiness`
   - `validator success != case promotion readiness`
   - current live payload is summary-only smoke linkage evidence

5. Stop without scan rerun by default.

   For the current state, the correct end point is documentation plus validation artifacts, not a second scan.

6. Reopen promotion review only after a future approved live capture provides:

   - finding-level payload objects
   - request/response records
   - evidence records

## Case Promotion Rule

Do not promote `run-juice-001` into `cases/`.

Current blocker:

- the live raw exposes no finding-level request, response, or evidence detail

Current promotion artifact:

- [synthetic-vs-live-delta.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/synthetic-vs-live-delta.json)
