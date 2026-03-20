# HexStrike Runtime Baseline

This note records the current runtime baseline and the fixed interpretation of the first approved live smoke result for `run-juice-001`.

## Date

- Baseline refreshed on `2026-03-20`
- Repository working directory: `d:\security-project`
- Target run: `intake/web/hexstrike-ai/run-juice-001`

## Runtime Summary

Current classification:

- `real scanner entrypoint confirmed`

Current approved live target:

- target name: `OWASP Juice Shop`
- canonical target: `http://192.168.10.130:3000`
- observed entry route: `http://192.168.10.130:3000/#/`

Current approved low-impact controls:

- `scan_type=passive`
- `max_depth=1`
- `max_pages=1`

## Smoke Run Outcome

One smoke run was executed after runtime discovery was confirmed.

Returned summary:

- `success=true`
- `pages_analyzed=0`
- `total_vulnerabilities=0`
- `security_score=100`

Saved raw payload:

- [hexstrike-result.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/raw/hexstrike-result.json)

Current payload classification:

- actual payload, not wrapper
- summary-only smoke linkage evidence
- not finding-ready

## Validator Outcome

The file-only validator now succeeds for the current live payload.

Verified commands:

```powershell
python apps\report-automation\src\cli\main.py validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
python -m src.cli.main validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
```

The second command was verified from `apps\report-automation`.

Current result:

- `linkage_status=pass`
- `validation_status=success`
- `observation_kind=summary-only-live-smoke`
- `finding_count_detected=0`
- `adapter_applied=true`
- `coverage_confidence=medium`
- `report_ready=false`
- `promotable_to_cases=false`

This is the required interpretation:

- `validator success != report readiness`
- `validator success != case promotion readiness`

## Current Derived Artifacts

- [validate-live-hexstrike.txt](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/validate-live-hexstrike.txt)
- [live-raw-shape-summary.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/live-raw-shape-summary.json)
- [format-observation.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/format-observation.json)
- [shape-bridge-report.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/shape-bridge-report.json)
- [synthetic-vs-live-delta.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/synthetic-vs-live-delta.json)
- [provenance.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/provenance.json)

## Promotion Baseline

Current blocker:

- the live payload contains no finding-level request, response, or evidence records

Current next requirement:

- future approved live capture must expose finding-level request/response/evidence before promotion review can reopen

Default completion path for the current run:

- keep the run under `intake/`
- do not rerun the scan by default
- do not promote into `cases/`

## Storage Rule

- runtime discovery evidence stays under `intake/.../raw/`
- live raw exports stay under `intake/web/hexstrike-ai/<run-id>/raw/`
- `validate-live-hexstrike` remains file-only
- `archive/original-sources/**` remains untouched
