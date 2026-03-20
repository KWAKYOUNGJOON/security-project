# run-juice-001

- Mode: `live-local-lab`
- Target name: `OWASP Juice Shop`
- Canonical target: `http://192.168.10.130:3000`
- Observed entry route: `http://192.168.10.130:3000/#/`
- Scope approval: approved local lab target only
- Purpose: low-impact smoke run for exporter and pipeline linkage verification
- Scanner entrypoint status: `real-scanner-entrypoint-confirmed`
- Current state: `summary-only-live-smoke-validated`

## Current Facts

- smoke run executed
- summary-only payload
- adapter bridge applied
- validation success
- promotion blocked
- next requirement: finding-level payload with request/response/evidence

## Raw Result Summary

- `success=true`
- `pages_analyzed=0`
- `total_vulnerabilities=0`
- `security_score=100`
- raw top-level keys: `scan_type`, `success`, `summary`, `target`, `timestamp`
- raw payload is the actual payload, not a wrapper or envelope

## Validator Status

Verified commands:

```powershell
python apps\report-automation\src\cli\main.py validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
python -m src.cli.main validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
```

Current result:

- `linkage_status=pass`
- `validation_status=success`
- `observation_kind=summary-only-live-smoke`
- `finding_count_detected=0`
- `warning_count=8`
- `adapter_applied=true`
- `report_ready=false`
- `promotable_to_cases=false`

Current validator stdout is recorded in `derived/validate-live-hexstrike.txt`.

## Derived Artifacts

- `derived/live-raw-shape-summary.json`
- `derived/format-observation.json`
- `derived/shape-bridge-report.json`
- `derived/synthetic-vs-live-delta.json`
- `derived/provenance.json`

## Promotion Policy

- validator success does not mean report readiness
- validator success does not mean case promotion readiness
- current smoke run succeeded as exporter/pipeline linkage evidence only
- no auto-promotion into `cases/`
- future approved live capture must confirm finding-level request/response/evidence presence before promotion review
