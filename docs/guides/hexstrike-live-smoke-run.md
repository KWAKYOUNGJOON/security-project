# HexStrike Live Smoke Run

This guide fixes the current meaning of `run-juice-001`.

## Purpose

The current live run exists only to confirm:

- the real HexStrike scanner entrypoint
- one approved low-impact raw export
- file-only validator linkage from live raw into `derived/`

It is not a case seed, a report seed, or a finding-ready payload.

## Scope

- Web only
- local lab only
- OWASP Juice Shop only
- canonical target only

Target recording:

- Canonical target: `http://192.168.10.130:3000`
- Observed entry route: `http://192.168.10.130:3000/#/`

## Current State

- scanner entrypoint: confirmed
- one low-impact smoke run: executed
- raw payload: captured
- raw payload class: `summary-only smoke linkage evidence`
- validator linkage: success
- report readiness: blocked
- case promotion readiness: blocked

`validator success` here means only that the current live raw can be parsed and validated through the hardened summary-only adapter path.

It does not mean:

- `report_ready`
- `finding_ready`
- `promotable_to_cases`

## Executed Smoke Run

Executed parameters:

- `target=http://192.168.10.130:3000`
- `scan_type=passive`
- `headless=true`
- `max_depth=1`
- `max_pages=1`

Returned summary:

- `success=true`
- `pages_analyzed=0`
- `total_vulnerabilities=0`
- `security_score=100`

Saved raw payload:

- [hexstrike-result.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/raw/hexstrike-result.json)

## Validator Linkage

Verified command from repo root:

```powershell
python apps\report-automation\src\cli\main.py validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
```

Verified command from `apps\report-automation`:

```powershell
python -m src.cli.main validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
```

Both commands were executed successfully. The second command also uses the repo-relative `--run intake\...` path; `..\..\` is not required.

Current validator result:

- `adapter_applied=true`
- `validation_status=success`
- `linkage_status=pass`
- `observation_kind=summary-only-live-smoke`
- `finding_count_detected=0`
- `warning_count=8`
- `coverage_confidence=medium`
- `report_ready=false`
- `promotable_to_cases=false`

Current derived artifacts:

- [validate-live-hexstrike.txt](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/validate-live-hexstrike.txt)
- [live-raw-shape-summary.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/live-raw-shape-summary.json)
- [format-observation.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/format-observation.json)
- [shape-bridge-report.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/shape-bridge-report.json)
- [synthetic-vs-live-delta.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/synthetic-vs-live-delta.json)
- [provenance.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/provenance.json)

Review command:

```powershell
python apps\report-automation\src\cli\main.py render-live-hexstrike-review --run intake\web\hexstrike-ai\run-juice-001
```

Review artifacts:

- [promotion-review.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/promotion-review.json)
- [promotion-review.md](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/promotion-review.md)

Interpretation rule:

- `validation passed != promotion allowed != review completed`
- both `summary_only_smoke_evidence` and `summary_nonzero_missing_detail` render as blocked review states

## Adapter Safety Contract

The summary-only adapter is now intentionally narrow.

Allowed:

- actual payload shape is summary-only
- `summary.total_vulnerabilities` is a non-negative integer
- `summary.total_vulnerabilities == 0`
- finding-level objects are absent
- `summary.vulnerability_breakdown` is missing, empty, or all-zero

Fail fast:

- `summary.total_vulnerabilities > 0` with no finding objects
- `summary.total_vulnerabilities` missing, null, non-numeric, or negative
- `summary.total_vulnerabilities == 0` with non-zero breakdown counts
- ambiguous or non-numeric breakdown counts

Preserved:

- raw payload remains immutable
- raw top-level fields stay visible through `unknown_fields`
- `parser_warnings`, `unknown_fields`, and `detected_top_level_keys` remain explicit
- no guessed finding, request, response, or evidence objects are invented

## Synthetic Versus Live Delta

The comparison is now fixed in [synthetic-vs-live-delta.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/synthetic-vs-live-delta.json).

Key deltas:

- synthetic root keys are canonical; live root keys are `scan_type/success/summary/target/timestamp`
- synthetic finding count comes from `len($.findings)`; live count comes from `$.summary.total_vulnerabilities`
- synthetic includes `id/title`, severity/status strings, request/response, and evidence
- live includes no finding objects, no request/response records, and no evidence records
- synthetic preserves 3 unknown fields; live preserves 5 raw root fields
- synthetic has 3 parser warnings; live has 8 because unknown root preservation and adapter warnings are both present

Comparison conclusion:

- linkage comparison succeeded
- promotion decision remains blocked
- blocked because the live payload is still summary-only smoke linkage evidence

## Default Completion Path

For the current state, the default path ends here:

- do not rerun the scan
- keep the run under `intake/web/hexstrike-ai/run-juice-001/`
- do not auto-promote into `cases/`
- wait for a future approved live capture that contains finding-level request, response, and evidence detail
