# HexStrike Operator Handoff

This handoff is limited to the approved local-lab Web smoke path.

## Scope

- Web only
- approved local lab target only
- OWASP Juice Shop only
- canonical target only: `http://192.168.10.130:3000`

## Runtime Evidence

Runtime discovery remains the prerequisite for any future approved live capture.

Raw runtime evidence location:

- `intake/web/hexstrike-ai/run-juice-001/raw/runtime-discovery/`

Current confirmed entrypoint state:

- `real scanner entrypoint confirmed`

Current confirmed low-impact MCP request fields:

- `target`
- `scan_type`
- `headless`
- `max_depth`
- `max_pages`

Current low-impact controls:

- `scan_type=passive`
- `max_depth=1`
- `max_pages=1`

## Current Live Smoke Result

The first approved smoke run already happened once.

Current result summary:

- `success=true`
- `pages_analyzed=0`
- `total_vulnerabilities=0`
- `security_score=100`

Current live raw interpretation:

- actual payload, not wrapper
- summary-only payload
- smoke linkage evidence only

This run is sufficient for exporter/pipeline linkage and validator verification only.

## Validator Commands

Verified from repo root:

```powershell
python apps\report-automation\src\cli\main.py validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
```

Verified from `apps\report-automation`:

```powershell
python -m src.cli.main validate-live-hexstrike --run intake\web\hexstrike-ai\run-juice-001
```

The second command was verified exactly as written. Do not replace the repo-relative `--run intake\...` path with `..\..\`.

## Interpretation Rules

If the validator succeeds for the current payload:

- treat that as `linkage_status=pass`
- treat that as `validation_status=success`
- treat that as `observation_kind=summary-only-live-smoke`
- do not treat that as report-ready
- do not treat that as case-promotion-ready

Current blocker set:

- `promotion_blocked_summary_only`
- `finding_level_detail_required`
- `request_response_evidence_required`

Current required future evidence:

- finding-level payload
- per-finding request/response
- per-finding evidence

Review command:

```powershell
python apps\report-automation\src\cli\main.py render-live-hexstrike-review --run intake\web\hexstrike-ai\run-juice-001
```

Review outputs:

- `derived/promotion-decision.json`
- `derived/promotion-review.json`
- `derived/promotion-review.md`

Operator rule:

- `validation passed != promotion allowed != review completed`
- when review status is `blocked_summary_only` or `blocked_missing_detail`, do not promote into `cases/`
- use the review artifacts to see the next missing evidence to capture

## Current Derived Artifacts

- `derived/live-raw-shape-summary.json`
- `derived/format-observation.json`
- `derived/shape-bridge-report.json`
- `derived/synthetic-vs-live-delta.json`
- `derived/provenance.json`
- `derived/validate-live-hexstrike.txt`
- `derived/promotion-decision.json`
- `derived/promotion-review.json`
- `derived/promotion-review.md`

Use them this way:

- `live-raw-shape-summary.json`: raw payload triage
- `shape-bridge-report.json`: hardened adapter contract plus status separation
- `synthetic-vs-live-delta.json`: fixed delta artifact for promotion review
- `format-observation.json`: validator-facing observation only
- `promotion-decision.json`: machine-readable promotion gate
- `promotion-review.json`: machine-readable reviewer summary
- `promotion-review.md`: operator handoff checklist

## Default End State

For the current run, the default end state is:

- no scan rerun
- no promotion into `cases/`
- no guessed finding reconstruction
- no request/response/evidence invention

Only a future approved live capture with real finding-level request, response, and evidence detail should reopen promotion review.
