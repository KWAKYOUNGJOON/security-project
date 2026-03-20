# HexStrike Live Shape Analysis

This note records the final shape interpretation for the approved live-local-lab smoke payload at [hexstrike-result.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/raw/hexstrike-result.json).

## Triage Result

- wrapper or envelope issue: `no`
- actual payload path: `$`
- payload class: `summary-only live smoke`
- top-level keys: `scan_type`, `success`, `summary`, `target`, `timestamp`
- finding counter source: `$.summary.total_vulnerabilities`
- request/response location: absent
- evidence/screenshot location: absent

Why this is the actual payload:

- the raw root is already a plain JSON object
- no `result`, `payload`, `data`, `content`, or `response` wrapper exists
- no nested string field contains a second JSON document
- the saved object matches the scanner summary result directly

## Adapter Decision

Selected path: `summary-only zero-finding bridge`

Allowed only because all of the following are true:

- the payload is summary-only
- `summary.total_vulnerabilities == 0`
- `summary.total_vulnerabilities` is numeric and non-negative
- finding-level objects are absent
- `summary.vulnerability_breakdown` is empty

Fail-fast conditions now fixed in code:

- positive `total_vulnerabilities` without finding objects
- missing, null, non-numeric, or negative `total_vulnerabilities`
- `total_vulnerabilities == 0` with non-zero breakdown counts
- ambiguous or non-numeric breakdown counts

What the bridge still does not do:

- it does not rewrite `raw/hexstrike-result.json`
- it does not fabricate finding objects
- it does not invent request, response, or evidence fields
- it does not weaken finding-level required-field checks

The hardened contract is recorded in [shape-bridge-report.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/shape-bridge-report.json).

## Status Separation

Current machine-readable status is stored in [shape-bridge-report.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/shape-bridge-report.json).

Current values:

- `linkage_status=pass`
- `validation_status=success`
- `observation_kind=summary-only-live-smoke`
- `report_ready=false`
- `promotable_to_cases=false`
- `summary_only_payload=true`
- `adapter_applied=true`
- `finding_detail_presence=false`
- `request_response_presence=false`
- `evidence_presence=false`

Current reason codes:

- `summary_only_payload`
- `zero_vuln_smoke_bridge`
- `no_finding_level_payload`
- `no_request_response_evidence`

Current blocker codes:

- `promotion_blocked_summary_only`
- `finding_level_detail_required`
- `request_response_evidence_required`

## Synthetic Versus Live

The comparison is now fixed in [synthetic-vs-live-delta.json](/d:/security-project/intake/web/hexstrike-ai/run-juice-001/derived/synthetic-vs-live-delta.json).

Key deltas:

- synthetic root keys are canonical; live root keys are summary-only
- synthetic detects findings from `$.findings`; live detects from `$.summary.total_vulnerabilities`
- synthetic exposes `id/title`, severity/status strings, request/response, and evidence
- live exposes no finding objects, no request/response, and no evidence
- synthetic unknown fields are `metadata`, `confidence`, and `experimental_trace`
- live unknown fields are the five raw root keys preserved during validation
- synthetic parser warnings count is `3`; live parser warnings count is `8`

## Promotion Decision

Current conclusion:

- linkage comparison succeeded
- promotion decision remains blocked

Why blocked:

- validator success only proves smoke linkage and file-only validation
- the live payload is still summary-only smoke linkage evidence
- no finding-level request, response, or evidence exists to seed a case or report
