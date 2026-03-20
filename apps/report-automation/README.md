# report-automation

`apps/report-automation` is the phase-1 Python automation scaffold for local Web report assembly.

## Scope

- Current implementation scope: `Web`
- Planned future scope: `Web + API + Server`
- Current report unit model: one case directory contains one report and one or more Web findings
- External SaaS or API calls: not used in the case pipeline

## Pipeline

The current deterministic local flow is:

`raw scan result -> normalized finding(s) -> reviewed finding(s) -> report payload -> report-template preview`

`apps/report-template/build_report.py` remains the renderer entrypoint. `apps/report-automation` owns validation, normalization, aggregation, provenance, and bridge shaping.

Pre-target and live-local-lab intake are separate file-based paths:

`intake raw -> format observation -> intake provenance`

It does not generate normalized findings or report payloads.

## Commands

Run from `apps/report-automation`:

```powershell
python -m src.cli.main build-all --case cases/web/case-001
python -m src.cli.main build-all --case cases/web/case-002
python -m src.cli.main build-all --case cases/web/case-003
python -m src.cli.main normalize --case cases/web/case-001
python -m src.cli.main apply-review --case cases/web/case-003
python -m src.cli.main build-payload --case cases/web/case-001
python -m src.cli.main render-report --case cases/web/case-001
python -m src.cli.main validate-live-hexstrike --run intake\synthetic\hexstrike-ai\rehearsal-001
```

`intake\web\hexstrike-ai\run-001` remains the pre-target baseline run.
`intake\web\hexstrike-ai\run-juice-001` now contains the first low-impact local-lab smoke raw payload, and `validate-live-hexstrike` can now generate `format-observation.json` for that run through a summary-only adapter.
The run still stays intake-only because the smoke payload contains no finding-level request, response, or evidence detail.

Legacy scaffold commands remain available:

```powershell
python -m src.cli.main
python -m src.cli.main --output ..\..\outputs\exports\sample-report-payload.json
```

Regression-focused test set:

```powershell
python -m unittest tests.test_smoke tests.test_schema_validation tests.test_manual_finding_schema tests.test_taxonomy_mapping tests.test_web_case_e2e tests.test_web_case_multi_e2e tests.test_provenance_ledger tests.test_tool_inventory_contract tests.test_document_control_optional tests.test_web_case_golden tests.test_review_key_stability tests.test_review_override tests.test_review_suppression tests.test_review_resolution tests.test_review_no_input_backward_compat tests.test_web_case_review_e2e tests.test_review_golden tests.test_hexstrike_pretarget_intake
```

## Case Models

Legacy single-finding case is still supported:

```text
cases/web/case-001/
  input/
    engagement.yaml
    target.json
    manual-finding.yaml
    raw/hexstrike-result.json
    http/request.txt
    http/response.txt
    evidence/*.png
```

Preferred multi-finding report unit:

```text
cases/web/case-002/
  input/
    engagement.yaml
    document-control.yaml          # optional
    tool-inventory.yaml            # explicit optional, no bridge guessing
    findings/
      F-001/
        manual-finding.yaml
        raw/hexstrike-result.json
        http/request.txt
        http/response.txt
        evidence/*.png
      F-002/
      F-003/
```

Review-enabled report unit:

```text
cases/web/case-003/
  input/
    engagement.yaml
    document-control.yaml          # optional
    tool-inventory.yaml            # optional
    findings/
      F-001/...
      F-002/...
      F-003/...
      F-004/...
  review/
    overrides.yaml                 # optional
    suppressions.yaml              # optional
    resolutions.yaml               # optional
    exceptions.yaml                # optional
```

Loader behavior:

- If `input/findings/*` exists, multi-finding mode is used.
- If not, the legacy single-finding layout is loaded and wrapped internally as a finding list of length 1.
- `case-001` therefore stays compatible without changing the CLI.

## Input Contracts

Required:

- `engagement.yaml`
- `manual-finding.yaml` for each finding
- raw scan JSON for each finding
- request/response text for each finding
- at least one evidence file for each finding

Explicit optional:

- `document-control.yaml`
- `tool-inventory.yaml`
- `review/overrides.yaml`
- `review/suppressions.yaml`
- `review/resolutions.yaml`
- `review/exceptions.yaml`

Validation rules:

- `manual-finding.yaml` is validated by `shared/schemas/manual-finding.schema.json`
- `engagement.yaml` is validated by `shared/schemas/engagement-metadata.schema.json`
- `document-control.yaml` is validated by `shared/schemas/document-control.schema.json`
- `tool-inventory.yaml` is validated by `shared/schemas/tool-inventory.schema.json`
- `review/overrides.yaml` is validated by `shared/schemas/review-override.schema.json`
- `review/suppressions.yaml` is validated by `shared/schemas/review-suppression.schema.json`
- `review/resolutions.yaml` is validated by `shared/schemas/review-resolution.schema.json`
- `review/exceptions.yaml` is validated by `shared/schemas/review-exception.schema.json`
- required metadata is not synthesized silently; validation must fail or the field must be explicitly optional

Review input format:

- `overrides.yaml`: `review_key`, `changes`, `reason`, `reviewer`, `reviewed_at`
- `suppressions.yaml`: `review_key`, `action=exclude_from_report`, `reason_code`, `reason`, `reviewer`, `reviewed_at`
- `resolutions.yaml`: `review_key`, `resolution`, `final_status`, `reason`, `reviewer`, `reviewed_at`
- `exceptions.yaml`: `review_key`, `exception_type`, `approved_by`, `expires_at`, `note`

Tool inventory policy:

- the bridge must read tools only from `payload.tool_inventory`
- it must not infer tools from raw findings, parsers, or template defaults
- absence of `tool-inventory.yaml` means `tool_inventory: []`, not guessed placeholders

Document control policy:

- `document-control.yaml` is optional
- if present, it is mapped to `payload.document_control`
- if absent, the payload keeps empty `history` and `approvals` unless legacy `engagement.document.history/approvals` values exist

## Taxonomy And Canonical Keys

- `classification.code` is not a stable internal identifier by itself
- each normalized finding carries:
  - `review_key`
  - `classification.taxonomy.name`
  - `classification.taxonomy.version`
  - `classification.canonical_key`
- taxonomy files live under `shared/taxonomies/`
- collisions are resolved by `canonical_key`
- example: `SF` means `session_fixation` in `web-legacy-template@1.0`, but `ssrf` in `web-kisa-2026@2026`
- KISA mappings are reference taxonomies, not an automatic good/bad rule engine

Review key policy:

- `review_key` is generated during normalization from a fingerprint of taxonomy, canonical key, target/service URL context, HTTP method/parameter, tool name, and raw source path
- it is immutable once written into `normalized-findings.json`
- review matching is exact by `review_key`; missing keys fail fast
- duplicate `review_key` values inside one case are rejected

Review application policy:

- review is a separate post-normalization layer; `normalized-findings.json` is never mutated in place
- application order is fixed: `overrides -> resolutions -> suppressions -> exceptions`
- duplicate actions of the same type for one `review_key` are rejected
- if both `resolution` and `suppression` exist for one finding, suppression wins for `included_in_report`
- `accepted_risk` must map to `final_status=accepted`
- `fixed` must map to `final_status=closed`
- `false_positive`, `duplicate`, and `not_applicable` must map to `final_status=excluded`

## Outputs

Canonical outputs for a case are:

```text
cases/web/<case-id>/
  derived/
    normalized-findings.json
    reviewed-findings.json
    review-log.json
    report-payload.json
    provenance.json
  output/
    report-preview.html
    report-preview.validation.json
    report-preview.pdf
```

Single-finding backward compatibility:

- when a case contains exactly one finding, `derived/normalized-finding.json` is also written
- canonical automation logic should prefer `normalized-findings.json`

Output contracts:

- `normalized-finding.schema.json`: per-finding contract
- `normalized-findings.schema.json`: case-level wrapper
- `reviewed-findings.schema.json`: post-review case-level wrapper
- `review-log.schema.json`: manual review audit trail
- `report-payload.schema.json`: renderer bridge contract
- `provenance.schema.json`: input/output ledger contract

Provenance policy:

- `derived/provenance.json` records input and output file paths with `sha256`
- inputs are tagged by role such as `engagement`, `manual-finding`, `raw`, `http`, `evidence`, `tool-inventory`, `document-control`, and `review-*`
- the ledger is for reproducibility and drift detection, not for mutating source files
- `provenance.json` does not include its own file hash in `outputs`; the self-hash exclusion policy remains intentional

Pre-target intake policy:

- `validate-live-hexstrike` is file-based only and must not touch a network target
- live intake originals stay under `intake/web/hexstrike-ai/<run-id>/raw/`
- synthetic rehearsal fixtures stay under `intake/synthetic/...`
- `format-observation.json` is generated under `intake/.../derived/format-observation.json`
- `live-raw-shape-summary.json` records wrapper-versus-payload triage for live runs
- `shape-bridge-report.json` records adapter coverage when a known live shape needs a validation-only bridge
- case-derived artifacts remain under `cases/.../derived`
- if no real HexStrike scanner `help/version` is available in the current environment, a live smoke run must be blocked rather than improvised

Reviewed artifact policy:

- `reviewed-findings.json` contains the post-review finding set with per-finding `review` metadata
- `reviewed.findings[].review.included_in_report` determines whether a finding flows into the payload/detail sections
- `review-log.json` is the human-diff-friendly audit trail of every reviewer action
- when review input is absent, reviewed artifacts still exist with empty review histories and `included_in_report=true`

Report inclusion policy:

- report detail sections use reviewed findings, not raw normalized findings
- suppressed findings are excluded from payload summaries, target sections, detailed findings, evidence appendix, and HTML detail sections
- `accepted_risk` remains in the report body with status `수용`
- `fixed` is excluded from the default detail body unless a future retest-specific contract is added
- review summary counts remain visible in `payload.review_summary` and in the rendered summary comment

## Hidden Default Policy

- the bridge may transform validated payload fields into template dataset fields
- it must not invent business metadata that was not provided by input or normalized data
- adding new hidden template defaults is out of scope
- if a field is optional, it should remain empty or absent by contract instead of being guessed

## Assumptions

- Web only
- lightweight built-in YAML subset parser
- immutable input files
- repo-relative paths with forward slashes in artifacts
- conservative raw mapping: unknown values are preserved in `source.raw` and `unmapped_fields`

## Remaining TODO

- multi-finding is supported only for `Web`
- API and Server adapters remain out of scope
- target criticality is carried for future deterministic prioritization but is not yet used as a tie-breaker
- the bridge groups multi-finding results by target and aggregates remediation, but template-native section design can still be improved later
- when a real local Web target is ready, the next step is to capture a live raw payload into `intake/web/hexstrike-ai/<run-id>/raw/`, run `validate-live-hexstrike`, compare its observation with the synthetic rehearsal, and only then promote stable inputs into a `cases/web/<case-id>/input/` workflow
- for the current Juice Shop smoke run, the raw shape now connects to the intake validator through a summary-only adapter, but it is still insufficient for `cases/` promotion
