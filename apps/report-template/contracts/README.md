# report-payload contract

This folder documents the payload contract consumed by the Web template bridge in `apps/report-automation`.

## Current files

- `report-payload.case-001.json`: legacy single-finding example
- `report-payload.case-002.json`: preferred multi-finding report-unit example

The canonical schema lives in `shared/schemas/report-payload.schema.json`.

## Contract Shape

Current top-level payload sections:

- `document`
- `document_control`
- `engagement`
- `overview`
- `tool_inventory`
- `summary`
- `review_summary`
- `target_sections`
- `findings`
- `remediation_plan`
- `appendix`

Key points:

- `findings[]` is the authoritative detailed result list
- `target_sections[]` is the deterministic target-level aggregation used for grouped summaries
- `tool_inventory` is explicit input, not a renderer guess
- `document_control` is optional at input time but always materialized in the payload as arrays
- `appendix.evidence[]` and `findings[].evidence[]` retain provenance-oriented file paths and `sha256`
- `review_summary` carries explicit review-layer counts so the bridge can surface manual review results without guessing
- `findings[].review` carries included/excluded state, override metadata, resolution metadata, suppression metadata, exception metadata, and review history

## Legacy vs Multi-Finding

Single-finding cases remain valid, but they are normalized internally as a finding list of length 1.

Implications:

- `report-payload.case-001.json` still uses the same multi-finding contract shape
- `summary.total_findings` can be `1` or more
- template display stays centered on `finding_name` and `code`, even though internal taxonomy fields remain present

## Taxonomy Policy

Internal taxonomy fields are preserved in the payload:

- `findings[].taxonomy.name`
- `findings[].taxonomy.version`
- `findings[].canonical_key`
- `appendix.checklist[].taxonomy`
- `appendix.checklist[].canonical_key`

Template display is intentionally based on `finding_name` and `code`. Taxonomy metadata is kept for contract stability and future automation, not for user-facing label replacement.

Taxonomy collisions must be resolved before rendering. Example:

- `SF` in `web-legacy-template@1.0` -> `session_fixation`
- `SF` in `web-kisa-2026@2026` -> `ssrf`

## Hidden Default Policy

- Missing required metadata must fail in `apps/report-automation` before rendering starts
- the bridge may reshape validated payload values, but it must not silently invent document metadata, scope metadata, or tool inventory
- when a field is optional, the bridge should preserve emptiness instead of substituting a template-era placeholder default

## Review Policy

- the payload is built from reviewed findings, not directly from normalized findings
- `findings[]`, `summary.*`, `target_sections[]`, and `appendix.evidence[]` include only findings with `review.included_in_report=true`
- `review_summary` is always materialized, even when no review files exist
- `accepted_risk` remains in `findings[]` with status `수용`
- suppressed findings are excluded from the rendered body instead of being silently dropped inside the bridge
- `findings[].review.review_history[]` is the payload-side copy of the review audit trail for each included finding

## Normalized vs Reviewed

- `normalized-findings.json` preserves parser output plus deterministic taxonomy mapping and `review_key`
- `reviewed-findings.json` adds manual review metadata and reviewer-driven overrides without mutating the normalized artifact
- the bridge consumes only the reviewed payload and must not attempt to reconstruct review decisions from raw source files

## Tool Inventory Policy

- bridge output must use only `payload.tool_inventory`
- absence of tool inventory input yields an empty rendered tool list
- source provenance in findings does not authorize the bridge to synthesize a human tool list

## Document Control Policy

- `document-control.yaml` is optional input
- if present, its `history` and `approvals` are mapped into `payload.document_control`
- if absent, the bridge receives empty lists unless legacy engagement metadata supplied equivalent values
