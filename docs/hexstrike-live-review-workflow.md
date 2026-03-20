# HexStrike Live Review Workflow

This workflow starts after live validation and promotion assessment artifacts already exist.

## State Separation

- `validation passed` means the live raw can be linked into the canonical observation contract
- `promotion blocked` means the run must not be promoted into `cases/web/<case-id>/input`
- `review rendered` means the operator now has a JSON summary and Markdown checklist

These states are intentionally separate.

## Command

From repo root:

```powershell
python apps\report-automation\src\cli\main.py render-live-hexstrike-review --run intake\web\hexstrike-ai\run-juice-001
```

From `apps\report-automation`:

```powershell
python -m src.cli.main render-live-hexstrike-review --run intake\web\hexstrike-ai\run-juice-001
```

## Inputs

- `manifest.json`
- `derived/promotion-decision.json`
- `derived/format-observation.json`
- `derived/shape-bridge-report.json`
- `derived/provenance.json`
- optional: `derived/live-raw-shape-summary.json`
- optional: `derived/validate-live-hexstrike.txt`

## Outputs

- `derived/promotion-review.json`
- `derived/promotion-review.md`

## Guardrails

- raw evidence remains immutable
- no rescan and no target recontact
- no guessed request/response/evidence records
- no promotion into `cases/` from this command

Both `summary_only_smoke_evidence` and `summary_nonzero_missing_detail` remain blocked review states until future finding-level evidence exists.
