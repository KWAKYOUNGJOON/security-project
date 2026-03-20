# HexStrike Live Promotion Policy

This note fixes the rule that `validation passed` and `promotion eligible` are separate decisions.

## Current rule

- raw evidence is immutable
- validation may succeed through adapter-first bridging
- promotion is assessed separately from validation
- summary-only live payloads remain `smoke linkage evidence only`
- non-zero summary without finding detail is also promotion blocked
- no validated live run is copied into `cases/web/<case-id>/input` until finding-level detail exists

## Evidence classes

- `summary_only_smoke_evidence`
  - zero detected findings
  - no finding-level request, response, or evidence records
  - retain as smoke linkage only
- `summary_nonzero_missing_detail`
  - summary counters indicate findings
  - but no finding detail records exist
  - still blocked
- `finding_detail_ready`
  - reserved for a future live capture with stable finding identifiers and request/response or equivalent evidence references

## Command

```powershell
cd D:\security-project\apps\report-automation
python -m src.cli.main assess-live-hexstrike-promotion --run intake\web\hexstrike-ai\run-juice-001
```

## Output

- `intake/web/hexstrike-ai/<run-id>/derived/promotion-decision.json`

The decision artifact records:

- promotion status
- case input promotion allowed or blocked
- evidence class
- blocking reasons
- advisory actions
- future requirements for any promotion attempt
